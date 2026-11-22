#!/usr/bin/env python3
"""IPTM network guard: configuration snapshots and console-only firewall rescue.

The rescue action can restore live IPv4 firewall rules; it never changes
NetworkManager, interfaces, DHCP, routes or CAKE. Backups are root-only.
"""
from __future__ import annotations
import hashlib
import subprocess
import shutil
import fcntl
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import stat
import sys
import tempfile
import time
import resource

from network_audit import MAX_FILE_BYTES, MAX_FILES, audit, validate_dhcp

VERSION = '5.20.22'
ROOT = Path('/')
SNAPSHOTS = Path('/var/lib/iptm-network-guard/snapshots')
ID_RE = re.compile(r'^[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}$')
MAX_REQUEST = 8192

class GuardError(ValueError):
    pass


def _safe_relative(name: str) -> tuple[str, ...]:
    if not isinstance(name, str) or not name.startswith('/') or '\\' in name or '\x00' in name:
        raise GuardError('Percorso backup non valido')
    parts = PurePosixPath(name[1:]).parts
    if not parts or any(p in ('', '..', '.') for p in parts):
        raise GuardError('Percorso backup non valido')
    return parts


def _safe_read(root: Path, absolute: str, *, max_bytes: int = MAX_FILE_BYTES) -> tuple[bytes, os.stat_result]:
    """Read a root-owned regular file without following symlinks in any component."""
    parts = _safe_relative(absolute)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd);fd = next_fd
        file_fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        try:
            meta = os.fstat(file_fd)
            if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or
                meta.st_size > max_bytes or meta.st_size < 0 or meta.st_mode & 0o002):
                raise GuardError('File configurazione non idoneo al backup: '+absolute)
            with os.fdopen(os.dup(file_fd), 'rb') as handle:
                raw = handle.read(max_bytes + 1)
            if len(raw) > max_bytes: raise GuardError('File configurazione troppo grande: '+absolute)
            return raw, meta
        finally:os.close(file_fd)
    finally:os.close(fd)


def _private_directory(path: Path, create: bool = True) -> None:
    if path.is_symlink(): raise GuardError('Directory snapshot simbolica non consentita')
    if create: path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not path.is_dir(): raise GuardError('Directory snapshot mancante')
    meta = path.stat()
    if meta.st_uid != 0 or meta.st_mode & 0o077:
        raise GuardError('Directory snapshot non privata: richiede root:0700')


def _write_private(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(data);handle.flush();os.fsync(handle.fileno())
    except BaseException:
        try:path.unlink()
        except OSError:pass
        raise


def create_snapshot(report: dict, *, source: Path = ROOT, store: Path = SNAPSHOTS) -> dict:
    """Capture exact network config bytes in an isolated root-only directory.

    No automatic restore: modifying a live NIC requires an independent watchdog.
    Never return contents, only paths/hashes/counts. Fail on incomplete inventory.
    """
    if report.get('scan_complete') is not True:
        raise GuardError('Inventario parziale: backup rifiutato')
    entries = report.get('network_files')
    if not isinstance(entries, list) or len(entries) > MAX_FILES or not entries:
        raise GuardError('Inventario configurazioni assente o troppo esteso')
    _private_directory(store.parent)
    _private_directory(store)
    stamp=time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
    ident=stamp+'-'+secrets.token_hex(6)
    folder=store/ident
    os.mkdir(folder,0o700)
    try:
        meta=[]; already=set()
        for row in entries:
            if not isinstance(row,dict):raise GuardError('Voce inventario non valida')
            rel=row.get('path')
            parts=_safe_relative(rel)
            if rel in already:raise GuardError('Duplicato inventario: '+rel)
            already.add(rel)
            expected=row.get('sha256')
            if not isinstance(expected,str) or not re.fullmatch('[0-9a-f]{64}',expected):
                raise GuardError('Digest inventario assente: '+rel)
            raw,st=_safe_read(source, rel)
            digest=hashlib.sha256(raw).hexdigest()
            if digest!=expected:raise GuardError('Configurazione cambiata durante il backup: '+rel)
            dest=folder/'files'
            for part in parts[:-1]:
                dest=dest/part
            dest.mkdir(parents=True,exist_ok=True,mode=0o700)
            # All subdirectories are private even if umask is restrictive.
            if any(p.is_symlink() for p in (folder/'files',dest)):raise GuardError('Directory backup simbolica')
            target=dest/parts[-1]
            _write_private(target,raw)
            meta.append({'path':rel,'sha256':digest,'size':len(raw),
                         'source_mode':stat.S_IMODE(st.st_mode),'source_uid':st.st_uid,'source_gid':st.st_gid})
        document={'schema':1,'version':VERSION,'id':ident,'created_utc':stamp,
                  'warning':'Backup root locale: include eventuali segreti; non pubblicare sul web',
                  'files':meta}
        data=json.dumps(document,sort_keys=True,separators=(',',':')).encode()
        _write_private(folder/'manifest.json',data)
        # Guard against incomplete writes when power is lost.
        for p in (folder/'files',folder):
            fd=os.open(p,os.O_DIRECTORY|os.O_RDONLY|os.O_NOFOLLOW)
            try:os.fsync(fd)
            finally:os.close(fd)
        return {'ok':True,'id':ident,'files':len(meta),'root_only':True,
                'restored':False,'secrets_included':True,'live_changes':False}
    except BaseException:
        import shutil
        shutil.rmtree(folder)
        raise


def verify_snapshot(ident: str, *, source: Path = ROOT, store: Path = SNAPSHOTS) -> dict:
    if not isinstance(ident,str) or not ID_RE.fullmatch(ident):raise GuardError('Identificativo snapshot non valido')
    _private_directory(store,create=False)
    folder=store/ident
    _private_directory(folder,create=False)
    raw,_=_safe_read(folder,'/manifest.json',max_bytes=256*1024)
    try:doc=json.loads(raw)
    except (ValueError,UnicodeError) as e:raise GuardError('Manifest snapshot non valido') from e
    if doc.get('schema') != 1 or doc.get('id') != ident or not isinstance(doc.get('files'),list):
        raise GuardError('Manifest snapshot incoerente')
    results=[]; paths=set()
    for row in doc['files']:
        if not isinstance(row,dict):raise GuardError('Voce manifest non valida')
        path=row.get('path');_safe_relative(path)
        if path in paths:raise GuardError('Voce duplicata nel manifest')
        paths.add(path);expected=row.get('sha256')
        if not isinstance(expected,str) or not re.fullmatch('[0-9a-f]{64}',expected):
            raise GuardError('Digest manifest malformato')
        backup,_=_safe_read(folder/'files',path)
        if hashlib.sha256(backup).hexdigest()!=expected:raise GuardError('Backup alterato: '+path)
        try:
            current,_=_safe_read(source,path)
            state='unchanged' if hashlib.sha256(current).hexdigest()==expected else 'modified'
        except (OSError,GuardError):state='missing-or-unreadable'
        results.append({'path':path,'status':state})
    return {'ok':True,'id':ident,'files_checked':len(results),
            'unchanged':sum(x['status']=='unchanged' for x in results),
            'changes':[x for x in results if x['status']!='unchanged'],
            'restore_performed':False}


def preflight(report: dict, *, dhcp: dict | None = None) -> dict:
    """A deployment gate, not a promise that a remote upgrade cannot disconnect."""
    blocker=[];warnings=[]
    links={x.get('name'):x for x in report.get('interfaces',[]) if isinstance(x,dict) and x.get('name')}
    services=report.get('services') or {}
    actives={k for k,v in services.items() if isinstance(v,dict) and v.get('active')}
    if report.get('scan_complete') is not True: blocker.append('inventario-file-incompleto')
    if not links: blocker.append('nessuna-interfaccia-verificata')
    if not any(x.get('physical') is True for x in links.values()):
        blocker.append('nessuna-nic-fisica-verificata')
    if not report.get('routes'):
        warnings.append('route-non-verificate')
    if 'iptm-wanfo.timer' in actives:
        blocker.append('legacy-multiwan-timer-attivo')
    if {'NetworkManager','systemd-networkd'}.issubset(actives):
        blocker.append('gestori-networkmanager-networkd-concorrenti')
    if 'networking' in actives and 'NetworkManager' in actives:
        warnings.append('verificare-ownership-networkmanager-ifupdown')
    if report.get('dhcp_listeners')!='collected':
        warnings.append('udp67-non-verificabile')
    for signal in report.get('warnings', []):
        if not isinstance(signal,dict):continue
        code=signal.get('code')
        if code in ('physical-link-not-ready','bond-redundancy-unavailable','bond-multiple-ipv4-subnets'):
            warnings.append(str(code) + ':' + str(signal.get('interface','unknown')))
    pihole=report.get('pihole') or {}
    if not pihole.get('installed_config'):
        warnings.append('config-pihole-non-rilevata')
    dhcp_plan=None
    if dhcp is not None:
        if not isinstance(dhcp,dict) or set(dhcp)!={'primary','secondary'}:
            raise GuardError('Configurazione doppio DHCP non valida')
        dhcp_plan=validate_dhcp(dhcp['primary'],dhcp['secondary'])
        first=dhcp_plan['primary']['interface'];second=dhcp_plan['secondary']['interface']
        if first not in links or second not in links:
            blocker.append('interfaccia-dhcp-mancante')
        if pihole.get('dhcp',{}).get('verified') is not True or 'pihole-FTL' not in actives:
            blocker.append('pihole-primario-non-verificato')
        if any(x in actives for x in ('dnsmasq','isc-dhcp-server','kea-dhcp4-server','udhcpd')):
            blocker.append('secondo-server-dhcp-gia-attivo-verificare-binding')
        first_master=links.get(first,{}).get('master')
        second_master=links.get(second,{}).get('master')
        if first_master and first_master==second_master:
            blocker.append('dhcp-stesso-bridge-l2')
        # This can only be proven with switch/VLAN inventory and packet captures.
        blocker.append('isolamento-l2-da-confermare-in-console')
        blocker.append('udp67-binding-e-pihole-api-da-validare')
    # Always fail closed: no real route/DHCP/manager migration through this command.
    return {'version':VERSION,'ok':True,'mode':'read-only',
            'physical_nics':sum(x.get('physical') is True for x in links.values()),
            'interfaces':sorted(links),'active_managers':sorted(actives.intersection({'NetworkManager','networking','systemd-networkd','dhcpcd'})),
            'blockers':sorted(set(blocker)),'warnings':sorted(set(warnings)),
            'dhcp_plan':dhcp_plan,'backup_recommended':True,
            'can_apply_live':False,'changes_performed':False,
            'next':'Acquisire snapshot root e verificare accesso console + L2/DHCP prima di eventuale trial'}


# Root-only last-known-working firewall snapshot. It never changes NetworkManager,
# DNS, the WAN route, or CAKE. It exists for the common case where an IPTM
# firewall policy made the web application unreachable.
RESCUE_ROOT = Path('/var/lib/iptm-network-guard/rescue')


def _rescue_command(argv, data=None, *, runner=None):
    call = runner or subprocess.run
    try:
        p=call(argv,input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
               timeout=18,check=False)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise GuardError('Ripristino: comando non disponibile: '+argv[0]) from exc
    if p.returncode:
        raise GuardError('Ripristino: '+argv[0]+' ha restituito exit '+str(p.returncode))
    if len(p.stdout)>4*1024*1024:
        raise GuardError('Ripristino: output troppo grande')
    return p.stdout


# A bounded, file-backed snapshot avoids capturing very large ipset output in
# subprocess.PIPE. Limits are intentionally finite to avoid disk exhaustion.
RESCUE_IPSET_MAX = 32 * 1024 * 1024
RESCUE_IPTABLES_MAX = 2 * 1024 * 1024


def _rescue_capture_file(argv, dest: Path, *, max_bytes: int, runner=None) -> tuple[str, int]:
    fd=os.open(dest,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,'wb') as output:
            os.fchmod(output.fileno(),0o600)
            if runner is not None:
                # Test injection uses the original CompletedProcess interface.
                result=runner(argv,input=None,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=45,check=False)
                if result.returncode:
                    raise GuardError('Ripristino: comando fallito: '+argv[0])
                value=result.stdout
                if len(value)>max_bytes:
                    raise GuardError('Ripristino: output troppo grande: '+argv[0])
                output.write(value)
            else:
                def limit_file_size():
                    resource.setrlimit(resource.RLIMIT_FSIZE,(max_bytes,max_bytes))
                try:
                    subprocess.run(argv,stdout=output,stderr=subprocess.DEVNULL,
                                   check=True,timeout=45,preexec_fn=limit_file_size)
                except (OSError,subprocess.TimeoutExpired,subprocess.CalledProcessError) as exc:
                    raise GuardError('Ripristino: acquisizione non riuscita: '+argv[0]) from exc
            output.flush();os.fsync(output.fileno())
    except BaseException:
        dest.unlink(missing_ok=True)
        raise
    size=dest.stat().st_size
    if size>max_bytes:
        dest.unlink(missing_ok=True)
        raise GuardError('Ripristino: output troppo grande: '+argv[0])
    digest=hashlib.sha256()
    with dest.open('rb') as handle:
        for chunk in iter(lambda:handle.read(65536),b''):
            digest.update(chunk)
    return digest.hexdigest(),size


def _rescue_read_folder(folder: Path):
    _private_directory(folder,create=False)
    manifest_bytes,_=_safe_read(folder,'/manifest.json',max_bytes=8192)
    meta=json.loads(manifest_bytes)
    if meta.get('schema')!=1 or meta.get('kind')!='firewall-live' or\
        set(meta.get('sha256',{}))!={'iptables.v4','ipsets.txt'}:
        raise GuardError('Snapshot rescue non valido')
    results={}
    for name in ('iptables.v4','ipsets.txt'):
        raw,_=_safe_read(folder,'/'+name,max_bytes=RESCUE_IPSET_MAX if name=='ipsets.txt' else RESCUE_IPTABLES_MAX)
        if hashlib.sha256(raw).hexdigest()!=meta['sha256'][name]:
            raise GuardError('Integrità snapshot non verificata: '+name)
        results[name]=raw
    if b'*filter\n' not in results['iptables.v4'] or b'COMMIT\n' not in results['iptables.v4']:
        raise GuardError('Regole IPv4 salvate non valide')
    return meta,results


def rescue_save(*, root=RESCUE_ROOT, runner=None):
    """Capture last-known-working firewall without altering live rules.

    Stage and verify fully before atomic publish. A failed capture never rotates
    the previous known-good snapshot.
    """
    _private_directory(root.parent)
    _private_directory(root)
    fd=os.open(root/'lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX)
        # Reserve room for new + old snapshots; do not overwrite on low disk.
        free=shutil.disk_usage(root).free
        if free < 3*(RESCUE_IPSET_MAX+RESCUE_IPTABLES_MAX):
            raise GuardError('Ripristino: spazio disco insufficiente per snapshot sicuro')
        tmp=Path(tempfile.mkdtemp(prefix='.rescue-',dir=root))
        try:
            iphash,ipsize=_rescue_capture_file(['iptables-save'],tmp/'iptables.v4',
                                                   max_bytes=RESCUE_IPTABLES_MAX,runner=runner)
            # Must be an actual parseable-looking ruleset before committing anything.
            with (tmp/'iptables.v4').open('rb') as handle:
                ipbytes=handle.read(RESCUE_IPTABLES_MAX+1)
            if b'*filter\n' not in ipbytes or b'COMMIT\n' not in ipbytes:
                raise GuardError('Firewall attivo non leggibile, snapshot rifiutato')
            if shutil.which('ipset'):
                sethash,setsize=_rescue_capture_file(['ipset','save'],tmp/'ipsets.txt',
                                                  max_bytes=RESCUE_IPSET_MAX,runner=runner)
            else:
                _write_private(tmp/'ipsets.txt',b'')
                sethash=hashlib.sha256(b'').hexdigest();setsize=0
            manifest={'schema':1,'kind':'firewall-live','created_at':int(time.time()),
                'sha256':{'iptables.v4':iphash,'ipsets.txt':sethash},
                'size':{'iptables.v4':ipsize,'ipsets.txt':setsize}}
            _write_private(tmp/'manifest.json',json.dumps(manifest,sort_keys=True).encode())
            _rescue_read_folder(tmp)  # Verify before touching previous generations.
            # Preserve the most recent known-good on a failure during publication.
            prior=root/'previous';current=root/'last-good';old=root/'.previous-old'
            if old.exists() or old.is_symlink():
                raise GuardError('Ripristino: rotazione incompleta da recuperare')
            for existing in (prior,current):
                if existing.exists() or existing.is_symlink():
                    _rescue_read_folder(existing)
            if prior.exists():os.replace(prior,old)
            try:
                if current.exists():os.replace(current,prior)
                try:os.replace(tmp,current)
                except BaseException:
                    if prior.exists():os.replace(prior,current)
                    raise
            except BaseException:
                if old.exists():os.replace(old,prior)
                raise
            if old.exists():shutil.rmtree(old)
            dirfd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:os.fsync(dirfd)
            finally:os.close(dirfd)
        finally:
            if tmp.exists():shutil.rmtree(tmp)
    finally:os.close(fd)
    return {'ok':True,'saved':True,'scope':'firewall-ipv4','network_manager_unchanged':True}


def rescue_read(*, root=RESCUE_ROOT):
    _private_directory(root,create=False)
    return _rescue_read_folder(root/'last-good')


def rescue_restore(*, root=RESCUE_ROOT, runner=None, interactive=True):
    """Emergency restore of confirmed live firewall, never interface settings."""
    if interactive:
        try:fd=os.open('/dev/tty',os.O_RDONLY|os.O_NOCTTY)
        except OSError as exc:raise GuardError('Richiesta console root per il recupero') from exc
        else:os.close(fd)
    _private_directory(root,create=False)
    lock=root/'lock'
    fd=os.open(lock,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX)
        # Read under the same lock used for snapshot rotation.
        meta,parts=rescue_read(root=root)
        if parts['ipsets.txt']:
            _rescue_command(['ipset','restore','-exist'],parts['ipsets.txt'],runner=runner)
        _rescue_command(['iptables-restore','--test'],parts['iptables.v4'],runner=runner)
        # Capture the pre-rescue rules in a separate private file to allow recovery
        # if a previously healthy snapshot no longer matches new runtime services.
        old=_rescue_command(['iptables-save'],runner=runner)
        if b'*filter\n' not in old or b'COMMIT\n' not in old:
            raise GuardError('Regole correnti non recuperabili, ripristino annullato')
        if (root/'pre-rescue.v4').exists() or (root/'pre-rescue.v4').is_symlink():
            (root/'pre-rescue.v4').unlink()
        _write_private(root/'pre-rescue.v4',old)
        _rescue_command(['iptables-restore'],parts['iptables.v4'],runner=runner)
        # The persistent rules are not overwritten automatically: this avoids
        # interfering with netfilter-persistent and IP sets restored at boot.
        return {'ok':True,'restored':'firewall-live','source_saved_at':meta['created_at'],
                'manager_changes':False,'requires_persistence_review':True}
    finally:os.close(fd)


def rescue_action(argv):
    if argv==['save']:return rescue_save()
    if argv==['status']:
        try:
            meta,_=rescue_read()
            return {'ok':True,'available':True,'saved_at':meta['created_at'],'scope':'firewall-ipv4'}
        except (OSError,ValueError,TypeError,GuardError):
            return {'ok':True,'available':False,'scope':'firewall-ipv4'}
    if argv==['restore'] or argv==[]:return rescue_restore()
    raise GuardError('Uso: rescue [save|status|restore]')


def main(argv: list[str]) -> int:
    if os.geteuid() != 0:
        print(json.dumps({'ok':False,'error':'Solo root via console/helper autorizzato'}));return 1
    try:
        if argv and argv[0]=='rescue':
            print(json.dumps(rescue_action(argv[1:]),ensure_ascii=False));return 0
        if argv == ['preflight']:
            print(json.dumps(preflight(audit()),ensure_ascii=False));return 0
        if argv == ['snapshot']:
            if not sys.stdin.isatty():
                raise GuardError('Snapshot consentito solo da console root TTY')
            print(json.dumps(create_snapshot(audit()),ensure_ascii=False));return 0
        if len(argv)==2 and argv[0]=='verify':
            print(json.dumps(verify_snapshot(argv[1]),ensure_ascii=False));return 0
        if argv == ['dhcp-preflight']:
            data=sys.stdin.buffer.read(MAX_REQUEST+1)
            if len(data)>MAX_REQUEST:raise GuardError('Input oltre 8KiB')
            doc=json.loads(data)
            print(json.dumps(preflight(audit(),dhcp=doc),ensure_ascii=False));return 0
        raise GuardError('Uso: preflight|snapshot|verify ID|dhcp-preflight')
    except (GuardError,ValueError,TypeError,OSError) as e:
        print(json.dumps({'ok':False,'error':str(e)},ensure_ascii=False));return 2

if __name__=='__main__':raise SystemExit(main(sys.argv[1:]))
