#!/usr/bin/env python3
"""IPTM DNS configuration bundle, v1. Privileged, deliberately non-executable ZIP.

Export from explicit config roots, skip query logs, use SQLite online backup.
Inspect without writing. Apply only after preflight, backup, and confirmation.
Never reload or restart DNS services automatically.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import zipfile
import fcntl

# Shared primitives. Recovery takes only its domain lock, never software admission.
def shared_transport():
    import importlib.util
    from pathlib import Path
    source=Path(__file__).resolve()
    if source.parent.name == 'runtime':
        module=source.parent.parent/'extensions'/'command_transport.py'
    else:
        module=Path('/usr/local/lib/iptables-manager/web/releases/6.0.8/extensions/command_transport.py')
    if not module.is_file() or module.is_symlink():
        raise OSError('Trasporto IPTM assente o non sicuro')
    cached=getattr(shared_transport,'_module',None)
    if cached is None:
        spec=importlib.util.spec_from_file_location('_iptm_runtime_transport',module)
        cached=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cached)
        shared_transport._module=cached
    return cached

def iptm_capture(argv, **options):
    return shared_transport().capture(argv, **options)


ROOTS = ('/etc/pihole', '/etc/dnsmasq.d', '/etc/unbound', '/etc/dnscrypt-proxy',
         '/etc/systemd/system/pihole-FTL.service.d', '/etc/systemd/system/unbound.service.d',
         '/etc/systemd/system/dnscrypt-proxy.service.d',
         '/etc/systemd/resolved.conf.d', '/etc/bind', '/etc/dnsdist', '/etc/knot-resolver',
         '/etc/pdns', '/etc/coredns', '/etc/AdGuardHome', '/opt/AdGuardHome')
EXACT = {'/etc/pihole/gravity.db', '/etc/pihole/setupVars.conf', '/etc/pihole/pihole.toml',
         '/etc/pihole/pihole-FTL.conf', '/etc/pihole/custom.list', '/etc/pihole/local.list',
         '/etc/pihole/dnsmasq.conf', '/etc/unbound/unbound.conf', '/var/lib/unbound/root.key',
         '/etc/default/unbound', '/etc/default/dnscrypt-proxy', '/etc/default/pihole-FTL',
         '/etc/default/dnsmasq', '/etc/dnsmasq.conf', '/etc/systemd/resolved.conf',
         '/etc/AdGuardHome.yaml', '/opt/AdGuardHome/AdGuardHome.yaml',
         '/etc/coredns/Corefile', '/etc/bind/named.conf', '/etc/bind/named.conf.local',
         '/etc/bind/named.conf.options', '/etc/bind/named.conf.default-zones'}
EXT = ('.conf','.toml','.list','.txt','.csv','.yaml','.yml','.pem','.crt','.key')
EXCLUDE_WORDS = ('query.log','pihole-ftl.db','dhcp.leases','log-queries','cache','session','password_backup','database_backup')
MAX_FILES = 320
MAX_FILE = 180*1024*1024
MAX_TOTAL = 256*1024*1024
MAX_ARCHIVE = 265*1024*1024
DATA = Path(os.environ.get('IPTM_DNS_BUNDLE_DATA','/var/lib/iptables-manager'))
# Test-only root prefix; must not be passed by web helper, and never used for production uploads.
TEST_ROOT = (os.environ.get('IPTM_DNS_BUNDLE_TEST_ROOT','')
             if os.environ.get('IPTM_DNS_BUNDLE_TEST') == '1'
             and Path(__file__).resolve().parent != Path('/usr/local/lib/iptables-manager') else '')


def disk(path):
    p = Path(path)
    return Path(TEST_ROOT) / str(p).lstrip('/') if TEST_ROOT else p


def allowed(path):
    if not isinstance(path,str) or not path.startswith('/') or '\\' in path or '\x00' in path or '//' in path or not re.fullmatch(r'/[A-Za-z0-9._/-]+',path):
        return False
    p=Path(path)
    if '..' in p.parts or any(x.startswith('.') for x in p.parts):
        return False
    if path not in EXACT and not (path.endswith(EXT) and any(path.startswith(base+'/') for base in ROOTS)):
        return False
    if any(word in path.lower() for word in EXCLUDE_WORDS):
        return False
    # Enforce max nesting to exclude home-grown archives or unknown application assets.
    for base in ROOTS:
        if path.startswith(base+'/') and len(Path(path).parts)-len(Path(base).parts)>4:
            return False
    return True


def sha(data): return hashlib.sha256(data).hexdigest()


def safe_source(path):
    target=disk(path)
    # No symlink anywhere along the path; protects root from redirected configuration roots.
    for parent in (target,*target.parents):
        if parent.exists() and parent.is_symlink(): raise ValueError('symlink non consentito: '+path)
    if not target.exists():return None
    st=target.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_nlink!=1:raise ValueError('file di configurazione non regolare o hardlink: '+path)
    if st.st_size>MAX_FILE:raise ValueError('configurazione troppo grande: '+path)
    return target


def discover():
    paths=[]
    for root in ROOTS:
        base=disk(root)
        if not base.exists():continue
        if base.is_symlink():raise ValueError('radice DNS symlink non ammessa: '+root)
        for directory,dirs,files in os.walk(base,followlinks=False):
            dirs[:]=[name for name in dirs if not name.startswith('.') and not (Path(directory)/name).is_symlink()]
            for name in files:
                d=Path(directory)/name
                orig='/' + d.relative_to(disk('/')).as_posix().lstrip('/')
                if allowed(orig):paths.append(orig)
                if len(paths)>MAX_FILES:raise ValueError('più di 320 configurazioni DNS; revisione manuale richiesta')
    for path in EXACT:
        if not any(path.startswith(r+'/') for r in ROOTS) and disk(path).is_file():paths.append(path)
    return sorted(set(paths))


def sqlite_snapshot(path, output):
    origin=sqlite3.connect(f'file:{path.as_posix()}?mode=ro',uri=True,timeout=15)
    try:
        target=sqlite3.connect(str(output),timeout=15)
        try:origin.backup(target,pages=256,sleep=0.05)
        finally:target.close()
    finally:origin.close()
    if output.stat().st_size>MAX_FILE:raise ValueError('gravity.db troppo grande per bundle')
    return output


def export_bundle(out):
    entries=[]; total=0
    with tempfile.TemporaryDirectory(prefix='iptm-gravity-') as work, tempfile.TemporaryFile() as tmp:
        with zipfile.ZipFile(tmp,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=5,allowZip64=True) as z:
            for path in discover():
                source=safe_source(path)
                if source is None:continue
                if path=='/etc/pihole/gravity.db':
                    source=sqlite_snapshot(source,Path(work)/'gravity.db')
                # One read only: calculate the digest from EXACTLY the same bytes written
                # to the ZIP, avoiding mismatch if a daemon edits a config during export.
                fd=os.open(source,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_CLOEXEC',0))
                with os.fdopen(fd,'rb') as inp:
                    st=os.fstat(inp.fileno())
                    sz=st.st_size;total+=sz
                    if not stat.S_ISREG(st.st_mode) or sz>MAX_FILE or total>MAX_TOTAL:
                        raise ValueError('backup DNS oltre 256 MiB o file non regolare')
                    mode=stat.S_IMODE(st.st_mode) & ~0o022
                    info=zipfile.ZipInfo('files'+path)
                    info.compress_type=zipfile.ZIP_DEFLATED
                    info.external_attr=(stat.S_IFREG|mode)<<16
                    dig=hashlib.sha256();actual=0
                    with z.open(info,'w',force_zip64=True) as zout:
                        while (chunk:=inp.read(128*1024)):
                            actual+=len(chunk)
                            if actual>sz:raise ValueError('configurazione DNS modificata durante export: '+path)
                            dig.update(chunk);zout.write(chunk)
                    if actual!=sz:raise ValueError('configurazione DNS modificata durante export: '+path)
                entries.append({'path':path,'sha256':dig.hexdigest(),'size':sz,
                                'mode':mode,'sqlite':path=='/etc/pihole/gravity.db'})
            if not entries: raise ValueError('nessuna configurazione DNS rilevata nei percorsi standard')
            manifest={'format':'iptm.dns.bundle.v1','created':dt.datetime.now(dt.timezone.utc).isoformat(),
                      'entries':entries,'skipped':[],
                      'warning':'Contiene potenzialmente PASSWORD, token, chiavi TLS e domini filtrati. Conservare cifrato e non condividere.',
                      'services':'La procedura non modifica né riavvia i servizi DNS durante export.'}
            z.writestr('manifest.json',json.dumps(manifest,sort_keys=True,separators=(',',':')))
        if tmp.tell()>MAX_ARCHIVE:raise ValueError('archivio compresso oltre limite 265 MiB')
        tmp.seek(0)
        while (chunk:=tmp.read(128*1024)):out.write(chunk)
        out.flush()


def read_secret_line(stream):
    secret=stream.readline(258)
    if not (15<=len(secret)<=257) or not secret.endswith(b'\n') or b'\x00' in secret:
        raise ValueError('Passphrase non valida (14–256 caratteri, senza newline)')
    return secret


def openpgp_run(action, source, target, secret):
    """GnuPG symmetric AES256, salted S2K and MDC integrity, no CLI secrets."""
    program=shutil.which('gpg')
    if not program:raise ValueError('GnuPG non installato: archivio cifrato non disponibile')
    if action not in ('encrypt','decrypt'):raise ValueError('Azione OpenPGP non valida')
    with tempfile.TemporaryDirectory(prefix='iptm-gpg-home-') as homedir:
        cmd=[program,'--no-options','--homedir',homedir,'--batch','--yes','--no-tty',
             '--pinentry-mode','loopback','--passphrase-fd','0','--output',str(target)]
        if action=='encrypt':
            cmd+=['--symmetric','--cipher-algo','AES256','--force-mdc','--s2k-mode','3',
                  '--s2k-digest-algo','SHA256','--s2k-count','1048576',str(source)]
        else:cmd+=['--decrypt',str(source)]
        try:
            r=iptm_capture(cmd, timeout=240, input_data=secret, text=False, stdout_limit=1048576, stderr_limit=262144)
        except subprocess.TimeoutExpired as ex:raise ValueError('GnuPG non ha completato la cifratura in tempo') from ex
        if r.returncode:
            raise ValueError('Cifratura/decrittazione OpenPGP non riuscita: verifica passphrase e integrità')
    if not target.exists() or not target.is_file() or target.stat().st_size==0:
        raise ValueError('Output OpenPGP non disponibile')


def encrypted_export(stream,output):
    secret=read_secret_line(stream)
    with tempfile.TemporaryDirectory(prefix='iptm-dns-encrypted-') as directory:
        source=Path(directory)/'bundle.zip';dest=Path(directory)/'bundle.zip.gpg'
        with source.open('wb') as f:export_bundle(f)
        openpgp_run('encrypt',source,dest,secret)
        with dest.open('rb') as f:
            while (chunk:=f.read(128*1024)):output.write(chunk)
        output.flush()


def encrypted_import(stream,action,confirmation):
    secret=read_secret_line(stream)
    with tempfile.TemporaryDirectory(prefix='iptm-dns-decrypt-') as directory:
        encrypted=Path(directory)/'input.gpg';decrypted=Path(directory)/'input.zip'
        with encrypted.open('wb') as f:
            count=0
            while (chunk:=stream.read(128*1024)):
                count+=len(chunk)
                if count>MAX_ARCHIVE:raise ValueError('Archivio DNS cifrato oltre il limite')
                f.write(chunk)
        openpgp_run('decrypt',encrypted,decrypted,secret)
        if decrypted.stat().st_size>MAX_ARCHIVE:raise ValueError('ZIP decrittato troppo grande')
        with decrypted.open('rb') as f:
            return inspect(f) if action=='inspect-encrypted' else apply(f,confirmation)


def read_bundle(stream):
    """Bounded disk-spooled ZIP validation. Caller closes returned ZIP and backing file."""
    tmp=tempfile.TemporaryFile()
    z=None
    try:
        compressed=0
        while (chunk:=stream.read(128*1024)):
            compressed+=len(chunk)
            if compressed>MAX_ARCHIVE:raise ValueError('ZIP troppo grande')
            tmp.write(chunk)
        tmp.seek(0)
        try:z=zipfile.ZipFile(tmp,'r')
        except (zipfile.BadZipFile,OSError) as ex:raise ValueError('ZIP DNS non valido') from ex
        infos=z.infolist();names=[i.filename for i in infos]
        if len(names)>MAX_FILES+1 or names.count('manifest.json')!=1 or len(set(names))!=len(names):
            raise ValueError('manifest mancante, file duplicati o troppi file')
        meta=z.getinfo('manifest.json')
        if meta.file_size>262144:raise ValueError('manifest troppo grande')
        try:
            with z.open(meta) as f:manifest=json.loads(f.read(262145))
        except (ValueError,KeyError,UnicodeError) as ex:raise ValueError('manifest JSON non valido') from ex
        if not isinstance(manifest,dict) or manifest.get('format')!='iptm.dns.bundle.v1':
            raise ValueError('formato bundle DNS sconosciuto')
        entries=manifest.get('entries')
        if not isinstance(entries,list) or len(entries)>MAX_FILES or len(entries)+1!=len(names):
            raise ValueError('elenco file non corrisponde al manifest')
        result=[];total=0
        for item in entries:
            if not isinstance(item,dict):raise ValueError('manifest non valido')
            path=item.get('path')
            if not allowed(path):raise ValueError('percorso non autorizzato')
            name='files'+path
            if name not in z.NameToInfo:raise ValueError('file mancante dal ZIP: '+path)
            info=z.getinfo(name)
            size=item.get('size');mode=item.get('mode',0o600)
            if type(size) is not int or size<0 or size>MAX_FILE or size!=info.file_size or type(mode) is not int or mode<0 or mode>0o777 or mode&0o022:
                raise ValueError('dimensione o permessi non ammessi nel manifest')
            if stat.S_IFMT(info.external_attr>>16) not in (0,stat.S_IFREG):
                raise ValueError('file non regolari non consentiti nel bundle')
            total+=size
            if total>MAX_TOTAL:raise ValueError('contenuto oltre 256 MiB')
            digest=hashlib.sha256();actual=0
            with z.open(info,'r') as f:
                while (chunk:=f.read(128*1024)):
                    actual+=len(chunk)
                    if actual>size:raise ValueError('ZIP non compresso più grande del manifest')
                    digest.update(chunk)
            if actual!=size or not re.fullmatch('[a-f0-9]{64}',str(item.get('sha256',''))) or digest.hexdigest()!=item['sha256']:
                raise ValueError('checksum non valido: '+path)
            if type(item.get('sqlite')) is not bool or item['sqlite'] != (path=='/etc/pihole/gravity.db'):
                raise ValueError('tipo SQLite non valido')
            result.append((path,info,mode))
        if set(names)!={'manifest.json',*('files'+p for p,_,_ in result)}:
            raise ValueError('file sconosciuti nel bundle')
        return result,manifest,z,tmp
    except BaseException:
        if z is not None:z.close()
        tmp.close()
        raise


def inspect(stream):
    files,m,z,tmp=read_bundle(stream)
    try:
        return {'ok':True,'mode':'preview-only','files':[
            {'path':p,'size':i.file_size,'exists':disk(p).is_file(),'sqlite':p.endswith('/gravity.db')} for p,i,_ in files],
            'sha256_manifest':sha(json.dumps(m,sort_keys=True).encode()),
            'warning':'Il file include potenzialmente segreti. L’anteprima non scrive nulla.'}
    finally:z.close();tmp.close()


def ensure_not_running_gravity(files):
    if not any(p=='/etc/pihole/gravity.db' for p,_,_ in files):return
    if TEST_ROOT:return
    if not shutil.which('systemctl'):
        raise ValueError('Non posso verificare FTL: ripristino gravity.db bloccato')
    try:
        p=iptm_capture(['systemctl', 'is-active', '--quiet', 'pihole-FTL'], timeout=5, text=False, stdout_limit=1048576, stderr_limit=262144)
    except (OSError,subprocess.TimeoutExpired):
        raise ValueError('Stato FTL non verificabile: ripristino gravity.db bloccato')
    if p.returncode == 0:
        raise ValueError('Per ripristinare gravity.db arrestare prima pihole-FTL (manutenzione offline)')
    if p.returncode != 3:
        raise ValueError('FTL non è dichiarato inattivo da systemd: ripristino gravity.db bloccato')
    # Some administrators run FTL outside systemd; check for such processes too.
    if shutil.which('pgrep'):
        try:
            proc=iptm_capture(['pgrep', '-x', 'pihole-FTL'], timeout=5, text=False, stdout_limit=1048576, stderr_limit=262144)
        except (OSError,subprocess.TimeoutExpired):
            raise ValueError('Processi FTL non verificabili: ripristino gravity.db bloccato')
        if proc.returncode == 0:raise ValueError('Processo pihole-FTL attivo: arrestarlo prima del ripristino')
        if proc.returncode != 1:raise ValueError('Processi FTL non verificabili: ripristino gravity.db bloccato')
    else:
        raise ValueError('pgrep mancante: impossibile verificare FTL, ripristino gravity.db bloccato')


def atomic_journal(path, payload):
    """Durable state transition; never depend on a partial JSON write."""
    shared_transport().durable_json(Path(path),payload)


def dns_import_lock():
    path=disk('/run/lock/iptm-dns-import.lock')
    if TEST_ROOT:path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    return path


def incomplete_dns_restores():
    """Find interrupted multi-file restores. A new import must not compound drift."""
    root=disk(DATA/'backups')
    if not root.is_dir():return []
    pending=[]
    for folder in sorted(root.glob('dns-import-*')):
        if folder.is_symlink() or not folder.is_dir():
            raise ValueError('directory backup DNS non affidabile: '+str(folder))
        journal=folder/'restore-journal.json'
        if not journal.exists() and not journal.is_symlink():continue
        if journal.is_symlink() or not journal.is_file():
            raise ValueError('journal DNS non regolare: '+str(journal))
        try:
            j=shared_transport().read_private_json(journal,limit=1024*1024)
            state=j['state']
        except (OSError,ValueError,KeyError,TypeError):
            raise ValueError('journal DNS non leggibile: '+str(journal))
        if state in ('prepared','recovering'):pending.append((folder,journal,j))
        elif state not in ('completed','recovered'):
            raise ValueError('stato journal DNS sconosciuto: '+str(journal))
    return pending


def _atomic_restore_file(source,dest):
    """Restore backup with same-directory rename, never stream directly to a live file."""
    fd,name=tempfile.mkstemp(dir=str(dest.parent),prefix='.iptm-dns-recovery-')
    try:
        with os.fdopen(fd,'wb') as output,source.open('rb') as inp:
            shutil.copyfileobj(inp,output,length=128*1024)
            output.flush();os.fsync(output.fileno())
        st=source.stat()
        os.chown(name,st.st_uid,st.st_gid)
        os.chmod(name,stat.S_IMODE(st.st_mode) & ~0o022)
        with open(name,'rb') as stream:os.fsync(stream.fileno())
        os.replace(name,dest)
        dir_fd=os.open(dest.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(dir_fd)
        finally:os.close(dir_fd)
    finally:
        if os.path.lexists(name):os.unlink(name)


def recover(ack):
    """Explicit, idempotent recovery of interrupted bundle restores."""
    if os.geteuid()!=0:raise ValueError('recupero DNS solo root')
    if ack!='RIPRISTINA DNS':raise ValueError('conferma esplicita RIPRISTINA DNS richiesta')
    with shared_transport().domain_lock(dns_import_lock(),nonblocking=True):
        operations=incomplete_dns_restores()
        # Preflight across the entire recovery batch before touching files.
        plans=[]
        for folder,journal,j in operations:
            entries=j.get('files')
            if not isinstance(entries,list) or len(entries)>MAX_FILES or not entries:
                raise ValueError('journal DNS senza file validi')
            one=[]
            for entry in entries:
                if not isinstance(entry,dict) or not allowed(entry.get('path')) or not isinstance(entry.get('existed'),bool):
                    raise ValueError('target DNS non autorizzato nel journal')
                path=entry['path']; dest=disk(path); backup=folder/path.lstrip('/')
                if not dest.parent.is_dir() or dest.parent.is_symlink():raise ValueError('directory target DNS non sicura: '+path)
                safe_source(path) # rifiuta symlink nel target e nei suoi genitori
                if entry['existed']:
                    if backup.is_symlink() or not backup.is_file() or backup.stat().st_nlink!=1:raise ValueError('backup DNS mancante o non regolare: '+path)
                    if backup.stat().st_size>MAX_FILE:raise ValueError('backup DNS troppo grande: '+path)
                # A file absent before import may only be removed if it still
                # contains exactly the version installed by that import.
                # Legacy journals without the hash require operator inspection.
                if not entry['existed'] and dest.exists():
                    expected=entry.get('new_sha256')
                    if not isinstance(expected,str) or not re.fullmatch('[0-9a-f]{64}',expected):
                        raise ValueError('file DNS creato durante restore legacy: rimozione automatica non verificabile: '+path)
                    h=hashlib.sha256()
                    with dest.open('rb') as source:
                        while (chunk:=source.read(128*1024)):h.update(chunk)
                    if h.hexdigest()!=expected:
                        raise ValueError('file DNS modificato dopo il crash: '+path)
                one.append((path,entry['existed'],dest,backup))
            ensure_not_running_gravity([(path,None,None) for path,_,_,_ in one])
            plans.append((folder,journal,j,one))
        count=0
        for folder,journal,j,one in plans:
            j['state']='recovering';atomic_journal(journal,j)
            for path,existed,dest,backup in reversed(one):
                if existed:_atomic_restore_file(backup,dest)
                elif dest.exists():
                    dest.unlink()
                    dir_fd=os.open(dest.parent,os.O_RDONLY|os.O_DIRECTORY)
                    try:os.fsync(dir_fd)
                    finally:os.close(dir_fd)
                count+=1
            j['state']='recovered';atomic_journal(journal,j)
        return {'ok':True,'recovered_files':count,'recovered_transactions':len(plans),
                'notes':'File precedenti recuperati; riavviare i resolver solo dopo averne verificato le configurazioni.'}


def apply(stream,ack):
    if os.geteuid()!=0:raise ValueError('ripristino DNS solo root')
    if ack!='RIPRISTINA DNS':raise ValueError('conferma esplicita RIPRISTINA DNS richiesta')
    files,manifest,z,tmp=read_bundle(stream)
    try:return _apply_validated(files,z)
    finally:z.close();tmp.close()


def _apply_validated(files,z):
    if not files:raise ValueError('bundle DNS vuoto: nessuna operazione')
    ensure_not_running_gravity(files)
    # Validate all TOML files before any target is modified; never install invalid FTL/DNSCrypt config.
    if any(p.endswith('.toml') for p,_,_ in files):
        try:import tomllib
        except ImportError:raise ValueError('Python tomllib necessario per validare i TOML (Python 3.11+)')
        for path,info,_ in files:
            if path.endswith('.toml'):
                try:
                    with z.open(info,'r') as source:tomllib.loads(source.read(MAX_FILE+1).decode('utf-8'))
                except (UnicodeError,ValueError) as e:raise ValueError('TOML non valido '+path+': '+str(e)[:70])
    backup_root=disk(DATA/'backups' / ('dns-import-'+dt.datetime.now().strftime('%Y%m%d-%H%M%S')+'-'+str(os.getpid())+'-'+os.urandom(4).hex()))
    with shared_transport().transaction_gate(gate=disk('/run/iptm-software-update.lock'),domain=dns_import_lock()):
        if incomplete_dns_restores():
            raise ValueError('Ripristino DNS precedente incompleto: usare dns-bundle recover da console prima di un nuovo import')
        for path,_,mode in files:
            if not allowed(path):raise ValueError('target DNS non autorizzato')
            parent=disk(path).parent
            if not parent.is_dir() or parent.is_symlink():raise ValueError('directory DNS mancante/symlink: '+path)
            safe_source(path)
        backup_root.mkdir(mode=0o700,parents=True)
        old=[];changed=[]
        try:
            for path,info,mode in files:
                dest=disk(path);existed=dest.exists()
                if existed:
                    backup=backup_root / path.lstrip('/')
                    backup.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
                    shutil.copy2(dest,backup,follow_symlinks=False)
                    metadata=dest.stat()
                    os.chown(backup,metadata.st_uid,metadata.st_gid)
                    os.chmod(backup,stat.S_IMODE(metadata.st_mode)&~0o022)
                    with backup.open('rb') as stream:os.fsync(stream.fileno())
                    # Persist the backup and all newly created directory entries.
                    for folder in (backup.parent,*backup.parent.parents):
                        if folder==backup_root.parent.parent:break
                        fd_dir=shared_transport().open_directory(folder)
                        try:os.fsync(fd_dir)
                        finally:os.close(fd_dir)
                old.append((path,existed))
            journal_files=[]
            for path,info,_ in files:
                existed=dict(old)[path]
                item={'path':path,'existed':existed}
                if not existed:
                    h=hashlib.sha256()
                    with z.open(info,'r') as inp:
                        while (chunk:=inp.read(128*1024)):h.update(chunk)
                    item['new_sha256']=h.hexdigest()
                journal_files.append(item)
            journal={'files':journal_files,
                     'state':'prepared','created':dt.datetime.now(dt.timezone.utc).isoformat()}
            atomic_journal(backup_root/'restore-journal.json',journal)
            for folder in (backup_root.parent,backup_root.parent.parent):
                fd_dir=shared_transport().open_directory(folder)
                try:os.fsync(fd_dir)
                finally:os.close(fd_dir)
            for path,info,mode in files:
                dest=disk(path)
                fd2,temp_name=tempfile.mkstemp(dir=str(dest.parent),prefix='.iptm-dns-')
                try:
                    with os.fdopen(fd2,'wb') as out, z.open(info,'r') as member:
                        shutil.copyfileobj(member,out,length=128*1024)
                        out.flush();os.fsync(out.fileno())
                    if dest.exists():
                        st=dest.stat()
                        os.chown(temp_name,st.st_uid,st.st_gid)
                        os.chmod(temp_name,stat.S_IMODE(st.st_mode) & ~0o022)
                    else:os.chmod(temp_name,mode & ~0o022)
                    with open(temp_name,'rb') as stream:os.fsync(stream.fileno())
                    os.replace(temp_name,dest)
                    changed.append(path)  # rename succeeded even if next fsync fails
                    # Persist directory rename before advertising the next step.
                    dir_fd=os.open(dest.parent,os.O_RDONLY|os.O_DIRECTORY)
                    try:os.fsync(dir_fd)
                    finally:os.close(dir_fd)
                finally:
                    if os.path.lexists(temp_name):os.unlink(temp_name)
            journal['state']='completed'
            atomic_journal(backup_root/'restore-journal.json',journal)
            return {'ok':True,'restored':len(changed),'backup':str(backup_root),
                    'notes':'File ripristinati; servizi NON riavviati. Eseguire verifiche Unbound/DNSCrypt/Pi-hole e riavviare in finestra di manutenzione.'}
        except BaseException:
            failures=[]
            for path,existed in reversed(old):
                if path not in changed:continue
                try:
                    dest=disk(path);bak=backup_root/path.lstrip('/')
                    if existed:
                        if not bak.is_file() or bak.is_symlink():raise ValueError('backup mancante o non regolare')
                        _atomic_restore_file(bak,dest)
                    else:
                        dest.unlink(missing_ok=True)
                        fd_dir=shared_transport().open_directory(dest.parent)
                        try:os.fsync(fd_dir)
                        finally:os.close(fd_dir)
                except (OSError,ValueError) as exc:failures.append(path+': '+str(exc))
            if 'journal' in locals() and not failures:
                journal['state']='recovered'
                atomic_journal(backup_root/'restore-journal.json',journal)
            # A remaining prepared/recovering journal prevents a second import;
            # operator can use the new explicit recovery action from console.
            if failures:raise ValueError('Rollback DNS parziale: usare dns-bundle recover; '+', '.join(failures)[:160])
            raise


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('action',choices=('export','export-encrypted','inspect','inspect-encrypted','apply','apply-encrypted','recover'))
    ap.add_argument('--confirm',default='')
    args=ap.parse_args()
    # Keep legacy plaintext export for SSH-only explicit compatibility. The
    # browser routes exclusively to the encrypted action.
    if args.action=='export': export_bundle(sys.stdout.buffer);return 0
    if args.action=='export-encrypted':encrypted_export(sys.stdin.buffer,sys.stdout.buffer);return 0
    if args.action in ('inspect-encrypted','apply-encrypted'):
        result=encrypted_import(sys.stdin.buffer,args.action,args.confirm)
        print(json.dumps(result,sort_keys=True));return 0
    if args.action=='recover': print(json.dumps(recover(args.confirm),sort_keys=True));return 0
    result=inspect(sys.stdin.buffer) if args.action=='inspect' else apply(sys.stdin.buffer,args.confirm)
    print(json.dumps(result,sort_keys=True));return 0

if __name__=='__main__':
    try:sys.exit(main())
    except (ValueError,OSError,sqlite3.Error,zipfile.BadZipFile,BlockingIOError) as e:
        print(json.dumps({'ok':False,'error':str(e)[:250]}),file=sys.stderr);sys.exit(2)
