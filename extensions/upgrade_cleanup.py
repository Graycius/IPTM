#!/usr/bin/env python3
"""Post-commit retirement of verified, unused IPTM artifacts.

The updater invokes this only *after* the durable upgrade recovery journal has
been committed. It deliberately never changes live iptables/nftables, tc/IFB,
interfaces, DNS, service files for active/ enabled services, or user backups.
All removed unit bytes are archived in a root-only snapshot first.
"""
from __future__ import annotations
import fcntl, hashlib, json, os, pathlib, re, shlex, shutil, stat, subprocess, sys, tempfile, time

STATE=pathlib.Path('/var/lib/iptm-update-cleanup')
PENDING=pathlib.Path('/var/lib/iptm-update-recovery/pending.json')
UNIT_DIR=pathlib.Path('/etc/systemd/system')
LEGACY_CONFIG=pathlib.Path('/etc/iptables-manager.conf')
# Identical stable signatures from the retired official QoS components; never
# match arbitrary names or locally customized units by guesswork.
RETIRED_UNITS={
 'qos.service':('Description=QoS Adattivo CAKE su bond0','/sbin/tc qdisc replace dev bond0 root cake'),
 'iot-warden.service':('Description=IoT Warden','ExecStart=/root/iot_warden.sh'),
 'iot_warden.service':('Description=IoT Warden','ExecStart=/root/iot_warden.sh'),
 'iptm-iot-warden.service':('Description=IPTM IoT Warden','ExecStart=/root/iot_warden.sh'),
 # HTTP caching proxy retired in 5.30.12 — residual units only.
 'iptm-cache-proxy.service':('Description=IPTM isolated LAN HTTP caching proxy','iptm-cache-proxy'),
 'iptm-cache-redirect.service':('Description=IPTM HTTP cache redirect reconciliation','iptm-cache'),
 'iptm-cache-redirect.timer':('# IPTM HTTP redirect timer','iptm-cache'),
}
# Current production services are *not* legacy. They remain functional and
# are intentionally not eligible for automatic retirement, even if disabled.
CURRENT_UNITS=frozenset('iptm-alias-boot-recover.service iptm-antidpi-persist.service iptm-dhcp-secondary.service\niptm-dns-boot-recover.service iptm-fabric-boot-recover.service iptm-guard.service\niptm-ipset.service iptm-ipv6-recovery.service iptm-network-runtime.service\niptm-network-wan-health.service iptm-network-wan-health.timer\niptm-pihole-bind-boot.service iptm-qos-adaptive.service iptm-qos-adaptive.timer\niptm-qos-auto-calibration.service iptm-qos-auto-calibration.timer\niptm-qos-policy-restore.service iptm-qos-watchdog.service\niptm-retention.service iptm-retention.timer iptm-sqm-calibrate.service\niptm-sqm-calibrate.timer iptm-sqm.service iptm-sqm-reconcile-recover.service\niptm-sqm-uplink-recover.service iptm-traffic-proxy.service\niptm-update-recover.service iptm-wanfo.service iptm-wanfo.timer'.split())
ORPHAN_RX=re.compile(r'^iptm-[a-z0-9][a-z0-9-]{0,70}\.(?:service|timer)$')

def obsolete_iptm_units():
    """Discover orphaned IPTM systemd units with an explicit local signature.

    Never treat a name prefix alone as proof of ownership. Symlinks,
    custom scripts, all supported units and any unusual directives are held.
    """
    result={}
    if UNIT_DIR.is_symlink() or not UNIT_DIR.is_dir():return result
    for path in UNIT_DIR.iterdir():
        name=path.name
        if not ORPHAN_RX.fullmatch(name) or name in CURRENT_UNITS or name in RETIRED_UNITS:
            continue
        if not secure_file(path) or path.stat().st_size>16384:continue
        data=path.read_bytes()
        if b'[Unit]' not in data or not re.search(rb'(?mi)^Description=[^\r\n]*\bIPTM\b',data):continue
        if name.endswith('.service'):
            starts=re.findall(rb'(?m)^ExecStart=(.+)$',data)
            if len(starts)!=1 or not any(x in starts[0] for x in (
                  b'/usr/local/sbin/iptm-helper',b'/usr/local/lib/iptables-manager/')):
                continue
            # A legacy-looking user-defined unit with arbitrary code is not ours.
            if b'/bin/sh -c ' in starts[0] or b'/bin/bash -c ' in starts[0]:continue
        else:
            if not (b'OnCalendar=' in data or b'OnBootSec=' in data or b'OnUnitInactiveSec=' in data):continue
            if b'ExecStart=' in data:continue
        result[name]=('[Unit]','Description=IPTM')
    return result

# Backup filename candidates are only old, automatically generated copies of
# executable software; settings, rules, credentials and named snapshots are out of scope.
OLD_SOFTWARE_BACKUP_DIRS={
 pathlib.Path('/usr/local/sbin'):('iptm-helper.bak-',),
 pathlib.Path('/usr/local/lib/iptables-manager'):('iptm-maintenance.py.bak-','iptm-traffic-av.py.bak-',
     'iptm-security.py.bak-','iptm-iot-warden.py.bak-','iptm-dns-bundle.py.bak-',
     'iptm-crowdsec-audit.py.bak-'),
}
BACKUP_NAME_RX=re.compile(r'^[0-9]{8}-[0-9]{6}$')
class CleanupError(Exception):pass

def secure_directory(path, create=False):
    if path.is_symlink():raise CleanupError('Percorso simbolico: '+str(path))
    if create:path.mkdir(mode=0o700,parents=True,exist_ok=True)
    if not path.is_dir():raise CleanupError('Directory assente: '+str(path))
    st=path.stat()
    if st.st_uid!=0 or st.st_mode & 0o022:raise CleanupError('Directory non protetta: '+str(path))

def secure_file(path):
    if path.is_symlink() or not path.is_file():return False
    st=path.stat()
    return st.st_uid==0 and not(st.st_mode & 0o022) and stat.S_ISREG(st.st_mode)

def call(*args):
    try:return subprocess.run(args,capture_output=True,text=True,stdin=subprocess.DEVNULL,timeout=8)
    except (OSError, subprocess.TimeoutExpired) as exc:raise CleanupError('Stato servizi non verificabile') from exc

def pending_network():
    if PENDING.exists() or PENDING.is_symlink():return 'aggiornamento non confermato'
    for raw in ('/var/lib/iptm-qos-engine/active.json','/var/lib/iptm-nm-editor/trial.json',
                '/var/lib/iptm-network-runtime/transaction.json',
                '/var/lib/iptm-sqm-uplink/state.json','/var/lib/iptm-sqm-reconcile/state.json'):
        path=pathlib.Path(raw)
        if not path.exists() and not path.is_symlink():continue
        if not secure_file(path) or path.stat().st_mode & 0o077:return 'journal non verificabile: '+raw
        try:data=json.loads(path.read_text())
        except (OSError, ValueError, UnicodeError):return 'journal incompleto: '+raw
        if not isinstance(data,dict):return 'journal non valido: '+raw
        if data.get('state') in ('pending','applying','rollback-failed','reconciling') or data.get('status') in ('pending','applying','rollback-failed','reconciling'):
            return 'transazione rete attiva: '+raw
    return None

def externally_referenced_unit(name, permitted_refs=frozenset()):
    # A disabled service may still be launched by another active timer/unit.
    # A custom reference means the unit is not proven redundant.
    try:
        for link in UNIT_DIR.rglob('*'):
            if link.name==name and link.is_symlink():return True
            if link.is_symlink() or not link.is_file() or link.name==name or link.name in permitted_refs:continue
            if link.stat().st_size>32768:continue
            if link.suffix not in ('.service','.timer','.socket','.path','.target'):continue
            if name.encode() in link.read_bytes():return True
        if name.endswith('.service'):
            timer=name[:-8]+'.timer'
            if (UNIT_DIR/timer).exists() or (UNIT_DIR/timer).is_symlink():
                active=call('systemctl','is-active',timer).stdout.strip()
                enabled=call('systemctl','is-enabled',timer).stdout.strip()
                if active not in ('inactive','failed') or enabled not in ('disabled','masked','not-found'):
                    return True
    except (OSError, PermissionError, CleanupError):return True
    return False

def inspect_unit(name,markers,permitted_refs=frozenset()):
    path=UNIT_DIR/name
    if not path.exists() and not path.is_symlink():return None
    record={'unit':name,'action':'preserve','reason':'file personalizzato o non verificato'}
    if not secure_file(path):return record
    content=path.read_bytes()
    if len(content)>16384 or not all(x.encode() in content for x in markers):return record
    if externally_referenced_unit(name,permitted_refs):
        record['reason']='riferimento systemd esterno non migrato';return record
    if any(term in content for term in (b'ExecStartPre=',b'ExecStartPost=',b'ExecStopPost=',
                                       b'ExecReload=',b'EnvironmentFile=',b'BindsTo=')):
        record['reason']='direttive aggiuntive non riconosciute';return record
    try:
        active=call('systemctl','is-active',name).stdout.strip()
        enabled=call('systemctl','is-enabled',name).stdout.strip()
    except CleanupError:
        record['reason']='impossibile verificare systemd';return record
    # A zero-returning one-shot can show inactive while it has a queued job:
    # use systemctl show too; uncertainty always means preserve.
    props=call('systemctl','show',name,'--property=ActiveState,SubState,Job','--no-pager')
    values=dict(x.split('=',1) for x in props.stdout.splitlines() if '=' in x)
    if (props.returncode or active not in ('inactive','failed') or
        enabled not in ('disabled','masked','static','not-found') or
        values.get('ActiveState') not in ('inactive','failed') or
        values.get('Job','') not in ('','0')):
        record['reason']='servizio attivo, pianificato o non classificabile ('+active+'/'+enabled+')'
        return record
    # A timer must not be retired while its paired service is active.
    if name.endswith('.timer'):
        service=name[:-6]+'.service'
        state=call('systemctl','is-active',service).stdout.strip()
        if state not in ('inactive','failed','unknown'):
            record['reason']='servizio associato operativo: '+service;return record
    record.update(action='retire',reason='firma IPTM verificata; unità inattiva, disabilitata e senza job',
                  sha256=hashlib.sha256(content).hexdigest(),mode=path.stat().st_mode & 0o777)
    return record

def backup_candidates(now=None):
    now=time.time() if now is None else now
    results=[]
    for folder,prefixes in OLD_SOFTWARE_BACKUP_DIRS.items():
        if not folder.is_dir() or folder.is_symlink():continue
        try:secure_directory(folder)
        except CleanupError:continue
        for prefix in prefixes:
            files=[]
            for file in folder.glob(prefix+'*'):
                if not BACKUP_NAME_RX.fullmatch(file.name[len(prefix):]) or not secure_file(file):continue
                files.append(file)
            files.sort(key=lambda item:(item.stat().st_mtime,item.name),reverse=True)
            for file in files[3:]:
                if now-file.stat().st_mtime < 30*86400:continue
                results.append({'file':str(file),'sha256':hashlib.sha256(file.read_bytes()).hexdigest(),
                                'mode':file.stat().st_mode & 0o777,'size':file.stat().st_size})
    return results

def disabled_iot_post_script():
    """Convert only a script that the helper ALREADY refuses to execute.

    Never interpret shell configuration and never rename/delete an IoT script.
    A customized or ambiguous assignment is preserved, not normalized.
    """
    path=LEGACY_CONFIG
    if not secure_file(path) or path.stat().st_size>65536:return None
    try:secure_directory(path.parent)
    except CleanupError:return None
    try:
        content=path.read_bytes()
        text=content.decode('utf-8')
        matches=list(re.finditer(r'(?m)^[ \t]*POST_SCRIPT[ \t]*=[ \t]*(.*)$',text))
        if len(matches)!=1:return None
        tokens=shlex.split(matches[0].group(1),posix=True)
        if len(tokens)!=1:return None
        value=tokens[0]
        if not re.fullmatch(r'(?:/[A-Za-z0-9_.-]+)*/iot_warden\.sh',value):return None
        output=text[:matches[0].start()]+ 'POST_SCRIPT=""'+text[matches[0].end():]
        return {'path':str(path),'sha256':hashlib.sha256(content).hexdigest(),
                'mode':path.stat().st_mode & 0o777,'replacement':output.encode()}
    except (UnicodeError, OSError, ValueError):return None

def plan():
    blocker=pending_network()
    entries=[]
    candidates=dict(RETIRED_UNITS)
    candidates.update(obsolete_iptm_units())
    # A retired timer may be the sole remaining reference to a retired service:
    # only ignore that reference after the timer itself passed independent checks.
    prelim={name:inspect_unit(name,markers) for name,markers in candidates.items()}
    linked={name for name,record in prelim.items() if name.endswith('.timer')
            and record is not None and record.get('action')=='retire'}
    for name,markers in candidates.items():
        entry=prelim[name]
        if entry is not None and entry.get('action')!='retire' and name.endswith('.service'):
            # Allow only the already verified disabled companion timer, not arbitrary references.
            paired=name[:-8]+'.timer'
            if paired in linked:
                entry=inspect_unit(name,markers,frozenset([paired]))
        if entry is not None:entries.append(entry)
    if blocker:
        for entry in entries:
            if entry['action']=='retire':entry.update(action='preserve',reason=blocker)
    backups=[] if blocker else backup_candidates()
    conversion=None if blocker else disabled_iot_post_script()
    # A digest is sufficient for planning; do not leak the replacement config in scan output.
    conversions=[{k:v for k,v in conversion.items() if k!='replacement'}] if conversion else []
    summary={'entries':entries,'old_software_backups':backups,
             'configuration_conversions':conversions,'blocked':blocker,
             'removable':[e['unit'] for e in entries if e['action']=='retire']}
    fingerprint=json.dumps(summary,sort_keys=True,separators=(',',':')).encode()
    return dict({'ok':True,'sha256':hashlib.sha256(fingerprint).hexdigest()},**summary)

def atomic_json(path,obj):
    fd,temp=tempfile.mkstemp(dir=path.parent,prefix='.iptm-cleanup-')
    try:
        with os.fdopen(fd,'w') as stream:
            os.fchmod(stream.fileno(),0o600)
            json.dump(obj,stream,sort_keys=True,ensure_ascii=False)
            stream.flush();os.fsync(stream.fileno())
        os.replace(temp,path)
    finally:
        if os.path.exists(temp):os.unlink(temp)

def run(expected=None):
    if os.geteuid():raise CleanupError('root richiesto')
    if PENDING.exists() or PENDING.is_symlink():
        raise CleanupError('Aggiornamento non ancora confermato; pulizia non avviata')
    secure_directory(STATE,create=True)
    lock_fd=os.open(STATE/'lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    with os.fdopen(lock_fd,'r+') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        before=plan()
        if expected is not None and before['sha256']!=expected:
            raise CleanupError('Inventario cambiato: eseguire nuova scansione')
        if before['blocked']:
            report={'ok':True,'state':'deferred','reason':before['blocked'],'retired':[],
                    'archived':[],'converted':[],'preserved':[e['unit'] for e in before['entries']],
                    'preserved_reasons':{e['unit']:e.get('reason','') for e in before['entries']}}
            atomic_json(STATE/'last.json',report)
            return report
        # Always keep a recoverable snapshot. No live firewall, qdisc, VPN, DNS
        # or running systemd service is touched here.
        retired=[];archived=[];preserved=[e['unit'] for e in before['entries'] if e['action']!='retire']
        eligible=[e for e in before['entries'] if e['action']=='retire']
        stale=before['old_software_backups']
        config=disabled_iot_post_script()
        if config and before['configuration_conversions'] != [{k:v for k,v in config.items() if k!='replacement'}]:
            raise CleanupError('Configurazione modificata durante la scansione')
        if not eligible and not stale and not config:
            report={'ok':True,'state':'clean','retired':[],'archived':[], 'preserved':preserved,
                    'preserved_reasons':{e['unit']:e.get('reason','') for e in before['entries']}}
            # Do not overwrite the last meaningful completed snapshot report.
            if not (STATE/'last.json').is_file() and not (STATE/'last.json').is_symlink():
                atomic_json(STATE/'last.json',report)
            return report
        stamp=time.strftime('%Y%m%dT%H%M%SZ',time.gmtime())
        folder=STATE/('snapshot-'+stamp+'-'+before['sha256'][:12])
        folder.mkdir(mode=0o700)
        # Verify bytes *again* before any mutation; copies in 0600 snapshot.
        snapshot=[]
        for entry in eligible:
            src=UNIT_DIR/entry['unit']
            if not secure_file(src) or hashlib.sha256(src.read_bytes()).hexdigest()!=entry['sha256']:
                raise CleanupError('Unità modificata dopo inventario: '+entry['unit'])
            dest=folder/entry['unit'];dest.write_bytes(src.read_bytes());dest.chmod(0o600)
            snapshot.append({'source':str(src),'copy':dest.name,'sha256':entry['sha256'],'mode':entry['mode']})
        for i,item in enumerate(stale):
            src=pathlib.Path(item['file'])
            if not secure_file(src) or hashlib.sha256(src.read_bytes()).hexdigest()!=item['sha256']:
                raise CleanupError('Backup variato: '+str(src))
            if item['size']>16*1024*1024:
                preserved.append(str(src));continue
            name='old-file-'+str(i)
            dest=folder/name;shutil.copyfile(src,dest);dest.chmod(0o600)
            snapshot.append({'source':str(src),'copy':name,'sha256':item['sha256'],'mode':item['mode']})
        if config:
            src=LEGACY_CONFIG
            if not secure_file(src) or hashlib.sha256(src.read_bytes()).hexdigest()!=config['sha256']:
                raise CleanupError('Configurazione post-apply cambiata durante la preparazione')
            config_backup=folder/'post-apply-config'
            shutil.copyfile(src,config_backup);config_backup.chmod(0o600)
            snapshot.append({'source':str(src),'copy':config_backup.name,'sha256':config['sha256'],
                             'mode':config['mode']})
        atomic_json(folder/'manifest.json',{'version':1,'files':snapshot,'created':int(time.time()),'status':'prepared'})
        # Reverify systemd immediately before removal; never stop an active service.
        changed=[];converted=[];did_convert=False
        try:
            if config:
                original=LEGACY_CONFIG.stat()
                if hashlib.sha256(LEGACY_CONFIG.read_bytes()).hexdigest()!=config['sha256']:
                    raise CleanupError('Configurazione modificata: conversione rinviata')
                fd,temp=tempfile.mkstemp(prefix='.iptm-post-apply-',dir=LEGACY_CONFIG.parent)
                try:
                    with os.fdopen(fd,'wb') as f:
                        os.fchmod(f.fileno(),config['mode']);os.fchown(f.fileno(),0,original.st_gid)
                        f.write(config['replacement']);f.flush();os.fsync(f.fileno())
                    os.replace(temp,LEGACY_CONFIG)
                finally:
                    if os.path.exists(temp):os.unlink(temp)
                did_convert=True
                converted.append('POST_SCRIPT IoT Warden disabilitato')
            current_candidates=dict(RETIRED_UNITS)
            current_candidates.update(obsolete_iptm_units())
            eligible_timer_names={x['unit'] for x in eligible if x['unit'].endswith('.timer')}
            for entry in eligible:
                markers=current_candidates.get(entry['unit'])
                if markers is None:
                    preserved.append(entry['unit']);continue
                paired=entry['unit'][:-8]+'.timer' if entry['unit'].endswith('.service') else ''
                permit=frozenset([paired]) if paired in eligible_timer_names else frozenset()
                rechecked=inspect_unit(entry['unit'],markers,permit)
                if not rechecked or rechecked.get('action')!='retire' or rechecked.get('sha256')!=entry['sha256']:
                    preserved.append(entry['unit']);continue
                (UNIT_DIR/entry['unit']).unlink()
                changed.append(entry['unit']);retired.append(entry['unit'])
            if changed:
                r=call('systemctl','daemon-reload')
                if r.returncode:raise CleanupError('systemd daemon-reload fallito')
        except Exception:
            if did_convert:
                src=LEGACY_CONFIG
                data=(folder/'post-apply-config').read_bytes()
                src.write_bytes(data);src.chmod(config['mode'])
            for name in changed:
                original=next(x for x in snapshot if x['source']==str(UNIT_DIR/name))
                src=UNIT_DIR/name
                if not src.exists() and not src.is_symlink():
                    src.write_bytes((folder/original['copy']).read_bytes());src.chmod(original['mode'])
            call('systemctl','daemon-reload')
            raise
        for item in stale:
            src=pathlib.Path(item['file'])
            match=next((x for x in snapshot if x['source']==str(src)),None)
            if match is None:continue
            if secure_file(src) and hashlib.sha256(src.read_bytes()).hexdigest()==item['sha256']:
                src.unlink();archived.append(str(src))
        atomic_json(folder/'manifest.json',{'version':1,'files':snapshot,'created':int(time.time()),'status':'completed'})
        report={'ok':True,'state':'completed','retired':retired,'archived':archived,
                'converted':converted,'preserved':preserved,'snapshot':str(folder),
                'preserved_reasons':{e['unit']:e.get('reason','') for e in before['entries']
                                     if e['unit'] in preserved}}
        atomic_json(STATE/'last.json',report)
        return report

def main():
    if os.geteuid():raise CleanupError('root richiesto')
    if sys.argv[1:]==['scan']:return plan()
    if sys.argv[1:]==['apply']:return run()
    if len(sys.argv)==3 and sys.argv[1]=='retire' and re.fullmatch(r'[a-f0-9]{64}',sys.argv[2]):
        return run(sys.argv[2])
    if sys.argv[1:]==['report']:
        target=STATE/'last.json'
        if not secure_file(target):return {'ok':True,'state':'not-run'}
        return json.loads(target.read_text())
    raise CleanupError('uso: scan | apply | retire SHA256 | report')

if __name__=='__main__':
    try:print(json.dumps(main(),ensure_ascii=False))
    except (CleanupError,OSError,ValueError,TypeError,subprocess.TimeoutExpired) as exc:
        print(json.dumps({'ok':False,'error':str(exc)},ensure_ascii=False));sys.exit(1)
