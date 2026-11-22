#!/usr/bin/env python3
"""IPTM 5.30.1: conservative retention of IPTM-owned completed artifacts.

CLI is root-only. Preview and run share the SAME selection function. No deletion of
live files, user-named backups, journals, locks, pending transactions or external logs.
This engine never touches iptables, resolvers, CAKE, journald or other services.
"""
from __future__ import annotations
import datetime as dt
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

DATA = Path('/var/lib/iptables-manager')
DIAG = Path('/var/lib/iptm-diagnostics')
SOURCES = Path('/var/lib/iptm-antidpi/sources')
RECOVERY = Path('/var/lib/iptm-update-recovery')
POLICY_NAME = 'retention-policy.json'
REPORT_NAME = 'retention-last.json'
DEFAULTS = {'backup_days': 45, 'backup_keep': 10, 'report_days': 30,
            'report_keep': 15, 'stats_days': 30, 'max_backup_mib': 1024,
            'log_copies': 14}
BOUNDS = {'backup_days': (7, 730), 'backup_keep': (3, 100),
          'report_days': (7, 365), 'report_keep': (3, 100),
          'stats_days': (14, 365), 'max_backup_mib': (128, 65536),
          'log_copies': (3, 90)}
MIN_AGE = 24 * 3600
MAX_ITEMS = 5000
MAX_DIR_FILES = 4000
MAX_TREE_DEPTH = 12

# Explicitly owned paths/patterns only. Every unmatched path is forever excluded.
CATEGORIES = (
    ('firewall', 'data/backups', r'rules\.v[46]\.\d{8}-\d{6}(?:-[0-9a-f]{8})?|settings\.migrate-\d{8}[^/]*\.json|live\.minimal-\d{8}[^/]*\.rules', 'file','backup'),
    ('upgrades','data/backups',r'pre-update-[a-zA-Z0-9._-]{4,90}','dir','backup'),
    ('fw_rescue','data/backups',r'fw-guard-[a-zA-Z0-9._-]{4,90}','dir','backup'),
    ('dns_import','data/backups',r'dns-import-[a-zA-Z0-9._-]{5,96}','dns_journal','backup'),
    ('dns_guard','data/backups/dns-guard',r'dnscrypt\.\d{8}-\d{6}-\d+\.toml','file','backup'),
    ('unbound','data/backups/unbound-managed',r'iptm-hardening\.[a-zA-Z0-9._-]+\.conf','file','backup'),
    ('maintenance','data/backups/maintenance',r'[a-zA-Z0-9_.-]+\.\d{8}-\d{6}\.\d+\.bak|pihole-api-before-[a-zA-Z0-9_.-]+\.json','file','backup'),
    ('lynis','data/lynis-audits',r'[0-9a-f]{16}','lynis','report'),
    ('diagnostics','diag',r'run-[0-9a-f]{20}\.json','file','report'),
    ('antidpi_jobs','sources',r'[0-9a-f]{24}\.json','file','report'),
    ('statistics','data/stats',r'day-\d{4}-\d{2}-\d{2}\.jsonl','file','stats'),
)


def safe_fd(path: Path):
    """Walk path from / with O_NOFOLLOW at EACH segment (not just final)."""
    if not path.is_absolute():raise ValueError('path non assoluto')
    fd = os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            if part in ('.','..',''):raise ValueError('path ambiguo')
            fd2=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            os.close(fd);fd=fd2
        return fd
    except (OSError, ValueError):
        os.close(fd)
        raise


def child_stat(fd,name):
    return os.stat(name,dir_fd=fd,follow_symlinks=False)


def safe_json(path,limit=200000):
    try:
        fd=safe_fd(path.parent)
        try:
            st=child_stat(fd,path.name)
            if not stat.S_ISREG(st.st_mode) or st.st_size>limit:return {}
            r=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=fd)
            try:
                with os.fdopen(r,'rb') as stream: data=stream.read(limit+1)
            except Exception:raise
            return json.loads(data) if len(data)<=limit else {}
        finally:os.close(fd)
    except (OSError,ValueError,TypeError):return {}


def atomic_json(path,record):
    root=path.parent
    if root.is_symlink():raise ValueError('directory non sicura')
    root.mkdir(mode=0o700,parents=True,exist_ok=True)
    fd=safe_fd(root)
    name='.retention-'+os.urandom(8).hex()+'.tmp'
    try:
        flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW
        w=os.open(name,flags,0o600,dir_fd=fd)
        try:
            blob=json.dumps(record,ensure_ascii=False,sort_keys=True).encode()
            with os.fdopen(w,'wb') as stream:
                stream.write(blob);stream.flush();os.fsync(stream.fileno())
            os.replace(name,path.name,src_dir_fd=fd,dst_dir_fd=fd)
            os.fsync(fd)
        finally:
            try:os.unlink(name,dir_fd=fd)
            except FileNotFoundError:pass
    finally:os.close(fd)


def load_policy(data=DATA):
    row=safe_json(data/POLICY_NAME)
    if not isinstance(row,dict):row={}
    out=dict(DEFAULTS)
    for key,(low,high) in BOUNDS.items():
        val=row.get(key)
        if type(val) is int and low<=val<=high:out[key]=val
    return out


def validate_policy(raw):
    if not isinstance(raw,dict) or set(raw)!=set(DEFAULTS):raise ValueError('Specificare tutti i parametri della retention')
    for key,(lo,hi) in BOUNDS.items():
        value=raw.get(key)
        if type(value) is not int or value<lo or value>hi:raise ValueError('Valore fuori intervallo: '+key)
    return dict(raw)


def active_recovery(data,rec):
    """Conservative: any uncertain update/pending state blocks backup pruning."""
    guards=[data/'pending.json',data/'fw-pending.json',data/'dns-guard/pending.json',
            data/'backups/dns-guard/pending.json',data/'update-pending.json']
    for f in guards:
        if f.is_symlink() or f.exists():return True
    if rec.exists():
        if rec.is_symlink():return True
        for p in rec.glob('*.json'):
            state=safe_json(p)
            if not state or state.get('status') not in ('committed','recovered','completed','done'):
                return True
    return False


def protected_names(data,diag,sources):
    protected={'lynis':set(),'diagnostics':set(),'antidpi_jobs':set(),'dns_guard':set()}
    lyn=safe_json(data/'lynis-job.json')
    if re.fullmatch(r'[0-9a-f]{16}',str(lyn.get('run_id',''))):protected['lynis'].add(lyn['run_id'])
    state=safe_json(diag/'state.json')
    if re.fullmatch(r'[0-9a-f]{20}',str(state.get('id',''))):protected['diagnostics'].add('run-'+state['id']+'.json')
    source=safe_json(sources/'latest.json')
    if re.fullmatch(r'[0-9a-f]{24}',str(source.get('token',''))):protected['antidpi_jobs'].add(source['token']+'.json')
    pending=safe_json(data/'backups/dns-guard/pending.json')
    if pending and isinstance(pending.get('backup'),str):protected['dns_guard'].add(pending['backup'])
    return protected


def tree_size(fd,depth=0,counter=None):
    if counter is None:counter=[0]
    if depth>MAX_TREE_DEPTH:raise ValueError('profondità backup eccessiva')
    total=0
    with os.scandir(fd) as entries:
        for e in entries:
            counter[0]+=1
            if counter[0]>MAX_DIR_FILES:raise ValueError('troppi file nel backup')
            st=child_stat(fd,e.name)
            if stat.S_ISREG(st.st_mode):total+=st.st_size
            elif stat.S_ISDIR(st.st_mode):
                sub=os.open(e.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
                try:total+=tree_size(sub,depth+1,counter)
                finally:os.close(sub)
            else:raise ValueError('oggetto non regolare nel backup')
    return total


def delete_tree(fd,depth=0):
    if depth>MAX_TREE_DEPTH:raise ValueError('profondità eccessiva')
    with os.scandir(fd) as entries:
        names=[e.name for e in entries]
    if len(names)>MAX_DIR_FILES:raise ValueError('backup modificato durante rotazione')
    for name in names:
        st=child_stat(fd,name)
        if stat.S_ISREG(st.st_mode):os.unlink(name,dir_fd=fd)
        elif stat.S_ISDIR(st.st_mode):
            sub=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            try:delete_tree(sub,depth+1)
            finally:os.close(sub)
            os.rmdir(name,dir_fd=fd)
        else:raise ValueError('oggetto non regolare durante pulizia')


def directory_marker(fd,name,kind):
    if kind=='dns_journal':
        # Only completed/recovered imports are eligible. Unknown state is protected.
        sub=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
        try:
            try:
                f=os.open('restore-journal.json',os.O_RDONLY|os.O_NOFOLLOW,dir_fd=sub)
                with os.fdopen(f,'rb') as stream:blob=stream.read(131073)
                state=json.loads(blob).get('state')
                return state in ('completed','recovered')
            except (OSError,ValueError,TypeError):return False
        finally:os.close(sub)
    if kind=='lynis':
        sub=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
        try:
            return any(stat.S_ISREG(child_stat(sub,n).st_mode) for n in ('report.dat','stdout.log') if n in os.listdir(sub))
        finally:os.close(sub)
    return True


def candidate_inventory(data=DATA,diag=DIAG,sources=SOURCES,rec=RECOVERY,now=None,policy=None):
    now=time.time() if now is None else now
    policy=policy or load_policy(data)
    roots={'data':data,'diag':diag,'sources':sources}
    protection=protected_names(data,diag,sources)
    pending=active_recovery(data,rec)
    notices=[]; all_rows=[]; candidates=[];total_bytes=0
    for category,rel,pattern,kind,group in CATEGORIES:
        base,*parts=rel.split('/')
        folder=roots[base].joinpath(*parts)
        try:fd=safe_fd(folder)
        except (OSError,ValueError):
            notices.append(category+': directory assente/non sicura');continue
        rows=[];matches=0
        try:
            # Enumerate once. Non-matching names are NEVER considered.
            for name in os.listdir(fd):
                if not re.fullmatch(pattern,name):continue
                matches+=1
                if matches>MAX_ITEMS:
                    notices.append(category+': catalogo oltre limite; nessuna pulizia');rows=[];break
                try:
                    st=child_stat(fd,name)
                    if kind=='file':
                        if not stat.S_ISREG(st.st_mode):continue
                        size=st.st_size
                    else:
                        if not stat.S_ISDIR(st.st_mode) or not directory_marker(fd,name,kind):continue
                        sub=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
                        try:size=tree_size(sub)
                        finally:os.close(sub)
                    if st.st_mtime>now+60:continue
                    rows.append({'category':category,'kind':kind,'group':group,'path':str(folder/name),
                                 'name':name,'mtime':st.st_mtime,'inode':st.st_ino,'size':size,
                                 'protected':name in protection.get(category,set())})
                except (OSError,ValueError):
                    notices.append(category+': elemento non regolare escluso')
            rows.sort(key=lambda row:(-row['mtime'],row['name']))
        finally:os.close(fd)
        total_bytes+=sum(x['size'] for x in rows if group=='backup')
        all_rows+=rows
        if group=='stats':
            # Last 14 days are required by graphs, and current day is never touched.
            keep=14;days=policy['stats_days']
        elif group=='backup':keep=policy['backup_keep'];days=policy['backup_days']
        else:keep=policy['report_keep'];days=policy['report_days']
        for i,row in enumerate(rows):
            if row['protected'] or i<keep or now-row['mtime']<max(days*86400,MIN_AGE):continue
            if group=='backup' and pending:continue
            candidates.append(row)
    if pending:notices.append('Transazione di recupero/aggiornamento pendente: eliminazione backup disattivata')
    # An overall backup budget may expire older non-critical backups earlier, but
    # never during the last day and never the newest N of any category.
    if not pending and total_bytes>policy['max_backup_mib']*1048576:
        cap=policy['max_backup_mib']*1048576
        sorted_rows=sorted((r for r in all_rows if r['group']=='backup'),key=lambda r:r['mtime'])
        for row in sorted_rows:
            if total_bytes<=cap:break
            if row in candidates:
                total_bytes-=row['size'];continue
            rank=sorted((r for r in all_rows if r['category']==row['category']),key=lambda r:-r['mtime']).index(row)
            if rank<policy['backup_keep'] or row['protected'] or now-row['mtime']<MIN_AGE:continue
            candidates.append(row);total_bytes-=row['size']
    candidates.sort(key=lambda x:(x['mtime'],x['category'],x['name']))
    return {'candidates':candidates,'all':all_rows,'warnings':list(dict.fromkeys(notices)),
            'backup_bytes':sum(x['size'] for x in all_rows if x['group']=='backup'),
            'pending_recovery':pending,'policy':policy}


def prune_one(row):
    path=Path(row['path']);fd=safe_fd(path.parent)
    try:
        st=child_stat(fd,path.name)
        if st.st_ino!=row['inode'] or abs(st.st_mtime-row['mtime'])>.001:
            return 'changed'
        if row['kind']=='file':
            if not stat.S_ISREG(st.st_mode):return 'changed'
            os.unlink(path.name,dir_fd=fd)
        else:
            if not stat.S_ISDIR(st.st_mode):return 'changed'
            sub=os.open(path.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            try:
                tree_size(sub)  # refuse symlinks, unusual entries and unbounded trees
                delete_tree(sub)
            finally:os.close(sub)
            os.rmdir(path.name,dir_fd=fd)
        return 'deleted'
    finally:os.close(fd)


def logrotate_config(policy,data=DATA):
    # Only IPTM-owned logs, not system journals nor logs of other applications.
    # copytruncate prevents a stale PHP file descriptor; retention engine only
    # installs this file on the explicit admin's own system.
    a=str(data/'audit.log');b=str(data/'sqm-decisions.log')
    return (f'{a} {b} {{\n  daily\n  maxsize 2M\n  rotate {policy["log_copies"]}\n'
            '  compress\n  delaycompress\n  missingok\n  notifempty\n  copytruncate\n  dateext\n'
            '  dateformat -%Y%m%d-%H%M%S\n  create 0600 root root\n}\n')


def atomic_system_file(path,content):
    fd=safe_fd(path.parent)
    tmp='.iptm-retention-'+os.urandom(6).hex()
    try:
        if path.is_symlink():raise ValueError('unità/logrotate simbolica non consentita')
        f=os.open(tmp,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o644,dir_fd=fd)
        with os.fdopen(f,'w') as out:out.write(content);out.flush();os.fsync(out.fileno())
        os.replace(tmp,path.name,src_dir_fd=fd,dst_dir_fd=fd)
        os.fsync(fd)
    finally:
        try:os.unlink(tmp,dir_fd=fd)
        except FileNotFoundError:pass
        os.close(fd)


def install(release=None,data=DATA):
    if os.geteuid()!=0:raise ValueError('Solo root')
    release=release or str(Path(__file__).resolve())
    if not re.fullmatch(r'/usr/local/lib/iptables-manager/web/releases/\d+(?:\.\d+){2}/extensions/retention_manager\.py',release):
        raise ValueError('percorso release non autorizzato')
    policy=load_policy(data)
    # Do not take ownership of pre-existing units not created by IPTM.
    unit=Path('/etc/systemd/system/iptm-retention.service')
    timer=Path('/etc/systemd/system/iptm-retention.timer')
    for p in (unit,timer):
        if p.exists() and (p.is_symlink() or 'IPTM managed retention' not in p.read_text(errors='replace')[:500]):
            raise ValueError('unità systemd esistente non riconosciuta: '+str(p))
    atomic_system_file(unit,('[Unit]\nDescription=IPTM managed retention - backups and logs\n'
       'After=local-fs.target\n[Service]\nType=oneshot\nUser=root\n'
       f'ExecStart=/usr/bin/python3 -B {release} run\n'
       'Nice=10\nIOSchedulingClass=best-effort\nIOSchedulingPriority=7\n'
       'NoNewPrivileges=true\nPrivateTmp=true\n'))
    atomic_system_file(timer,('[Unit]\nDescription=IPTM managed retention - daily\n'
       '[Timer]\nOnCalendar=daily\nPersistent=true\nRandomizedDelaySec=15min\nUnit=iptm-retention.service\n'
       '[Install]\nWantedBy=timers.target\n'))
    if Path('/usr/sbin/logrotate').is_file() or Path('/usr/bin/logrotate').is_file():
        atomic_system_file(Path('/etc/logrotate.d/iptm'),logrotate_config(policy,data))
    r=subprocess.run(['/usr/bin/systemctl','daemon-reload'],capture_output=True,timeout=15)
    if r.returncode:raise ValueError('systemd daemon-reload fallito')
    r=subprocess.run(['/usr/bin/systemctl','enable','--now','iptm-retention.timer'],capture_output=True,timeout=20)
    if r.returncode:raise ValueError('timer systemd non avviabile')
    return {'ok':True,'timer':'iptm-retention.timer','logrotate_present':bool(Path('/usr/sbin/logrotate').exists() or Path('/usr/bin/logrotate').exists())}


def status(data=DATA):
    row=safe_json(data/REPORT_NAME)
    return {'ok':True,'policy':load_policy(data),'last_run':row if isinstance(row,dict) else {},
            'scope':'Solo archivi IPTM. Journald/Pi-hole/Suricata/CrowdSec esclusi.'}


def preview(data=DATA,diag=DIAG,sources=SOURCES,rec=RECOVERY,now=None):
    inv=candidate_inventory(data,diag,sources,rec,now)
    counts={}
    for r in inv['candidates']:
        group=counts.setdefault(r['category'],{'items':0,'bytes':0})
        group['items']+=1;group['bytes']+=r['size']
    return {'ok':True,'dry_run':True,'total':len(inv['candidates']),
            'reclaim_bytes':sum(r['size'] for r in inv['candidates']),
            'backup_bytes':inv['backup_bytes'],'groups':counts,'warnings':inv['warnings'],
            'policy':inv['policy'],'pending_recovery':inv['pending_recovery'],
            'note':'Anteprima: nessun file cancellato, nessun servizio modificato'}


def run(data=DATA,diag=DIAG,sources=SOURCES,rec=RECOVERY,now=None,rotate_logs=True):
    data.mkdir(parents=True,exist_ok=True)
    if data.is_symlink():raise ValueError('Directory IPTM non sicura')
    fd=safe_fd(data)
    try:
        lock=os.open('retention.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600,dir_fd=fd)
    finally:os.close(fd)
    try:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(lock);return {'ok':False,'reason':'rotation-already-running'}
    try:
        inventory=candidate_inventory(data,diag,sources,rec,now)
        deleted=0;reclaimed=0;errors=[]
        for row in inventory['candidates']:
            try:
                # Recheck live protection before EVERY deletion, not just at scan time.
                if row['group']=='backup' and active_recovery(data,rec):
                    continue
                current=protected_names(data,diag,sources)
                if row['name'] in current.get(row['category'],set()):
                    continue
                outcome=prune_one(row)
                if outcome=='deleted':deleted+=1;reclaimed+=row['size']
            except (OSError,ValueError) as exc:
                errors.append(row['category']+': '+type(exc).__name__)
        logs='not-available'
        if rotate_logs and data==DATA:
            exe='/usr/sbin/logrotate' if Path('/usr/sbin/logrotate').exists() else '/usr/bin/logrotate'
            cfg=Path('/etc/logrotate.d/iptm')
            if Path(exe).is_file() and cfg.is_file():
                try:
                    state_dir=Path('/var/lib/iptm-retention')
                    if state_dir.is_symlink():raise ValueError('logrotate state directory symlink')
                    state_dir.mkdir(mode=0o700,parents=True,exist_ok=True)
                    if state_dir.stat().st_uid!=0 or state_dir.stat().st_mode&0o077:
                        raise ValueError('logrotate state directory insecure')
                    r=subprocess.run([exe,'-s','/var/lib/iptm-retention/logrotate.state',str(cfg)],
                                     timeout=20,capture_output=True,stdin=subprocess.DEVNULL)
                    logs='ok' if r.returncode==0 else 'error'
                except (OSError,subprocess.TimeoutExpired,ValueError):logs='error'
            if logs=='error':errors.append('logrotate: errore; controllare il journal timer')
        out={'ok':not errors,'time':dt.datetime.now(dt.timezone.utc).isoformat(),
             'deleted':deleted,'reclaimed_bytes':reclaimed,'errors':errors[:30],
             'warnings':inventory['warnings'][:30],'logs':logs,
             'note':'Solo backup e report IPTM completati; stato live invariato'}
        atomic_json(data/REPORT_NAME,out)
        return out
    finally:
        fcntl.flock(lock,fcntl.LOCK_UN);os.close(lock)


def main():
    if os.geteuid()!=0:raise ValueError('Gestore retention riservato a root')
    if len(sys.argv)!=2:raise ValueError('Comando invalido')
    op=sys.argv[1]
    if op=='status':return status()
    if op=='preview':return preview()
    if op=='run':return run()
    if op=='install':return install()
    if op=='configure':
        raw=sys.stdin.buffer.read(4097)
        if len(raw)>4096:raise ValueError('Configurazione troppo grande')
        values=validate_policy(json.loads(raw))
        atomic_json(DATA/POLICY_NAME,values)
        if Path('/etc/logrotate.d/iptm').exists():
            atomic_system_file(Path('/etc/logrotate.d/iptm'),logrotate_config(values))
        return {'ok':True,'policy':values}
    if op=='trigger':
        p=subprocess.run(['/usr/bin/systemctl','start','--no-block','iptm-retention.service'],
                         capture_output=True,timeout=8)
        return {'ok':p.returncode==0,'queued':p.returncode==0}
    raise ValueError('Operazione retention non autorizzata')

if __name__=='__main__':
    try:
        print(json.dumps(main(),ensure_ascii=False))
    except (OSError,ValueError,TypeError) as e:
        print(json.dumps({'ok':False,'error':str(e)[:240]},ensure_ascii=False));sys.exit(1)
