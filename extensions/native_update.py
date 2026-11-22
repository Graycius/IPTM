#!/usr/bin/env python3
"""IPTM native modular updater.

The web entrypoint dispatches only to this verified root worker for native
archives. No shell installer, tar extraction or arbitrary paths. Manifest SHA256
checks integrity, not publisher identity; HTTP downloads and unsigned packages
remain allowed by user request.
"""
from __future__ import annotations
import hashlib,json,os,pathlib,re,shutil,stat,subprocess,sys,tempfile,zipfile,tokenize,time,traceback

VERSION_RX=re.compile(r'[0-9]+(?:\.[0-9]+){2,3}\Z')
PATH_RX=re.compile(r'(?:modules/[0-9]{2}_[a-z0-9_]+\.php|actions/[a-z_]+\.php|assets/[a-z]+\.(?:css|js)|extensions/[a-z0-9_]+\.py|runtime/iptm-[a-z-]+(?:\.py)?|loader/iptables-manager\.php|CHANGELOG\.md)\Z')
ROOT=pathlib.Path('/usr/local/lib/iptables-manager')
RELEASE_BASE=ROOT/'web/releases'
HELPER=pathlib.Path('/usr/local/sbin/iptm-helper')
RECOVERY=ROOT/'iptm-update-rescue.py'
STATE=pathlib.Path('/var/lib/iptm-update-recovery')
RUNTIME={
  'runtime/iptm-helper':HELPER,
  'runtime/iptm-maintenance.py':ROOT/'iptm-maintenance.py',
  'runtime/iptm-traffic-av.py':ROOT/'iptm-traffic-av.py',
  'runtime/iptm-security.py':ROOT/'iptm-security.py',
  'runtime/iptm-iot-warden.py':ROOT/'iptm-iot-warden.py',
  'runtime/iptm-dns-bundle.py':ROOT/'iptm-dns-bundle.py',
  'runtime/iptm-crowdsec-audit.py':ROOT/'iptm-crowdsec-audit.py'
}
REQUIRED=set(RUNTIME)|{'loader/iptables-manager.php','CHANGELOG.md'}

class UpdateError(Exception):pass

def check_dir(path,create=False):
    if path.is_symlink():raise UpdateError('Directory simbolica non autorizzata')
    if create and not path.exists():path.mkdir(mode=0o755,parents=True)
    if not path.is_dir():raise UpdateError('Directory richiesta non disponibile')
    st=path.stat()
    if st.st_uid!=0 or st.st_mode & 0o022:raise UpdateError('Directory non protetta da root: '+str(path))


def parse_package(path,sha):
    if not re.fullmatch(r'[a-f0-9]{64}',sha):raise UpdateError('SHA-256 non valido')
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for chunk in iter(lambda:f.read(65536),b''):h.update(chunk)
    if h.hexdigest()!=sha:raise UpdateError('Hash archivio differente')
    with zipfile.ZipFile(path,'r') as z:
        infos=z.infolist()
        names=[x.filename for x in infos]
        if len(names)>128 or len(names)<len(REQUIRED)+1 or len(set(names))!=len(names):raise UpdateError('Membri ZIP mancanti o duplicati')
        if 'native-manifest.json' not in names:raise UpdateError('Archivio non native')
        total=0
        for info in infos:
            name=info.filename
            if (name!='native-manifest.json' and not PATH_RX.fullmatch(name)) or info.is_dir() or info.flag_bits&1:
                raise UpdateError('Percorso archivio non consentito: '+name)
            if (info.external_attr>>16)&0o170000 not in (0,stat.S_IFREG):
                raise UpdateError('File non regolare nello ZIP')
            if info.file_size>900000 or info.file_size<1:raise UpdateError('Dimensione membro non valida')
            total+=info.file_size
            if total>18*1024*1024:raise UpdateError('Archivio espanso eccessivo')
        if z.testzip() is not None:raise UpdateError('CRC archivio non valido')
        manifest=json.loads(z.read('native-manifest.json'))
        if not isinstance(manifest,dict) or set(manifest)!= {'format','schema','version','sha256'} or manifest['format']!='iptm-native' or manifest['schema']!=1 or not isinstance(manifest['sha256'],dict):
            raise UpdateError('Manifest native non valido')
        version=manifest['version']
        if not isinstance(version,str) or not VERSION_RX.fullmatch(version):raise UpdateError('Versione nativa non valida')
        digests=manifest['sha256']
        if set(digests)!=set(names)-{'native-manifest.json'} or not REQUIRED.issubset(digests) or len([k for k in digests if k.startswith('modules/')])<32 or not any(k.startswith('actions/') for k in digests):
            raise UpdateError('Manifest dei moduli incompleto')
        data={}
        for name,expected in digests.items():
            if not isinstance(expected,str) or not re.fullmatch(r'[a-f0-9]{64}',expected):raise UpdateError('Digest membro non valido')
            content=z.read(name)
            if hashlib.sha256(content).hexdigest()!=expected:raise UpdateError('Hash non valido: '+name)
            data[name]=content
        loader=data['loader/iptables-manager.php'].decode('utf-8')
        helper=data['runtime/iptm-helper'].decode('utf-8')
        if ("APP_VERSION = '"+version+"'" not in loader or
            not re.search(r'(?m)^# iptm-helper v'+re.escape(version)+r'(?:\s|$)',helper)):raise UpdateError('Versioni incoerenti in loader/helper')
        if '/web/releases/'+version not in loader:raise UpdateError('Loader native non punta alla propria release')
        return version,data


def run_check(cmd,timeout=40):
    result=subprocess.run(cmd,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
    if result.returncode:
        raise UpdateError('Verifica non superata: '+pathlib.Path(cmd[0]).name+' ('+str(result.returncode)+')')


def validate_python_source(path):
    """Compile Python without writing orphan __pycache__ into the staged release.

    A former subprocess call to `python -m py_compile` left compiled files in
    staged extensions which were then moved into the immutable release without
    being covered by its manifest.
    """
    try:
        with tokenize.open(path) as source:
            compile(source.read(), str(path), 'exec', dont_inherit=True)
    except (SyntaxError, UnicodeError, OSError) as exc:
        raise UpdateError('Sintassi Python non valida: '+path.name+' ('+type(exc).__name__+')') from exc


def put_file(path,content,mode):
    parent=path.parent
    check_dir(parent)
    fd,tmp=tempfile.mkstemp(prefix='.iptm-native-',dir=parent)
    try:
        with os.fdopen(fd,'wb') as f:
            os.fchmod(f.fileno(),mode);f.write(content);f.flush();os.fsync(f.fileno())
        os.replace(tmp,path)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)


def checked_recovery(args):
    if not RECOVERY.is_file() or RECOVERY.is_symlink() or RECOVERY.stat().st_uid!=0 or RECOVERY.stat().st_mode&0o022:
        raise UpdateError('Recovery agent root non disponibile; aggiornamento non iniziato')
    run_check(['/usr/bin/python3',str(RECOVERY),'update-recovery',*args],timeout=90)


def verified_confirmed_qos(profile):
    """Read-only preflight: never stop an existing confirmed shaper during staging."""
    old=profile.get('version')
    if not isinstance(old,str) or not VERSION_RX.fullmatch(old):return False
    engine=RELEASE_BASE/old/'extensions/qos_engine.py'
    unit=pathlib.Path('/etc/systemd/system/iptm-qos-watchdog.service')
    if not engine.is_file() or engine.is_symlink() or engine.stat().st_uid:return False
    if not unit.is_file() or unit.is_symlink() or f'/web/releases/{old}/extensions/qos_engine.py watchdog' not in unit.read_text():return False
    try:
        check=subprocess.run(['/usr/bin/python3','-B',str(engine),'status'],
                             capture_output=True,text=True,timeout=20)
        if check.returncode:return False
        data=json.loads(check.stdout)
        if data.get('state')!='confirmed' or data.get('verified') is not True or data.get('interface')!=profile.get('interface'):return False
        adaptive=pathlib.Path('/var/lib/iptm-qos-engine/adaptive.json')
        if adaptive.exists():
            if adaptive.is_symlink() or not adaptive.is_file() or adaptive.stat().st_uid or adaptive.stat().st_mode&0o077:return False
            if json.loads(adaptive.read_text()).get('trial') is not None:return False
        return True
    except (OSError,ValueError,subprocess.TimeoutExpired):return False

def preflight_network_transactions(target_version):
    """Reject unsafe upgrades BEFORE swapping the loader/helper or watchdog.

    Confirmed CAKE is owned by a specific immutable engine version. Migrating
    the watchdog while its kernel topology is live would orphan its rollback.
    """
    candidates = (
        '/var/lib/iptm-qos-engine/active.json',
        '/var/lib/iptm-sqm-uplink/state.json',
        '/var/lib/iptm-sqm-reconcile/state.json',
        '/var/lib/iptm-nm-editor/trial.json',
        '/var/lib/iptm-network-runtime/transaction.json',
    )
    for raw in candidates:
        p=pathlib.Path(raw)
        if not p.exists() and not p.is_symlink(): continue
        if p.is_symlink() or not p.is_file() or p.stat().st_uid!=0 or p.stat().st_mode & 0o077:
            raise UpdateError('Journal rete non protetto: '+raw)
        try:doc=json.loads(p.read_text())
        except (ValueError,UnicodeError):raise UpdateError('Journal rete non valido: '+raw)
        if not isinstance(doc,dict):raise UpdateError('Journal rete non valido: '+raw)
        if doc.get('state') in ('pending','applying','rollback-failed','confirmed','reconciling') or doc.get('status') in ('pending','applying','rollback-failed','confirmed','reconciling'):
            if doc.get('version')!=target_version:
                if raw.endswith('/iptm-qos-engine/active.json') and doc.get('state')=='confirmed' and verified_confirmed_qos(doc):
                    continue  # Handoff only AFTER recovery journal is committed.
                raise UpdateError('Transazione rete non migrabile in sicurezza ('+raw+'). Non cancellare qdisc o journal.')

def quarantine_failed_release(release, web, *, state=STATE, base=RELEASE_BASE):
    """Preserve a failed tree outside releases only after verified recovery.

    Never move an active tree, a symlink, a pending transaction or a tree
    referred to by systemd. Caller must have completed rollback successfully.
    """
    if (state/'pending.json').exists() or (state/'pending.json').is_symlink():
        return 'pending-update'
    if release.is_symlink() or not release.is_dir() or release.parent!=base:
        return 'unsafe-release'
    if not VERSION_RX.fullmatch(release.name):return 'invalid-version'
    try:
        if f'/web/releases/{release.name}/' in web.read_text():return 'loader-references-release'
        for parent in (pathlib.Path('/etc/systemd/system'), pathlib.Path('/etc/cron.d')):
            if not parent.exists():continue
            for f in parent.rglob('*'):
                if not f.is_file() or f.is_symlink() or f.stat().st_size>1048576:continue
                if f'/web/releases/{release.name}/' in f.read_text(errors='replace'):
                    return 'service-references-release'
        check_dir(release)
        # No deletion, preserve exact tree for forensic recovery.
        destination=base/('.failed-'+release.name+'-'+str(time.time_ns()))
        os.replace(release,destination)
        return str(destination)
    except (OSError, UnicodeError, UpdateError) as exc:
        return 'quarantine-skipped: '+str(exc)


def migrate(web,archive,sha,force):
    if os.geteuid()!=0:raise UpdateError('Aggiornamento consentito solo a root')
    web=pathlib.Path(web)
    if not web.is_absolute() or '..' in web.parts or web.name!='iptables-manager.php' or web.is_symlink():
        raise UpdateError('Percorso PHP non autorizzato')
    check_dir(ROOT)
    check_dir(RELEASE_BASE.parent)
    check_dir(RELEASE_BASE)
    check_dir(HELPER.parent)
    check_dir(web.parent)  # must succeed before staging or modifying root workers
    if not web.is_file() or web.stat().st_uid!=0:raise UpdateError('Entrypoint PHP non protetto')
    version,data=parse_package(archive,sha)
    old_match=re.search(rb"APP_VERSION\s*=\s*'([0-9.]+)'",web.read_bytes())
    if not old_match:raise UpdateError('Versione installata sconosciuta')
    current=old_match.group(1).decode()
    if not VERSION_RX.fullmatch(current):raise UpdateError('Versione installata malformata')
    current_order=tuple(map(int,current.split('.')))
    candidate_order=tuple(map(int,version.split('.')))
    if candidate_order<current_order:
        raise UpdateError('Downgrade non consentito: ripristinare da backup verificato, non usare force')
    if force!='force' and candidate_order==current_order:
        raise UpdateError('Versione già installata; force consente soltanto reinstallazione della stessa versione')
    if (STATE/'pending.json').exists() or (STATE/'pending.json').is_symlink():
        raise UpdateError('Journal aggiornamento precedente ancora pendente')
    if not shutil.which('php') or not shutil.which('bash'):raise UpdateError('Validatori PHP/Bash non disponibili')
    preflight_network_transactions(version)
    if not pathlib.Path('/etc/systemd/system/iptm-update-recover.service').is_file():
        raise UpdateError('Unità recovery update non presente')
    with tempfile.TemporaryDirectory(prefix='.native-stage-',dir=RELEASE_BASE) as stage_str:
        stage=pathlib.Path(stage_str)
        for name,content in data.items():
            local=stage/name;local.parent.mkdir(parents=True,exist_ok=True)
            local.write_bytes(content);local.chmod(0o755 if name=='runtime/iptm-helper' else 0o644)
        for path in stage.rglob('*.php'):run_check(['php','-l',str(path)])
        for path in stage.rglob('*.py'):validate_python_source(path)
        run_check(['bash','-n',str(stage/'runtime/iptm-helper')])
        new_root=RELEASE_BASE/version
        if new_root.exists() or new_root.is_symlink():
            raise UpdateError('Versione già installata: non sovrascrivere un albero live')
        for entry in stage.iterdir():
            if entry.name in ('modules','actions','assets','extensions'):
                for p in entry.rglob('*'):
                    p.chmod(0o755 if p.is_dir() else 0o644)
        new_root.mkdir(mode=0o755)
        try:
            for group in ('modules','actions','assets','extensions'):
                os.replace(stage/group,new_root/group)
            manifest={'version':version,'files':{k:v for k,v in data.items() if k.startswith(('modules/','actions/','assets/','extensions/'))}}
            # The physical version directory is immutable after publication.
            (new_root/'native-manifest.json').write_text(json.dumps({'version':version,'sha256':{
                k:hashlib.sha256(v).hexdigest() for k,v in manifest['files'].items()}},sort_keys=True))
            for p in new_root.rglob('*'):p.chmod(0o755 if p.is_dir() else 0o644)
            backup_started=False
            try:
                checked_recovery(['stage','--state',str(STATE),'--web',str(web)])
                backup_started=True
                for name,dest in RUNTIME.items():put_file(dest,data[name],0o755 if dest==HELPER else 0o644)
                put_file(web,data['loader/iptables-manager.php'],0o644)
                # Smoke test the helper, and verify its version and deployed files.
                check= subprocess.run([str(HELPER),'version'],capture_output=True,text=True,timeout=15)
                if check.returncode or (check.stdout.splitlines() or [''])[0].strip()!=version:
                    raise UpdateError('Versione helper post installazione incoerente')
                check=subprocess.run([str(HELPER),'ping'],capture_output=True,text=True,timeout=90)
                if check.returncode or (check.stdout.splitlines() or [''])[0].strip()!='ok':
                    raise UpdateError('Verifica post-installazione fallita: '+((check.stderr or check.stdout or 'nessuna diagnostica')[-900:]).strip())
                if web.read_bytes()!=data['loader/iptables-manager.php']:
                    raise UpdateError('Loader PHP non corrisponde al pacchetto')
                for name,dest in RUNTIME.items():
                    if hashlib.sha256(dest.read_bytes()).hexdigest()!=hashlib.sha256(data[name]).hexdigest():
                        raise UpdateError('File root modificato durante aggiornamento: '+name)
                checked_recovery(['commit','--state',str(STATE)])
            except BaseException as original_error:
                recovered=False
                if backup_started:
                    try:
                        checked_recovery(['recover','--state',str(STATE)])
                        recovered=True
                    except Exception as recovery_error:
                        print('IPTM RECOVERY FAILED: '+str(recovery_error),file=sys.stderr,flush=True)
                else:
                    recovered=True  # no root worker or loader was replaced
                if recovered:
                    result=quarantine_failed_release(new_root,web)
                    print('IPTM failed release: '+result,file=sys.stderr,flush=True)
                raise
        except BaseException:
            # Preserve trees where recovery is uncertain, never delete blindly.
            raise
    # Post-commit ownership handoff must NEVER be part of the smoke test:
    # the previous updater may still need to restore its runtime files.
    migration={'state':'pending','detail':'post-installazione non ancora verificata'}
    post=RELEASE_BASE/version/'extensions/postinstall.py'
    if post.is_file() and not post.is_symlink():
        try:
            r=subprocess.run(['/usr/bin/python3','-B',str(post),'ensure'],capture_output=True,text=True,timeout=100)
            if not r.returncode:
                migration={'state':'completed','detail':json.loads(r.stdout)}
            else:
                migration={'state':'pending','detail':(r.stderr or r.stdout)[-600:]}
        except (OSError,ValueError,subprocess.TimeoutExpired) as e:
            migration={'state':'pending','detail':str(e)[:300]}
    # Cleanup is independent of the QoS handoff: an unrelated QoS warning must
    # never prevent safe retirement of fully verified dormant software artifacts.
    post_cleanup=migration.get('detail',{}).get('cleanup') if isinstance(migration.get('detail'),dict) else None
    if not post_cleanup:
        worker=RELEASE_BASE/version/'extensions/upgrade_cleanup.py'
        if worker.is_file() and not worker.is_symlink():
            try:
                result=subprocess.run(['/usr/bin/python3','-B',str(worker),'apply'],
                                      capture_output=True,text=True,timeout=45)
                post_cleanup=json.loads(result.stdout) if result.returncode==0 else {
                    'ok':False,'error':(result.stderr or result.stdout)[-400:]}
            except (OSError,ValueError,subprocess.TimeoutExpired) as exc:
                post_cleanup={'ok':False,'error':str(exc)[:220]}
    # Never delete a release still referenced by a fallback watchdog.
    cleanup=prune_old_releases(version,current)
    return {'ok':True,'version':version,'previous':current,'format':'iptm-native',
            'restore':'journal-committed','postinstall':migration,
            'cleanup':post_cleanup,'release_cleanup':cleanup}



def prune_old_releases(current, previous, *, base=RELEASE_BASE, days=7):
    """Conservative post-commit housekeeping. Never delete referenced or unverified trees.

    Only native-managed immutable releases whose files still match their manifest,
    older than the retention interval, may be removed. Keep at least three recent
    releases and both update endpoints. A failure never aborts a committed update.
    """
    import time
    report={'deleted':[], 'preserved':[], 'errors':[]}
    try:
        check_dir(base)
        # Refuse pruning during an unresolved update or active QoS/NM trial.
        if (STATE/'pending.json').exists():return dict(report,reason='pending-update')
        for candidate in ('/var/lib/iptm-qos-engine/active.json',
                          '/var/lib/iptm-nm-editor/trial.json'):
            f=pathlib.Path(candidate)
            if f.is_file():
                try:
                    state=json.loads(f.read_text())
                    if state.get('state') in ('pending','applying','rollback-failed'):
                        return dict(report,reason='network-transaction')
                except (OSError, ValueError):return dict(report,reason='unreadable-state')
        version_dirs=[]
        for item in base.iterdir():
            if item.is_symlink() or not item.is_dir() or not VERSION_RX.fullmatch(item.name):continue
            version_dirs.append(item)
        version_dirs.sort(key=lambda x:tuple(map(int,x.name.split('.'))),reverse=True)
        protected={current,previous}|{f.name for f in version_dirs[:3]}
        # All systemd unit/drop-in and IPTM runtime/loader files may pin old releases.
        reference_locations=[pathlib.Path('/etc/systemd/system'),
                             pathlib.Path('/etc/cron.d'),pathlib.Path('/etc/cron.daily'),
                             pathlib.Path('/etc/cron.hourly'),pathlib.Path('/etc/crontab'),
                             pathlib.Path('/var/spool/cron/crontabs'),
                             pathlib.Path('/usr/local/sbin'),ROOT,HELPER]
        referenced=set()
        for folder in reference_locations:
            if not folder.exists():continue
            try:
                files=[folder] if folder.is_file() else folder.rglob('*')
                for f in files:
                    if not f.is_file() or f.is_symlink() or f.stat().st_size>1000000:continue
                    # Do not treat historical release source itself as a live reference.
                    if base in f.parents:continue
                    if f.suffix not in ('.service','.timer','.socket','.path','.php','.py','.sh',''):
                        continue
                    content=f.read_bytes()
                    for m in re.finditer(rb'/web/releases/([0-9]+(?:\.[0-9]+){2,3})/',content):
                        referenced.add(m.group(1).decode())
            except (OSError,PermissionError) as exc:
                return dict(report,reason='reference-scan-failed',errors=[str(exc)])
        protected |= referenced
        for item in version_dirs:
            if item.name in protected or time.time()-item.stat().st_mtime<days*86400:
                report['preserved'].append(item.name);continue
            try:
                check_dir(item)
                man=item/'native-manifest.json'
                if man.is_symlink() or not man.is_file():continue
                metadata=json.loads(man.read_text())
                if metadata.get('version')!=item.name or not isinstance(metadata.get('sha256'),dict):continue
                hashes=metadata['sha256']
                expected={x for x in hashes if x.startswith(('modules/','actions/','assets/','extensions/'))}
                if set(hashes)!=expected or not expected:continue
                # Unrecognized extra files or changed files -> preserve, never recursively delete.
                actual={str(f.relative_to(item)) for f in item.rglob('*') if f.is_file()}
                if actual!=expected|{'native-manifest.json'}:continue
                if any(f.is_symlink() or f.stat().st_uid!=0 for f in item.rglob('*')):continue
                if any(hashlib.sha256((item/name).read_bytes()).hexdigest()!=digest
                       for name,digest in hashes.items()):continue
                shutil.rmtree(item)
                report['deleted'].append(item.name)
            except (OSError,ValueError,TypeError) as exc:
                report['errors'].append(item.name+': '+str(exc))
    except (OSError,UpdateError) as exc:
        report['errors'].append(str(exc))
    return report


def main():
    if len(sys.argv)!=5:raise UpdateError('Uso: native-update WEB ZIP SHA256 force|-')
    result=migrate(pathlib.Path(sys.argv[1]),pathlib.Path(sys.argv[2]),sys.argv[3],sys.argv[4])
    print('versione '+result['previous']+' -> '+result['version']+' [NATIVE]')
    print(json.dumps(result))

if __name__=='__main__':
    try:main()
    except (UpdateError, OSError, ValueError, KeyError, zipfile.BadZipFile, json.JSONDecodeError, subprocess.TimeoutExpired) as exc:
        print('IPTM native update rifiutato: '+str(exc),file=sys.stderr);sys.exit(1)
