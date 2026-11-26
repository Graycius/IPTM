#!/usr/bin/env python3
"""IPTM native modular updater.

The web entrypoint dispatches only to this verified root worker for native
archives. No shell installer, tar extraction or arbitrary paths. Manifest SHA256
checks integrity, not publisher identity; URL-based downloads support HTTP/HTTPS; HTTP requires a trusted external SHA-256.
Authenticated local ZIP uploads remain possible. Ed25519 signatures are optional even with a root-pinned public key; external SHA-256 remains required for HTTP.
"""
from __future__ import annotations
import hashlib,json,os,pathlib,re,shutil,stat,subprocess,sys,tempfile,zipfile,tokenize,time,fcntl,contextlib,io

VERSION_RX=re.compile(r'[0-9]+(?:\.[0-9]+){1,3}\Z')
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
    if create and not path.exists():
        path.mkdir(mode=0o755,parents=True)
        path.chmod(0o755)
    if not path.is_dir():raise UpdateError('Directory richiesta non disponibile')
    st=path.stat()
    if st.st_uid!=0 or st.st_mode & 0o022:raise UpdateError('Directory non protetta da root: '+str(path))


def shared_transport():
    import importlib.util
    module=pathlib.Path(__file__).resolve().with_name('command_transport.py')
    cached=getattr(shared_transport,'_module',None)
    if cached is None:
        spec=importlib.util.spec_from_file_location('_iptm_native_transport',module)
        cached=importlib.util.module_from_spec(spec);spec.loader.exec_module(cached)
        shared_transport._module=cached
    return cached

@contextlib.contextmanager
def software_lock(path=None):
    path=pathlib.Path(path or '/run/iptm-software-update.lock')
    check_dir(path.parent)
    try:fd=shared_transport().acquire_domain_lock(path,nonblocking=True)
    except (BlockingIOError,ValueError) as exc:raise UpdateError('Lock software occupato o non protetto') from exc
    try:yield
    finally:os.close(fd)


def read_verified_archive(path,sha):
    if not re.fullmatch(r'[a-f0-9]{64}',sha):raise UpdateError('SHA-256 non valido')
    # Hash and parse the same bounded immutable snapshot. Never reopen a
    # pathname after verification (upload replacement / concurrent rename).
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        meta=os.fstat(fd)
        if not stat.S_ISREG(meta.st_mode) or not 1<=meta.st_size<=18*1024*1024:
            raise UpdateError('Archivio non regolare o dimensione eccessiva')
        with os.fdopen(fd,'rb',closefd=False) as f:archive=f.read(18*1024*1024+1)
    finally:os.close(fd)
    if len(archive)>18*1024*1024 or hashlib.sha256(archive).hexdigest()!=sha:
        raise UpdateError('Hash archivio differente o dimensione eccessiva')
    return archive

SIGNING_KEY=pathlib.Path('/etc/iptm-update-ed25519.pub')

def verify_publisher_signature(archive, key=None):
    """Unsigned archives are accepted even with an enrolled key.
    If a signature is supplied and a key is enrolled, verify it strictly.
    ZIP comment holds the detached Ed25519 signature of the exact manifest bytes.
    Unsigned legacy archives remain eligible for installation.
    """
    with zipfile.ZipFile(io.BytesIO(archive)) as z:
        comment=z.comment
    if not comment.startswith(b'IPTM-ED25519:'): return False
    if not re.fullmatch(rb'IPTM-ED25519:[0-9a-f]{128}',comment):
        raise UpdateError('Firma Ed25519 malformata')
    key=pathlib.Path(key or SIGNING_KEY)
    if not key.exists() and not key.is_symlink(): return False
    check_dir(key.parent)
    meta=key.lstat()
    if not stat.S_ISREG(meta.st_mode) or meta.st_uid!=0 or meta.st_mode&0o022 or meta.st_size>4096:
        raise UpdateError('Chiave pubblica aggiornamenti non protetta')
    with zipfile.ZipFile(io.BytesIO(archive)) as z:
        info=z.getinfo('native-manifest.json')
        if info.file_size>900000: raise UpdateError('Manifest troppo grande')
        manifest=z.read(info)
    if not shutil.which('openssl'): raise UpdateError('OpenSSL richiesto per verifica firma aggiornamenti')
    pub=subprocess.run(['openssl','pkey','-pubin','-in',str(key),'-outform','DER'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15)
    if pub.returncode or len(pub.stdout)!=44 or not pub.stdout.startswith(bytes.fromhex('302a300506032b6570032100')):
        raise UpdateError('Chiave pubblica non Ed25519')
    with tempfile.TemporaryDirectory(prefix='iptm-signature-') as d:
        msg=pathlib.Path(d)/'manifest'; sig=pathlib.Path(d)/'signature'
        msg.write_bytes(manifest); sig.write_bytes(bytes.fromhex(comment.split(b':',1)[1].decode()))
        r=subprocess.run(['openssl','pkeyutl','-verify','-pubin','-inkey',str(key),'-rawin','-in',str(msg),'-sigfile',str(sig)],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15)
        if r.returncode: raise UpdateError('Firma Ed25519 non valida o chiave non riconosciuta')
    return True

def parse_package(path,sha,require_publisher=False):
    archive=read_verified_archive(path,sha)
    with zipfile.ZipFile(io.BytesIO(archive),'r') as z:
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
        if set(digests)!=set(names)-{'native-manifest.json'} or not REQUIRED.issubset(digests) or len([k for k in digests if k.startswith('modules/')])!=43 or not any(k.startswith('actions/') for k in digests):
            raise UpdateError('Manifest dei moduli incompleto')
        data={}
        for name,expected in digests.items():
            if not isinstance(expected,str) or not re.fullmatch(r'[a-f0-9]{64}',expected):raise UpdateError('Digest membro non valido')
            content=z.read(name)
            if hashlib.sha256(content).hexdigest()!=expected:raise UpdateError('Hash non valido: '+name)
            data[name]=content
        loader=data['loader/iptables-manager.php'].decode('utf-8')
        helper=data['runtime/iptm-helper'].decode('utf-8')
        required_modules=set(re.findall(r'modules/[0-9]{2}_[a-z0-9_]+\.php',loader))
        if required_modules!={k for k in data if k.startswith('modules/')}: raise UpdateError('Moduli diversi dal loader')
        if tuple(map(int,version.split('.'))) >= (5,38,0):
            actions=set(re.findall(r'actions/[a-z_]+\.php',loader))
            if actions!={k for k in data if k.startswith('actions/')}:raise UpdateError('Controller diversi dal loader')
        if ("APP_VERSION = '"+version+"'" not in loader or
            not re.search(r'(?m)^# iptm-helper v'+re.escape(version)+r'(?:\s|$)',helper)):raise UpdateError('Versioni incoerenti in loader/helper')
        if '/web/releases/'+version not in loader:raise UpdateError('Loader native non punta alla propria release')
        if require_publisher: verify_publisher_signature(archive)
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
    check_dir(path.parent)
    shared_transport().durable_replace(path,content,mode=mode)


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
    config=pathlib.Path('/etc/iptables-manager.web.json')
    data_dir='/var/lib/iptables-manager'
    if config.exists() or config.is_symlink():
        if config.is_symlink() or not config.is_file() or config.stat().st_uid!=0 or config.stat().st_mode&0o022:
            raise UpdateError('Configurazione web non protetta')
        try: cfg=json.loads(config.read_text())
        except (OSError,ValueError) as exc: raise UpdateError('Configurazione web non valida') from exc
        if not isinstance(cfg,dict): raise UpdateError('Configurazione web non valida')
        data_dir=cfg.get('DATA_DIR',data_dir)
        if not isinstance(data_dir,str) or not re.fullmatch(r'/[A-Za-z0-9._/-]{1,200}',data_dir) or '..' in pathlib.Path(data_dir).parts:
            raise UpdateError('DATA_DIR non valida')
    for pending_path in (pathlib.Path(data_dir)/'pending.json',pathlib.Path('/var/lib/iptm/ipv6-control/pending.json')):
        if pending_path.exists() or pending_path.is_symlink():
            raise UpdateError('Transazione firewall/IPv6 pendente: '+str(pending_path))
    # DNS Guard uses a fixed BACKUP path independently of web DATA_DIR.
    for dns_pending in {pathlib.Path(data_dir)/'backups/dns-guard/pending.json', pathlib.Path('/var/lib/iptables-manager/backups/dns-guard/pending.json')}:
        if dns_pending.exists() or dns_pending.is_symlink():
            raise UpdateError('Transazione DNSCrypt pendente: confermare o ripristinare prima dell’aggiornamento')
    dns_backups=pathlib.Path(data_dir)/'backups'
    if dns_backups.is_dir():
        for folder in dns_backups.glob('dns-import-*'):
            journal=folder/'restore-journal.json'
            if not journal.exists() and not journal.is_symlink():continue
            try:state=shared_transport().read_private_json(journal,limit=1024*1024)
            except (OSError,ValueError) as exc:raise UpdateError('Journal import DNS non verificabile: '+str(journal)) from exc
            if not state or state.get('state') not in ('completed','recovered'):
                raise UpdateError('Import DNS incompleto: recuperare prima dell’aggiornamento')
    candidates = (
        '/var/lib/iptm-qos-engine/unshaped-calibration.json',
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
        if raw.endswith('/unshaped-calibration.json') and doc.get('state')=='pending':
            raise UpdateError('Calibrazione senza shaping in corso: attendere il ripristino CAKE')
        if journal_blocks_update(doc,target_version,raw):
            raise UpdateError('Transazione rete non migrabile in sicurezza ('+raw+'). Non cancellare qdisc o journal.')

def journal_blocks_update(doc,target_version,raw):
    # A reinstall of the same version is also unsafe during a trial or rollback.
    busy={'pending','applying','rolling-back','rollback-failed','reconciling','recovery_required'}
    if any(doc.get(k) in busy for k in ('state','status')):return True
    if 'confirmed' in (doc.get('state'),doc.get('status')) and doc.get('version')!=target_version:
        return not (raw.endswith('/iptm-qos-engine/active.json') and doc.get('state')=='confirmed' and verified_confirmed_qos(doc))
    return False

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


WEB_GROUPS = ('modules/', 'actions/', 'assets/', 'extensions/')

def release_matches(root, data, version):
    try:
        check_dir(root)
        if root.stat().st_mode & 0o005 != 0o005: return False
        expected = {k: hashlib.sha256(v).hexdigest() for k,v in data.items() if k.startswith(WEB_GROUPS)}
        manifest = root/'native-manifest.json'
        if manifest.is_symlink() or json.loads(manifest.read_text()) != {'version':version,'sha256':expected}: return False
        actual = set()
        for path in root.rglob('*'):
            st = path.lstat()
            if path.is_symlink() or st.st_uid != 0 or st.st_mode & 0o022: return False
            if path.is_dir():
                if st.st_mode & 0o005 != 0o005: return False
                continue
            if not path.is_file() or st.st_mode & 0o004 == 0: return False
            actual.add(path.relative_to(root).as_posix())
        if actual != set(expected)|{'native-manifest.json'}: return False
        return all(hashlib.sha256((root/k).read_bytes()).hexdigest()==v for k,v in expected.items())
    except (OSError, ValueError, UpdateError):
        return False

def exchange_release(a, b):
    # Linux renameat2 RENAME_EXCHANGE: no missing active directory window.
    import ctypes
    libc=ctypes.CDLL(None,use_errno=True)
    rename=getattr(libc,'renameat2',None)
    if rename is None: raise UpdateError('Scambio atomico non supportato: release precedente conservata')
    rename.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint]
    rename.restype=ctypes.c_int
    if rename(-100,os.fsencode(a),-100,os.fsencode(b),2):
        raise OSError(ctypes.get_errno(),'Scambio atomico release fallito')


def check_http_health(url, version, data):
    """Check the real HTTP worker and every shipped public asset, without redirects."""
    import urllib.request, urllib.parse
    q=urllib.parse.urlsplit(url)
    if q.scheme!='http' or q.hostname not in ('127.0.0.1','::1') or q.username or q.password or q.query or q.fragment or not q.path.endswith('/iptables-manager.php'):
        raise UpdateError('URL health HTTP loopback non valida')
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,*a,**k): return None
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    with opener.open(url+'?iptm_health=1',timeout=15) as response:
        if response.status!=200 or response.read(256)!=('IPTM_HEALTH '+version).encode():
            raise UpdateError('Health HTTP fallito')
    for name,content in data.items():
        if not name.startswith('assets/') or not name.endswith(('.css','.js')): continue
        with opener.open(url+'?iptm_asset='+urllib.parse.quote(name.split('/')[1]),timeout=15) as response:
            if response.status!=200 or response.read(len(content)+1)!=content:
                raise UpdateError('Asset HTTP non corrispondente: '+name)


def cli_loader_health(web, version):
    """Read-only fallback for installations without a configured HTTP URL.

    Exercises the actual loader as www-data, without bootstrapping the app or
    touching network state. It is not a PHP-FPM/HTTP health test.
    """
    web=pathlib.Path(web)
    if not web.is_absolute() or '..' in web.parts or web.name!='iptables-manager.php' or web.is_symlink() or not web.is_file():
        raise UpdateError('Loader health non valido')
    if web.stat().st_uid!=0 or web.stat().st_mode&0o022:
        raise UpdateError('Loader health non protetto')
    code='$_GET=["iptm_health"=>"1"];$_SERVER["REMOTE_ADDR"]="127.0.0.1";require $argv[1];'
    result=subprocess.run(['runuser','-u','www-data','--','php','-r',code,'--',str(web)],capture_output=True,timeout=20)
    if result.returncode or result.stdout!=('IPTM_HEALTH '+version).encode():
        raise UpdateError('Loader non utilizzabile da www-data: '+result.stderr.decode(errors='replace')[-300:])
    return 'php-cli-www-data'


def legacy_journal_web(state=STATE):
    """Recognize both original v1 and FULL journal layouts, never trust an upload."""
    state=pathlib.Path(state);check_dir(state)
    if state.stat().st_mode&0o077:raise UpdateError('Journal non privato')
    marker=state/'pending.json'
    if marker.is_symlink() or not marker.is_file() or marker.stat().st_uid or marker.stat().st_mode&0o077 or marker.stat().st_size>16*1024*1024:
        raise UpdateError('Journal aggiornamento non protetto')
    obj=json.loads(marker.read_text())
    if not isinstance(obj,dict):raise UpdateError('Journal non valido')
    if obj.get('format')=='iptm.update.v1' and obj.get('phase')=='pending':
        rows=obj.get('files')
        if not isinstance(rows,list):raise UpdateError('Journal v1 non valido')
        candidates=[row.get('target') for row in rows if isinstance(row,dict) and isinstance(row.get('target'),str) and pathlib.Path(row['target']).name=='iptables-manager.php']
    elif isinstance(obj.get('web'),str) and isinstance(obj.get('files'),dict) and obj['web'] in obj['files']:
        candidates=[obj['web']]
    else:raise UpdateError('Formato journal aggiornamento non riconosciuto')
    if len(candidates)!=1:raise UpdateError('Loader nel journal non univoco')
    web=pathlib.Path(candidates[0])
    if not web.is_absolute() or '..' in web.parts or web.name!='iptables-manager.php' or web.is_symlink():
        raise UpdateError('Loader nel journal non valido')
    check_dir(web.parent)
    return web


def health_for_upgrade(web, version, data, health=None):
    health=pathlib.Path(health or ROOT/'health-url')
    if health.exists() or health.is_symlink():
        if health.is_symlink() or not health.is_file() or health.stat().st_uid or health.stat().st_mode&0o022:
            raise UpdateError('Health URL non protetta')
        check_http_health(health.read_text().strip(),version,data)
        return 'http'
    return cli_loader_health(web,version)


def legacy_precommit_health(version):
    web=legacy_journal_web()
    root=RELEASE_BASE/version
    check_dir(root)
    manifest=root/'native-manifest.json'
    if manifest.is_symlink() or not manifest.is_file() or manifest.stat().st_uid or manifest.stat().st_mode&0o022:
        raise UpdateError('Manifest release non protetto')
    meta=json.loads(manifest.read_text())
    if meta.get('version')!=version or not isinstance(meta.get('sha256'),dict):raise UpdateError('Manifest release non valido')
    data={}
    for name,digest in meta['sha256'].items():
        if not name.startswith('assets/'):continue
        if not PATH_RX.fullmatch(name):raise UpdateError('Asset non valido')
        p=root/name
        if p.is_symlink() or not p.is_file():raise UpdateError('Asset assente')
        content=p.read_bytes()
        if hashlib.sha256(content).hexdigest()!=digest:raise UpdateError('Asset corrotto')
        data[name]=content
    mode=health_for_upgrade(web,version,data)
    try:
        previous=previous_from_journal(web,STATE)
        if previous:
            put_file(STATE/'release-cleanup-context.json',json.dumps({'current':version,'previous':previous}).encode(),0o600)
    except (OSError,ValueError,UpdateError,TypeError,KeyError):
        pass # no cleanup if exact old endpoint cannot be identified
    return mode


def previous_from_journal(web,state):
    import base64
    j=json.loads((state/'pending.json').read_text())
    if j.get('format')=='iptm.update.v1':
        rows=[r for r in j['files'] if r.get('target')==str(web) and r.get('present') is True]
        if len(rows)!=1:return None
        row=rows[0];name=row['backup']
        if not re.fullmatch(r'[0-9]{2}\.bak',name):return None
        src=state/'snapshot'/name
        if src.is_symlink() or not src.is_file() or src.stat().st_uid or src.stat().st_size>8*1024*1024:return None
        data=src.read_bytes()
        if hashlib.sha256(data).hexdigest()!=row['sha256']:return None
    else:
        entry=j['files'].get(str(web))
        if not isinstance(entry,list) or len(entry)!=2:return None
        data=base64.b64decode(entry[1],validate=True)
    match=re.search(rb"APP_VERSION\s*=\s*'([0-9.]+)'",data)
    version=match.group(1).decode() if match else None
    return version if version and VERSION_RX.fullmatch(version) else None


def repair_release_modes(root, data, version):
    """Repair only an exact root-owned release; never follow links or alter data."""
    check_dir(root)
    expected={k:hashlib.sha256(v).hexdigest() for k,v in data.items() if k.startswith(WEB_GROUPS)}
    manifest=root/'native-manifest.json'
    if manifest.is_symlink() or not manifest.is_file() or json.loads(manifest.read_text())!={'version':version,'sha256':expected}: return False
    paths=list(root.rglob('*')); actual=set()
    for p in paths:
        st=p.lstat()
        if p.is_symlink() or st.st_uid!=0 or st.st_mode&0o022: return False
        if p.is_dir(): continue
        if not p.is_file(): return False
        actual.add(p.relative_to(root).as_posix())
    if actual!=set(expected)|{'native-manifest.json'}: return False
    if any(hashlib.sha256((root/k).read_bytes()).hexdigest()!=v for k,v in expected.items()): return False
    for p in [root,*paths]: p.chmod(0o755 if p.is_dir() else 0o644)
    return release_matches(root,data,version)


def migrate(web,archive,sha,force):
    with software_lock():
        return _migrate(web,archive,sha,force)

def _migrate(web,archive,sha,force):
    if os.geteuid()!=0:raise UpdateError('Aggiornamento consentito solo a root')
    web=pathlib.Path(web)
    if not web.is_absolute() or not str(web).startswith('/var/www/') or '..' in web.parts or web.name!='iptables-manager.php' or web.is_symlink():
        raise UpdateError('Percorso PHP non autorizzato')
    check_dir(ROOT)
    check_dir(RELEASE_BASE.parent)
    check_dir(RELEASE_BASE)
    check_dir(HELPER.parent)
    check_dir(web.parent)  # must succeed before staging or modifying root workers
    if not web.is_file() or web.stat().st_uid!=0:raise UpdateError('Entrypoint PHP non protetto')
    version,data=parse_package(archive,sha,require_publisher=True)
    old_match=re.search(rb"APP_VERSION\s*=\s*'([0-9.]+)'",web.read_bytes())
    if not old_match:raise UpdateError('Versione installata sconosciuta')
    current=old_match.group(1).decode()
    if not VERSION_RX.fullmatch(current):raise UpdateError('Versione installata malformata')
    current_order=tuple(map(int,current.split('.')))
    candidate_order=tuple(map(int,version.split('.')))
    # Same version and lower versions require an explicit force flag so an
    # accidental upload cannot roll the appliance back or no-op silently.
    if candidate_order<current_order and force!='force':
        raise UpdateError(
            'Downgrade verso '+version+' richiede la conferma force '
            '(dalla versione installata '+current+'). '
            'Verifica backup e regole attive prima di procedere.'
        )
    if force!='force' and candidate_order==current_order and release_matches(RELEASE_BASE/version,data,version) and all(dest.is_file() and not dest.is_symlink() and dest.read_bytes()==data[name] for name,dest in RUNTIME.items()) and web.read_bytes()==data['loader/iptables-manager.php']:
        raise UpdateError('Versione già installata; force consente reinstallazione o conferma di downgrade')
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
        # Do not mutate live network during software staging. Legacy retirement is separate.
        new_root=RELEASE_BASE/version
        if new_root.is_symlink():
            raise UpdateError('Release target è un symlink: intervento manuale richiesto')
        if new_root.exists():
            check_dir(new_root)
            if version==current and not release_matches(new_root,data,version):
                raise UpdateError('Riparazione release attiva: usare installatore console')
            if release_matches(new_root,data,version) and force!='force' and candidate_order!=current_order:
                raise UpdateError('Release già presente e integra: usa force per reinstallare')
        # Assemble and validate before exposing any path to the loader.
        candidate=stage/'publish'
        candidate.mkdir(mode=0o755)
        for group in ('modules','actions','assets','extensions'):
            os.replace(stage/group,candidate/group)
        (candidate/'native-manifest.json').write_text(json.dumps({'version':version,'sha256':{
            k:hashlib.sha256(v).hexdigest() for k,v in data.items() if k.startswith(WEB_GROUPS)}},sort_keys=True))
        candidate.chmod(0o755)
        for entry in candidate.rglob("*"):
            entry.chmod(0o755 if entry.is_dir() else 0o644)
        if not release_matches(candidate,data,version): raise UpdateError('Staging release non integro')
        backup_started=False
        preserved=None
        published=False
        try:
            try:
                checked_recovery(['stage','--state',str(STATE),'--web',str(web)])
                backup_started=True
                if new_root.exists() and release_matches(new_root,data,version):
                    pass
                elif new_root.exists():
                    # Retain the old directory outside the temporary staging tree.
                    preserved=RELEASE_BASE/('.previous-'+version+'-'+str(time.time_ns()))
                    os.replace(candidate,preserved)
                    exchange_release(preserved,new_root)
                else:
                    os.replace(candidate,new_root)
                published=True
                for name,dest in RUNTIME.items():put_file(dest,data[name],0o755 if dest==HELPER else 0o644)
                put_file(web,data['loader/iptables-manager.php'],0o644)
                # Smoke test the helper, and verify its version and deployed files.
                check= subprocess.run([str(HELPER),'version'],capture_output=True,text=True,timeout=15)
                if check.returncode or (check.stdout.splitlines() or [''])[0].strip()!=version:
                    raise UpdateError('Versione helper post installazione incoerente')
                check=subprocess.run([str(HELPER),'ping'],capture_output=True,text=True,timeout=90)
                if check.returncode or (check.stdout.splitlines() or [''])[0].strip()!='ok':
                    raise UpdateError('Verifica post-installazione fallita: '+((check.stderr or check.stdout or 'nessuna diagnostica')[-900:]).strip())
                # The newly installed helper repairs modes and tests real web-user access.
                run_check([str(HELPER),'modules-deploy'],timeout=40)
                user_check=subprocess.run(['runuser','-u','www-data','--','sudo','-n',str(HELPER),'version'],capture_output=True,text=True,timeout=15)
                if user_check.returncode or user_check.stdout.strip()!=version:
                    raise UpdateError('Helper non utilizzabile da www-data tramite sudo')
                if not release_matches(new_root,data,version):
                    raise UpdateError("Release pubblicata non leggibile o non integra")
                if web.read_bytes()!=data['loader/iptables-manager.php']:
                    raise UpdateError('Loader PHP non corrisponde al pacchetto')
                for name,dest in RUNTIME.items():
                    if hashlib.sha256(dest.read_bytes()).hexdigest()!=hashlib.sha256(data[name]).hexdigest():
                        raise UpdateError('File root modificato durante aggiornamento: '+name)
                health_mode='not-supported'
                if b'iptm_health' in data['loader/iptables-manager.php']:
                    health_mode=health_for_upgrade(web,version,data)
                cache=ROOT/'packages'
                check_dir(cache,create=True); cache.chmod(0o700)
                put_file(cache/(version+'.zip'),read_verified_archive(archive,sha),0o600)
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
                if recovered and published and preserved is not None:
                    exchange_release(preserved,new_root)
                if recovered and published and preserved is None:
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
            'restore':'journal-committed','health_mode':health_mode,'postinstall':migration,
            'cleanup':post_cleanup,'release_cleanup':cleanup}



def scan_reference_sources(locations, inspect, *, proc=pathlib.Path('/proc')):
    """Bounded inventory of static paths and live processes. Never execute files."""
    count=0
    def inspect_file(f):
        nonlocal count
        count+=1
        if count>30000:raise UpdateError('Inventario riferimenti troppo esteso')
        if f.is_symlink():
            inspect(os.fsencode(os.readlink(f)),f)
            inspect(os.fsencode(f.resolve()),f)
            # Read linked unit/script content if it is a regular file.
            if not f.is_file():return
        if not f.is_file():return
        if f.stat().st_size>8*1024*1024:raise UpdateError('Riferimento troppo grande: '+str(f))
        inspect(f.read_bytes(),f)
    for location in locations:
        if location.is_symlink():inspect_file(location)
        elif location.is_dir():
            for f in location.rglob('*'):
                if f.is_file() or f.is_symlink():inspect_file(f)
        elif location.exists():inspect_file(location)
    if proc is not None:
        for process in proc.iterdir():
            if not process.name.isdigit():continue
            try:
                inspect((process/'cmdline').read_bytes(),f'PID {process.name}: cmdline')
                for name in ('cwd','exe','root'):
                    try:inspect(os.fsencode(os.readlink(process/name)),f'PID {process.name}: {name}')
                    except FileNotFoundError:pass
                for descriptor in (process/'fd').iterdir():
                    try:inspect(os.fsencode(os.readlink(descriptor)),f'PID {process.name}: fd')
                    except FileNotFoundError:pass
                # A loaded immutable release may still be referenced by a process.
                maps=process/'maps'
                with maps.open('rb') as stream:
                    for line in stream:inspect(line,f'PID {process.name}: maps')
            except (FileNotFoundError,ProcessLookupError):continue


def release_reference_versions(locations, *, proc=pathlib.Path('/proc'), evidence=None):
    """Conservative inventory, including transient systemd units."""
    rx=re.compile(rb'/web/releases/([0-9]+(?:\.[0-9]+){1,3})(?=/|[\s\x00\'\"]|$)')
    found=set()
    def inspect(content, source):
        versions={m.decode() for m in rx.findall(content)}
        found.update(versions)
        if evidence is not None:
            for v in versions:
                entries=evidence.setdefault(v,set())
                if len(entries)<32:entries.add(str(source))
    scan_reference_sources(locations,inspect,proc=proc)
    return found


def verified_retired_tree(item):
    check_dir(item)
    man=item/'native-manifest.json'
    if man.is_symlink() or not man.is_file() or man.stat().st_uid or man.stat().st_mode&0o022 or man.stat().st_size>256*1024:
        return False
    metadata=json.loads(man.read_text())
    if not isinstance(metadata,dict):return False
    hashes=metadata.get('sha256')
    if metadata.get('version')!=item.name or not isinstance(hashes,dict) or not hashes:return False
    if any(not isinstance(n,str) or not PATH_RX.fullmatch(n) or not n.startswith(WEB_GROUPS) or not isinstance(d,str) or not re.fullmatch(r'[a-f0-9]{64}',d) for n,d in hashes.items()):return False
    entries=list(item.rglob('*'))
    if any(f.is_symlink() or f.stat().st_uid or f.stat().st_mode&0o022 or (not f.is_file() and not f.is_dir()) or (f.is_file() and f.stat().st_nlink!=1) for f in entries):return False
    actual={str(f.relative_to(item)) for f in entries if f.is_file()}
    if actual != set(hashes)|{'native-manifest.json'}:return False
    # Do not delete unknown empty directories either.
    expected_dirs={str(p) for n in hashes for p in pathlib.PurePosixPath(n).parents if str(p)!='.'}
    if {str(f.relative_to(item)) for f in entries if f.is_dir()}!=expected_dirs:return False
    if len([n for n in hashes if n.startswith('modules/')])!=43:return False
    return all((item/n).stat().st_size<=900000 and hashlib.sha256((item/n).read_bytes()).hexdigest()==d for n,d in hashes.items())


def release_locations():
    locations=[pathlib.Path(x) for x in ('/etc/systemd/system','/run/systemd/system','/run/systemd/transient','/run/systemd/generator','/run/systemd/generator.early','/run/systemd/generator.late','/run/systemd/system.control','/etc/systemd/system.control','/usr/lib/systemd/system','/lib/systemd/system','/etc/cron.d','/etc/cron.daily','/etc/cron.hourly','/etc/cron.weekly','/etc/cron.monthly','/etc/crontab','/etc/rc.local','/etc/init.d','/etc/network','/etc/iptables-manager.conf','/etc/iptables-manager.d','/var/spool/cron/crontabs','/etc/lighttpd','/etc/php','/etc/nginx','/etc/apache2','/usr/local/sbin','/var/lib/iptm-qos-engine/active.json','/var/lib/iptm-qos-engine/handoff.json','/var/lib/iptm-sqm-uplink/state.json','/var/lib/iptm-sqm-reconcile/state.json')]
    # Include all configured loader copies, without scanning unrelated web assets.
    locations.extend(pathlib.Path('/var/www').rglob('iptables-manager.php'))
    locations.extend(RUNTIME.values())
    return locations

def prune_old_releases(current, previous, *, base=RELEASE_BASE, keep=3, cache=None,
                       locations=None, proc=pathlib.Path('/proc'), check_transactions=True, dry_run=False, include_archives=True, extra_protected=()):
    """Post-commit only: retain current, immediate rollback, newest three and all references.

    Remove only manifest-verified version trees and validated private native archives.
    Preserve unknown/modified trees, quarantines, future versions and user backups.
    """
    report={'deleted':[], 'archives_deleted':[], 'preserved':[], 'archives_preserved':[], 'errors':[], 'keep':keep,'preview':dry_run,'candidates':[],'reasons':{}}
    try:
        check_dir(base)
        if not VERSION_RX.fullmatch(current) or (previous and not VERSION_RX.fullmatch(previous)):raise UpdateError('Versione pulizia non valida')
        if (STATE/'pending.json').exists() or (STATE/'pending.json').is_symlink():return dict(report,reason='pending-update')
        if check_transactions:preflight_network_transactions(current)
        if not verified_retired_tree(base/current):raise UpdateError('Release corrente non verificabile: pulizia sospesa')
        if locations is None:locations=release_locations()
        referenced=release_reference_versions(locations,proc=proc)
        key=lambda v:tuple(map(int,v.split('.')))
        items=[x for x in base.iterdir() if VERSION_RX.fullmatch(x.name)]
        versions=sorted([x.name for x in items if x.is_dir() and not x.is_symlink() and key(x.name)<=key(current)],key=key,reverse=True)
        protected={current,previous}|set(versions[:max(3,int(keep))])|referenced|set(extra_protected)
        cache=pathlib.Path(cache or ROOT/'packages')
        archives=[]
        if include_archives and (cache.exists() or cache.is_symlink()):
            check_dir(cache)
            if cache.stat().st_mode&0o077:raise UpdateError('Archivio rollback non privato')
            archives=[x for x in cache.iterdir() if x.suffix=='.zip' and VERSION_RX.fullmatch(x.stem)]
        archive_versions=sorted([x.stem for x in archives if key(x.stem)<=key(current)],key=key,reverse=True)
        archive_protected=protected|set(archive_versions[:max(3,int(keep))])|{'5.30.29'}
        for item in sorted(items,key=lambda x:key(x.name),reverse=True):
            if item.name in protected or key(item.name)>key(current):
                report['preserved'].append(item.name);report['reasons'][item.name]='attiva, recente, ripristino, riferimento o futura';continue
            try:
                if not verified_retired_tree(item):report['preserved'].append(item.name);report['reasons'][item.name]='integrità o formato non verificabile';continue
                if check_transactions:preflight_network_transactions(current)
                if item.name in release_reference_versions(locations,proc=proc):report['preserved'].append(item.name);continue
                report['candidates'].append(item.name)
                if not dry_run:
                    shutil.rmtree(item);report['deleted'].append(item.name)
            except (OSError,ValueError,TypeError,UpdateError) as exc:
                report['preserved'].append(item.name);report['errors'].append(item.name+': '+str(exc))
        for archive in archives:
            version=archive.stem
            if version in archive_protected or version in report['preserved'] or key(version)>key(current):report['archives_preserved'].append(version);continue
            try:
                if archive.is_symlink() or not archive.is_file() or archive.stat().st_uid or archive.stat().st_mode&0o077 or archive.stat().st_nlink!=1 or archive.stat().st_size>18*1024*1024:
                    report['archives_preserved'].append(version);continue
                digest=hashlib.sha256(archive.read_bytes()).hexdigest()
                if parse_package(archive,digest)[0]!=version:report['archives_preserved'].append(version);continue
                if check_transactions:preflight_network_transactions(current)
                if version in release_reference_versions(locations,proc=proc):report['archives_preserved'].append(version);continue
                if hashlib.sha256(archive.read_bytes()).hexdigest()!=digest:raise UpdateError('Archivio cambiato')
                if not dry_run:
                    archive.unlink();report['archives_deleted'].append(version)
            except (OSError,ValueError,TypeError,UpdateError,zipfile.BadZipFile) as exc:
                report['archives_preserved'].append(version);report['errors'].append(version+': '+str(exc))
        report['unknown_preserved']=[x.name for x in base.iterdir() if not VERSION_RX.fullmatch(x.name)]
    except (OSError,ValueError,TypeError,UpdateError) as exc:report['errors'].append(str(exc))
    return report

def cleanup_after_legacy_commit(version):
    marker=STATE/'release-cleanup-context.json'
    try:
        with software_lock():
            if (STATE/'pending.json').exists() or not marker.is_file() or marker.is_symlink() or marker.stat().st_uid or marker.stat().st_mode&0o077:
                return {'reason':'missing-or-pending-context'}
            context=json.loads(marker.read_text())
            if context.get('current')!=version:return {'reason':'context-version-mismatch'}
            check=subprocess.run([str(HELPER),'version'],capture_output=True,text=True,timeout=15)
            if check.returncode or check.stdout.strip()!=version:return {'reason':'helper-version-mismatch'}
            report=prune_old_releases(version,context['previous'])
            # Context is retained on error for diagnostics; no blind retry.
            if not report.get('errors') and not report.get('reason'):marker.unlink(missing_ok=True)
            return report
    except (OSError,ValueError,TypeError,KeyError,UpdateError,subprocess.TimeoutExpired) as exc:
        return {'reason':'deferred','detail':str(exc)[:300]}


def list_local_releases(*, base=RELEASE_BASE, limit=3, cache=None):
    """Advertise only complete, verified, locally restorable Native archives."""
    cache=pathlib.Path(cache or ROOT/'packages')
    found=[]
    try:
        check_dir(cache)
        if cache.stat().st_mode&0o077:return []
        for item in cache.glob('*.zip'):
            if not VERSION_RX.fullmatch(item.stem) or item.is_symlink() or not item.is_file():continue
            st=item.stat()
            if st.st_uid or st.st_mode&0o077 or st.st_nlink!=1 or not 1<=st.st_size<=18*1024*1024:continue
            try:
                digest=hashlib.sha256(item.read_bytes()).hexdigest()
                if parse_package(item,digest)[0]==item.stem:found.append(item.stem)
            except (OSError,ValueError,UpdateError,zipfile.BadZipFile):continue
    except (OSError,UpdateError):return []
    found.sort(key=lambda v:tuple(map(int,v.split('.'))),reverse=True)
    return found[:max(1,int(limit))]


def pack_local_release(version, dest_zip, *, base=RELEASE_BASE):
    """Build a native-format zip from an immutable on-disk release tree."""
    if not VERSION_RX.fullmatch(version):
        raise UpdateError('Versione non valida')
    root=base/version
    check_dir(root)
    man=root/'native-manifest.json'
    if man.is_symlink() or not man.is_file():
        raise UpdateError('Manifest release assente')
    metadata=json.loads(man.read_text())
    if metadata.get('version')!=version or not isinstance(metadata.get('sha256'), dict):
        raise UpdateError('Manifest release non valido')
    hashes=metadata['sha256']
    if not hashes:
        raise UpdateError('Manifest vuoto')
    # Verify integrity before packaging.
    for name, digest in hashes.items():
        if '..' in name or name.startswith('/'):
            raise UpdateError('Path non sicuro nel manifest')
        f=root/name
        if f.is_symlink() or not f.is_file() or f.stat().st_uid!=0:
            raise UpdateError('File release non integro: '+name)
        if hashlib.sha256(f.read_bytes()).hexdigest()!=digest:
            raise UpdateError('Hash non corrispondente: '+name)
    dest=pathlib.Path(dest_zip)
    if dest.exists():
        raise UpdateError('ZIP destinazione già presente')
    with zipfile.ZipFile(dest, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
        zf.write(man, 'native-manifest.json')
        for name in sorted(hashes):
            zf.write(root/name, name)
    return hashlib.sha256(dest.read_bytes()).hexdigest()


def rollback_local_release(web, version, force='force'):
    """Reinstall an on-disk release (downgrade/switch) via the normal migrate path."""
    if force!='force':
        raise UpdateError('Il ripristino da release locale richiede force')
    archive=ROOT/'packages'/(version+'.zip')
    if not VERSION_RX.fullmatch(version) or archive.is_symlink() or not archive.is_file() or archive.stat().st_uid or archive.stat().st_mode&0o077:
        raise UpdateError('Archivio completo non disponibile: usare lo ZIP originale da console')
    sha=hashlib.sha256(archive.read_bytes()).hexdigest()
    return migrate(pathlib.Path(web),archive,sha,'force')


def forced_tree_fingerprint(path):
    """Recognize safe root-owned version directories even with missing manifests.
    No symlinks, hardlinks, special files, mounts or unbounded reads are accepted.
    """
    check_dir(path)
    root=path.lstat();digest=hashlib.sha256();count=0;size=0
    def identity(st):return (st.st_dev,st.st_ino,st.st_mode,st.st_uid,st.st_gid,st.st_nlink,st.st_size,st.st_mtime_ns,st.st_ctime_ns)
    # mountinfo includes bind mounts on the same device, unlike ismount alone.
    mountpoints=set()
    for line in pathlib.Path('/proc/self/mountinfo').read_text().splitlines():
        raw=line.split()[4]
        mountpoints.add(re.sub(r'\\([0-7]{3})',lambda m:chr(int(m.group(1),8)),raw))
    if os.path.ismount(path) or str(path.resolve()) in mountpoints:raise UpdateError('Release montata')
    for item in [path,*sorted(path.rglob('*'))]:
        count+=1
        if count>4096:raise UpdateError('Troppi elementi nella release')
        st=item.lstat()
        if st.st_uid or st.st_mode&0o022 or st.st_dev!=root.st_dev or os.path.ismount(item) or str(item.absolute()) in mountpoints:
            raise UpdateError('Elemento non protetto o montato')
        digest.update(json.dumps([str(item.relative_to(path)),st.st_mode,st.st_uid,st.st_gid,st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns],ensure_ascii=True).encode()+b'\n')
        if stat.S_ISDIR(st.st_mode):continue
        if not stat.S_ISREG(st.st_mode) or st.st_nlink!=1:raise UpdateError('Link o file speciale')
        size+=st.st_size
        if size>64*1024*1024:raise UpdateError('Release troppo grande per verifica')
        fd=os.open(item,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as stream:
            opened=os.fstat(stream.fileno())
            if identity(opened)!=identity(st):raise UpdateError('Elemento cambiato')
            data=stream.read(st.st_size+1)
            if len(data)!=st.st_size or identity(os.fstat(stream.fileno()))!=identity(opened):raise UpdateError('Elemento cambiato durante lettura')
        digest.update(hashlib.sha256(data).digest())
    return digest.hexdigest(),size


def selected_release_plan(current, previous=None, *, base=RELEASE_BASE, locations=None, proc=pathlib.Path('/proc'), archives=(), check_transactions=True):
    if not VERSION_RX.fullmatch(current) or (previous and not VERSION_RX.fullmatch(previous)):raise UpdateError('Versione non valida')
    check_dir(base)
    if (STATE/'pending.json').exists() or (STATE/'pending.json').is_symlink():raise UpdateError('Aggiornamento pendente')
    if check_transactions:preflight_network_transactions(current)
    if not verified_retired_tree(base/current):raise UpdateError('Release attiva non verificabile')
    locations=release_locations() if locations is None else locations
    evidence={}
    refs=release_reference_versions(locations,proc=proc,evidence=evidence)
    key=lambda v:tuple(map(int,v.split('.')))
    rows=[]
    for item in sorted(base.iterdir(),key=lambda p:p.name):
        name=item.name
        if not VERSION_RX.fullmatch(name):continue
        row={'version':name,'allowed':False,'reason':'','bytes':0}
        if name==current:row['reason']='Release attiva'
        elif key(name)>=key(current):row['reason']='Release futura o equivalente'
        elif name in refs:
            row['reason']='Referenziata da servizio o processo'
            row['references']=sorted(evidence.get(name,()))
        elif name==previous and name not in archives:row['reason']='Ripristino precedente senza ZIP verificato'
        else:
            try:
                fingerprint,size=forced_tree_fingerprint(item)
                try:verified=verified_retired_tree(item)
                except (OSError,ValueError,TypeError,UpdateError):verified=False
                row.update(allowed=True,reason='Integra' if verified else 'Incompleta o modificata: rimozione forzata',fingerprint=fingerprint,bytes=size,archive=name in archives)
            except (OSError,ValueError,TypeError,UpdateError) as exc:row['reason']=str(exc)
        rows.append(row)
    # If previous is unknown and no rollback archive exists, preserve newest old safe tree.
    if not previous and not any(key(v)<key(current) for v in archives):
        eligible=[row for row in rows if row['allowed'] and row['reason']=='Integra'] or [row for row in rows if row['allowed']]
        if eligible:
            row=max(eligible,key=lambda r:key(r['version']));row.update(allowed=False,reason='Ultima copia di recupero locale')
    payload={'current':current,'previous':previous,'rows':rows}
    payload['sha256']=hashlib.sha256(json.dumps(payload,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    return payload


def remove_selected_releases(current,previous,expected,versions,**opts):
    if not isinstance(expected,str) or not re.fullmatch(r'[a-f0-9]{64}',expected) or not 1<=len(versions)<=100 or len(set(versions))!=len(versions) or any(not VERSION_RX.fullmatch(v) for v in versions):
        raise UpdateError('Selezione o digest non validi')
    plan=selected_release_plan(current,previous,**opts)
    if plan['sha256']!=expected:raise UpdateError('Inventario cambiato: ricalcolare anteprima')
    allowed={r['version']:r for r in plan['rows'] if r['allowed']}
    if not set(versions)<=allowed.keys():raise UpdateError('Selezione contiene release protette')
    base=opts.get('base',RELEASE_BASE);locations=opts.get('locations');proc=opts.get('proc',pathlib.Path('/proc'))
    locations=release_locations() if locations is None else locations
    report={'deleted':[],'errors':[],'quarantined':[]}
    for version in versions:
        item=base/version;quarantine=None
        try:
            if (STATE/'pending.json').exists() or (STATE/'pending.json').is_symlink():raise UpdateError('Aggiornamento pendente')
            if opts.get('check_transactions',True):preflight_network_transactions(current)
            if version in release_reference_versions(locations,proc=proc):raise UpdateError('Nuovo riferimento attivo')
            if forced_tree_fingerprint(item)[0]!=allowed[version]['fingerprint']:raise UpdateError('Release cambiata')
            # Move out of the executable release path first. On interruption the
            # quarantine is intentionally excluded from automatic retention.
            quarantine=pathlib.Path(tempfile.mkdtemp(prefix='.retired-',dir=base))
            os.rename(item,quarantine/version)
            if version in release_reference_versions(locations,proc=proc):
                os.rename(quarantine/version,item);quarantine.rmdir();quarantine=None
                raise UpdateError('Riferimento apparso durante la rimozione')
            shutil.rmtree(quarantine/version);quarantine.rmdir();report['deleted'].append(version)
        except (OSError,ValueError,TypeError,UpdateError) as exc:
            report['errors'].append(version+': '+str(exc))
            if quarantine is not None and quarantine.exists():
                if not (quarantine/version).exists():quarantine.rmdir()
                else:report['quarantined'].append(quarantine.name+'/'+version)
            break
    return report


# Only exact generated oneshot units may be rebound. Active recovery owners,
# custom units, drop-ins, cron and processes require their own migration path.
GUARD_TEMPLATE = ('[Unit]\nDescription=IPTM {description}\n{ordering}'
                  '[Service]\nType=oneshot\nExecStart=/usr/bin/python3 -B {script} {operation}\n{install}')
GUARD_MIGRATIONS={
    'iptm-dns-boot-recover.service': ('dns_tls_guard.py','recover-boot','DNSCrypt unconfirmed change boot recovery','After=local-fs.target\nBefore=dnscrypt-proxy.service\n','[Install]\nWantedBy=multi-user.target\n','iptables-manager/backups/dns-guard/pending.json'),
    'iptm-fabric-boot-recover.service': ('fabric_runtime.py','boot-recover','Fabric boot trial recovery','DefaultDependencies=no\nAfter=local-fs.target\nBefore=network-pre.target\nWants=network-pre.target\n','[Install]\nWantedBy=sysinit.target\n','iptm-fabric-runtime/fabric-trial.json'),
    'iptm-alias-boot-recover.service': ('network_alias_trial.py','boot-recover','Alias trial boot recovery','DefaultDependencies=no\nAfter=local-fs.target\nBefore=network-pre.target\nWants=network-pre.target\n','[Install]\nWantedBy=sysinit.target\n','iptm-alias-trial/state.json'),
    'iptm-network-runtime.service': ('network_runtime.py','boot-recover','network transaction boot recovery','After=local-fs.target network-online.target\nWants=network-online.target\nAfter=pihole-FTL.service\n','[Install]\nWantedBy=multi-user.target\n','iptm-network-runtime/transaction.json'),
    'iptm-network-wan-health.service': ('network_runtime.py','health-check','WAN health and route selection','After=network-online.target iptm-network-runtime.service\n','','iptm-network-runtime/transaction.json'),
    'iptm-sqm-uplink-recover.service': ('sqm_uplink.py','boot-recover','SQM uplink boot recovery','After=network-online.target\n','[Install]\nWantedBy=multi-user.target\n','iptm-sqm-uplink/state.json'),
    'iptm-sqm-reconcile-recover.service': ('sqm_uplink.py','reconcile boot-recover','SQM reconcile recovery','After=local-fs.target\n','[Install]\nWantedBy=multi-user.target\n','iptm-sqm-reconcile/state.json'),
}

def dns_unit_signature(raw):
    """Recognize only the generated DNS boot unit, including older formatting.

    No additional directives, duplicated keys, continuations, substitutions or
    alternate executables are accepted. The canonical unit is published on migration.
    """
    try:text=raw.decode('ascii')
    except UnicodeError:return None
    result=[];section=None;seen=set()
    for line in text.splitlines():
        if line.rstrip().endswith('\\') or any(ord(c)<32 and c!='\t' for c in line):return None
        line=line.strip()
        if not line or line.startswith(('#',';')):continue
        if line in ('[Unit]','[Service]','[Install]'):
            if line in seen:return None
            section=line;seen.add(line);result.append(line);continue
        if section is None or '=' not in line:return None
        key,value=map(str.strip,line.split('=',1))
        if (section,key) in seen:return None
        seen.add((section,key))
        value=' '.join(value.split())
        if key=='ExecStart' and section=='[Service]':
            value=re.sub(r'^/usr/bin/python3 -B ', '/usr/bin/python3 ',value)
        result.append((section,key,value))
    return result


def guard_migration_plan(current, *, base=RELEASE_BASE, unit_dir=pathlib.Path('/etc/systemd/system'), state_root=pathlib.Path('/var/lib'), run=None, only=None):
    if run is None:run=shared_transport().capture
    if not VERSION_RX.fullmatch(current) or not verified_retired_tree(base/current):raise UpdateError('Release di destinazione non verificabile')
    check_dir(unit_dir)
    rows=[]
    for name,(module,operation,description,ordering,install,state) in GUARD_MIGRATIONS.items():
        if only is not None and name!=only:continue
        path=unit_dir/name
        if not path.exists() and not path.is_symlink():continue
        row={'unit':name,'allowed':False,'reason':'Unità non riconosciuta o personalizzata'}
        rows.append(row)
        try:
            st=path.lstat()
            if not stat.S_ISREG(st.st_mode) or st.st_uid or st.st_mode&0o022 or st.st_nlink!=1 or st.st_size>16384:continue
            raw=path.read_bytes()
            match=re.search(rb'/web/releases/([0-9]+(?:\.[0-9]+){1,3})/',raw)
            if not match:continue
            old=match[1].decode();row['from']=old
            if old==current:row['reason']='Già migrata';continue
            if tuple(map(int,old.split('.')))>=tuple(map(int,current.split('.'))):row['reason']='Release futura';continue
            old_script=str(base/old/'extensions'/module);new_script=str(base/current/'extensions'/module)
            expected=GUARD_TEMPLATE.format(description=description,ordering=ordering,script=old_script,operation=operation,install=install).encode()
            if raw!=expected:
                if name!='iptm-dns-boot-recover.service' or dns_unit_signature(raw)!=dns_unit_signature(expected):
                    row['reason']='Contenuto unità diverso dal modello IPTM (direttive o ExecStart non riconosciuti)';continue
            if (state_root/state).exists() or (state_root/state).is_symlink():row['reason']='Stato di recupero presente: migrazione da verificare separatamente';continue
            if not (base/current/'extensions'/module).is_file():row['reason']='Driver destinazione mancante';continue
            query=run(['systemctl','show',name,'--all','--property=ActiveState,SubState,Job,FragmentPath,DropInPaths,NeedDaemonReload,ExecStart','--no-pager'],timeout=10,stdout_limit=65536,stderr_limit=16384)
            props=dict(line.split('=',1) for line in query.stdout.splitlines() if '=' in line)
            checks=((query.returncode==0,'systemctl show fallito'),(props.get('FragmentPath')==str(path),'FragmentPath diverso'),(props.get('DropInPaths')=='','DropInPaths presente o non restituito'),(props.get('NeedDaemonReload')=='no','daemon-reload necessario o stato non disponibile'),(props.get('ActiveState')=='inactive','ActiveState='+str(props.get('ActiveState','non disponibile'))),(props.get('SubState')=='dead','SubState='+str(props.get('SubState','non disponibile'))),(props.get('Job') in ('','0'),'Job attivo o non restituito'),(old_script in props.get('ExecStart',''),'ExecStart caricato diverso'))
            failures=[reason for ok,reason in checks if not ok]
            if failures:
                row['reason']='; '.join(failures);continue
            row.update(allowed=True,reason='Unità IPTM inattiva migrabile',sha256=hashlib.sha256(raw).hexdigest(),mode=stat.S_IMODE(st.st_mode),gid=st.st_gid)
        except (OSError,ValueError,TypeError,UpdateError,subprocess.TimeoutExpired) as exc:row['reason']='Verifica non riuscita: '+str(exc)[:180]
    result={'current':current,'rows':rows}
    result['sha256']=hashlib.sha256(json.dumps(result,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    return result


def migrate_guard_units(current,expected, *, base=RELEASE_BASE, unit_dir=pathlib.Path('/etc/systemd/system'), state_root=pathlib.Path('/var/lib'), backup_dir=None, run=None):
    if run is None:run=shared_transport().capture
    options=dict(base=base,unit_dir=unit_dir,state_root=state_root,run=run)
    plan=guard_migration_plan(current,**options)
    if plan['sha256']!=expected:raise UpdateError('Inventario unità cambiato: ricalcolare anteprima')
    report={'migrated':[],'errors':[],'deferred':[r for r in plan['rows'] if not r['allowed']]}
    rows=[r for r in plan['rows'] if r['allowed']]
    if not rows:return report
    store=pathlib.Path(backup_dir or STATE/'unit-migrations')
    store.mkdir(mode=0o700,exist_ok=True);check_dir(store)
    if store.stat().st_mode&0o077:raise UpdateError('Backup unità non privato')
    snapshot=pathlib.Path(tempfile.mkdtemp(prefix='migration-',dir=store));report['backup']=str(snapshot)
    for row in rows:
        name=row['unit'];path=unit_dir/name;published=False
        try:
            # Check each unit immediately before replacing; recovery state takes precedence.
            fresh=next(r for r in guard_migration_plan(current,only=name,**options)['rows'] if r['unit']==name)
            if fresh!=row:raise UpdateError('Unità cambiata durante la migrazione')
            original=path.read_bytes()
            if hashlib.sha256(original).hexdigest()!=row['sha256']:raise UpdateError('Contenuto unità cambiato')
            transport=shared_transport()
            transport.durable_replace(snapshot/name,original,mode=0o600,create_only=True)
            transport.durable_replace(snapshot/(name+'.json'),json.dumps(row,sort_keys=True).encode(),mode=0o600,create_only=True)
            new=original.replace(f'/web/releases/{row["from"]}/'.encode(),f'/web/releases/{current}/'.encode())
            if name=='iptm-dns-boot-recover.service':
                module,operation,description,ordering,install,_state=GUARD_MIGRATIONS[name]
                new=GUARD_TEMPLATE.format(description=description,ordering=ordering,script=str(base/current/'extensions'/module),operation=operation,install=install).encode()
            published=True
            transport.durable_replace(path,new,mode=row['mode'],group=row['gid'])
            state=GUARD_MIGRATIONS[name][-1]
            if (state_root/state).exists() or (state_root/state).is_symlink():raise UpdateError('Stato di recupero apparso durante migrazione')
            reload=run(['systemctl','daemon-reload'],timeout=20,stdout_limit=65536,stderr_limit=16384)
            if reload.returncode:raise UpdateError('daemon-reload fallito')
            verify=run(['systemctl','show',name,'--all','--property=ExecStart,FragmentPath,DropInPaths,NeedDaemonReload','--no-pager'],timeout=10,stdout_limit=65536,stderr_limit=16384)
            props=dict(line.split('=',1) for line in verify.stdout.splitlines() if '=' in line)
            target=str(base/current/'extensions'/GUARD_MIGRATIONS[name][0])
            if verify.returncode or props.get('FragmentPath')!=str(path) or props.get('DropInPaths')!='' or props.get('NeedDaemonReload')!='no' or target not in props.get('ExecStart',''):raise UpdateError('Nuovo riferimento systemd non verificato')
            report['migrated'].append(name)
        except (OSError,ValueError,TypeError,UpdateError,subprocess.TimeoutExpired,StopIteration) as exc:
            report['errors'].append(name+': '+str(exc))
            if published:
                try:
                    shared_transport().durable_replace(path,original,mode=row['mode'],group=row['gid'])
                    if run(['systemctl','daemon-reload'],timeout=20,stdout_limit=65536,stderr_limit=16384).returncode:raise UpdateError('daemon-reload rollback fallito')
                except (OSError,ValueError,UpdateError,subprocess.TimeoutExpired) as rollback:report['errors'].append('Ripristino non verificato: '+str(rollback))
            break
    return report


BACKUP_HELPER_RX = re.compile(r'iptm-helper\.bak-[0-9]{8}-[0-9]{6}\Z')

def read_legacy_helper_backup(path):
    transport=shared_transport()
    dfd=transport.open_directory(path.parent)
    try:
        st_dir=os.fstat(dfd)
        if st_dir.st_uid or st_dir.st_mode & 0o022:raise UpdateError('Directory backup non protetta')
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=dfd)
        with os.fdopen(fd,'rb') as stream:
            st=os.fstat(stream.fileno())
            if not stat.S_ISREG(st.st_mode) or st.st_uid or st.st_nlink!=1 or st.st_mode&0o7022 or st.st_size>8*1024*1024:
                raise UpdateError('Backup non regolare o non protetto')
            raw=stream.read(8*1024*1024+1)
            after=os.fstat(stream.fileno())
            identity=lambda x:(x.st_dev,x.st_ino,x.st_size,x.st_mtime_ns,x.st_ctime_ns,x.st_mode,x.st_gid,x.st_nlink)
            if len(raw)!=st.st_size or identity(st)!=identity(after):raise UpdateError('Backup modificato durante la lettura')
            header=re.search(rb'(?m)^# iptm-helper v([0-9]+(?:\.[0-9]+){1,3})(?:[ \t]|$)',raw[:4096])
            if not header or not raw.startswith(b'#!'):raise UpdateError('Intestazione IPTM non riconosciuta')
            return raw, {'version':header[1].decode(),'sha256':hashlib.sha256(raw).hexdigest(),'mode':stat.S_IMODE(st.st_mode),'gid':st.st_gid,'bytes':len(raw),'identity':list(identity(st))}
    finally:os.close(dfd)


def legacy_helper_plan(current, *, folder=pathlib.Path('/usr/local/sbin'), locations=None, proc=pathlib.Path('/proc')):
    """Archive only precisely named older helper copies; no live helper changes."""
    check_dir(folder)
    if not VERSION_RX.fullmatch(current):raise UpdateError('Versione non valida')
    candidates=[]
    for path in sorted(folder.iterdir()):
        if not BACKUP_HELPER_RX.fullmatch(path.name):continue
        row={'file':str(path),'allowed':False,'reason':'Backup non verificato'}
        candidates.append(row)
        if len(candidates)>256:raise UpdateError('Troppi backup helper: bonifica sospesa')
        try:
            raw,meta=read_legacy_helper_backup(path)
            row.update(meta)
            if tuple(map(int,meta['version'].split('.')))>=tuple(map(int,current.split('.'))):
                row['reason']='Backup della versione corrente o futura';continue
            row.update(allowed=True,reason='Copia helper precedente archiviabile')
        except (OSError,ValueError,UpdateError) as exc:row['reason']=str(exc)[:200]
    eligible=[r for r in candidates if r['allowed']]
    if eligible:
        roots=list(release_locations() if locations is None else locations)
        # The backup's own content does not establish use of its filename.
        # Match basename as well as absolute path, to catch relative invocation.
        tokens={r['file']:os.fsencode(pathlib.Path(r['file']).name) for r in eligible}
        refs={p:set() for p in tokens}
        def inspect(content,source):
            for name,token in tokens.items():
                if str(source)!=name and token in content and len(refs[name])<32:refs[name].add(str(source))
        scan_reference_sources(roots,inspect,proc=proc)
        for row in eligible:
            if refs[row['file']]:row.update(allowed=False,reason='Backup richiamato da servizio, script o processo',references=sorted(refs[row['file']]))
    payload={'current':current,'rows':candidates}
    payload['sha256']=hashlib.sha256(json.dumps(payload,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    return payload


def archive_legacy_helpers(current, expected, *, folder=pathlib.Path('/usr/local/sbin'), locations=None, proc=pathlib.Path('/proc'), store=None):
    opts=dict(folder=folder,locations=locations,proc=proc)
    plan=legacy_helper_plan(current,**opts)
    if plan['sha256']!=expected:raise UpdateError('Inventario backup cambiato: ricalcolare anteprima')
    report={'archived':[],'errors':[],'deferred':[r for r in plan['rows'] if not r['allowed']]}
    selected=[r for r in plan['rows'] if r['allowed']]
    if not selected:return report
    store=pathlib.Path(store or STATE/'legacy-helper-archive')
    check_dir(store.parent)
    store.mkdir(mode=0o700,exist_ok=True);check_dir(store)
    if store.stat().st_mode&0o077:raise UpdateError('Archivio backup non privato')
    snapshot=pathlib.Path(tempfile.mkdtemp(prefix='archive-',dir=store))
    # Make the snapshot directory durable before removing any original.
    dfd=shared_transport().open_directory(store)
    try:os.fsync(dfd)
    finally:os.close(dfd)
    report['backup']=str(snapshot)
    transport=shared_transport()
    for row in selected:
        path=pathlib.Path(row['file'])
        try:
            fresh=next((r for r in legacy_helper_plan(current,**opts)['rows'] if r['file']==row['file']),None)
            if fresh!=row:raise UpdateError('Backup o riferimenti cambiati')
            raw,meta=read_legacy_helper_backup(path)
            if any(row[k]!=v for k,v in meta.items()):raise UpdateError('Backup modificato')
            transport.durable_replace(snapshot/path.name,raw,mode=0o600,create_only=True)
            transport.durable_replace(snapshot/(path.name+'.json'),json.dumps(row,sort_keys=True).encode(),mode=0o600,create_only=True)
            # A reference appearing during snapshot creation prevents unlink.
            fresh=next((r for r in legacy_helper_plan(current,**opts)['rows'] if r['file']==row['file']),None)
            if fresh!=row:raise UpdateError('Nuovo riferimento o modifica durante archiviazione')
            transport.durable_unlink(path)
            report['archived'].append(str(path))
        except (OSError,ValueError,UpdateError) as exc:
            report['errors'].append(str(path)+': '+str(exc));break
    return report


def manual_release_cleanup(mode, expected=None, versions=()):
    if os.geteuid()!=0:raise UpdateError('Root richiesto')
    if mode not in ('preview','apply','select-preview','select-apply','migrate-preview','migrate-apply','archive-preview','archive-apply'):raise UpdateError('Modalità non valida')
    with software_lock():
        current=subprocess.check_output([str(HELPER),'version'],text=True,timeout=10).strip()
        if not VERSION_RX.fullmatch(current) or pathlib.Path(__file__).resolve().parents[1].name!=current:
            raise UpdateError('Versione helper/release incoerente')
        # Keep all locally restorable archive versions as additional protection.
        # The immediately previous tree is also preserved if recorded by the legacy bridge.
        previous=None
        marker=STATE/'release-cleanup-context.json'
        if marker.exists() or marker.is_symlink():
            context=shared_transport().read_private_json(marker,limit=16384)
            if context.get('current')==current and isinstance(context.get('previous'),str):previous=context['previous']
        if mode in ('archive-preview','archive-apply'):
            if (STATE/'pending.json').exists() or (STATE/'pending.json').is_symlink():raise UpdateError('Aggiornamento pendente')
            preflight_network_transactions(current)
            if mode=='archive-preview':return legacy_helper_plan(current)
            if not isinstance(expected,str) or not re.fullmatch(r'[a-f0-9]{64}',expected):raise UpdateError('Digest archivio non valido')
            return archive_legacy_helpers(current,expected)
        if mode in ('migrate-preview','migrate-apply'):
            if (STATE/'pending.json').exists() or (STATE/'pending.json').is_symlink():raise UpdateError('Aggiornamento pendente')
            preflight_network_transactions(current)
            if mode=='migrate-preview':return guard_migration_plan(current)
            if not isinstance(expected,str) or not re.fullmatch(r'[a-f0-9]{64}',expected):raise UpdateError('Digest migrazione non valido')
            # Preserve the global -> domain lock ordering of DNS apply. Never
            # wait for the watchdog or restart a service during unit migration.
            try:fd=shared_transport().acquire_domain_lock(pathlib.Path('/run/lock/iptm-dns-guard.lock'),nonblocking=True)
            except (OSError,ValueError) as exc:raise UpdateError('DNS Guard occupato o lock non protetto: riprovare dopo il recupero') from exc
            try:
                preflight_network_transactions(current)
                return migrate_guard_units(current,expected)
            finally:os.close(fd)
        archives=list_local_releases(limit=1000)
        if mode=='select-preview':return selected_release_plan(current,previous,archives=archives)
        if mode=='select-apply':return remove_selected_releases(current,previous,expected,versions,archives=archives)
        return prune_old_releases(current,previous,dry_run=mode=='preview',include_archives=False,extra_protected=archives)


def main():
    if len(sys.argv)>=3 and sys.argv[1]=='release-cleanup':
        mode=sys.argv[2]
        if len(sys.argv)==3 and mode in ('preview','apply','select-preview','migrate-preview','archive-preview'):result=manual_release_cleanup(mode)
        elif len(sys.argv)==4 and mode in ('migrate-apply','archive-apply'):result=manual_release_cleanup(mode,sys.argv[3])
        elif len(sys.argv)>=5 and mode=='select-apply':result=manual_release_cleanup(mode,sys.argv[3],sys.argv[4:])
        else:raise UpdateError('Argomenti pulizia non validi')
        print(json.dumps(result,ensure_ascii=False));return
    if len(sys.argv)==3 and sys.argv[1]=='legacy-precommit-health' and VERSION_RX.fullmatch(sys.argv[2]):
        if os.geteuid()!=0:raise UpdateError('Root richiesto')
        print(legacy_precommit_health(sys.argv[2]));return
    if len(sys.argv) >= 2 and sys.argv[1] == 'list-releases':
        print(json.dumps({'ok': True, 'releases': list_local_releases()}))
        return
    if len(sys.argv) == 4 and sys.argv[1] == 'rollback':
        # native-update rollback WEB VERSION
        result = rollback_local_release(sys.argv[2], sys.argv[3], 'force')
        print('versione '+result['previous']+' -> '+result['version']+' [NATIVE-ROLLBACK]')
        print(json.dumps(result))
        return
    if len(sys.argv)!=5:raise UpdateError('Uso: native-update WEB ZIP SHA256 force|-')
    result=migrate(pathlib.Path(sys.argv[1]),pathlib.Path(sys.argv[2]),sys.argv[3],sys.argv[4])
    print('versione '+result['previous']+' -> '+result['version']+' [NATIVE]')
    print(json.dumps(result))

if __name__=='__main__':
    try:main()
    except (UpdateError, OSError, ValueError, KeyError, zipfile.BadZipFile, json.JSONDecodeError, subprocess.TimeoutExpired) as exc:
        print('IPTM native update rifiutato: '+str(exc),file=sys.stderr);sys.exit(1)
