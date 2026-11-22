#!/usr/bin/env python3
"""Zapret2 (nfqws2) opt-in installation, independent of classic nfqws.

Only curated ELF and standard Lua assets are copied from an official HTTPS
GitHub release. Never run upstream shell installers or insert NFQUEUE rules.
"""
from __future__ import annotations
import hashlib,json,os,pathlib,re,sys,tarfile,tempfile,subprocess,shutil
import zapret_manager as classic

API='https://api.github.com/repos/bol-van/zapret2/releases/latest'
TAG=re.compile(r'v\d+\.\d+(?:\.\d+){0,2}\Z')
ARCHIVE=re.compile(r'https://github\.com/bol-van/zapret2/releases/download/(v\d+\.\d+(?:\.\d+){0,2})/zapret2-\1\.tar\.gz\Z')
BASE=pathlib.Path('/usr/local/lib/iptables-manager/zapret2')
CONF_DIR=pathlib.Path('/etc/iptables-manager-zapret2')
BIN=BASE/'nfqws2'; VERSION=BASE/'installed.json'; CONF=CONF_DIR/'config.json'
# nfqws2 validates files *after dropping privileges*. Never use the root-only
# /etc/iptables-manager-zapret2 directory as the runtime hostlist location.
HOSTLIST=BASE/'hostlist.txt'
LEGACY_HOSTLIST=CONF_DIR/'hostlist.txt'
ALLOWED_LUA={'zapret-lib.lua','zapret-antidpi.lua','zapret-auto.lua'}

def validate(payload):
    """Shared Anti-DPI profile validator required by antidpi_sources.request_start.

    Zapret2 uses the same strict profile schema as classic nfqws.
    This is validation only: no disk writes, downloads or live rules.
    """
    return classic.validate(payload)

def fail(message):raise classic.ZapretError(message)

def root():classic.root()

def base_dir(p,private=False):
    root()
    if p.is_symlink():fail('Directory simbolica non consentita')
    if not p.exists():p.mkdir(parents=True,mode=0o700 if private else 0o755)
    if not p.is_dir() or p.stat().st_uid!=0 or p.stat().st_mode & (0o077 if private else 0o022):fail('Directory non protetta')
    return p

def atomic(p,data,mode=0o600):
    base_dir(p.parent,p.parent==CONF_DIR)
    if p.is_symlink():fail('File simbolico non consentito')
    fd,name=tempfile.mkstemp(prefix='.iptm-',dir=p.parent)
    try:
        with os.fdopen(fd,'wb') as f:
            os.fchmod(f.fileno(),mode);f.write(data);f.flush();os.fsync(f.fileno())
        os.replace(name,p)
    finally:
        if os.path.exists(name):os.unlink(name)

def metadata():
    with classic.github_open(API,timeout=12) as r:
        if r.status!=200:fail('GitHub HTTP '+str(r.status))
        data=r.read(1024*1024+1)
    if len(data)>1024*1024:fail('Metadati troppo grandi')
    obj=json.loads(data);tag=obj.get('tag_name')
    if obj.get('draft') or obj.get('prerelease') or not isinstance(tag,str) or not TAG.fullmatch(tag):fail('Release Zapret2 non valida')
    name=f'zapret2-{tag}.tar.gz'
    assets=[a for a in obj.get('assets',[]) if isinstance(a,dict) and a.get('name')==name]
    if len(assets)!=1:fail('Archivio ufficiale Zapret2 assente')
    a=assets[0];url=a.get('browser_download_url');digest=a.get('digest') or ''
    if not isinstance(url,str) or not ARCHIVE.fullmatch(url) or url!=f'https://github.com/bol-van/zapret2/releases/download/{tag}/{name}':fail('URL Zapret2 non ufficiale')
    if not isinstance(a.get('size'),int) or not 10000<=a['size']<=40*1024*1024:fail('Dimensione non valida')
    if digest and (not isinstance(digest,str) or not re.fullmatch(r'sha256:[a-f0-9]{64}',digest)):
        fail('SHA256 upstream non valido')
    return {'ok':True,'tag':tag,'url':url,'sha256':digest[7:] if digest else '',
            'architecture':classic.detect_arch()[0], 'size':a['size'],'changes_live':False}

def config_read():
    if CONF_DIR.exists() and (CONF_DIR.is_symlink() or CONF_DIR.stat().st_uid!=0 or CONF_DIR.stat().st_mode&0o077):fail('Directory config Zapret2 non sicura')
    if not CONF.is_file():return None
    if CONF.is_symlink() or CONF.stat().st_uid!=0 or CONF.stat().st_mode&0o077:fail('Config Zapret2 non sicura')
    return classic.validate(json.loads(CONF.read_text()))

def status():
    root();tag=''
    external=[]
    candidates=[pathlib.Path('/usr/local/bin/nfqws2'),pathlib.Path('/usr/bin/nfqws2'),
                pathlib.Path('/opt/zapret2/nfqws2'),pathlib.Path('/opt/zapret2/binaries/'+classic.detect_arch()[0]+'/nfqws2')]
    found=shutil.which('nfqws2')
    if found:candidates.append(pathlib.Path(found))
    for candidate in candidates:
        try:
            if candidate!=BIN and candidate.is_file() and candidate.stat().st_uid==0 and os.access(candidate,os.X_OK):
                external.append(str(candidate))
        except OSError:pass
    if VERSION.is_file() and not VERSION.is_symlink() and VERSION.stat().st_uid==0:
        tag=str(json.loads(VERSION.read_text()).get('tag',''))[:32]
    cfg=config_read()
    return {'ok':True,'engine':'zapret2','installed':BIN.is_file() and not BIN.is_symlink() and os.access(BIN,os.X_OK),
            'installed_version':tag,'configuration':cfg,'configured':bool(cfg),
            'activation':'disabled-until-network-acceptance','external_paths':sorted(set(external)),
            'external_detected':bool(external),'managed_binary':str(BIN),'changes_live':False}

def configure(payload):
    # A configured daemon may still be using the old hostlist. Require a
    # stop/retest cycle so persistent boot never activates unapproved domains.
    import antidpi_live
    if antidpi_live.current() is not None or (antidpi_live.persistent() or {}).get('enabled'):
        fail('Anti-DPI ancora attivo o persistente: arresta prima di cambiare la hostlist')
    if not isinstance(payload,dict):fail('Profilo non valido')
    cfg=classic.validate(payload)
    # Strategy is a label mapped into nfqws2 Lua, never old --dpi-desync.
    plan={HOSTLIST:(''.join(h+'\n' for h in cfg['domains'])).encode(),
          CONF:(json.dumps(cfg,sort_keys=True,indent=2)+'\n').encode()}
    previous={}
    for path in plan:
        if path.is_symlink():fail('File configurazione simbolico non consentito')
        if path.exists():
            if not path.is_file() or path.stat().st_uid!=0:fail('Configurazione preesistente non sicura')
            previous[path]=path.read_bytes()
        else:previous[path]=None
    changed=[]
    try:
        for path,data in plan.items():
            atomic(path,data,0o644 if path==HOSTLIST else 0o600);changed.append(path)
    except Exception:
        errors=[]
        for path in reversed(changed):
            try:
                if previous[path] is None:path.unlink(missing_ok=True)
                else:atomic(path,previous[path],0o644 if path==HOSTLIST else 0o600)
            except Exception:errors.append(path.name)
        if errors:fail('Salvataggio incompleto: recupero manuale necessario per '+','.join(errors))
        raise
    return {'ok':True,'configured':True,'changes_live':False}

def prepare_runtime_hostlist(cfg):
    """Materialize the non-secret domains in a safe, globally readable root path.

    This operation does not modify DNS, iptables or a running NFQUEUE daemon.
    The private JSON configuration stays under /etc, mode 0600 / 0700.
    """
    root()
    base_dir(BASE)
    # Only the product-owned runtime folder may be relaxed; never expose CONF_DIR.
    # nfqws2 drops to an unprivileged user before file_open_test.
    for folder in (BASE, BASE/'lua'):
        if not folder.exists():continue
        if folder.is_symlink() or not folder.is_dir() or folder.stat().st_uid!=0 or folder.stat().st_mode & 0o022:
            fail('Directory runtime Zapret2 non protetta: '+folder.name)
        if folder.stat().st_mode & 0o005 != 0o005:
            os.chmod(folder,0o755)
    expected=(''.join(h+'\n' for h in cfg['domains'])).encode('utf-8')
    if len(expected)>16*1024*1024:fail('Hostlist oltre il limite di 16 MiB')
    if HOSTLIST.is_symlink():fail('Hostlist runtime simbolica non consentita')
    if HOSTLIST.exists():
        st=HOSTLIST.stat()
        if not HOSTLIST.is_file() or st.st_uid!=0 or st.st_mode & 0o022:
            fail('Hostlist runtime esistente non sicura')
        if HOSTLIST.read_bytes()==expected and (st.st_mode & 0o004):
            return False
    atomic(HOSTLIST,expected,0o644)
    return True

def nfqws_args(cfg):
    """Single source of truth for preview, preflight and live NFQUEUE.

    This is syntactic option construction only, not proof that the selected
    strategy works with the installed Lua scripts or network path.
    """
    desync='multisplit:pos=1' if cfg['strategy']=='multisplit' else 'fake:blob=0x00000000:ip_ttl=5'
    return ['--qnum='+str(cfg['queue']),
            '--lua-init=@'+str(BASE/'lua/zapret-lib.lua'),
            '--lua-init=@'+str(BASE/'lua/zapret-antidpi.lua'),
            '--filter-tcp=80','--filter-l7=http','--hostlist='+str(HOSTLIST),
            '--lua-desync='+desync,'--new','--filter-tcp=443','--filter-l7=tls',
            '--hostlist='+str(HOSTLIST),'--lua-desync='+desync]

def preview():
    """Build a selective nfqws2 *command preview* with upstream syntax.

    No process is started and no NFQUEUE/firewall rule is installed. The hostlist
    is scoped to configured domains; packet filtering is limited to forwarding
    clients and the first few packets, avoiding all-host desync strategies.
    """
    cfg=config_read()
    if not cfg:fail('Configurazione Zapret2 non presente')
    q=cfg['queue'];wan=cfg['wan_if']
    rules=[f'iptables -t mangle -I FORWARD -o {wan} -s {net} -p tcp -m multiport --dports 80,443 -m connbytes --connbytes-dir original --connbytes-mode packets --connbytes 1:6 -j NFQUEUE --queue-num {q} --queue-bypass' for net in cfg['clients']]
    # Repair hostlists created by older versions inside a root-only directory.
    prepare_runtime_hostlist(cfg)
    options=nfqws_args(cfg)
    dry={'attempted':False,'ok':False,'note':'Binario locale non presente; nessun test dei parametri.'}
    if BIN.is_file() and not BIN.is_symlink() and BIN.stat().st_uid==0 and os.access(BIN,os.X_OK):
        # --dry-run checks syntax and path access only; Lua strategy runtime
        # behavior and real network reachability are not guaranteed.
        try:
            result=subprocess.run([str(BIN),'--dry-run',*options],stdin=subprocess.DEVNULL,
                                  stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,
                                  timeout=8,check=False)
            dry={'attempted':True,'ok':result.returncode==0,
                 'note':'Validazione CLI senza apertura NFQUEUE; non valida il codice Lua.',
                 'exit_code':result.returncode}
        except (OSError,subprocess.TimeoutExpired):
            dry={'attempted':True,'ok':False,'note':'Dry-run non riuscito o scaduto; nessuna attivazione.'}
    return {'ok':True,'engine':'zapret2','mode':'preview','rules':rules,
            'nfqws_options':options,'dry_run':dry,'domains_count':len(cfg['domains']),
            'clients_count':len(cfg['clients']),'strategy_note':'nfqws2 usa --lua-desync e filtri hostlist, separati per HTTP e TLS.',
            'changes_live':False,
            'warning':'Non attiva NFQUEUE/servizi. Il dry-run non prova Lua, ECH, QUIC o raggiungibilità LAN; serve collaudo con rollback prima dell’attivazione.'}

def install(payload):
    root()
    if not isinstance(payload,dict) or set(payload)!={'tag'} or not isinstance(payload['tag'],str) or not TAG.fullmatch(payload['tag']):fail('Tag confermato non valido')
    m=metadata()
    if m['tag']!=payload['tag']:fail('Release ufficiale cambiata: ripetere la ricerca')
    h=hashlib.sha256();total=0
    with tempfile.TemporaryDirectory(prefix='iptm-zapret2-') as tmp:
        archive=pathlib.Path(tmp)/'release.tar.gz'
        with classic.github_open(m['url'],timeout=35) as r,archive.open('wb') as dst:
            while True:
                part=r.read(65536)
                if not part:break
                total+=len(part)
                if total>40*1024*1024:fail('Archivio oltre il limite')
                h.update(part);dst.write(part)
        if total!=m.get('size',total):fail('Archivio Zapret2 incompleto o dimensione incoerente')
        if m['sha256'] and h.hexdigest()!=m['sha256']:fail('Digest GitHub non corrisponde')
        arch=classic.detect_arch();found=[];lua={};entries=0;expanded=0
        with tarfile.open(archive,'r|gz') as t:
            for member in t:
                entries+=1;expanded+=max(0,member.size)
                if entries>7000 or expanded>270*1024*1024:fail('Tar troppo grande')
                if not member.isfile():continue
                name=member.name.lstrip('./')
                if (name=='binaries/'+arch[0]+'/nfqws2' or name.endswith('/binaries/'+arch[0]+'/nfqws2')) and 64<=member.size<=12*1024*1024:
                    f=t.extractfile(member)
                    if f is None:fail('Binario non leggibile')
                    found.append(f.read(12*1024*1024+1))
                elif any(name=='lua/'+x or name.endswith('/lua/'+x) for x in ALLOWED_LUA) and 10<=member.size<=2*1024*1024:
                    name_short=pathlib.PurePosixPath(name).name
                    if name_short in lua:fail('Script Lua duplicato')
                    f=t.extractfile(member)
                    if f is None:fail('Lua non leggibile')
                    lua[name_short]=f.read(2*1024*1024+1)
        if len(found)!=1 or len(lua)<2 or not {'zapret-lib.lua','zapret-antidpi.lua'}<=set(lua):fail('Binario/Lua Zapret2 mancanti o duplicati')
        classic.validate_elf(found[0],arch)
        base_dir(BASE);base_dir(BASE/'lua')
        # Validate all selected objects before writing; never execute during install.
        for name,data in lua.items():
            if b'\x00' in data:fail('Lua contiene byte nulli')
        for name,data in lua.items():atomic(BASE/'lua'/name,data,0o644)
        atomic(BIN,found[0],0o755)
        atomic(VERSION,(json.dumps({'tag':m['tag'],'sha256':h.hexdigest()},sort_keys=True)+'\n').encode())
    return {'ok':True,'installed':True,'version':m['tag'],'sha256':h.hexdigest(),'changes_live':False}

def main():
    root();action=sys.argv[1] if len(sys.argv)==2 else ''
    if action=='status':return status()
    if action=='latest':return metadata()
    if action=='preview':return preview()
    if action in ('install-latest','configure'):
        raw=sys.stdin.buffer.read(20*1024*1024+1)
        if len(raw)>8*1024*1024:fail('Dati troppo grandi (massimo 8 MiB)')
        payload=json.loads(raw)
        return install(payload) if action=='install-latest' else configure(payload)
    fail('Operazione Zapret2 sconosciuta')

if __name__=='__main__':
    try:print(json.dumps(main(),ensure_ascii=False))
    except (classic.ZapretError,OSError,ValueError,KeyError,TypeError,tarfile.TarError) as exc:
        print(json.dumps({'ok':False,'error':str(exc)},ensure_ascii=False));sys.exit(1)
