#!/usr/bin/env python3
"""IPTM nfqws lifecycle: verified install and inert, root-owned configuration.

No firewall mutation, service enable or third-party shell installer is invoked.
Activation is deliberately a separate, guarded rollout after a real gateway test.
"""
from __future__ import annotations
import hashlib, ipaddress, json, os, pathlib, platform, re, subprocess, sys, tarfile, tempfile, urllib.request, urllib.error, urllib.parse

ENGINE_DIR=pathlib.Path('/usr/local/lib/iptables-manager/zapret')
BIN=ENGINE_DIR/'nfqws'
CONF_DIR=pathlib.Path('/etc/iptables-manager-zapret')
CONF=CONF_DIR/'config.json'
HOSTLIST=CONF_DIR/'hostlist.txt'
VERSION_FILE=ENGINE_DIR/'installed.json'
GITHUB_API='https://api.github.com/repos/bol-van/zapret/releases/latest'
TAG_RE=re.compile(r'v[0-9]+(?:\.[0-9]+){1,3}\Z')
GITHUB_RELEASE=re.compile(r'https://github\.com/bol-van/zapret/releases/download/(v[0-9][A-Za-z0-9._-]{0,30})/zapret-[A-Za-z0-9._-]+\.tar\.gz\Z')
IFACE=re.compile(r'[A-Za-z0-9_.:-]{1,15}\Z')
HOST=re.compile(r'(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\Z')

class OfficialHTTPSRedirect(urllib.request.HTTPRedirectHandler):
    """Permit official GitHub release CDN redirects but never HTTP or arbitrary hosts."""
    allowed={'github.com','api.github.com','release-assets.githubusercontent.com',
             'objects.githubusercontent.com','github-releases.githubusercontent.com'}
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        u=urllib.parse.urlsplit(newurl)
        if u.scheme!='https' or (u.hostname or '').lower() not in self.allowed or u.username or u.password or u.port not in (None,443):
            raise ZapretError('Redirect release non ammesso')
        return super().redirect_request(req,fp,code,msg,headers,newurl)

def github_open(url,timeout=15):
    u=urllib.parse.urlsplit(url)
    if u.scheme!='https' or u.hostname not in OfficialHTTPSRedirect.allowed or u.username or u.password or u.port not in (None,443):
        fail('Origine HTTPS non ufficiale')
    opener=urllib.request.build_opener(OfficialHTTPSRedirect())
    return opener.open(urllib.request.Request(url,headers={
        'User-Agent':'IPTM-zapret/4.0.0','Accept':'application/vnd.github+json'}),timeout=timeout)

def latest_release():
    """Obtain live official release metadata; do not execute downloaded scripts."""
    with github_open(GITHUB_API,timeout=12) as response:
        if response.status!=200:fail('GitHub API HTTP '+str(response.status))
        raw=response.read(1024*1024+1)
    if len(raw)>1024*1024:fail('GitHub metadata troppo grandi')
    meta=json.loads(raw)
    if not isinstance(meta,dict) or meta.get('draft') or meta.get('prerelease'):fail('Release GitHub non valida')
    tag=meta.get('tag_name')
    if not isinstance(tag,str) or not TAG_RE.fullmatch(tag):fail('Tag ufficiale non valido')
    wanted='zapret-'+tag+'.tar.gz'
    matches=[x for x in meta.get('assets',[]) if isinstance(x,dict) and x.get('name')==wanted]
    if len(matches)!=1:fail('Release ufficiale priva di archivio '+wanted)
    asset=matches[0];url=asset.get('browser_download_url')
    if not isinstance(url,str) or not GITHUB_RELEASE.fullmatch(url):fail('URL asset non ufficiale')
    if url!=f'https://github.com/bol-van/zapret/releases/download/{tag}/{wanted}':fail('Asset/tag incoerenti')
    size=asset.get('size')
    if not isinstance(size,int) or not 10000<=size<=40*1024*1024:fail('Dimensione archivio incompatibile')
    digest=asset.get('digest') or ''
    if digest and (not isinstance(digest,str) or not re.fullmatch(r'sha256:[a-fA-F0-9]{64}',digest)):
        fail('Digest GitHub non valido')
    return {'ok':True,'tag':tag,'version':tag,'url':url,'size':size,
        'sha256': digest[7:].lower() if digest else '',
        'digest_source':'github-release-asset' if digest else 'calculated-after-https-download',
        'architecture':detect_arch()[0], 'changes_live':False}

def detect_arch():
    machine=platform.machine().lower()
    arch={'x86_64':('linux-x86_64',62,2),'amd64':('linux-x86_64',62,2),
          'i686':('linux-x86',3,1),'i586':('linux-x86',3,1),'i386':('linux-x86',3,1),
          'aarch64':('linux-arm64',183,2),'armv7l':('linux-arm',40,1),
          'armv6l':('linux-arm',40,1)}.get(machine)
    if not arch:fail('Architettura '+machine+' non supportata')
    return arch

def validate_elf(blob,arch):
    if len(blob)<64 or blob[:4]!=b'\x7fELF' or blob[5]!=1:
        fail('nfqws non è un ELF little-endian valido')
    if blob[4]!=arch[2] or int.from_bytes(blob[18:20],'little')!=arch[1]:
        fail('nfqws ELF non corrisponde alla CPU')

class ZapretError(Exception):pass

def fail(s):raise ZapretError(s)
def root():
    if os.geteuid()!=0:fail('Richiesto root')

def secure_dir(p,create=False):
    root()
    if not p.exists() and create:p.mkdir(parents=True,mode=0o700 if p==CONF_DIR else 0o755)
    if not p.exists():return False
    if p.is_symlink() or not p.is_dir() or p.stat().st_uid!=0 or p.stat().st_mode & (0o077 if p==CONF_DIR else 0o022):
        fail('Directory non sicura: '+str(p))
    return True

def atomic(p,blob,mode):
    secure_dir(p.parent,True)
    from command_transport import durable_replace
    durable_replace(p,blob,mode=mode)


def read_config():
    if not secure_dir(CONF_DIR):return None
    if CONF.is_symlink():fail('Config Zapret simbolica')
    if not CONF.exists():return None
    if CONF.is_symlink() or not CONF.is_file() or CONF.stat().st_uid!=0 or CONF.stat().st_mode&0o077:fail('Config Zapret non protetta')
    with CONF.open('rb') as stream:
        raw=stream.read(20*1024*1024+1)
    if len(raw)>20*1024*1024:fail('Config Zapret troppo grande')
    data=json.loads(raw)
    return validate(data)

def validate(data):
    if not isinstance(data,dict) or set(data)!={'wan_if','clients','domains','queue','strategy'}:fail('Campi Zapret non validi')
    wan=data['wan_if'];clients=data['clients'];domains=data['domains'];queue=data['queue'];strategy=data['strategy']
    if not isinstance(wan,str) or not IFACE.fullmatch(wan):fail('WAN non valida')
    if not isinstance(clients,list) or not (1<=len(clients)<=24):fail('Seleziona 1-24 reti private')
    ips=[]
    for client in clients:
        try: network=ipaddress.ip_network(client,strict=False)
        except (ValueError,TypeError):fail('Rete client invalida')
        if network.version!=4 or not (network.is_private and not network.is_loopback and not network.is_link_local) or network.prefixlen<16:fail('Sono consentite solo sottoreti IPv4 private /16 o più ristrette')
        if str(network) not in ips:ips.append(str(network))
    if not isinstance(domains,list) or not domains:fail('Inserisci almeno un dominio')
    hosts=[];seen=set();hostlist_bytes=0
    for name in domains:
        if not isinstance(name,str):fail('Dominio non valido')
        normalized=name.strip().lower().rstrip('.')
        if not HOST.fullmatch(normalized):fail('Dominio non valido')
        if normalized not in seen:
            hostlist_bytes+=len(normalized)+1
            if hostlist_bytes>16*1024*1024:fail('Elenco domini oltre 16 MiB')
            seen.add(normalized);hosts.append(normalized)
    if type(queue)!=int or queue<100 or queue>999:fail('Coda NFQUEUE non valida')
    if strategy not in ('multisplit','fake'):fail('Strategia non autorizzata')
    return {'wan_if':wan,'clients':ips,'domains':hosts,'queue':queue,'strategy':strategy}

def status():
    root()
    candidate=next((p for p in (BIN,pathlib.Path('/opt/zapret/nfq/nfqws')) if p.is_file() and not p.is_symlink() and os.access(p,os.X_OK)),None)
    cfg=read_config()
    recorded=''
    if VERSION_FILE.is_file() and not VERSION_FILE.is_symlink() and VERSION_FILE.stat().st_uid==0:
        try: recorded=str(json.loads(VERSION_FILE.read_text()).get('tag',''))[:32]
        except (OSError,ValueError,TypeError): pass
    return {'ok':True,'installed':bool(candidate),'installed_version':recorded,
            'binary':str(candidate) if candidate else '', 
            'configured':bool(cfg),'configuration':cfg,
            'activation':'disabled-until-network-acceptance','rooted':True}

def preview():
    cfg=read_config()
    if not cfg:fail('Configura prima il profilo')
    queue=cfg['queue'];wan=cfg['wan_if']; rules=[]
    for client in cfg['clients']:
        rules.append('iptables -t mangle -I FORWARD -o '+wan+' -s '+client+' -p tcp -m multiport --dports 80,443 -m connbytes --connbytes-dir original --connbytes-mode packets --connbytes 1:6 -j NFQUEUE --queue-num '+str(queue)+' --queue-bypass')
    return {'ok':True,'mode':'preview','rules':rules,
      'nfqws_options':['--qnum='+str(queue),'--dpi-desync='+cfg['strategy'],'--hostlist='+str(HOSTLIST)],
      'changes_live':False,'warning':'Solo anteprima. Non abilita NFQUEUE o servizi. Verificare routing WAN, hw offload, iptables mangle e rollback prima di attivare.'}

def configure(payload):
    # A configured daemon may still be using the old hostlist. Require a
    # stop/retest cycle so persistent boot never activates unapproved domains.
    import antidpi_live
    if antidpi_live.current() is not None or (antidpi_live.persistent() or {}).get('enabled'):
        fail('Anti-DPI ancora attivo o persistente: arresta prima di cambiare la hostlist')
    cfg=validate(payload)
    secure_dir(CONF_DIR,True)
    # Transactional best-effort compensation across the two configuration files.
    # Both remain inert until an explicitly approved network activation.
    plan={HOSTLIST:(''.join(h+'\n' for h in cfg['domains'])).encode(),
          CONF:(json.dumps(cfg,sort_keys=True,indent=2)+'\n').encode()}
    previous={}
    for path in plan:
        if path.is_symlink():fail('File di configurazione simbolico non consentito')
        if path.exists():
            if not path.is_file() or path.stat().st_uid!=0:fail('Configurazione esistente non protetta')
            previous[path]=path.read_bytes()
        else:previous[path]=None
    done=[]
    try:
        for path,data in plan.items():
            atomic(path,data,0o600);done.append(path)
    except Exception:
        failed=[]
        for path in reversed(done):
            try:
                if previous[path] is None:path.unlink(missing_ok=True)
                else:atomic(path,previous[path],0o600)
            except Exception:failed.append(path.name)
        if failed:fail('Salvataggio incompleto: recupero manuale per '+','.join(failed))
        raise
    return {'ok':True,'configured':True,'changes_live':False}

def install(payload,allow_no_digest=False):
    root()
    if not isinstance(payload,dict) or set(payload)!={'url','sha256'}:fail('URL e hash SHA256 richiesti')
    url=payload['url'];digest=payload['sha256']
    if not isinstance(url,str) or not GITHUB_RELEASE.fullmatch(url):fail('Scaricamento consentito solo dalle release ufficiali bol-van/zapret HTTPS')
    if not allow_no_digest and (not isinstance(digest,str) or not re.fullmatch('[a-f0-9]{64}',digest)):fail('SHA256 valido richiesto per installazione manuale')
    if allow_no_digest and digest is not None and (not isinstance(digest,str) or not re.fullmatch('[a-f0-9]{64}',digest)):fail('SHA256 del provider non valido')
    architecture=detect_arch()
    with tempfile.TemporaryDirectory(prefix='iptm-zapret-') as folder:
        tmp=pathlib.Path(folder)/'release.tar.gz'
        # Restrict initial host; redirects go through GitHub's release distribution.
        with github_open(url,timeout=35) as stream, tmp.open('wb') as f:
            h=hashlib.sha256();size=0
            while True:
                part=stream.read(65536)
                if not part:break
                size+=len(part)
                if size>40*1024*1024:fail('Release troppo grande')
                h.update(part);f.write(part)
        if digest and h.hexdigest()!=digest:fail('Hash release non corrispondente: nessuna installazione')
        # Stream the archive; do not load all member headers into RAM or
        # extract arbitrary paths from upstream archive as root.
        binary=None;seen=0;expanded=0;entries=0
        with tarfile.open(tmp,'r|gz') as tar:
            for member in tar:
                entries+=1;expanded+=max(0,member.size)
                if entries>6000 or expanded>250*1024*1024:
                    fail('Archivio tar.gz con troppi elementi o dati espansi')
                if member.isfile() and re.search(
                    r'(?:^|/)binaries/'+re.escape(architecture[0])+r'/nfqws\Z',member.name):
                    seen+=1
                    if seen>1 or not 64<=member.size<=12*1024*1024:
                        fail('Binari nfqws duplicati o dimensione invalida')
                    stream=tar.extractfile(member)
                    if stream is None: fail('Impossibile leggere nfqws dal tar.gz')
                    binary=stream.read(12*1024*1024+1)
        if seen!=1 or binary is None:fail('Binario nfqws corretto non trovato nel pacchetto')
        validate_elf(binary,architecture)
        secure_dir(ENGINE_DIR,True)
        if BIN.exists() and (BIN.is_symlink() or not BIN.is_file() or BIN.stat().st_uid!=0):fail('Installazione preesistente non sicura')
        atomic(BIN,binary,0o755)
        tag=re.search(r'/download/(v[0-9.]+)/',url).group(1)
        atomic(VERSION_FILE,(json.dumps({'tag':tag,'sha256':h.hexdigest()},sort_keys=True)+'\n').encode(),0o600)
    return {'ok':True,'installed':True,'version':tag,'changes_live':False,'sha256':h.hexdigest()}

def main():
    root()
    action=sys.argv[1] if len(sys.argv)==2 else ''
    if action=='status':return status()
    if action=='latest':return latest_release()
    if action=='preview':return preview()
    if action not in ('configure','install','install-latest'):fail('Uso: status|latest|preview|install|install-latest|configure')
    data=sys.stdin.buffer.read(20*1024*1024+1)
    if len(data)>8*1024*1024:fail('Payload eccessivo (massimo 8 MiB)')
    payload=json.loads(data)
    if action=='configure':return configure(payload)
    if action=='install-latest':
        if not isinstance(payload,dict) or set(payload)!={'tag'} or not isinstance(payload['tag'],str) or not TAG_RE.fullmatch(payload['tag']):
            fail('Tag confermato non valido')
        candidate=latest_release()
        if candidate['tag']!=payload['tag']:fail('Nuova release disponibile: controlla il nuovo tag prima di installare')
        return install({'url':candidate['url'],'sha256':candidate['sha256'] or None}, allow_no_digest=True)
    return install(payload)

def coordinated_main():
    from command_transport import driver_admission
    with driver_admission('zapret_manager',sys.argv[1:]):
        return main()

if __name__=='__main__':
    try:print(json.dumps(coordinated_main(),ensure_ascii=False))
    except (ZapretError,OSError,ValueError,subprocess.TimeoutExpired,urllib.error.URLError,tarfile.TarError,KeyError,TypeError) as e:
        print(json.dumps({'ok':False,'error':str(e)},ensure_ascii=False));sys.exit(1)
