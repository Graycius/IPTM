#!/usr/bin/env python3
"""Transactional LAN-only HTTP cache / HTTPS CONNECT proxy using system Squid.

No transparent interception, MITM, remote CDN server, NAT or firewall changes.
Only explicitly configured LAN clients can use the proxy. Existing system
Squid installations and foreign systemd services are never overwritten.
"""
from __future__ import annotations
import fcntl,hashlib,ipaddress,json,os,pathlib,pwd,re,subprocess,sys,tempfile,time

BASE=pathlib.Path('/var/lib/iptm-cache-proxy')
STAGE=BASE/'stage.json'
STATE=BASE/'active.json'
CONF_DIR=pathlib.Path('/etc/iptm-cache-proxy')
CONF=CONF_DIR/'squid.conf'
UNIT=pathlib.Path('/etc/systemd/system/iptm-cache-proxy.service')
CACHE=pathlib.Path('/var/cache/iptm-cache-proxy')
LOG=pathlib.Path('/var/log/iptm-cache-proxy')
SQUID=pathlib.Path('/usr/sbin/squid')
LOCK=BASE/'lock'
PORT_MIN=1024
MAX_INPUT=4096
IFACE=re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,14}\Z')
SHA=re.compile(r'[a-f0-9]{64}\Z')
MARKER='Description=IPTM isolated LAN HTTP caching proxy'
class ProxyError(ValueError):pass


def command(args,timeout=12,check=True):
    try:r=subprocess.run(args,capture_output=True,text=True,stdin=subprocess.DEVNULL,timeout=timeout)
    except (OSError,subprocess.TimeoutExpired) as exc:raise ProxyError('Comando non verificabile: '+str(exc)[:180]) from exc
    if check and r.returncode:raise ProxyError('Comando fallito: '+(r.stderr or r.stdout)[-220:])
    return r


def guard_root():
    if os.geteuid()!=0:raise ProxyError('root richiesto')
    if BASE.is_symlink():raise ProxyError('Directory stato simbolica')
    BASE.mkdir(parents=True,mode=0o700,exist_ok=True)
    st=BASE.stat()
    if st.st_uid or st.st_mode&0o077:raise ProxyError('Stato non protetto')


def ensure_dir(path,mode,uid=0,gid=0):
    if path.is_symlink():raise ProxyError('Directory simbolica: '+str(path))
    if not path.exists():path.mkdir(parents=True,mode=mode)
    if not path.is_dir():raise ProxyError('Percorso directory non valido')
    st=path.stat()
    if st.st_uid not in (0,uid) or st.st_mode&0o002:raise ProxyError('Directory non sicura: '+str(path))
    os.chown(path,uid,gid);os.chmod(path,mode)


def atom_file(path,content,mode=0o600):
    if path.is_symlink():raise ProxyError('File simbolico non consentito: '+str(path))
    fd,temp=tempfile.mkstemp(dir=path.parent,prefix='.iptm-cache-')
    try:
        with os.fdopen(fd,'wb') as out:
            os.fchmod(out.fileno(),mode);out.write(content);out.flush();os.fsync(out.fileno())
        os.replace(temp,path)
    finally:
        if os.path.exists(temp):os.unlink(temp)


def atom_json(path,obj):atom_file(path,json.dumps(obj,sort_keys=True).encode())


def read_json(path):
    if path.is_symlink():raise ProxyError('File stato simbolico')
    if not path.exists():return None
    st=path.stat()
    if not path.is_file() or st.st_uid or st.st_mode&0o077 or st.st_size>16384:
        raise ProxyError('File stato non protetto')
    try:value=json.loads(path.read_text())
    except (OSError,UnicodeError,ValueError) as exc:raise ProxyError('Stato non decodificabile') from exc
    if not isinstance(value,dict):raise ProxyError('Stato malformato')
    return value


def parse_config(obj):
    if not isinstance(obj,dict) or set(obj)!={'interface','listen_ip','port','allowed_nets','disk_mib','memory_mib'}:
        raise ProxyError('Schema del proxy non valido')
    iface=obj['interface']
    if not isinstance(iface,str) or not IFACE.fullmatch(iface) or iface=='lo':
        raise ProxyError('Interfaccia LAN non valida')
    try:ip=ipaddress.IPv4Address(obj['listen_ip'])
    except (ipaddress.AddressValueError,TypeError,ValueError) as exc:raise ProxyError('Indirizzo IPv4 non valido') from exc
    rfc1918=(ipaddress.IPv4Network('10.0.0.0/8'),ipaddress.IPv4Network('172.16.0.0/12'),ipaddress.IPv4Network('192.168.0.0/16'))
    if not any(ip in prefix for prefix in rfc1918):
        raise ProxyError('Ascolto consentito solo su IP LAN privato')
    port=obj['port'];disk=obj['disk_mib'];memory=obj['memory_mib']
    if type(port) is not int or not PORT_MIN<=port<=65535:raise ProxyError('Porta proxy 1024..65535')
    if type(disk) is not int or not 64<=disk<=1024:raise ProxyError('Cache disco 64..1024 MiB')
    if type(memory) is not int or not 8<=memory<=64:raise ProxyError('Cache RAM 8..64 MiB')
    nets=obj['allowed_nets']
    if not isinstance(nets,list) or not 1<=len(nets)<=8 or len(set(map(str,nets)))!=len(nets):
        raise ProxyError('Specificare da 1 a 8 subnet LAN diverse')
    checked=[]
    for net in nets:
        if not isinstance(net,str) or len(net)>50:raise ProxyError('Subnet LAN non valida')
        try:network=ipaddress.IPv4Network(net,strict=True)
        except (ipaddress.NetmaskValueError,ipaddress.AddressValueError,TypeError) as exc:
            raise ProxyError('CIDR LAN non valido') from exc
        if not any(network.subnet_of(prefix) for prefix in rfc1918) or network.prefixlen<16:
            raise ProxyError('CIDR LAN troppo ampio o non privato: minimo /16')
        checked.append(network)
    if not any(ip in net for net in checked):raise ProxyError('IP di ascolto non presente nelle LAN autorizzate')
    return {'interface':iface,'listen_ip':str(ip),'port':port,'allowed_nets':[str(n) for n in checked],
            'disk_mib':disk,'memory_mib':memory}


def verify_interface(profile):
    try:links=json.loads(command(['ip','-j','-4','addr','show','dev',profile['interface']]).stdout)
    except ValueError as exc:raise ProxyError('Interfaccia non verificabile') from exc
    if len(links)!=1 or links[0].get('ifname')!=profile['interface']:
        raise ProxyError('Scheda LAN cambiata')
    addresses=[entry.get('local') for entry in links[0].get('addr_info',[]) if entry.get('family')=='inet']
    if profile['listen_ip'] not in addresses:raise ProxyError('L’indirizzo LAN non è assegnato alla scheda')
    return True


def config_text(profile):
    networks='\n'.join('acl iptm_clients src '+n for n in profile['allowed_nets'])
    return f'''# IPTM cache proxy - local, explicit configuration only.
visible_hostname iptm-cache
http_port {profile['listen_ip']}:{profile['port']}
pid_filename none
{networks}
acl CONNECT method CONNECT
acl SSL_ports port 443
acl Safe_ports port 80 443
acl blocked_dst dst 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 224.0.0.0/4 240.0.0.0/4 ::1/128 fc00::/7 fe80::/10
http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access deny blocked_dst
http_access allow iptm_clients
http_access deny all
cache_mem {profile['memory_mib']} MB
cache_dir ufs {CACHE} {profile['disk_mib']} 16 256
maximum_object_size 16 MB
minimum_object_size 0 KB
cache_swap_low 85
cache_swap_high 90
cache_store_log none
access_log stdio:{LOG}/access.log squid
cache_log {LOG}/cache.log
forwarded_for delete
via on
client_db off
shutdown_lifetime 4 seconds
'''


def unit_text():
    return f'''[Unit]
{MARKER}
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=proxy
Group=proxy
ExecStart={SQUID} -N -f {CONF}
ExecStop=/bin/kill -TERM $MAINPID
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths={CACHE} {LOG}
CapabilityBoundingSet=
[Install]
WantedBy=multi-user.target
'''


def verify_ownership():
    if not SQUID.is_file() or SQUID.is_symlink() or SQUID.stat().st_uid!=0 or SQUID.stat().st_mode&0o022:
        raise ProxyError('Squid non installato o binario non protetto: installare pacchetto Debian squid')
    try:identity=pwd.getpwnam('proxy')
    except KeyError as exc:raise ProxyError('Utente Linux proxy mancante') from exc
    if UNIT.exists() or UNIT.is_symlink():
        if UNIT.is_symlink() or not UNIT.is_file() or UNIT.stat().st_uid!=0 or UNIT.stat().st_mode&0o022 or MARKER not in UNIT.read_text():
            raise ProxyError('Servizio preesistente non appartenente a IPTM')
    if CONF.exists() or CONF.is_symlink():
        if CONF.is_symlink() or not CONF.is_file() or CONF.stat().st_uid!=0 or CONF.stat().st_mode&0o022 or not CONF.read_text().startswith('# IPTM cache proxy'):
            raise ProxyError('Configurazione proxy preesistente non riconosciuta')
    return identity


def stage(obj):
    profile=parse_config(obj)
    verify_interface(profile)
    verify_ownership()
    digest=hashlib.sha256(json.dumps(profile,sort_keys=True).encode()).hexdigest()
    atom_json(STAGE,{'profile':profile,'sha256':digest,'created':time.time()})
    return {'ok':True,'sha256':digest,'profile':profile,'preview':config_text(profile),
            'mode':'proxy esplicito HTTP + HTTPS CONNECT (nessuna intercettazione TLS)',
            'applied':False}


def apply(digest):
    if not isinstance(digest,str) or not SHA.fullmatch(digest):raise ProxyError('Digest non valido')
    staged=read_json(STAGE)
    if not staged or not isinstance(staged.get('profile'),dict) or staged.get('sha256')!=digest:
        raise ProxyError('Anteprima assente o differente')
    if time.time()-staged.get('created',0)>600:raise ProxyError('Anteprima scaduta')
    profile=parse_config(staged['profile'])
    verify_interface(profile)
    identity=verify_ownership()
    # Never modify anything on a live firewall/rollback transaction.
    if pathlib.Path('/var/lib/iptables-manager/pending.json').exists():
        raise ProxyError('Apply firewall pendente: configurazione proxy rinviata')
    ensure_dir(CONF_DIR,0o750,0,identity.pw_gid)
    ensure_dir(CACHE,0o750,identity.pw_uid,identity.pw_gid)
    ensure_dir(LOG,0o750,identity.pw_uid,identity.pw_gid)
    old_conf=CONF.read_bytes() if CONF.exists() else None
    old_unit=UNIT.read_bytes() if UNIT.exists() else None
    previous=read_json(STATE)
    candidate=config_text(profile).encode()
    candidate_temp=CONF_DIR/'.candidate.conf'
    atom_file(candidate_temp,candidate,0o644)
    try:
        command([str(SQUID),'-k','parse','-f',str(candidate_temp)],timeout=25)
        atom_file(CONF,candidate,0o644)
        if UNIT.is_symlink():raise ProxyError('Servizio simbolico')
        atom_file(UNIT,unit_text().encode(),0o644)
        command(['systemctl','daemon-reload'],timeout=20)
        # Init only our own cache root; never operate on system Squid.
        if not (CACHE/'00').is_dir():command([str(SQUID),'-z','-f',str(CONF)],timeout=65)
        command(['systemctl','enable',UNIT.name],timeout=20)
        command(['systemctl','restart',UNIT.name],timeout=25)
        if command(['systemctl','is-active',UNIT.name],check=False).stdout.strip()!='active':
            raise ProxyError('Proxy non attivo dopo applicazione')
        atom_json(STATE,{'profile':profile,'enabled':True,'updated':time.time()})
        STAGE.unlink(missing_ok=True)
        return {'ok':True,'enabled':True,'listen':f'{profile["listen_ip"]}:{profile["port"]}',
                'http_cache':True,'https':'CONNECT cifrato non memorizzato'}
    except Exception as exc:
        # Fail safe: after a failure restore both config and prior service state.
        rollback_failed=[]
        try:
            command(['systemctl','disable','--now',UNIT.name],timeout=20)
            if old_conf is not None:atom_file(CONF,old_conf,0o644)
            else:CONF.unlink(missing_ok=True)
            if old_unit is not None:atom_file(UNIT,old_unit,0o644)
            else:UNIT.unlink(missing_ok=True)
            command(['systemctl','daemon-reload'])
            if previous and previous.get('enabled') and old_unit is not None and old_conf is not None:
                command(['systemctl','enable','--now',UNIT.name])
        except Exception as recover:
            rollback_failed.append(type(recover).__name__)
        if rollback_failed:raise ProxyError('Errore applicazione, recupero unità incerto: '+','.join(rollback_failed)) from exc
        raise ProxyError('Config proxy non attivata; vecchia configurazione ripristinata: '+str(exc)[:220]) from exc
    finally:
        candidate_temp.unlink(missing_ok=True)


def disable():
    verify_ownership()
    if UNIT.is_file():
        command(['systemctl','disable','--now',UNIT.name],timeout=25)
        if command(['systemctl','is-active',UNIT.name],check=False).stdout.strip()=='active':
            raise ProxyError('Squid ancora attivo: non dichiarare disattivazione')
    previous=read_json(STATE) or {}
    previous.update(enabled=False,updated=time.time())
    atom_json(STATE,previous)
    return {'ok':True,'enabled':False,'note':'Nessuna regola firewall o DNS modificata'}


def status():
    previous=read_json(STATE) or {}
    running=False
    if UNIT.is_file() and not UNIT.is_symlink():
        try:running=command(['systemctl','is-active',UNIT.name],check=False,timeout=4).stdout.strip()=='active'
        except ProxyError:pass
    return {'ok':True,'installed':SQUID.is_file(),'managed':UNIT.is_file() and not UNIT.is_symlink(),
            'active':running,'configured':bool(previous.get('profile')),
            'profile':previous.get('profile',{}),'enabled':bool(previous.get('enabled')),
            'tls_interception':False,'auto_browser_setup':False,
            'note':'Cache HTTP esplicita: HTTPS CONNECT resta cifrato e non è memorizzato. Nessuna CDN privata è creata.'}


def main(argv):
    if os.geteuid()!=0:raise ProxyError('Operazione proxy riservata a root')
    guard_root()
    if argv==['status']:return status()
    fd=os.open(LOCK,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'r+') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        if argv==['stage']:
            raw=sys.stdin.buffer.read(MAX_INPUT+1)
            if len(raw)>MAX_INPUT:raise ProxyError('Configurazione troppo grande')
            return stage(json.loads(raw))
        if len(argv)==2 and argv[0]=='apply':return apply(argv[1])
        if argv==['disable']:return disable()
        raise ProxyError('Comando non riconosciuto')

if __name__=='__main__':
    try:print(json.dumps(main(sys.argv[1:]),ensure_ascii=False))
    except (ProxyError,OSError,ValueError,TypeError,KeyError,subprocess.TimeoutExpired) as exc:
        print(json.dumps({'ok':False,'error':str(exc)[:350]},ensure_ascii=False));sys.exit(1)
