#!/usr/bin/env python3
"""Transactional LAN-only Squid cache with opt-in HTTP/80 interception.

Never intercept HTTPS, alter gateway/DNS, or touch foreign firewall rules.
Use a dedicated owned iptables chain and fail-open cleanup.
"""
from __future__ import annotations
import fcntl,hashlib,ipaddress,json,os,pathlib,pwd,re,socket,subprocess,sys,tempfile,time
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
import cache_redirect as redir

BASE=pathlib.Path('/var/lib/iptm-cache-proxy')
STAGE=BASE/'stage.json'
STATE=BASE/'active.json'
PREFS=BASE/'preferences.json'
REDIRECT=BASE/'redirect.json'
CONF_DIR=pathlib.Path('/etc/iptm-cache-proxy')
CONF=CONF_DIR/'squid.conf'
UNIT=pathlib.Path('/etc/systemd/system/iptm-cache-proxy.service')
RECONCILE_UNIT=pathlib.Path('/etc/systemd/system/iptm-cache-redirect.service')
RECONCILE_TIMER=pathlib.Path('/etc/systemd/system/iptm-cache-redirect.timer')
CACHE=pathlib.Path('/var/cache/iptm-cache-proxy')
LOG=pathlib.Path('/var/log/iptm-cache-proxy')
SQUID=pathlib.Path('/usr/sbin/squid')
LOCK=BASE/'lock'
PORT_MIN=1024
MAX_INPUT=4096
IFACE=re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,14}\Z')
SHA=re.compile(r'[a-f0-9]{64}\Z')
MARKER='Description=IPTM isolated LAN HTTP caching proxy'
REDIRECT_MARKER='Description=IPTM HTTP cache redirect reconciliation'
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
    if not isinstance(obj,dict) or set(obj)-{'interface','listen_ip','port','allowed_nets','disk_mib','memory_mib','intercept_http'} or not {'interface','listen_ip','port','allowed_nets','disk_mib','memory_mib'}.issubset(obj):
        raise ProxyError('Schema del proxy non valido')
    intercept=obj.get('intercept_http',False)
    if type(intercept) is not bool:raise ProxyError('Modalità intercettazione non valida')
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
            'disk_mib':disk,'memory_mib':memory,'intercept_http':intercept}


def verify_interface(profile):
    try:links=json.loads(command(['ip','-j','-4','addr','show','dev',profile['interface']]).stdout)
    except ValueError as exc:raise ProxyError('Interfaccia non verificabile') from exc
    if len(links)!=1 or links[0].get('ifname')!=profile['interface']:
        raise ProxyError('Scheda LAN cambiata')
    addresses=[entry.get('local') for entry in links[0].get('addr_info',[]) if entry.get('family')=='inet']
    if profile['listen_ip'] not in addresses:raise ProxyError('L’indirizzo LAN non è assegnato alla scheda')
    if profile['intercept_http'] and addresses[0] != profile['listen_ip']:
        raise ProxyError('Intercettazione HTTP: seleziona il primo indirizzo IPv4 LAN della scheda')
    return True


def config_text(profile):
    networks='\n'.join('acl iptm_clients src '+n for n in profile['allowed_nets'])
    mode=' intercept' if profile['intercept_http'] else ''
    return f'''# IPTM cache proxy - LAN-only HTTP/HTTPS explicit or HTTP intercept.
visible_hostname iptm-cache
http_port {profile['listen_ip']}:{profile['port']}{mode}
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


def unit_text(binary=None):
    if binary is None:binary=trusted_binary()
    if binary is None:raise ProxyError('Binario Squid non verificato')
    return f'''[Unit]
{MARKER}
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=proxy
Group=proxy
ExecStart={binary} -N -f {CONF}
ExecStop=/bin/kill -TERM $MAINPID
# Unconditional direct fail-open cleanup: no lock, even on a service crash.
ExecStopPost=+/usr/local/sbin/iptm-helper cache-proxy failopen
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


def trusted_binary():
    """Resolve Debian usrmerge aliases while rejecting untrusted executable trees."""
    candidates=[SQUID,pathlib.Path('/usr/bin/squid'),pathlib.Path('/sbin/squid'),pathlib.Path('/bin/squid')]
    # Some Debian variants install Squid below /usr/lib; discover only paths
    # actually reported by dpkg and then apply the same strict root checks.
    try:
        listing=command(['dpkg-query','-L','squid'],check=False,timeout=5)
        if listing.returncode==0:
            candidates.extend(pathlib.Path(p) for p in listing.stdout.splitlines()
                              if p.endswith('/squid') and p.startswith(('/usr/sbin/','/usr/bin/','/usr/lib/squid/')))
    except ProxyError:pass
    for entry in candidates:
        try:
            if not entry.is_file():continue
            target=entry.resolve(strict=True)
            if target.name!='squid' or not target.is_file() or not os.access(entry,os.X_OK):continue
            if not str(target).startswith(('/usr/sbin/','/usr/bin/','/usr/lib/squid/')):continue
            # Inspect every component: an attacker must not substitute the binary.
            unsafe=False
            for ancestor in (target,*target.parents):
                stat=ancestor.stat()
                if stat.st_uid!=0 or stat.st_mode&0o022:
                    unsafe=True;break
                if str(ancestor)=='/':break
            if not unsafe:return target
        except (OSError,RuntimeError):continue
    return None


def package_installed():
    try:
        r=command(['dpkg-query','-W','-f=${Status}','squid'],timeout=5,check=False)
        return r.returncode==0 and r.stdout.strip()=='install ok installed'
    except ProxyError:return False


def owned_file(path,marker):
    if not path.exists() and not path.is_symlink():return False
    if path.is_symlink() or not path.is_file():raise ProxyError('File del proxy simbolico o non regolare: '+str(path))
    st=path.stat()
    if st.st_uid!=0 or st.st_mode&0o022 or marker not in path.read_text():
        raise ProxyError('File preesistente non gestito da IPTM: '+str(path))
    return True


def verify_owned_files():
    owned_file(UNIT,MARKER)
    owned_file(CONF,'# IPTM cache proxy')
    owned_file(RECONCILE_UNIT,REDIRECT_MARKER)
    owned_file(RECONCILE_TIMER,'# IPTM HTTP redirect timer')


def verify_ownership():
    binary=trusted_binary()
    if binary is None:
        raise ProxyError('Squid installato ma binario non trovato o non protetto: verifica dpkg -L squid e percorso /usr/sbin/squid')
    try:identity=pwd.getpwnam('proxy')
    except KeyError as exc:raise ProxyError('Utente Linux proxy mancante: verificare pacchetto Debian squid') from exc
    verify_owned_files()
    return identity


def reconcile_unit_text():
    return f"""[Unit]
{REDIRECT_MARKER}
After=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/iptm-helper cache-proxy reconcile
TimeoutStartSec=25
"""


def reconcile_timer_text():
    return """# IPTM HTTP redirect timer
[Unit]
Description=IPTM HTTP redirect integrity monitor
[Timer]
OnBootSec=30s
OnUnitInactiveSec=30s
AccuracySec=5s
Unit=iptm-cache-redirect.service
[Install]
WantedBy=timers.target
"""


def redirect_state():
    info=read_json(REDIRECT)
    if not info:return None
    if not isinstance(info.get('profile'),dict):raise ProxyError('Journal NAT privo del profilo')
    profile=parse_config(info['profile'])
    binary=info.get('backend')
    if binary not in redir.BACKENDS.values():raise ProxyError('Backend NAT nel journal non valido')
    return {'profile':profile,'backend':binary}


def redirect_off():
    previous=redirect_state()
    if previous:
        redir.remove(previous['backend'],previous['profile'])
        REDIRECT.unlink(missing_ok=True)
    return True


def redirect_on(profile):
    binary=redir.backend_path()
    redir.security_preflight(binary)
    if redir.chain_snapshot(binary) is not None:
        redir.chain_trusted(binary,profile)
    # Journal FIRST, before adding rules; cleanup works even after interruption.
    atom_json(REDIRECT,{'profile':profile,'backend':binary,'created':time.time()})
    try:redir.install(binary,profile)
    except Exception:
        redirect_off()
        raise
    if not redir.healthy(binary,profile):
        redirect_off()
        raise ProxyError('Intercettazione NAT non verificabile: regole rimosse')


def require_forwarding():
    try:enabled=pathlib.Path('/proc/sys/net/ipv4/ip_forward').read_text().strip()
    except OSError as exc:raise ProxyError('IPv4 forwarding non verificabile') from exc
    if enabled!='1':
        raise ProxyError('HTTP trasparente richiede IPTM come gateway IPv4 con ip_forward=1; nessuna modifica a routing/firewall effettuata')


def proxy_ready(profile):
    if command(['systemctl','is-active',UNIT.name],check=False,timeout=4).stdout.strip()!='active':return False
    try:
        with socket.create_connection((profile['listen_ip'],profile['port']),timeout=2):return True
    except (OSError,TimeoutError):return False


def failopen():
    """Called by systemd ExecStopPost, not holding the global proxy lock."""
    redirect_off()
    return {'ok':True,'redirect':False,'note':'Traffico HTTP diretto ripristinato'}


def reconcile():
    state=read_json(STATE) or {}
    profile=state.get('profile')
    if not state.get('enabled') or not isinstance(profile,dict) or not profile.get('intercept_http'):
        redirect_off()
        return {'ok':True,'redirect':False}
    profile=parse_config(profile)
    verify_interface(profile)
    try:require_forwarding()
    except ProxyError:
        redirect_off()
        return {'ok':True,'redirect':False,'warning':'IPTM non è più un gateway IPv4: NAT rimosso'}
    if pathlib.Path('/var/lib/iptables-manager/pending.json').exists():
        redirect_off()
        return {'ok':True,'redirect':False,'skipped':'Transazione firewall in corso; redirect temporaneamente rimosso'}
    if not proxy_ready(profile):
        redirect_off()
        return {'ok':True,'redirect':False,'warning':'Squid fermo; redirect rimosso'}
    journal=redirect_state()
    if journal:
        try:redir.security_preflight(journal['backend'])
        except redir.RedirectError as exc:
            redirect_off()
            return {'ok':True,'redirect':False,'warning':str(exc)[:240]}
    if journal and journal['profile']!=profile:
        redirect_off()
        journal=None
    if journal and redir.healthy(journal['backend'],profile):
        return {'ok':True,'redirect':True}
    if journal:redirect_off()
    redirect_on(profile)
    return {'ok':True,'redirect':True}


def stage(obj):
    profile=parse_config(obj)
    verify_interface(profile)
    verify_owned_files()
    digest=hashlib.sha256(json.dumps(profile,sort_keys=True).encode()).hexdigest()
    atom_json(STAGE,{'profile':profile,'sha256':digest,'created':time.time()})
    atom_json(PREFS,{'profile':profile,'updated':time.time()})
    return {'ok':True,'sha256':digest,'profile':profile,'preview':config_text(profile),
            'mode':'HTTP trasparente LAN (porta 80)' if profile['intercept_http'] else 'proxy esplicito HTTP + HTTPS CONNECT',
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
    if profile['intercept_http']:
        require_forwarding()
        redir.security_preflight(redir.backend_path())
    ensure_dir(CONF_DIR,0o750,0,identity.pw_gid)
    ensure_dir(CACHE,0o750,identity.pw_uid,identity.pw_gid)
    ensure_dir(LOG,0o750,identity.pw_uid,identity.pw_gid)
    old_conf=CONF.read_bytes() if CONF.exists() else None
    old_unit=UNIT.read_bytes() if UNIT.exists() else None
    old_reconcile=RECONCILE_UNIT.read_bytes() if RECONCILE_UNIT.exists() else None
    old_timer=RECONCILE_TIMER.read_bytes() if RECONCILE_TIMER.exists() else None
    previous=read_json(STATE)
    candidate=config_text(profile).encode()
    candidate_temp=CONF_DIR/'.candidate.conf'
    try:
        # A restart with a stale NAT hook could interrupt HTTP clients; remove first.
        command(['systemctl','disable','--now',RECONCILE_TIMER.name],check=False)
        redirect_off()
        atom_file(candidate_temp,candidate,0o644)
        binary=trusted_binary()
        if binary is None:raise ProxyError('Binario Squid non disponibile')
        command([str(binary),'-k','parse','-f',str(candidate_temp)],timeout=25)
        atom_file(CONF,candidate,0o644)
        if UNIT.is_symlink():raise ProxyError('Servizio simbolico')
        atom_file(UNIT,unit_text(str(binary)).encode(),0o644)
        atom_file(RECONCILE_UNIT,reconcile_unit_text().encode(),0o644)
        atom_file(RECONCILE_TIMER,reconcile_timer_text().encode(),0o644)
        command(['systemctl','daemon-reload'],timeout=20)
        # Init only our own cache root; never operate on system Squid.
        if not (CACHE/'00').is_dir():
            command(['/usr/sbin/runuser','-u','proxy','--',str(binary),'-z','-f',str(CONF)],timeout=65)
        command(['systemctl','enable',UNIT.name],timeout=20)
        command(['systemctl','restart',UNIT.name],timeout=25)
        if not proxy_ready(profile):
            raise ProxyError('Proxy non raggiungibile sulla porta LAN dopo applicazione')
        if profile['intercept_http']:
            require_forwarding()
            redirect_on(profile)
        command(['systemctl','enable','--now',RECONCILE_TIMER.name],timeout=20)
        atom_json(STATE,{'profile':profile,'enabled':True,'updated':time.time()})
        STAGE.unlink(missing_ok=True)
        return {'ok':True,'enabled':True,'listen':f'{profile["listen_ip"]}:{profile["port"]}',
                'http_cache':True,'redirect':bool(profile['intercept_http']),
                'https':'Cifrato, fuori cache' if profile['intercept_http'] else 'CONNECT cifrato non memorizzato'}
    except Exception as exc:
        # Fail safe: after a failure restore both config and prior service state.
        rollback_failed=[]
        try:
            command(['systemctl','disable','--now',RECONCILE_TIMER.name],check=False)
            redirect_off()
            command(['systemctl','disable','--now',UNIT.name],timeout=20)
            if old_conf is not None:atom_file(CONF,old_conf,0o644)
            else:CONF.unlink(missing_ok=True)
            if old_unit is not None:atom_file(UNIT,old_unit,0o644)
            else:UNIT.unlink(missing_ok=True)
            for path,raw in ((RECONCILE_UNIT,old_reconcile),(RECONCILE_TIMER,old_timer)):
                if raw is not None:atom_file(path,raw,0o644)
                else:path.unlink(missing_ok=True)
            command(['systemctl','daemon-reload'])
            if previous and previous.get('enabled') and old_unit is not None and old_conf is not None:
                command(['systemctl','enable','--now',UNIT.name])
                if previous.get('profile',{}).get('intercept_http') and proxy_ready(previous['profile']):
                    redirect_on(parse_config(previous['profile']))
                    command(['systemctl','enable','--now',RECONCILE_TIMER.name])
        except Exception as recover:
            rollback_failed.append(type(recover).__name__)
        if rollback_failed:raise ProxyError('Errore applicazione, recupero unità incerto: '+','.join(rollback_failed)) from exc
        raise ProxyError('Config proxy non attivata; vecchia configurazione ripristinata: '+str(exc)[:220]) from exc
    finally:
        candidate_temp.unlink(missing_ok=True)


def disable():
    # Must work even when Squid was uninstalled and no binary is present.
    verify_owned_files()
    if RECONCILE_TIMER.is_file():
        command(['systemctl','disable','--now',RECONCILE_TIMER.name],timeout=20)
    redirect_off() # Restore direct traffic BEFORE stopping Squid.
    if UNIT.is_file():
        command(['systemctl','disable','--now',UNIT.name],timeout=25)
        if command(['systemctl','is-active',UNIT.name],check=False).stdout.strip()=='active':
            raise ProxyError('Squid ancora attivo: disattivazione non confermata')
    previous=read_json(STATE) or {}
    previous.update(enabled=False,updated=time.time())
    atom_json(STATE,previous)
    return {'ok':True,'enabled':False,'redirect':False,'note':'HTTP diretto; preferenze salvate'}


def status():
    state=read_json(STATE) or {}
    prefs=read_json(PREFS) or {}
    profile=prefs.get('profile') or state.get('profile') or {}
    applied_profile=state.get('profile') or {}
    running=False
    if UNIT.is_file() and not UNIT.is_symlink():
        try:running=command(['systemctl','is-active',UNIT.name],check=False,timeout=4).stdout.strip()=='active'
        except ProxyError:pass
    redirect=False
    warning=''
    try:
        info=redirect_state()
        if info:redirect=redir.healthy(info['backend'],info['profile'])
    except (ProxyError,redir.RedirectError) as exc:warning=str(exc)[:200]
    installed_binary=trusted_binary()
    return {'ok':True,'installed':installed_binary is not None,'package_installed':package_installed(),
            'binary':str(installed_binary) if installed_binary else '',
            'managed':UNIT.is_file() and not UNIT.is_symlink(),
            'active':running,'intercept_active':redirect,'configured':bool(profile),
            'profile':profile,'applied_profile':applied_profile,
            'pending_changes':bool(profile!=applied_profile),
            'enabled':bool(state.get('enabled')),
            'tls_interception':False,'auto_browser_setup':False,'warning':warning,
            'note':'Solo TCP/80 in modalità trasparente su gateway; HTTPS/443 non intercettato.'}


def main(argv):
    if os.geteuid()!=0:raise ProxyError('Operazione proxy riservata a root')
    guard_root()
    if argv==['status']:return status()
    if argv==['failopen']:return failopen()
    fd=os.open(LOCK,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'r+') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        if argv==['stage']:
            raw=sys.stdin.buffer.read(MAX_INPUT+1)
            if len(raw)>MAX_INPUT:raise ProxyError('Configurazione troppo grande')
            return stage(json.loads(raw))
        if len(argv)==2 and argv[0]=='apply':return apply(argv[1])
        if argv==['disable']:return disable()
        if argv==['reconcile']:return reconcile()
        raise ProxyError('Comando non riconosciuto')

if __name__=='__main__':
    try:print(json.dumps(main(sys.argv[1:]),ensure_ascii=False))
    except (ProxyError,OSError,ValueError,TypeError,KeyError,subprocess.TimeoutExpired) as exc:
        print(json.dumps({'ok':False,'error':str(exc)[:350]},ensure_ascii=False));sys.exit(1)
