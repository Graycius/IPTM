#!/usr/bin/env python3
"""IPTM optional diagnostics and safe network segmentation planner.
No firewall/sysctl/DNS configuration is modified by this module. Standard library only.
"""
import argparse
import fcntl
import time
import csv
import datetime
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import urllib.parse
import ssl
import secrets
import hashlib
import urllib.error

DATA = Path(os.environ.get('IPTM_SECURITY_DATA', '/var/lib/iptables-manager'))
OUI_PATH = DATA / 'oui-vendors.tsv'
IF_RE = re.compile(r'^[a-zA-Z0-9_.:-]{1,15}$')
MAC_RE = re.compile(r'^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$')
IEEE_OUI = 'https://standards-oui.ieee.org/oui/oui.csv'


def emit(obj):
    print(json.dumps(obj, ensure_ascii=False, sort_keys=True))


def shell(argv, timeout=8, max_output=280):
    try:
        p = subprocess.run(argv, text=True, capture_output=True, timeout=timeout, stdin=subprocess.DEVNULL)
        # Reports deliberately do not include full stdout/stderr; they can contain identifiers.
        return {'status': p.returncode, 'summary': (p.stdout + '\n' + p.stderr).strip()[:max_output]}
    except (FileNotFoundError, subprocess.TimeoutExpired) as ex:
        return {'status': None, 'summary': type(ex).__name__}


def service(name):
    if not shutil.which('systemctl'):
        return 'unknown'
    val = shell(['systemctl', 'is-active', name], 3)
    return 'active' if val['status'] == 0 else 'inactive/unknown'


def read_json(path):
    try:
        if Path(path).stat().st_size > 4*1024*1024:
            return {}
        v = json.loads(Path(path).read_text(encoding='utf-8'))
        return v if isinstance(v, dict) else {}
    except (OSError, ValueError):
        return {}


def pihole_privacy_findings(config_path=Path('/etc/pihole/pihole.toml')):
    """Read-only, bounded audit of Pi-hole v6 TOML; never return secrets or edit config.

    Parsed configuration may be superseded by FTLCONF_*; this is an indication,
    not an authoritative runtime attestation.
    """
    findings=[]
    try:
        if config_path.stat().st_size > 1048576: return [{'level':'warning','key':'pihole_config','message':'Configurazione Pi-hole troppo grande per audit in sola lettura'}]
        import tomllib
        with config_path.open('rb') as f: cfg=tomllib.load(f)
    except (FileNotFoundError,ImportError): return findings
    except Exception:
        return [{'level':'warning','key':'pihole_config','message':'TOML Pi-hole non leggibile/valido: verifica da Pi-hole prima di modificare'}]
    dns=cfg.get('dns') or {}; misc=cfg.get('misc') or {}
    if not isinstance(dns,dict) or not isinstance(misc,dict): return findings
    mode=str(dns.get('listeningMode','LOCAL')).upper()
    if mode in ('SINGLE','NONE','BIND'):
        findings.append({'level':'warning','key':'pihole_listening',
          'message':'Pi-hole listeningMode='+mode+': verifica che la porta 53 sia accessibile solo da LAN/VLAN autorizzate; non cambiare in automatico la modalità'})
    if dns.get('queryLogging') is True:
        findings.append({'level':'info','key':'pihole_dns_logs',
          'message':'Query logging Pi-hole attivo: per aumentare privacy valuta di disattivarlo dalle impostazioni Pi-hole, se non serve diagnosi'})
    privacy=misc.get('privacylevel')
    if isinstance(privacy,int) and privacy<2:
        findings.append({'level':'info','key':'pihole_privacy_level',
          'message':'Livello privacy Pi-hole '+str(privacy)+': valutare 2 o 3 se non servono statistiche per client; il cambio può riavviare FTL'})
    upstream=dns.get('upstreams',[])
    if isinstance(upstream,list):
        public=[]
        for value in upstream[:32]:
            if not isinstance(value,str): continue
            host=value.split('#',1)[0].strip('[]')
            try:
                ip=ipaddress.ip_address(host)
                if ip.is_global: public.append(str(ip))
            except ValueError: continue
        if public:
            findings.append({'level':'warning','key':'pihole_plaintext_upstream',
                'message':'Pi-hole usa upstream IP pubblici diretti: il trasporto DNS/53 potrebbe non essere cifrato. Considera il resolver locale DNSCrypt/Unbound senza creare loop.'})
    if dns.get('dnssec') is False:
        findings.append({'level':'info','key':'pihole_dnssec',
            'message':'DNSSEC FTL disabilitato: può essere corretto se la validazione è già effettuata da Unbound; verifica la catena effettiva'})
    return findings


def dns_audit(settings=None):
    s = settings if settings is not None else read_json(DATA/'settings.json')
    findings = []
    def add(level, key, msg): findings.append({'level': level, 'key': key, 'message': msg})
    dns = str(s.get('dns_ip') or '')
    if s.get('dns_redirect'):
        try:
            target=ipaddress.ip_address(dns)
            if target.version != 4 or target.is_unspecified or target.is_loopback or target.is_multicast or target.is_link_local:
                raise ValueError('destinazione non raggiungibile dai client')
        except ValueError:
            add('critical','dns_ip','DNS forzato attivo ma IP di destinazione non valido o non raggiungibile dalla LAN')
        if not str(s.get('lan_nets') or '').strip():
            add('critical','lan_nets','DNS redirect attivo senza reti LAN: generazione regole incompleta')
        if bool((s.get('v6') or {}).get('on',False)):
            add('warning','ipv6_dns','IPv6 attivo: le regole DNS IPv4 non impediscono DNS diretto o cifrato su IPv6')
    if s.get('dns_rebind'):
        add('warning','dns_rebind','L’opzione IPTM segnala soltanto il rischio; il DNS rebinding si blocca nel resolver Pi-hole/Unbound/DNSCrypt, non filtrando le destinazioni LAN in iptables')
    lan=[]
    for item in re.split(r'[\s,;]+', str(s.get('lan_nets') or '')):
        if not item: continue
        try: lan.append(ipaddress.ip_network(item, strict=False))
        except ValueError: add('warning','lan_nets','Rete LAN non valida: verificare prima del reindirizzamento DNS')
    if s.get('dns_redirect') and dns:
        try:
            addr=ipaddress.ip_address(dns)
            if lan and not any(addr in net for net in lan):
                add('warning','dns_outside_lan','IP DNS forzato non appartiene alle reti LAN definite; verifica routing e accessibilità')
            if any(addr in net and addr in (net.network_address, net.broadcast_address) for net in lan if net.version == 4):
                add('critical','dns_network_address','Indirizzo DNS uguale all’indirizzo rete o broadcast: correggi prima di applicare')
        except ValueError: pass
    if s.get('dot_block') and not s.get('dns_redirect'):
        add('warning','dot_without_redirect','Blocco DoT attivo senza forzatura DNS/53: i client possono usare DNS ordinario esterno')
    if s.get('dns_redirect'):
        add('info','doh_bypass','Il solo redirect della porta 53 non forza DoH/DoQ, VPN, IPv6 o DNS già cifrati; nessuna garanzia di controllo universale')
    if not s.get('lockout_on'):
        add('warning','admin_access','Anti-lockout IPTM non attivo: evitare combinazioni INPUT DROP e gestione da reti non autorizzate')
    if bool(s.get('guest_on')) and str(s.get('guest_nets','')).strip() == '':
        add('warning','guest_network','Rete ospiti attiva ma subnet non impostata')
    if bool(s.get('iso_on')) and str(s.get('iso_nets','')).strip() == '':
        add('warning','isolation_network','Isolamento attivo senza subnet esplicite')
    try:
        resolv=Path('/etc/resolv.conf').read_text()[:10000]
        upstream=[ln.split()[1] for ln in resolv.splitlines() if re.match(r'^\s*nameserver\s+\S+',ln)]
    except OSError: upstream=[]
    if any(x in upstream for x in ['127.0.0.1','127.0.0.53','::1']) and not shutil.which('ss'):
        add('info','resolver_loopback','Il resolver host usa il loopback: verificare il servizio DNS in ascolto')
    findings.extend(pihole_privacy_findings())
    services={k:service(unit) for k,unit in [('pihole','pihole-FTL'),('unbound','unbound'),('dnscrypt','dnscrypt-proxy'),('resolved','systemd-resolved')]}
    # systemd-resolved inactive/unknown is normal when FTL or another local resolver owns :53.
    if s.get('dns_redirect') and all(v != 'active' for k,v in services.items() if k != 'resolved'):
        add('warning','dns_unavailable','DNS forzato ma Pi-hole/Unbound/DNSCrypt non risultano attivi su questo host: verificare se DNS è su un altro dispositivo')
    if s.get('dns_redirect') and shutil.which('ss'):
        # Only read the port/socket summaries, not packet contents or query logs.
        check=shell(['ss','-H','-lunt'],3,65536)
        if check['status']==0 and not any(re.search(r'(?<!\d):53\b',ln.split()[4] if len(ln.split())>4 else '') for ln in check['summary'].splitlines()):
            add('info','dns_local_listener','Nessun listener TCP/UDP 53 identificato su questo host: se il DNS è remoto è normale')
    return {'ok':True,'mode':'read-only','services':services,'host_resolver':upstream[:6],
            'findings':findings,'limits':'Non esegue query DNS e non prova la raggiungibilità dei client; DNS su IPv6, DoH/DoQ e VPN richiedono politiche separate.'}


def parse_pihole_web_ports(raw):
    """Interpret Pi-hole FTL v6 webserver.port without guessing legacy ports.

    Supports optional (o), redirect (r), TLS (s), +dual-stack, IPv4 and
    bracketed IPv6 bindings. An empty value means the web UI is disabled.
    Invalid members are returned separately and are never probed.
    """
    raw = str(raw).strip()
    if raw.startswith('webserver.port') and '=' in raw:
        raw = raw.split('=', 1)[1].strip()
    if len(raw) > 2048:
        return [], ['configurazione troppo lunga']
    if len(raw) >= 2 and raw[0] in ('"', "'") and raw[-1] == raw[0]:
        raw = raw[1:-1]
    if not raw:
        return [], []
    ports, invalid = [], []
    rx = re.compile(r'(?:(?P<bind>\[[0-9A-Fa-f:.%]+\]|[0-9.]+):)?(?P<dual>\+)?(?P<port>[0-9]{1,5})(?P<flags>[ors]{0,3})')
    for item in raw.split(','):
        item = item.strip()
        match = rx.fullmatch(item)
        if not match:
            invalid.append(item[:60]); continue
        bind, dual, flags = match.group('bind'), match.group('dual'), match.group('flags')
        port = int(match.group('port'))
        if not 1 <= port <= 65535 or len(flags) != len(set(flags)) or ('r' in flags and 's' in flags) or (dual and bind):
            invalid.append(item[:60]); continue
        if bind:
            try:
                address = ipaddress.ip_address(bind.strip('[]').split('%', 1)[0])
                # IPv6 zones are not accepted by the diagnostic parser.
                if '%' in bind or (bind.startswith('[') != (address.version == 6)):
                    raise ValueError()
            except ValueError:
                invalid.append(item[:60]); continue
        ports.append({'port': port, 'secure': 's' in flags, 'optional': 'o' in flags,
                      'redirect': 'r' in flags, 'bind': bind.strip('[]') if bind else '',
                      'dual': bool(dual)})
    return ports, invalid


def pihole_web_listeners(text):
    """ss -H -ltnp output -> {port: [{address, owner_ftl}]} (read only)."""
    result = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        match = re.fullmatch(r'(.*):([0-9]{1,5})', parts[3])
        if not match or not 0 < int(match[2]) <= 65535:
            continue
        address = match[1].strip('[]')
        result.setdefault(int(match[2]), []).append({'address': address,
                                                       'owner_ftl': 'pihole-FTL' in line})
    return result


def pihole_loopback_target(entry, listeners):
    """Only local-loopback URL targets; never connect to arbitrary LAN hosts."""
    address = entry['bind']
    port = entry['port']
    if address:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return None
        if not ip.is_loopback and not ip.is_unspecified:
            return None
        v6 = ip.version == 6
    else:
        v6 = False
    ip = '::1' if v6 else '127.0.0.1'
    # For dual stack or unspecified bind, verify there is a compatible socket.
    def accepts(listener):
        loc = listener['address']
        if loc in ('*', '0.0.0.0', '::', '[::]'):
            return v6 if loc in ('::', '[::]') else not v6
        try:
            li = ipaddress.ip_address(loc.split('%', 1)[0])
            return li.is_loopback and li.version == (6 if v6 else 4)
        except ValueError:
            return False
    # If ss is available and no compatible local socket exists, don't claim
    # a local HTTP failure for a service intentionally bound to LAN only.
    if listeners is not None and not any(accepts(l) for l in listeners):
        if entry.get('dual') and any(l['address'] in ('::', '[::]') for l in listeners):
            ip = '::1'
        else:
            return None
    return f'[{ip}]' if ':' in ip else ip


def pihole_health():
    """Pi-hole v6 read-only local audit. Never follow redirects or proxy requests."""
    checks, warnings = [], []
    def add(name, status, detail):
        checks.append({'name':name, 'status':status, 'detail':str(detail)[:260]})

    active = service('pihole-FTL')
    add('Servizio pihole-FTL', 'ok' if active == 'active' else 'unknown', active)
    cfg = shell(['pihole-FTL', '--config', 'webserver.port'], 3, 2300)
    configured = cfg['summary'].splitlines()[0].strip() if cfg['status'] == 0 else ''
    ports, invalid = parse_pihole_web_ports(configured)
    if cfg['status'] != 0:
        add('Porte web configurate', 'unknown', 'FTL non restituisce webserver.port; consultare pihole.toml e FTLCONF_webserver_port')
    elif not configured or configured in ('""', "''"):
        add('Porte web configurate', 'unknown', 'webserver.port vuoto: il server web FTL è disabilitato')
    else:
        add('Porte web configurate', 'ok' if ports and not invalid else 'unknown',
            ', '.join(f"{p['port']}{' HTTPS' if p['secure'] else ' HTTP'}{' (facoltativa)' if p['optional'] else ''}"
                      for p in ports[:12]) or 'nessuna porta valida')
    if invalid:
        warnings.append('Voci webserver.port non riconosciute: ' + ', '.join(invalid[:6]))
    if not ports:
        warnings.append('Nessuna porta eseguibile dedotta: non usare 8089/8489 come fallback senza verificare la configurazione FTL.')

    ss = shell(['ss', '-H', '-ltnp'], 3, 16000)
    listeners = pihole_web_listeners(ss['summary']) if ss['status'] == 0 else None
    if listeners is None:
        warnings.append('Socket TCP non leggibili con ss: controllo di binding incompleto.')
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, hdrs, newurl):
            return None

    unique = set()
    for entry in ports[:16]:
        port, secure = entry['port'], entry['secure']
        label = f"{'HTTPS' if secure else 'HTTP'} :{port}"
        key = (port, secure, entry['bind'], entry['dual'])
        if key in unique: continue
        unique.add(key)
        actual = listeners.get(port, []) if listeners is not None else None
        if actual == []:
            add(f'Listener {label}', 'unknown' if entry['optional'] else 'error',
                'Porta facoltativa non aperta (consentito da Pi-hole)' if entry['optional']
                else 'Nessun socket TCP su questa porta; controlla FTL e conflitti con altri servizi')
            continue
        if actual is not None:
            owners = [x['owner_ftl'] for x in actual]
            if owners and not any(owners):
                add(f'Proprietario {label}', 'unknown',
                    'Il socket è occupato ma non risulta attribuito a pihole-FTL: possibile reverse proxy, altro servizio o permessi ss insufficienti')
        target = pihole_loopback_target(entry, actual)
        if target is None:
            add(f'Web {label}', 'unknown',
                'Porta non verificabile su loopback (bind IP LAN/IPv6 o socket non corrispondente). Esegui prova dal client autorizzato.')
            continue
        uri = f"{'https' if secure else 'http'}://{target}:{port}/admin/"
        try:
            req = urllib.request.Request(uri, headers={'User-Agent':'IPTM-local-health/5.30.23'})
            handler = urllib.request.HTTPSHandler(context=ssl._create_unverified_context()) if secure else urllib.request.HTTPHandler()
            client = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(), handler)
            with client.open(req, timeout=2.0) as response:
                code = response.status
        except urllib.error.HTTPError as error:
            code = error.code
        except (OSError, ValueError) as error:
            add(f'Web {label}', 'error', 'Nessuna risposta HTTP locale (' + type(error).__name__ + ')')
            continue
        # A 3xx response counts as a web listener; redirects are never followed.
        add(f'Web {label}', 'ok' if 200 <= code < 400 or code in (401,403) else 'error',
            f'HTTP {code} da loopback; identità applicativa non garantita se il socket è condiviso/proxy')

    if listeners is not None:
        rows = []
        for entry in ports[:16]:
            for item in listeners.get(entry['port'], []):
                rows.append(f"{item['address']}:{entry['port']}")
        add('Indirizzi in ascolto', 'ok' if rows else 'unknown', ', '.join(sorted(set(rows))[:12]) or 'nessun listener corrispondente')

    # UDP connect does NOT prove presence of a DNS service; do not label it OK.
    add('Porta DNS locale', 'unknown', 'Il controllo web non verifica DNS/53: eseguire DNS test separato con dig e un client LAN')
    filter_rules = shell(['iptables','-S','INPUT'], 3, 16000)
    if filter_rules['status'] == 0:
        lines = filter_rules['summary'].splitlines()
        policy_drop = any(re.fullmatch(r'-P INPUT DROP', line.strip()) for line in lines)
        def explicit_accept(port):
            for line in lines:
                if not line.startswith('-A INPUT ') or '-j ACCEPT' not in line: continue
                if not re.search(r'(?:^|\s)-p tcp(?:\s|$)', line): continue
                m = re.search(r'--dports?\s+([0-9,:]+)',line)
                if not m: return True
                for item in m[1].split(','):
                    if item.isdigit() and int(item) == port: return True
                    bounds = item.split(':',1)
                    if len(bounds)==2 and all(x.isdigit() for x in bounds) and int(bounds[0]) <= port <= int(bounds[1]): return True
            return False
        for port in sorted({p['port'] for p in ports})[:16]:
            msg = ('Policy INPUT DROP: nessuna regola TCP ACCEPT esplicita per la porta; controllare anche catene/ordine.'
                   if policy_drop and not explicit_accept(port) else
                   'La lettura delle regole INPUT non sostituisce una verifica di accesso dalla LAN.')
            add(f'INPUT TCP :{port}', 'unknown', msg)
    else:
        add('Firewall INPUT verso Pi-hole', 'unknown', 'iptables INPUT non leggibile; testare accesso dalla LAN')
    success = any(x['name'].startswith('Web ') and x['status'] == 'ok' for x in checks)
    if active == 'active' and success:
        summary = 'FTL attivo e almeno un endpoint locale risponde. Per accesso LAN verificare bind effettivo, firewall e porta dal dispositivo client.'
    elif active == 'active':
        summary = 'FTL attivo, ma nessun endpoint locale provato: il web può essere disabilitato, vincolato a IP specifico, su altra porta o bloccato.'
    else:
        summary = 'FTL non confermato attivo: verificare servizio, configurazione e conflitti di porta, senza cambiare iptables automaticamente.'
    warnings.append('Audit di sola lettura: non riavvia FTL, non modifica firewall e non prova la raggiungibilità da LAN.')
    return {'ok':True, 'mode':'read-only', 'checks':checks, 'warnings':warnings, 'summary':summary}

def system_audit():
    tools=['iptables','iptables-save','iptables-restore','ip6tables','ipset','wg','pihole','unbound-checkconf','dnscrypt-proxy','suricata','cscli','freshclam','clamdscan','lynis']
    presence={k:bool(shutil.which(k)) for k in tools}
    checks={}
    if presence['iptables-save']: checks['iptables-save']=shell(['iptables-save'],5)['status']
    if presence['unbound-checkconf']: checks['unbound-checkconf']=shell(['unbound-checkconf'],8)['status']
    if shutil.which('sshd'): checks['sshd-config']=shell(['sshd','-t'],8)['status']
    if shutil.which('nginx'): checks['nginx-config']=shell(['nginx','-t'],8)['status']
    if shutil.which('apache2ctl'): checks['apache-config']=shell(['apache2ctl','configtest'],8)['status']
    if presence['dnscrypt-proxy']: checks['dnscrypt-config']=shell(['dnscrypt-proxy','-check'],8)['status']
    failures=[k for k,v in checks.items() if v != 0]
    # Inspect metadata only: do not return credential or configuration contents.
    watched=[DATA/'users.json', DATA/'settings.json', DATA/'notify.env',
             Path('/etc/wireguard/wg0.conf'), Path('/etc/iptables-manager.web.json')]
    permissions=[]
    for f in watched:
        try:
            st=f.lstat()
            mode=stat.S_IMODE(st.st_mode)
            if stat.S_ISLNK(st.st_mode):
                permissions.append({'path':str(f),'risk':'symlink inatteso: controllare destinazione e proprietario'})
            elif not stat.S_ISREG(st.st_mode):
                permissions.append({'path':str(f),'risk':'non è un file regolare'})
            elif mode & 0o002:
                permissions.append({'path':str(f),'risk':'scrivibile da tutti: rischio di manomissione'})
            elif mode & 0o004:
                permissions.append({'path':str(f),'risk':'leggibile da tutti: possibile esposizione di credenziali'})
        except FileNotFoundError:
            continue
        except OSError:
            permissions.append({'path':str(f),'risk':'impossibile verificare i permessi'})
    return {'ok':True,'mode':'read-only','date':datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'dietpi_detected':Path('/boot/dietpi').exists() or Path('/boot/dietpi.txt').exists(),
            'tools':presence,'config_checks':checks,'failed_checks':failures,'permission_findings':permissions,'dns':dns_audit(),
            'notes':['Test di configurazione limitati ai programmi rilevati: non modifica regole, servizi o configurazioni.',
                     'Programmi non installati e differenze fra versioni richiedono controllo su DietPi reale.']}


def parse_oui(text):
    reader=csv.DictReader(text.splitlines())
    if not {'Assignment','Organization Name'}.issubset(set(reader.fieldnames or [])):
        raise ValueError('CSV IEEE non riconosciuto')
    out={}
    for row in reader:
        mac=(row.get('Assignment') or '').upper()
        vendor=(row.get('Organization Name') or '').replace('\t',' ').replace('\n',' ').strip()[:140]
        if re.fullmatch(r'[A-F0-9]{6}',mac) and vendor: out[mac]=vendor
    if len(out)<100 and os.environ.get('IPTM_OUI_TEST')!='1':
        raise ValueError('database OUI incompleto')
    return out


def update_oui():
    if os.geteuid()!=0: raise ValueError('aggiornamento vendor riservato a root')
    req=urllib.request.Request(IEEE_OUI,headers={'User-Agent':'IPTM-security/5.30.23'})
    class SecureRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request, fp, code, msg, headers, newurl):
            url=urllib.parse.urlsplit(newurl)
            if url.scheme!='https' or url.hostname!='standards-oui.ieee.org':
                raise ValueError('redirect IEEE non HTTPS o host diverso: aggiornamento annullato')
            return super().redirect_request(request,fp,code,msg,headers,newurl)
    opener=urllib.request.build_opener(SecureRedirect())
    source=IEEE_OUI
    try:
        with opener.open(req,timeout=12) as res:
            # No MAC/device identifiers are transmitted; only the bulk IEEE directory.
            payload=res.read(24*1024*1024+1)
        if len(payload)>24*1024*1024: raise ValueError('database IEEE troppo grande')
        vendors=parse_oui(payload.decode('utf-8-sig'))
    except (OSError, ValueError, UnicodeError) as ex:
        # Debian's ieee-data package may ship a verified offline copy. On a
        # gateway with no outbound HTTP access this is preferable to failure.
        vendors=None
        for local in (Path('/usr/share/ieee-data/oui.csv'), Path('/usr/share/misc/oui.csv')):
            try:
                if local.is_file() and local.stat().st_size <= 24*1024*1024:
                    vendors=parse_oui(local.read_text(encoding='utf-8-sig'))
                    source=str(local)+' (copia locale Debian)'
                    break
            except (OSError,ValueError,UnicodeError):
                continue
        if vendors is None:
            raise ValueError('Download IEEE fallito ('+type(ex).__name__+'): nessuna copia locale valida. Nessun database esistente modificato.') from ex
    DATA.mkdir(mode=0o700,parents=True,exist_ok=True)
    fd,tmp=tempfile.mkstemp(prefix='.oui-',dir=str(DATA))
    try:
        with os.fdopen(fd,'w',encoding='utf-8') as out:
            for k,v in sorted(vendors.items()): out.write(f'{k}\t{v}\n')
            out.flush();os.fsync(out.fileno())
        os.chmod(tmp,0o600);os.replace(tmp,OUI_PATH)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)
    return {'ok':True,'updated':len(vendors),'source':source,'privacy':'nessun MAC inviato al servizio'}


# Vendor suggestions are hints, never privileged policy decisions.
# Local IEEE OUI data stays offline; randomized MACs are never auto-classified.
IOT_VENDOR_HINTS = ('espressif','tuya','xiaomi','philips lighting','signify','sonoff',
    'shelly','allterco','belkin','wemo','ring','wyze','yeelight','netatmo',
    'lifx','broadlink','foscam','hikvision','dahua','ezviz','govee','meross',
    'inkbird','switchbot','aqara','lumi united','sengled','shenzhen')

def vendor_iot_hint(vendor, locally_administered=False):
    if locally_administered or not isinstance(vendor,str): return False
    name=vendor.casefold()
    # Broad labels (e.g. Google, Amazon, Shenzhen) are deliberately not hard denies.
    return any(fragment in name for fragment in IOT_VENDOR_HINTS if fragment != 'shenzhen')

def oui_lookup():
    """Load the vendor database once per process and cap memory on slow DietPi."""
    result={}
    try:
        if OUI_PATH.is_symlink(): return result
        with OUI_PATH.open('r',encoding='utf-8',errors='replace') as source:
            for idx,line in enumerate(source):
                if idx>=80000:break
                prefix,sep,name=line.rstrip('\n').partition('\t')
                if sep and re.fullmatch(r'[A-F0-9]{6}',prefix) and name:
                    result[prefix]=name[:140]
    except (OSError,UnicodeError): pass
    return result


def mac_inventory():
    vendors=oui_lookup()
    found={}
    def add(ip,mac,iface):
        mac=mac.lower().replace('-',':')
        if not MAC_RE.fullmatch(mac) or mac=='00:00:00:00:00:00' or mac=='ff:ff:ff:ff:ff:ff':return
        if int(mac[:2],16)&1:return # multicast is not a client
        entry=found.setdefault(mac,{'mac':mac,'addresses':[],'interfaces':[],'vendor':vendors.get(mac.replace(':','').upper()[:6],'sconosciuto'),
                                    'locally_administered':bool(int(mac[:2],16)&2),'classification':'da verificare'})
        if ip not in entry['addresses']:entry['addresses'].append(ip)
        if iface not in entry['interfaces']:entry['interfaces'].append(iface)
    try:
        for ln in Path('/proc/net/arp').read_text().splitlines()[1:]:
            parts=ln.split()
            if len(parts)>=6:add(parts[0],parts[3],parts[5])
    except OSError:pass
    if shutil.which('ip'):
        for family in ('-4','-6'):
            r=shell(['ip',family,'neigh','show'],3, 65536)
            for ln in r['summary'].splitlines():
                m=re.search(r'^(\S+)\s+dev\s+(\S+).*?\blladdr\s+([0-9a-fA-F:]{17})',ln)
                if m:add(m[1],m[3],m[2])
    for entry in found.values():
        entry['iot_vendor_hint']=vendor_iot_hint(entry['vendor'],entry['locally_administered'])
    return {'ok':True,'mode':'read-only','devices':sorted(found.values(),key=lambda a:a['mac']),
            'database_entries':len(vendors),'privacy':'OUI consultato offline; classificazione IoT non automatica. MAC randomizzati e spoofing non riconoscibili.'}


RFC1918 = tuple(ipaddress.IPv4Network(n) for n in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'))

def ipv4_net(v, *, zone=True):
    obj=ipaddress.ip_network(v, strict=True)
    if obj.version!=4 or not any(obj.subnet_of(allowed) for allowed in RFC1918):
        raise ValueError('solo subnet RFC1918 sono permesse')
    if zone and not (16 <= obj.prefixlen <= 30):
        raise ValueError('subnet VLAN IPv4 RFC1918 /16…/30 richiesta')
    return obj


def ipv6_zone_net(value):
    net = ipaddress.ip_network(value, strict=True)
    if net.version != 6 or not 48 <= net.prefixlen <= 80 or not (net.subnet_of(ipaddress.IPv6Network('fc00::/7')) or (net.network_address.is_global and net.broadcast_address.is_global)):
        raise ValueError('subnet IPv6 /48…/80 ULA o global unicast richiesta')
    if net.overlaps(ipaddress.IPv6Network('fe80::/10')) or net.overlaps(ipaddress.IPv6Network('ff00::/8')):
        raise ValueError('prefisso IPv6 link-local/multicast non utilizzabile')
    return net


def parse_block_nets(text, family, max_items=40):
    tokens = [v.strip() for v in re.split(r'[,\s;]+', str(text)) if v.strip()]
    if len(tokens) > max_items:
        raise ValueError('troppi intervalli DNS/VPN da bloccare')
    values = []
    for v in tokens:
        net = ipaddress.ip_network(v, strict=False)
        if net.version != family or net.is_multicast or net.is_loopback or net.is_unspecified or net.is_link_local:
            raise ValueError('endpoint di blocco non valido per IPv'+str(family))
        if net.prefixlen < (24 if family == 4 else 48):
            raise ValueError('intervallo troppo ampio per il blocco DNS/VPN')
        values.append(net)
    return list(dict.fromkeys(values))


def ipv6_zone_rules(iface, mode, dns, trusted, block_quic, strict_egress, deny_nets, zone_net=None, wan_if=None):
    """Rules for filter table, inserted ahead of all existing ACCEPT rules in a separate IPv6 draft."""
    if mode not in ('block', 'route'):
        raise ValueError('selezionare blocco IPv6 oppure instradamento con DNS IPv6 locale')
    result=[]
    def a(chain, tail): result.append(f'-A IPTM6-IOT-{chain} {tail}')
    # All packets entering the VLAN are filtered, regardless of spoofed source prefix.
    # INPUT chain intentionally preserves essential ND/RA solicitation, errors and DHCPv6.
    for typ in (1,2,3,4,133,135,136):
        a('IN', f'-p ipv6-icmp --icmpv6-type {typ} -j ACCEPT')
    a('IN', '-p udp --sport 546 --dport 547 -j ACCEPT')
    if mode == 'route':
        for proto in ('udp','tcp'):
            a('IN', f'-d {dns} -p {proto} --dport 53 -j ACCEPT')
    a('IN', '-j REJECT --reject-with icmp6-adm-prohibited')
    # Never short-circuit egress restrictions with ESTABLISHED. An existing
    # VPN/DoH session must not bypass deny-lists or strict egress after apply.
    if mode == 'block':
        a('FWD','-j REJECT --reject-with icmp6-adm-prohibited')
    else:
        if zone_net is None: raise ValueError('prefisso IoT IPv6 richiesto per bloccare lo spoofing')
        a('FWD', f'! -s {zone_net} -j REJECT --reject-with icmp6-adm-prohibited')
        for proto in ('udp','tcp'):
            a('FWD', f'-d {dns} -p {proto} --dport 53 -j ACCEPT')
        # Prevent direct plaintext IPv6 DNS outside the on-LAN resolver.
        for proto in ('udp','tcp'):
            a('FWD', f'-p {proto} --dport 53 -j REJECT --reject-with icmp6-adm-prohibited')
        for net in trusted:
            a('FWD', f'-d {net} -j REJECT --reject-with icmp6-adm-prohibited')
        a('FWD', '-d fc00::/7 -j REJECT --reject-with icmp6-adm-prohibited')
        a('FWD', '-d fe80::/10 -j REJECT --reject-with icmp6-adm-prohibited')
        for net in deny_nets:
            a('FWD', f'-d {net} -j REJECT --reject-with icmp6-adm-prohibited')
        for proto in ('tcp','udp'):
            a('FWD', f'-p {proto} --dport 853 -j REJECT --reject-with icmp6-adm-prohibited')
        for port in (500,4500,1194,1701,51820):
            a('FWD', f'-p udp --dport {port} -j REJECT --reject-with icmp6-adm-prohibited')
        for port in (1194,1723):
            a('FWD', f'-p tcp --dport {port} -j REJECT --reject-with icmp6-adm-prohibited')
        for proto in (4,41,47,50,51):
            a('FWD', f'-p {proto} -j REJECT --reject-with icmp6-adm-prohibited')
        if block_quic:
            a('FWD', '-p udp --dport 443 -j REJECT --reject-with icmp6-adm-prohibited')
        # Inter-zone deny: even public-address services on internal interfaces
        # cannot be reached from IoT, unless they are the chosen DNS resolver.
        if wan_if:
            a('FWD', f'! -o {wan_if} -j REJECT --reject-with icmp6-adm-prohibited')
        if strict_egress:
            for port in (80,443): a('FWD', f'-p tcp --dport {port} -j ACCEPT')
            # Many IoT devices need NTP; do not enable by default here.
            a('FWD', '-j REJECT --reject-with icmp6-adm-prohibited')
        else:
            a('FWD','-j ACCEPT')
    return result


def zone_runtime_readiness(iface, net, dns, wan_if='', *, net_root=Path('/sys/class/net'), forward_file=Path('/proc/sys/net/ipv4/ip_forward')):
    """Read-only checks, not a proof of isolation. No network configuration changes."""
    checks=[]
    def check(name,status,detail):checks.append({'name':name,'status':status,'detail':detail})
    if wan_if and not (net_root / wan_if).exists():
        check('Uscita WAN','blocked',f'{wan_if} non presente: le regole e il NAT non potranno instradare Internet')
    network_path=net_root / iface
    if not network_path.exists():
        check('Interfaccia IoT','blocked',f'{iface} non presente: creare/configurare la VLAN o rete separata prima di applicare')
    else:
        check('Interfaccia IoT','ok',f'{iface} presente nel kernel; isolamento L2 non verificato')
        # An interface name alone proves neither a tagged VLAN nor switch/AP isolation.
        if not (network_path/'uevent').exists():
            check('Tipo rete','warning','Tipo di interfaccia non verificabile; controllare switch/AP, bridge e subnet')
        else:
            details=(network_path/'uevent').read_text(errors='replace')[:1500]
            if 'DEVTYPE=vlan' in details:
                check('Tipo rete','ok','Interfaccia VLAN presente; verificare che AP/switch instradino qui i dispositivi')
            else:
                check('Tipo rete','warning','Interfaccia non confermata come VLAN: controllare L2, bridge e AP')
    try:
        fwd=forward_file.read_text().strip()
        check('Forwarding IPv4','ok' if fwd=='1' else 'blocked',
              'Abilitato' if fwd=='1' else 'Disabilitato o inatteso: i dispositivi non raggiungeranno Internet tramite DietPi')
    except OSError:
        check('Forwarding IPv4','warning','Non verificabile sul sistema')
    if shutil.which('ip'):
        result=shell(['ip','-4','route','get',str(dns)],3,350)
        if result['status']==0:
            parts=result['summary'].splitlines()[0]
            m=re.search(r'(?:^|\s)dev\s+([^\s]+)',parts)
            if m and m[1]==iface:
                check('Percorso DNS','blocked','Il DNS locale risulta raggiunto tramite la stessa interfaccia IoT; verificare routing/indirizzamento')
            else:
                check('Percorso DNS','ok','Route IPv4 verso il DNS presente; il servizio DNS non è stato interrogato')
        else:
            check('Percorso DNS','blocked','Nessuna route confermata verso il DNS locale: non applicare la policy')
    else:
        check('Percorso DNS','blocked','Comando ip non disponibile: impossibile verificare il resolver locale')
    check('Isolamento layer 2','manual','Richiede rete guest/VLAN isolata sull’access point o switch; iptables non filtra traffico tra client nello stesso segmento')
    return checks



# Managed Linux VLAN: explicit opt-in, no direct edits to parent links or firewall.
# This is a runtime device, not a substitute for VLAN tagging/client isolation on AP/switch.
IOT_VLAN_DIR = Path('/var/lib/iptm/iot-network')
IOT_VLAN_RECORD = IOT_VLAN_DIR / 'managed-vlan.json'


def _vlan_state():
    if IOT_VLAN_RECORD.is_symlink():
        raise ValueError('record VLAN non sicuro')
    return read_json(IOT_VLAN_RECORD)


def _vlan_cmd(argv):
    result=subprocess.run(['ip'] + argv, capture_output=True, text=True,
                          timeout=6, stdin=subprocess.DEVNULL)
    if result.returncode:
        raise ValueError('configurazione VLAN non riuscita: ip ' + argv[0] + ' ' + argv[1])
    return result.stdout


def vlan_manage(data):
    """Create only a *new* 802.1Q subinterface with a dedicated RFC1918 gateway.

    Never change the parent interface, a default route, kernel forwarding,
    DNS, or firewall. An explicit root-only opt-in is required. No persistence.
    """
    if not isinstance(data,dict): raise ValueError('richiesta VLAN non valida')
    op=str(data.get('mode') or 'status')
    if op not in ('status','create','delete'): raise ValueError('azione VLAN non valida')
    if op=='status':
        state=_vlan_state()
        if not state: return {'ok':True,'managed':False,'status':'not-created'}
        name=state.get('iface','')
        exists=(Path('/sys/class/net') / name).exists() if IF_RE.fullmatch(name) else False
        verified=False
        if exists:
            found=shell(['ip','-d','-j','link','show','dev',name],3,4000)
            if found['status']==0:
                try:
                    parsed=json.loads(found['summary'])
                    verified=(parsed[0]['linkinfo']['info_kind']=='vlan' and
                              parsed[0]['linkinfo']['info_data']['id']==state.get('vlan_id'))
                except (ValueError,KeyError,TypeError,IndexError): pass
        return {'ok':True,'managed':True,'present':verified,
                'status':('up' if verified else 'mismatch' if exists else 'absent'),
                'iface':name,'parent':state.get('parent',''), 'network':state.get('network',''),
                'gateway':state.get('gateway',''), 'vlan_id':state.get('vlan_id',0),
                'persistent':False,
                'note':'VLAN Linux temporanea. Dopo riavvio la configurazione va ripristinata. Isolamento L2 sullo switch/AP obbligatorio.'}
    if os.geteuid()!=0: raise ValueError('richiesti privilegi root')
    if not shutil.which('ip'): raise ValueError('iproute2 non disponibile')
    IOT_VLAN_DIR.mkdir(parents=True,exist_ok=True,mode=0o700)
    dstat=IOT_VLAN_DIR.lstat()
    if IOT_VLAN_DIR.is_symlink() or not stat.S_ISDIR(dstat.st_mode) or dstat.st_uid!=0 or dstat.st_mode & 0o022:
        raise ValueError('directory di gestione VLAN non sicura: richiesto owner root e permessi non scrivibili dal gruppo/altri')
    lock=IOT_VLAN_DIR/'iot-vlan.lock'
    if lock.is_symlink(): raise ValueError('lock VLAN non sicuro')
    with lock.open('a+b') as fp:
        try: fcntl.flock(fp,fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError: raise ValueError('altra operazione VLAN in corso')
        state=_vlan_state()
        if op=='delete':
            if data.get('confirm')!='RIMUOVI VLAN IOT':raise ValueError('conferma eliminazione non valida')
            if not state:raise ValueError('nessuna VLAN gestita da IPTM')
            name=state['iface']
            # Fail closed: the interface may now host live policy or management.
            for family in ('iptables-save','ip6tables-save'):
                rules=shell([family],4,120000)
                if (rules['status']!=0 or len(rules['summary'])>=120000 or
                    re.search(r'(?<![A-Za-z0-9_.-])'+re.escape(name)+r'(?![A-Za-z0-9_.-])', rules['summary'])):
                    raise ValueError('VLAN referenziata dal firewall o controllo '+family+' non affidabile: rimuovere prima la policy con rollback')
            for saved in (Path('/etc/iptables/rules.v4'),Path('/etc/iptables/rules.v6')):
                if saved.exists():
                    if saved.is_symlink() or saved.stat().st_size > 2*1024*1024:
                        raise ValueError('file regole salvate non verificabile: rimozione VLAN rifiutata')
                    if re.search(r'(?<![A-Za-z0-9_.-])'+re.escape(name)+r'(?![A-Za-z0-9_.-])',
                                 saved.read_text(errors='replace')):
                        raise ValueError('VLAN ancora presente nelle regole salvate: rimuovere prima la policy')
            # Never delete a manually repurposed interface with the same name.
            if (Path('/sys/class/net') / name).exists():
                kind=shell(['ip','-d','-j','link','show','dev',name],3,4000)
                if kind['status']!=0: raise ValueError('impossibile verificare tipo VLAN')
                try:
                    details=json.loads(kind['summary'])
                    vlan_id=details[0]['linkinfo']['info_data']['id']
                    vlan_kind=details[0]['linkinfo']['info_kind']
                except (IndexError,KeyError,TypeError,ValueError):
                    raise ValueError('interfaccia non verificabile come VLAN IPTM')
                if vlan_kind!='vlan' or vlan_id!=state.get('vlan_id'):
                    raise ValueError('interfaccia non più corrispondente alla VLAN IPTM')
            admin=str(data.get('admin_ip') or '').strip()
            if admin:
                route=shell(['ip','route','get',admin],3,1000)
                if route['status']!=0 or re.search(r'\bdev\s+'+re.escape(name)+r'\b',route['summary']):
                    raise ValueError('possibile connessione amministrativa sulla VLAN: operazione rifiutata')
            if (Path('/sys/class/net') / name).exists():
                _vlan_cmd(['link','delete','dev',name])
            IOT_VLAN_RECORD.unlink()
            return {'ok':True,'mode':'removed','iface':name,'note':'Nessuna regola firewall è stata modificata'}
        if data.get('confirm')!='CREA VLAN IOT':raise ValueError('conferma creazione non valida')
        # A runtime-only VLAN disappears after reboot. Permit safe re-creation
        # of the *exact* managed configuration when the interface is absent.
        if state and (Path('/sys/class/net') / str(state.get('iface',''))).exists():
            raise ValueError('VLAN IPTM già attiva: non modifico la rete in uso')
        parent=str(data.get('parent') or '').strip()
        vid=str(data.get('vlan_id') or '')
        if not IF_RE.fullmatch(parent) or parent=='lo' or not re.fullmatch('[0-9]{1,4}',vid) or not 2<=int(vid)<=4094:
            raise ValueError('parent o VLAN ID non validi')
        name=parent+'.'+vid
        if len(name)>15 or not IF_RE.fullmatch(name):raise ValueError('nome VLAN oltre 15 caratteri')
        if state and any((str(state.get(k,''))!=str(v)) for k,v in (
                ('iface',name),('parent',parent),('vlan_id',int(vid)),
                ('network',str(ipv4_net(str(data.get('network') or '')))),
                ('gateway',str(data.get('gateway') or '')))):
            raise ValueError('configurazione VLAN salvata differente: non sostituisco un profilo esistente')
        if not (Path('/sys/class/net') / parent).exists():raise ValueError('interfaccia parent non presente')
        if (Path('/sys/class/net') / name).exists():raise ValueError('interfaccia VLAN già presente: IPTM non la sovrascrive')
        network=ipv4_net(str(data.get('network') or ''))
        gateway=ipaddress.ip_address(str(data.get('gateway') or ''))
        if gateway.version!=4 or gateway not in network or gateway in (network.network_address,network.broadcast_address):
            raise ValueError('gateway IPv4 deve essere un host della subnet IoT')
        admin=str(data.get('admin_ip') or '').strip()
        if admin:
            try:
                if ipaddress.ip_address(admin) in network:
                    raise ValueError('connessione amministrativa dentro la nuova VLAN: non procedere')
            except ValueError as exc:
                if 'amministrativa' in str(exc): raise
                raise ValueError('indirizzo amministrativo non valido')
        # Refuse overlapping connected subnets, including bridges and Docker.
        raw=_vlan_cmd(['-j','-4','addr','show'])
        try: info=json.loads(raw)
        except ValueError:raise ValueError('impossibile leggere indirizzi IPv4 per il preflight')
        if not isinstance(info,list):raise ValueError('informazioni interfacce non valide')
        for nic in info:
            for address in nic.get('addr_info',[]):
                try:
                    if address.get('family')=='inet':
                        current=ipaddress.ip_network(str(address['local'])+'/'+str(address['prefixlen']),strict=False)
                        if current.overlaps(network):
                            raise ValueError('subnet IoT sovrapposta a '+str(nic.get('ifname','altra interfaccia')))
                except KeyError: raise ValueError('inventario IPv4 incompleto')
        # An overlapping static route would be hijacked by the connected VLAN route.
        raw_routes=_vlan_cmd(['-j','-4','route','show','table','main'])
        try: routes=json.loads(raw_routes)
        except ValueError: raise ValueError('impossibile verificare route IPv4 prima della VLAN')
        if not isinstance(routes,list): raise ValueError('inventario route IPv4 inatteso')
        for route in routes:
            destination=route.get('dst','default')
            if destination=='default':continue
            try: routed=ipaddress.ip_network(destination,strict=False)
            except ValueError:raise ValueError('route IPv4 non valida nel preflight')
            if routed.version==4 and routed.overlaps(network):
                raise ValueError('subnet IoT sovrapposta a una route esistente ('+str(destination)+')')
        created=False
        try:
            _vlan_cmd(['link','add','link',parent,'name',name,'type','vlan','id',vid]);created=True
            _vlan_cmd(['addr','add',str(gateway)+'/'+str(network.prefixlen),'dev',name])
            _vlan_cmd(['link','set','dev',name,'up'])
            _vlan_cmd(['-d','link','show','dev',name])
            record={'format':'iptm.managed-vlan.v1','iface':name,'parent':parent,'vlan_id':int(vid),
                    'network':str(network),'gateway':str(gateway)}
            fd,tmp=tempfile.mkstemp(dir=str(IOT_VLAN_DIR),prefix='.iot-vlan-',text=True)
            try:
                with os.fdopen(fd,'w') as f:
                    json.dump(record,f);f.flush();os.fsync(f.fileno())
                os.chmod(tmp,0o600)
                os.replace(tmp,IOT_VLAN_RECORD)
            finally:
                if os.path.exists(tmp):os.unlink(tmp)
            return {'ok':True,'mode':'created','iface':name,'network':str(network),'gateway':str(gateway),
                    'persistent':False,'note':'VLAN creata solo nel runtime Linux. Configurare tagging sullo switch/AP e applicare la policy tramite il watchdog. Nessun forwarding/DNS/firewall cambiato.'}
        except Exception:
            if created:
                try:_vlan_cmd(['link','delete','dev',name])
                except Exception:pass
            raise

def zone_plan(data):
    """Generate a *draft* only; never alter running iptables or L2/VLAN state."""
    if not isinstance(data,dict):raise ValueError('piano non valido')
    iface=str(data.get('iface') or ''); wan=str(data.get('wan_if') or '')
    if not IF_RE.fullmatch(iface) or iface=='lo' or not IF_RE.fullmatch(wan) or iface==wan:
        raise ValueError('Seleziona prima la WAN; interfaccia IoT non valida o uguale alla WAN')
    net=ipv4_net(str(data.get('network') or ''))
    local_nets=[]
    for v in str(data.get('trusted_nets') or '').replace(' ','').split(','):
        if v:
            n=ipv4_net(v,zone=False)
            if n.overlaps(net):raise ValueError('la subnet IoT non può sovrapporsi a una subnet fidata')
            local_nets.append(n)
    if not local_nets:raise ValueError('imposta prima la subnet LAN fidata')
    admin=str(data.get('admin_ip') or '').strip()
    if admin:
        try:
            if ipaddress.ip_address(admin) in net:raise ValueError('la connessione amministrativa attuale è nella zona da isolare')
        except ValueError as ex:
            if 'amministrativa' in str(ex):raise
            raise ValueError('IP amministrativo non valido')
    dns=str(data.get('dns_ip') or '')
    try:dn=ipaddress.ip_address(dns)
    except ValueError:raise ValueError('DNS locale IPv4 valido obbligatorio')
    if dn.version!=4 or dn.is_multicast or dn.is_unspecified or dn in net:
        raise ValueError('DNS locale fuori dalla VLAN IoT richiesto')
    if not any(dn in n for n in local_nets):
        raise ValueError('DNS locale deve appartenere alla rete LAN fidata')
    if any(dn in (n.network_address,n.broadcast_address) for n in local_nets if dn in n):
        raise ValueError('DNS locale non può essere indirizzo di rete o broadcast')
    ipv6_mode=str(data.get('ipv6_mode') or 'block')
    # A remote admin connected over IPv6 may be inside the VLAN even if we cannot
    # determine its receiving interface. Refuse IPv6 blocking in that case.
    if ipv6_mode == 'block' and admin and ':' in admin:
        raise ValueError('sessione amministrativa IPv6: blocco VLAN IPv6 rifiutato senza accesso IPv4 fidato/console')
    if ipv6_mode not in ('block','route'):
        raise ValueError('scegli esplicitamente blocco IPv6 o routing IPv6 locale')
    strict_egress=bool(data.get('strict_egress'))
    blocked4=parse_block_nets(data.get('blocked_resolvers4',''),4)
    blocked6=parse_block_nets(data.get('blocked_resolvers6',''),6)
    if bool(data.get('block_common_resolvers')):
        # Opt-in public DNS endpoint IPs. This is not a complete DoH blocklist:
        # addresses can change and some IPs host non-DNS services.
        for ip in ('1.1.1.1','1.0.0.1','8.8.8.8','8.8.4.4',
                   '9.9.9.9','149.112.112.112','208.67.222.222','208.67.220.220'):
            blocked4.append(ipaddress.ip_network(ip+'/32'))
        for ip in ('2606:4700:4700::1111','2606:4700:4700::1001',
                   '2001:4860:4860::8888','2001:4860:4860::8844',
                   '2620:fe::fe','2620:fe::9'):
            blocked6.append(ipaddress.ip_network(ip+'/128'))
        blocked4=list(dict.fromkeys(blocked4));blocked6=list(dict.fromkeys(blocked6))
    if any(ipaddress.ip_address(dns) in item for item in blocked4):
        raise ValueError('il DNS locale IPv4 non può essere fra i resolver bloccati')
    dns6=''
    trusted6=[]
    if ipv6_mode=='route':
        ipv6_zone_net(str(data.get('network6') or ''))
        for v in re.split(r'[,\s;]+',str(data.get('trusted_nets6') or '')):
            if v: trusted6.append(ipv6_zone_net(v))
        if not trusted6: raise ValueError('IPv6 instradato richiede almeno una rete IPv6 fidata')
        dn6=ipaddress.ip_address(str(data.get('dns_ip6') or ''))
        if dn6.version!=6 or not any(dn6 in n for n in trusted6):
            raise ValueError('DNS IPv6 locale deve appartenere alla rete IPv6 fidata')
        if any(dn6 in n for n in blocked6):
            raise ValueError('il DNS IPv6 locale non può essere bloccato')
        dns6=str(dn6)
        ipv6net=ipv6_zone_net(str(data.get('network6')))
        if any(ipv6net.overlaps(n) for n in trusted6):
            raise ValueError('subnet IPv6 IoT sovrapposta a prefissi fidati')
        if admin and ':' in admin and ipaddress.ip_address(admin) in ipv6net:
            raise ValueError('amministrazione corrente nella VLAN IPv6 isolata')
    v6rules=ipv6_zone_rules(iface,ipv6_mode,dns6,trusted6,bool(data.get('block_quic')),strict_egress,blocked6,ipv6net if ipv6_mode=='route' else None,wan)
    # INPUT rules only authorize DNS queries; management remains untouched.
    rules=[]
    def rule(t,r):rules.append({'t':t,'r':r})
    for proto in ('udp','tcp'):
        rule('nat',f'-A PREROUTING -i {iface} -s {net} -p {proto} --dport 53 -j DNAT --to-destination {dns}')
        rule('filter',f'-A FORWARD -i {iface} -s {net} -d {dns} -p {proto} --dport 53 -j ACCEPT')
        # Router-hosted DNS also needs INPUT; only port 53, not admin ports.
        rule('filter',f'-A INPUT -i {iface} -s {net} -d {dns} -p {proto} --dport 53 -j ACCEPT')
    # Permit DHCP broadcasts to router if its INPUT policy is restrictive.
    rule('filter',f'-A INPUT -i {iface} -s 0.0.0.0/0 -p udp --sport 68 --dport 67 -j ACCEPT')
    # Stop IoT clients accessing router management services. DNS/DHCP exceptions are above.
    # This may also block router-hosted NTP/other services; the preview explicitly shows it.
    rule('filter',f'-A INPUT -i {iface} -j REJECT')
    # Spoofed source addresses from the IoT interface must not bypass the rules
    # scoped to the declared IoT subnet. Limit by INPUT interface, not just CIDR.
    rule('filter',f'-A FORWARD -i {iface} ! -s {net} -j REJECT')
    # Restrict all private IPv4 ranges, not just the trusted nets entered in UI.
    for n in RFC1918:
        rule('filter',f'-A FORWARD -i {iface} -s {net} -d {n} -j REJECT')
    rule('filter',f'-A FORWARD -o {iface} -d {net} -m conntrack --ctstate NEW -j REJECT')
    for proto in ('tcp','udp'):
        rule('filter',f'-A FORWARD -i {iface} -s {net} -p {proto} --dport 853 -j REJECT')
    # Explicit IPv4 DNS egress restriction; port 53 must reach only the chosen resolver.
    for proto in ('udp','tcp'):
        rule('filter',f'-A FORWARD -i {iface} -s {net} -p {proto} --dport 53 -j REJECT')
    for blocked in blocked4:
        rule('filter',f'-A FORWARD -i {iface} -s {net} -d {blocked} -j REJECT')
    for proto in ('udp','tcp'):
        for port in ((500,4500,1194,51820) if proto=='udp' else (1194,1723)):
            rule('filter',f'-A FORWARD -i {iface} -s {net} -p {proto} --dport {port} -j REJECT')
    for proto in (4,41,47,50,51):
        rule('filter',f'-A FORWARD -i {iface} -s {net} -p {proto} -j REJECT')
    if bool(data.get('block_quic')):
        rule('filter',f'-A FORWARD -i {iface} -s {net} -p udp --dport 443 -j REJECT')
    # Explicit zone-pair rules (Cisco ZBF/PAN-OS model): IoT -> WAN only.
    # Preserve replies while denying new sessions from LAN/WAN into IoT.
    rule('filter',f'-A FORWARD -o {iface} -d {net} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT')
    rule('filter',f'-A FORWARD -o {iface} -d {net} -j REJECT')
    # Other local interfaces are never an IoT egress path; DNS to the trusted
    # resolver was explicitly accepted before this check.
    rule('filter',f'-A FORWARD -i {iface} -s {net} ! -o {wan} -j REJECT')
    if strict_egress:
        for port in (80,443):
            rule('filter',f'-A FORWARD -i {iface} -s {net} -o {wan} -p tcp --dport {port} -j ACCEPT')
    else:
        rule('filter',f'-A FORWARD -i {iface} -s {net} -o {wan} -j ACCEPT')
    # A final deny is essential even if the base firewall's FORWARD policy is ACCEPT.
    rule('filter',f'-A FORWARD -i {iface} -j REJECT')
    # NAT is restricted to the IoT subnet and the designated Internet WAN.
    rule('nat',f'-A POSTROUTING -s {net} -o {wan} -j MASQUERADE')
    readiness=zone_runtime_readiness(iface,net,dn,wan)
    return {'ok':True,'mode':'draft-only','interface':iface,'network':str(net),'dns':str(dn),'ipv6_mode':ipv6_mode,'ipv6_rules':v6rules,
            'readiness':readiness,'ready_to_apply':not any(x['status']=='blocked' for x in readiness),
            'rules':rules, 'caveats':['Richiede VLAN/subnet reali già configurate su switch/AP e gateway; nessuna VLAN creata.',
                'Il modello è zero-trust per coppie di zone: solo IoT → WAN, ritorni conntrack, DNS locale e DHCP. I filtri INPUT/FORWARD, NAT e DNAT richiedono verifica e rollback IPTM.',
                'IPv6 è gestito da una bozza ip6tables separata; entrambe le famiglie devono essere applicate e confermate con i rispettivi watchdog.',
                'DoH e VPN mimetizzate su HTTPS TCP/443 non sono distinguibili senza proxy esplicito o whitelist di destinazioni; nessuna protezione assoluta.',
                'I servizi locali sul router (es. NTP) sono bloccati salvo DNS/DHCP; rivedere la bozza.',
                'Un MAC non prova identità né isola traffico tra client nella stessa VLAN.']}


# MAC-only policy for traffic ROUTED THROUGH DietPi. Layer-2 peer traffic cannot
# be filtered by iptables when endpoints share a Wi-Fi/LAN segment.
IOT_MAC_RE = re.compile(r'(?i)^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$')
IOT_IF_RE = re.compile(r'^[A-Za-z0-9_.:-]{1,15}$')

def mac_policy_plan(data):
    if not isinstance(data,dict): raise ValueError('richiesta non valida')
    lan=str(data.get('lan_if','')).strip()
    wan=str(data.get('wan_if','')).strip()
    if not IOT_IF_RE.fullmatch(lan) or not IOT_IF_RE.fullmatch(wan) or lan=='lo' or wan=='lo':
        raise ValueError('interfaccia LAN/WAN non valida')
    local_dns=ipaddress.ip_address(str(data.get('dns_ip','')).strip())
    if local_dns.version!=4 or local_dns.is_loopback or local_dns.is_multicast:
        raise ValueError('Pi-hole deve avere un indirizzo IPv4 LAN')
    admin=str(data.get('admin_ip','')).strip()
    if admin:
        ipaddress.ip_address(admin)
    selected=data.get('macs')
    if not isinstance(selected,list) or not 1<=len(selected)<=32:
        raise ValueError('selezionare da 1 a 32 dispositivi identificati')
    inv=mac_inventory()
    bymac={d['mac']:d for d in inv['devices']}
    macs=[]; source_ips={}; warnings=[]
    for raw in selected:
        if not isinstance(raw,str) or not IOT_MAC_RE.fullmatch(raw):
            raise ValueError('MAC non valido')
        mac=raw.lower()
        if mac in macs: raise ValueError('MAC duplicato')
        item=bymac.get(mac)
        if not item: raise ValueError(f'MAC non presente nell’inventario corrente: {mac}')
        if lan not in item['interfaces']: raise ValueError(f'MAC non rilevato sulla LAN indicata: {mac}')
        if admin and admin in item['addresses']:
            raise ValueError('il dispositivo amministrativo attuale non può essere isolato')
        ipv4=[]
        for address in item['addresses']:
            try: ip=ipaddress.ip_address(address)
            except ValueError: continue
            if ip.version==4 and ip.is_private and not ip.is_link_local and not ip.is_loopback:
                ipv4.append(str(ip))
        ipv4=list(dict.fromkeys(ipv4))
        if not ipv4: raise ValueError(f'nessun indirizzo IPv4 privato verificato per {mac}')
        if len(ipv4)>4: raise ValueError(f'troppi IP per un dispositivo: {mac}')
        macs.append(mac); source_ips[mac]=ipv4
        if item.get('locally_administered'):
            warnings.append(f'{mac}: MAC randomizzato, riconoscimento non affidabile')
    if len({ip for ips in source_ips.values() for ip in ips}) != sum(map(len, source_ips.values())):
        raise ValueError('conflitto IPv4 fra MAC selezionati: correggere inventario DHCP/ARP')
    # No deployment if DNS isn't a local address: NAT hairpin would require
    # additional SNAT and a proof that replies return through this gateway.
    local_addrs=set()
    if shutil.which('ip'):
        r=shell(['ip','-o','-4','addr','show'],3,32768)
        for addr in re.findall(r'\binet (\d+\.\d+\.\d+\.\d+)/\d+',r['summary']):
            local_addrs.add(addr)
    checks=[]
    def ck(name,state,detail): checks.append({'name':name,'status':state,'detail':detail})
    for iface,label in ((lan,'LAN'),(wan,'WAN')):
        ck('Interfaccia '+label,'ok' if (Path('/sys/class/net')/iface).exists() else 'blocked',iface)
    ck('DNS sul DietPi','ok' if str(local_dns) in local_addrs else 'blocked',
       'DNS host locale; reindirizzamento possibile' if str(local_dns) in local_addrs else
       'DNS non confermato sul DietPi: hairpin/routing non verificato; non attivare')
    try: enabled=Path('/proc/sys/net/ipv4/ip_forward').read_text().strip()=='1'
    except OSError: enabled=False
    ck('Forwarding IPv4','ok' if enabled else 'blocked','Necessario per IoT → Internet')
    ck('Isolamento client L2','manual','LAN condivisa: traffico diretto tra client e IPv6 locale non attraversano DietPi')
    rules=[]; v6=[]
    def add(table,line):rules.append({'t':table,'r':line})
    # Shared chains avoid O(N * policy-rules) duplication on slow CPUs.
    # Parent-chain jumps carry the per-device MAC match. Chains are created by
    # IPTM's own draft compiler, not by direct iptables mutations.
    for proto in ('udp','tcp'):
        add('filter',f'-A IPTM-MAC-IN -d {local_dns} -p {proto} --dport 53 -j ACCEPT')
        add('filter',f'-A IPTM-MAC-FWD -d {local_dns} -p {proto} --dport 53 -j ACCEPT')
    add('filter','-A IPTM-MAC-IN -p udp --sport 68 --dport 67 -j ACCEPT')
    add('filter','-A IPTM-MAC-IN -j REJECT')
    for net in tuple(RFC1918) + tuple(ipaddress.IPv4Network(n) for n in ('169.254.0.0/16','127.0.0.0/8','0.0.0.0/8','100.64.0.0/10','224.0.0.0/4','240.0.0.0/4')):
        add('filter',f'-A IPTM-MAC-FWD -d {net} -j REJECT')
    for proto in ('udp','tcp'):
        for port in (53,853):add('filter',f'-A IPTM-MAC-FWD -p {proto} --dport {port} -j REJECT')
    for proto,ports in (('udp',(500,4500,1194,51820)),('tcp',(1194,1723))):
        for port in ports:add('filter',f'-A IPTM-MAC-FWD -p {proto} --dport {port} -j REJECT')
    if data.get('block_quic',False):
        add('filter','-A IPTM-MAC-FWD -p udp --dport 443 -j REJECT')
    if data.get('strict_egress',False):
        for port in (80,443):
            add('filter',f'-A IPTM-MAC-FWD -o {wan} -p tcp --dport {port} -j ACCEPT')
        add('filter',f'-A IPTM-MAC-FWD -o {wan} -p udp --dport 123 -j ACCEPT')
    else:
        add('filter',f'-A IPTM-MAC-FWD -o {wan} -j ACCEPT')
    add('filter','-A IPTM-MAC-FWD -j REJECT')
    for mac in macs:
        match=f'-i {lan} -m mac --mac-source {mac}'
        for proto in ('udp','tcp'):
            add('nat',f'-A PREROUTING {match} -p {proto} --dport 53 -j DNAT --to-destination {local_dns}')
        add('filter',f'-A INPUT {match} -j IPTM-MAC-IN')
        add('filter',f'-A FORWARD {match} -j IPTM-MAC-FWD')
        for ip in source_ips[mac]:
            add('nat',f'-A POSTROUTING -s {ip}/32 -o {wan} -j MASQUERADE')
        for typ in (133,135,136):
            v6.append(f'-A INPUT {match} -p ipv6-icmp --icmpv6-type {typ} -j ACCEPT')
        v6.append(f'-A INPUT {match} -j REJECT')
        v6.append(f'-A FORWARD {match} -j REJECT')
    if len(rules)>450: raise ValueError('policy oltre limite regole; dividere il gruppo')
    return {'ok':True,'mode':'draft-only','policy':'mac-only','rules':rules,'ipv6_rules':v6,
       'macs':macs,'source_ips':source_ips,'lan_if':lan,'wan_if':wan,'dns':str(local_dns),
       'readiness':checks,'ready_to_stage':not any(x['status']=='blocked' for x in checks),
       'warnings':warnings,'caveats':[
        'Non è una VLAN. Su Wi-Fi/LAN condivisa il traffico locale L2 tra dispositivi può bypassare il firewall.',
        'Solo le connessioni che attraversano DietPi possono subire DNAT DNS, NAT Internet e filtri per MAC.',
        'Il MAC può essere falsificato; OUI identifica solo il costruttore, non dimostra che un dispositivo sia IoT.',
        'DoH su TCP 443 e VPN occultate non possono essere bloccati universalmente con iptables.',
        'Le regole vengono solo preparate in bozza; devono essere applicate con rollback e confermate separatamente per IPv4/IPv6.'
       ]}

def mac_policy_input():
    raw=sys.stdin.read(16385)
    if len(raw)>16384: raise ValueError('richiesta MAC policy troppo grande')
    return mac_policy_plan(json.loads(raw))

# Lynis is an advisory scanner. Never translate its free-form report into shell
# commands. Interactive recommendations use this closed, reviewed catalog.
LYNIS_GUIDANCE = {
 'BOOT-5122': ('Avvio', 'Protezione GRUB', 'Proteggi il bootloader se il computer è fisicamente accessibile. Verifica prima l’accesso di recupero.', 'manuale', '?p=health'),
 'BOOT-5180': ('Avvio', 'Servizi al boot', 'Verifica i servizi abilitati e quelli realmente necessari.', 'verifica', '?p=postcheck'),
 'BOOT-5264': ('Servizi', 'Hardening dei servizi systemd', 'Esamina separatamente systemd-analyze security per i servizi, senza applicare impostazioni generiche.', 'verifica', '?p=postcheck'),
 'KRNL-5788': ('Kernel', 'Percorso kernel /vmlinuz', 'Su DietPi/Debian controlla il layout di /boot e il pacchetto kernel prima di modificare i link.', 'manuale', '?p=health'),
 'AUTH-9262': ('Accessi', 'Qualità delle password', 'Valuta un modulo PAM compatibile con Debian e prova una sessione alternativa prima di renderlo obbligatorio.', 'manuale', '?p=progs'),
 'AUTH-9282': ('Accessi', 'Scadenza account', 'Controlla gli utenti interattivi e configura scadenze caso per caso, senza bloccare l’account amministrativo.', 'manuale', '?p=admin'),
 'AUTH-9328': ('Accessi', 'Umask predefinita', 'Valuta umask 027 dopo aver verificato servizi e directory condivise. Non applicare globalmente senza collaudo.', 'manuale', '?p=health'),
 'FILE-6310': ('Filesystem', 'Separazione partizioni', 'Valuta backup, spazio e partizionamento. Richiede pianificazione fuori dalla UI, non è un fix immediato.', 'manuale', '?p=health'),
 'USB-1000': ('Dispositivi', 'Storage USB', 'Disabilita i driver soltanto dopo avere verificato che avvio, backup e recupero non li utilizzino.', 'manuale', '?p=health'),
 'NAME-4028': ('DNS', 'Nome dominio DNS', 'Verifica risoluzione, dominio locale e catena Pi-hole → Unbound → DNSCrypt.', 'verifica', '?p=dnsguard'),
 'PKGS-7346': ('Pacchetti', 'Configurazioni residue', 'Verifica la lista dei pacchetti rimossi prima di eliminare configurazioni con apt/dpkg.', 'verifica', '?p=progs'),
 'PKGS-7370': ('Pacchetti', 'Verifica integrità debsums', 'Valuta installazione e controllo periodico di debsums; non aggiornare pacchetti automaticamente.', 'verifica', '?p=progs'),
 'PKGS-7388': ('Pacchetti', 'Repository di sicurezza Debian', 'Controlla anche i file .sources (deb822) e apt-cache policy prima di modificare i repository.', 'verifica', '?p=progs'),
}
_LYNIS_ID_RE = re.compile(r'^[A-Z]{2,6}-[0-9]{4,5}$')
_LYNIS_RUN_RE = re.compile(r'^[0-9a-f]{16}$')


def lynis_audit_dir(run_id):
    if not isinstance(run_id,str) or not _LYNIS_RUN_RE.fullmatch(run_id):
        raise ValueError('Identificatore audit non valido')
    return DATA/'lynis-audits'/run_id


def lynis_job_write(payload):
    DATA.mkdir(mode=0o700,parents=True,exist_ok=True)
    tmp=DATA/('lynis-job.%d.tmp'%os.getpid())
    with tmp.open('w',encoding='utf-8') as stream:
        os.fchmod(stream.fileno(),0o600)
        json.dump(payload,stream,sort_keys=True)
        stream.flush();os.fsync(stream.fileno())
    os.replace(tmp,DATA/'lynis-job.json')


def lynis_job_state():
    state=read_json(DATA/'lynis-job.json')
    if not state:return {'ok':True,'state':'idle'}
    value=state.get('state','unknown');pid=state.get('pid')
    if value=='running' and isinstance(pid,int) and pid>1:
        # Avoid PID reuse: only the exact root worker command is accepted.
        try:
            proc_cmd=(Path('/proc')/str(pid)/'cmdline').read_bytes()[:1024]
            alive=(b'iptm-security.py' in proc_cmd and b'lynis-worker' in proc_cmd)
        except (OSError,PermissionError):
            alive=False
        if not alive:
            value='interrupted'
    elapsed=max(0,int(time.time())-int(state.get('started') or time.time()))
    result={'ok':True,'state':value,'run_id':state.get('run_id',''),
            'started':state.get('started'),'finished':state.get('finished'),
            'exit_code':state.get('exit_code'),'summary':str(state.get('summary',''))[:280],
            'report_found':bool(state.get('report_found',False)),
            'suggestions_count':int(state.get('suggestions_count') or 0),
            'elapsed_seconds':elapsed if value=='running' else max(0,int(state.get('finished') or time.time())-int(state.get('started') or time.time()))}
    if value=='running' and _LYNIS_RUN_RE.fullmatch(str(state.get('run_id',''))):
        run=lynis_audit_dir(state['run_id'])
        for k,n in [('activity','stdout.log'),('detail','lynis.log')]:
            try:result[k+'_updated']=int((run/n).stat().st_mtime)
            except OSError:pass
    return result


def lynis_suggestions():
    status=lynis_job_state();run_id=status.get('run_id','')
    complete=status['state'] in ('done','done_warnings')
    report=lynis_audit_dir(run_id)/'report.dat' if complete and _LYNIS_RUN_RE.fullmatch(run_id) else None
    # Never silently display a global, potentially stale Lynis report as the new audit.
    findings=[];metadata={}
    if report and report.is_file() and not report.is_symlink() and report.stat().st_size<=4*1024*1024:
        lines=report.read_text(encoding='utf-8',errors='replace').splitlines()
        reviews=read_json(lynis_audit_dir(run_id)/'reviews.json')
        for line in lines:
            if line.startswith(('hardening_index=','lynis_version=')):
                key,val=line.split('=',1);metadata[key]=val[:80]
            if not line.startswith(('suggestion[]=','warning[]=')):continue
            kind,raw=line.split('=',1);kind=kind.replace('[]','')
            pieces=raw.split('|',4);key=pieces[0].strip()
            if not _LYNIS_ID_RE.fullmatch(key):continue
            group,title,instructions,level,link=LYNIS_GUIDANCE.get(key,('Altro','Verifica '+key,'Esamina i dettagli e il log della scansione prima di modificare il sistema.','manuale','?p=health'))
            # Same Lynis test can produce multiple distinct findings (e.g. /home and /var).
            fid=kind+':'+key+':'+hashlib.sha256(raw.encode('utf-8')).hexdigest()[:8]
            findings.append({'id':fid,'code':key,'type':kind,'text':pieces[1].strip()[:360] if len(pieces)>1 else key,
                             'group':group,'title':title,'guidance':instructions,'mode':level,'link':link,
                             'review':reviews.get(fid,'open') if isinstance(reviews,dict) else 'open'})
            if len(findings)>=300:break
    return {'ok':True,'report_found':bool(report and report.is_file()),'audit_id':run_id if complete else '',
            'audit_state':status['state'],'metadata':metadata,'suggestions':findings,
            'remediations':[{'id':'aslr','title':'ASLR kernel (randomize_va_space=2)','key':'kernel.randomize_va_space','value':'2'},
                            {'id':'suid','title':'Nessun core dump di programmi SUID','key':'fs.suid_dumpable','value':'0'}],
            'note':'Ogni rilievo è una raccomandazione, non un comando da eseguire automaticamente.'}


def lynis_review():
    if os.geteuid()!=0:raise ValueError('Modifica riservata a root')
    raw=sys.stdin.read(1025)
    if len(raw)>1024:raise ValueError('Richiesta troppo grande')
    item=json.loads(raw)
    if not isinstance(item,dict):raise ValueError('Richiesta non valida')
    status=lynis_job_state();job=item.get('audit_id','');fid=item.get('finding','');new=item.get('review','')
    if job!=status.get('run_id') or status['state'] not in ('done','done_warnings'):
        raise ValueError('Audit differente o non completato: ricarica il report')
    if new not in ('open','planned','reviewed') or not isinstance(fid,str):raise ValueError('Stato revisione non valido')
    if fid not in {entry['id'] for entry in lynis_suggestions()['suggestions']}:
        raise ValueError('Rilievo inesistente nel report attuale')
    path=lynis_audit_dir(job)/'reviews.json'
    with (DATA/'lynis-job.lock').open('a+') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        values=read_json(path);values[fid]=new
        tmp=path.with_name('reviews.%d.tmp'%os.getpid())
        with tmp.open('w') as f:
            os.fchmod(f.fileno(),0o600);json.dump(values,f,sort_keys=True)
        os.replace(tmp,path)
    return {'ok':True,'summary':'Stato della raccomandazione aggiornato; non è stata modificata alcuna configurazione.'}


def lynis_run():
    # Backward-compatible CLI alias; no more synchronous audit or 240-second limit.
    return lynis_start()


def lynis_start():
    if os.geteuid()!=0:raise ValueError('Audit riservato a root')
    if not shutil.which('lynis'):raise ValueError('Lynis non installato')
    DATA.mkdir(mode=0o700,parents=True,exist_ok=True)
    with (DATA/'lynis-job.lock').open('a+') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        state=lynis_job_state()
        if state['state']=='running':return {'ok':True,'state':'running','summary':'Audit già in esecuzione','run_id':state.get('run_id')}
        run_id=secrets.token_hex(8)
        audits=DATA/'lynis-audits';audits.mkdir(mode=0o700,parents=True,exist_ok=True)
        rundir=lynis_audit_dir(run_id);rundir.mkdir(mode=0o700)
        # No HTTP worker ever waits for the audit to finish.
        with open(os.devnull,'rb') as inp,open(os.devnull,'wb') as out:
            child=subprocess.Popen([sys.executable,'-B',str(Path(__file__).resolve()),'lynis-worker'],
                stdin=inp,stdout=out,stderr=out,start_new_session=True,close_fds=True)
        lynis_job_write({'state':'running','run_id':run_id,'pid':child.pid,'started':int(time.time()),
                        'summary':'Audit completo avviato; puoi chiudere questa pagina e tornare più tardi'})
        return {'ok':True,'state':'running','run_id':run_id,'summary':'Audit avviato in background'}


def lynis_worker():
    if os.geteuid()!=0:raise ValueError('Worker riservato a root')
    with (DATA/'lynis-job.lock').open('a+') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        state=read_json(DATA/'lynis-job.json')
        if state.get('pid')!=os.getpid() or not _LYNIS_RUN_RE.fullmatch(str(state.get('run_id',''))):
            return {'ok':False,'summary':'Worker non autorizzato'}
    run_id=state['run_id'];started=int(state.get('started') or time.time())
    # On older Atom hardware keep the web interface responsive while auditing.
    # This affects only the detached worker and its Lynis child.
    try:os.nice(10)
    except OSError:pass
    run=lynis_audit_dir(run_id)
    args=['lynis','audit','system','--cronjob','--no-colors','--report-file',str(run/'report.dat'),
          '--logfile',str(run/'lynis.log')]
    rc=None;failure=''
    try:
        # Streaming to 0600 file avoids memory growth and a blocked stdout pipe.
        fd=os.open(run/'stdout.log',os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as log:
            proc=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,
                                  close_fds=True,start_new_session=False)
            rc=proc.wait()  # Intentionally NO 600-second cap: let the full audit finish.
    except (OSError,subprocess.SubprocessError) as exc:
        failure=type(exc).__name__
    report=run/'report.dat'
    report_ok=report.is_file() and not report.is_symlink() and 0<report.stat().st_size<=4*1024*1024
    # Lynis code 78 can denote warnings with error-on-warnings policy.
    ok=report_ok and rc in (0,78)
    kind='done_warnings' if ok and rc==78 else ('done' if ok else 'failed')
    count=0
    if report_ok:
        with report.open('r',encoding='utf-8',errors='replace') as stream:
            for line in stream:
                if line.startswith(('suggestion[]=','warning[]=')):count+=1
                if count>10000:break
    summary=('Audit concluso; consulta il rapporto e scegli quali interventi valutare.' if ok else
             'Audit non completato: codice '+str(rc)+'; '+failure+'. Consulta i log Lynis.')
    lynis_job_write({'state':kind,'run_id':run_id,'pid':os.getpid(),'started':started,
            'finished':int(time.time()),'exit_code':rc,'report_found':report_ok,
            'suggestions_count':count,'summary':summary})
    return {'ok':ok,'state':kind}


def lynis_update():
    # Explicit admin action only. Never run apt update or install any other package.
    if os.geteuid()!=0: raise ValueError('aggiornamento Lynis riservato a root')
    if lynis_job_state()['state']=='running':raise ValueError('Audit in corso: attendi il completamento prima dell’aggiornamento')
    if not shutil.which('apt-get') or not shutil.which('lynis'):
        raise ValueError('Lynis o apt-get non disponibile: installa Lynis da Programmi/DietPi')
    try:
        proc=subprocess.run(['apt-get','-y','--no-install-recommends','--only-upgrade','install','lynis'],
                            capture_output=True,text=True,timeout=240,stdin=subprocess.DEVNULL,
                            env={**os.environ,'DEBIAN_FRONTEND':'noninteractive'})
    except subprocess.TimeoutExpired:
        return {'ok':False,'exit_code':None,
                'summary':'Timeout aggiornamento Lynis: verificare lo stato di apt/dpkg prima di riprovare',
                'note':'Nessun altro aggiornamento viene avviato automaticamente.'}
    return {'ok':proc.returncode==0,'exit_code':proc.returncode,
            'summary':'Aggiornamento Lynis completato o già aggiornato' if proc.returncode==0 else
                      'Aggiornamento Lynis non riuscito: verificare apt/dpkg; nessun altro pacchetto richiesto',
            'note':'Operazione apt esplicita: i maintainer script del pacchetto possono modificare il sistema.'}

def vlan_input():
    raw=sys.stdin.read(4097)
    if len(raw)>4096: raise ValueError('richiesta VLAN troppo grande')
    return vlan_manage(json.loads(raw))


def zone_input():
    # Root subcommand: never let a compromised web worker send unbounded JSON.
    raw=sys.stdin.read(16385)
    if len(raw)>16384: raise ValueError('piano zona oltre 16 KiB')
    return zone_plan(json.loads(raw))


def main():
    p=argparse.ArgumentParser(description='IPTM security analysis and safe planning')
    p.add_argument('action',choices=['dns-audit','dietpi-audit','mac-inventory','oui-update','zone-plan','mac-plan','vlan-manage','lynis-run','lynis-start','lynis-status','lynis-worker','lynis-suggestions','lynis-update','lynis-review','pihole-health'])
    a=p.parse_args()
    result={'dns-audit':dns_audit,'dietpi-audit':system_audit,'mac-inventory':mac_inventory,
            'oui-update':update_oui,'pihole-health':pihole_health,'zone-plan':zone_input,'mac-plan':mac_policy_input,'vlan-manage':vlan_input,
            'lynis-run':lynis_run,'lynis-start':lynis_start,'lynis-status':lynis_job_state,'lynis-worker':lynis_worker,'lynis-suggestions':lynis_suggestions,'lynis-update':lynis_update,'lynis-review':lynis_review}[a.action]()
    emit(result)
    return 0 if result.get('ok') else 1

if __name__=='__main__':
    try:sys.exit(main())
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        emit({'ok':False,'error':str(exc)[:300]});sys.exit(2)
