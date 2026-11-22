#!/usr/bin/env python3
"""IPTM DNS/TLS safety controller; explicit opt-in, never edits firewall or CAKE.

DNSCrypt fallback and certificate-pinned DoH stamps are implemented here.
SNI/anti-DPI are policy previews for integration with an independently verified
Suricata IPS or zapret installation, NOT an inline packet interception engine.
"""
import base64
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import secrets
from datetime import datetime, timezone

VERSION='5.20.25'
CONFIG_CANDIDATES=(Path('/etc/dnscrypt-proxy/dnscrypt-proxy.toml'),Path('/etc/dnscrypt-proxy.toml'))
BACKUP=Path('/var/lib/iptables-manager/backups/dns-guard')
EVE=Path('/var/log/suricata/eve.json')
LOCK=Path('/run/lock/iptm-dns-guard.lock')
PENDING=BACKUP/'pending.json'
ROLLBACK_SECONDS=300
HOST_RE=re.compile(r'(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\Z')
PIN_STAMP_RE=re.compile(r'sdns://[A-Za-z0-9_-]{32,2048}={0,2}\Z')
# Curated, prefilled *proposals* (never applied at install time).
# Published in DNSCrypt/dnscrypt-resolvers v3/public-resolvers.md, checked
# 2026-11-19. The stamp includes an explicit IP and the publisher's cert hash.
# Resolver operators can rotate hashes/IPs; apply must validate both live.
PRESET_PRIMARY='sdns://AgMAAAAAAAAABzkuOS45LjkgsBkgdEu7dsmrBT4B4Ht-BQ5HPSD3n3vqQ1-v5DydJC8SZG5zOS5xdWFkOS5uZXQ6NDQzCi9kbnMtcXVlcnk'
PRESET_SECONDARY='sdns://AgcAAAAAAAAACzE1OC42NC4xLjI5IFu-VnwzuH-_lDuVxbNpQAXPH2I1byMEB2hd7keNdtjLEWRuc3B1Yi5yZXN0ZW5hLmx1Ci9kbnMtcXVlcnk'
PRESET_SOURCE='https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md'

class PolicyError(ValueError): pass

def fail(message): raise PolicyError(message)

def lp(buf, p):
    if p>=len(buf): fail('Stamp DoH troncato')
    n=buf[p];p+=1
    if p+n>len(buf):fail('Campo stamp non valido')
    return buf[p:p+n],p+n

def decode_pinned_doh(stamp):
    if not isinstance(stamp,str) or not PIN_STAMP_RE.fullmatch(stamp): fail('Stamp DoH non valido')
    s=stamp[7:]
    try: b=base64.urlsafe_b64decode(s+'='*((-len(s))%4))
    except Exception:fail('Stamp Base64 non valido')
    if len(b)<16 or b[0]!=2:fail('È richiesto uno stamp DoH (tipo 0x02)')
    p=9; raw_ip,p=lp(b,p)
    if not raw_ip:fail('Stamp privo di IP predefinito: richiedo bootstrap IP esplicito')
    try:
        endpoint=raw_ip.decode('ascii')
        iptext=endpoint.rsplit(':',1)[0] if endpoint.count(':')==1 else (endpoint.split(']')[0][1:] if endpoint.startswith('[') else endpoint)
        ip=ipaddress.ip_address(iptext)
        if endpoint not in (str(ip), f'{ip}:443', f'[{ip}]:443'):
            fail('Usa solamente il servizio DoH HTTPS sulla porta 443')
    except (UnicodeDecodeError,ValueError):fail('Indirizzo nello stamp non valido')
    if not ip.is_global:fail('Lo stamp deve usare un IP Internet pubblico')
    hashes=[]
    while True:
        if p>=len(b):fail('Elenco hash stamp troncato')
        size=b[p];p+=1
        count=size&0x7f
        if count!=32 or p+count>len(b):fail('È richiesto un hash certificato SHA-256 di 32 byte')
        hashes.append(b[p:p+count].hex());p+=count
        if len(hashes)>8:fail('Troppi hash nel certificato')
        if not (size&0x80):break
    name,p=lp(b,p);path,p=lp(b,p)
    try:
        hostname=name.decode('ascii').lower().rstrip('.')
        uri=path.decode('ascii')
    except UnicodeDecodeError:fail('Nome DoH non valido')
    if hostname.count(':')==1:
        hostname,port=hostname.rsplit(':',1)
        if port!='443':fail('Il probe TLS supporta solo DoH sulla porta 443')
    if not HOST_RE.fullmatch(hostname) or not uri.startswith('/') or '\\' in uri or any(ord(c)<33 for c in uri):fail('Hostname o percorso DoH non valido')
    if p<len(b):fail('Campi stamp ulteriori non supportati: verifica manuale richiesta')
    return {'ip':str(ip),'hostname':hostname,'cert_pins_sha256':hashes,'path':uri}

def validate_domains(domains, *, dpi=False):
    if not isinstance(domains,list):fail('Elenco domini non valido')
    if not dpi and len(domains)>40:fail('Massimo 40 domini SNI')
    result=[]; seen=set(); byte_count=0
    for domain in domains:
        if not isinstance(domain,str):fail('Dominio non valido')
        d=domain.strip().lower().rstrip('.')
        if not HOST_RE.fullmatch(d):fail('Nome dominio non valido: '+d[:100])
        if d not in seen:
            byte_count += len(d)+1
            if dpi and byte_count>4*1024*1024:fail('Domini DPI oltre 4 MiB')
            seen.add(d);result.append(d)
    return result

def validate(payload, require_stamps=True):
    if not isinstance(payload,dict):fail('JSON non valido')
    if set(payload)-{'primary_stamp','secondary_stamp','bootstrap','timeout','sni_domains','sni_mode','dpi_domains','dpi_clients'}:fail('Campi inattesi')
    have=bool(payload.get('primary_stamp')) or bool(payload.get('secondary_stamp'))
    if require_stamps and not have:fail('Inserisci due stamp DoH per applicare la configurazione DNS')
    if have and not (payload.get('primary_stamp') and payload.get('secondary_stamp')):fail('Servono entrambi gli stamp DoH')
    prim=decode_pinned_doh(payload['primary_stamp']) if have else None
    sec=decode_pinned_doh(payload['secondary_stamp']) if have else None
    if prim and prim['ip']==sec['ip'] and prim['hostname']==sec['hostname']:fail('I resolver devono essere indipendenti')
    boot=payload.get('bootstrap',[])
    if not isinstance(boot,list) or len(boot)>4:fail('Massimo 4 IP bootstrap')
    bootstrap=[]
    for addr in boot:
        try:ip=ipaddress.ip_address(addr)
        except (ValueError,TypeError):fail('IP bootstrap non valido')
        if not ip.is_global:fail('Il bootstrap richiede un IP Internet pubblico')
        rendered=('[%s]:53'%ip) if ip.version==6 else '%s:53'%ip
        if rendered not in bootstrap:bootstrap.append(rendered)
    try:t=int(payload.get('timeout',5))
    except (TypeError,ValueError):fail('Timeout non valido')
    if t<2 or t>15:fail('Timeout consentito: 2–15 secondi')
    sni=validate_domains(payload.get('sni_domains',[]))
    dpi=validate_domains(payload.get('dpi_domains',[]),dpi=True)
    sm=payload.get('sni_mode','alert')
    if sm not in ('alert','drop'):fail('Modo SNI non valido')
    clients=payload.get('dpi_clients',[])
    if not isinstance(clients,list) or len(clients)>32:fail('Massimo 32 client DPI')
    clientlist=[]
    for c in clients:
        if not isinstance(c,str):fail('Client DPI non valido')
        try:net=ipaddress.ip_network(c,strict=False)
        except ValueError:fail('Rete client DPI non valida')
        if not (net.is_private or net.is_link_local):fail('Solo client privati possono essere inseriti nella policy DPI')
        if str(net) not in clientlist:clientlist.append(str(net))
    return {'primary':prim,'secondary':sec,'stamps':[payload.get('primary_stamp',''),payload.get('secondary_stamp','')],
            'bootstrap':bootstrap,'timeout':t,'sni':sni,'sni_mode':sm,'dpi':dpi,'clients':clientlist}

def suricata_rules(plan):
    """Preview only. Actual drop requires a separately enabled inline IPS."""
    out=[]
    for ix,domain in enumerate(plan['sni'],1):
        # bsize avoids suffix collisions (badexample.com vs example.com).
        action=plan['sni_mode']
        out.append(f'{action} tls any any -> any any (msg:"IPTM TLS SNI {ix}"; flow:established,to_server; tls.sni; content:"{domain}"; nocase; bsize:{len(domain)}; sid:{9911900+ix}; rev:1;)')
    return out

def dpi_preview(plan):
    available=shutil.which('nfqws') or '/opt/zapret/nfq/nfqws'
    exists=Path(available).is_file() and os.access(available,os.X_OK)
    return {'engine':'zapret nfqws','installed':bool(exists),'enabled':False,
      'client_ranges':plan['clients'],'hostnames_count':len(plan['dpi']),'hostnames_sample':plan['dpi'][:20],
      'note':'Policy limitata ai client e domini selezionati; anteprima soltanto. Attivazione richiede NFQUEUE/iptables verificati e rollback sulla macchina DietPi. Nessuna intercettazione HTTPS o TLS MITM.',
      'command_template':'nfqws --dpi-desync=multisplit --hostlist=<file-root-only> (argomenti da validare per la versione installata)' if exists else 'Installa e convalida zapret/nfqws prima di abilitare.'}

def proposed_config(plan):
    # Deliberately use static resolver stamps so pin hashes/addresses are actually
    # enforced by DNSCrypt on EVERY query, not merely in a one-time curl probe.
    return {'server_names':"['iptm-pinned-primary', 'iptm-pinned-secondary']",
      'timeout':str(plan['timeout']*1000),
      'ignore_system_dns':'true','require_nolog':'true',
      'bootstrap_resolvers':'['+', '.join("'"+s+"'" for s in plan['bootstrap'])+']'}

def without_unsupported_doh(text):
    """Strip a 2.1.20-only top-level knob from legacy IPTM output.

    Never touch similarly named keys in TOML sections or unrelated options.
    Preserve comments and all other configuration bytes.
    """
    lines=text.splitlines(keepends=True)
    top=True; result=[];removed=0
    for line in lines:
        if re.match(r'^\s*\[',line):top=False
        if top and re.match(r'^\s*doh_check_cert_hashes_on_connect\s*=',line):
            removed+=1;continue
        result.append(line)
    if removed>1:fail('Chiave DNSCrypt incompatibile duplicata: ripristino manuale necessario')
    return ''.join(result),removed

def patch_config(text,plan):
    if len(text)>1048576:fail('File dnscrypt troppo grande')
    # Existing managed static entries can be updated, but never replace user-owned ones.
    markers=('# IPTM_DNS_GUARD_BEGIN','# IPTM_DNS_GUARD_END')
    if (markers[0] in text)!=(markers[1] in text):fail('Blocco IPTM corrotto')
    if markers[0] in text:
        text=re.sub(r'(?ms)^# IPTM_DNS_GUARD_BEGIN\n.*?^# IPTM_DNS_GUARD_END\n?', '',text,count=1)
    if '[static.iptm-pinned-primary]' in text or '[static.iptm-pinned-secondary]' in text:
        fail('Configurazione statica IPTM presente fuori dal blocco gestito')
    text,_=without_unsupported_doh(text)
    lines=text.splitlines(keepends=True)
    first_section=next((i for i,line in enumerate(lines) if re.match(r'^\s*\[',line)),len(lines))
    root=lines[:first_section];other=lines[first_section:]
    desired=proposed_config(plan)
    for key,value in desired.items():
        if value is None:continue
        matches=[i for i,line in enumerate(root) if re.match(r'^\s*'+re.escape(key)+r'\s*=',line)]
        if len(matches)>1:fail('Parametro dnscrypt duplicato: '+key)
        if matches:root[matches[0]]=key+' = '+value+'\n'
        else:root.append(key+' = '+value+'\n')
    managed='\n'+markers[0]+'\n'
    for idx,key in enumerate(('primary','secondary')):
        managed+=f'[static.iptm-pinned-{key}]\n'+'stamp = '+json.dumps(plan['stamps'][idx])+'\n'
    managed+=markers[1]+'\n'
    return ''.join(root+other).rstrip()+'\n'+managed

def locate_config():
    for path in CONFIG_CANDIDATES:
        if path.exists():return path
    fail('File dnscrypt-proxy.toml non trovato: controlla il percorso configurato in systemd')

def file_is_safe(path):
    if path.is_symlink() or not path.is_file():fail('File dnscrypt non regolare')
    st=path.stat()
    if st.st_uid!=0 or (st.st_mode&0o022):fail('File dnscrypt non protetto')
    par=path.parent
    if par.is_symlink() or (par.stat().st_mode&0o022):fail('Directory dnscrypt scrivibile da altri')

def run_checked(command,timeout=25):
    p=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=timeout)
    if p.returncode:fail(' '.join(command[:2])+' fallito: '+(p.stderr or p.stdout)[-300:])
    return p.stdout

def probe_stamp(info,timeout=6):
    """TLS CA/name verification to the IP embedded in a DoH stamp; pin enforced by DNSCrypt."""
    if not shutil.which('curl'):fail('curl assente: verifica TLS non disponibile')
    ip=info['ip'];host=info['hostname'];uri='https://'+host+info['path']
    curl_ip=('[%s]'%ip) if ':' in ip else ip
    # -f is intentionally omitted: DoH endpoints commonly return HTTP 400 to GET without DNS query.
    run_checked(['curl','--silent','--show-error','--output','/dev/null','--noproxy','*','--proto','=https',
                 '--max-time',str(timeout),'--connect-timeout',str(timeout),
                 '--resolve',f'{host}:443:{curl_ip}',uri],timeout=timeout+3)

def validate_candidate(binary,filepath):
    run_checked([binary,'-check','-config',str(filepath)],timeout=30)

def write_atomic_secure(path, payload, metadata):
    fd,name=tempfile.mkstemp(prefix='.iptm-dns-',dir=str(path.parent))
    try:
        with os.fdopen(fd,'wb') as f:
            os.fchown(f.fileno(),metadata.st_uid,metadata.st_gid)
            os.fchmod(f.fileno(),stat.S_IMODE(metadata.st_mode))
            f.write(payload);f.flush();os.fsync(f.fileno())
        os.replace(name,path)
        directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(directory)
        finally:os.close(directory)
    finally:
        if os.path.exists(name):os.unlink(name)


def pending_read():
    if PENDING.is_symlink():fail('Stato DNS transazione non sicuro')
    if not PENDING.exists():return None
    st=PENDING.stat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_mode&0o077 or st.st_size>4096:
        fail('Stato DNS transazione non protetto')
    try: data=json.loads(PENDING.read_text())
    except (ValueError,UnicodeError): fail('Stato DNS transazione illeggibile')
    if not isinstance(data,dict) or not re.fullmatch('[a-f0-9]{32}',str(data.get('txid',''))):
        fail('Stato DNS transazione incoerente')
    if data.get('config') not in [str(x) for x in CONFIG_CANDIDATES]:fail('Path DNS non autorizzato')
    name=data.get('backup')
    if not isinstance(name,str) or not re.fullmatch(r'dnscrypt\.\d{8}-\d{6}-\d{6}\.toml',name):
        fail('Backup DNS non valido')
    if not isinstance(data.get('until'),int) or data['until']<=0:fail('Timer DNS invalido')
    return data


def pending_write(data):
    # Do not follow a symlink created by an unprivileged process.
    if PENDING.exists() or PENDING.is_symlink():fail('Esiste una transazione DNS non confermata')
    fd,name=tempfile.mkstemp(prefix='.dns-pending-',dir=str(BACKUP))
    try:
        with os.fdopen(fd,'wb') as f:
            os.fchmod(f.fileno(),0o600)
            f.write(json.dumps(data,sort_keys=True,separators=(',',':')).encode())
            f.flush();os.fsync(f.fileno())
        os.replace(name,PENDING)
    finally:
        if os.path.exists(name):os.unlink(name)


def timer_unit(txid): return 'iptm-dns-guard-'+txid


def timer_arm(txid):
    if not shutil.which('systemd-run'):fail('systemd-run non disponibile: DNS non modificato')
    unit=timer_unit(txid)
    run_checked(['systemd-run','--quiet','--unit='+unit,
                '--on-active='+str(ROLLBACK_SECONDS)+'s',
                '/usr/bin/python3','-B',str(Path(__file__).resolve()),'watchdog',txid],timeout=15)
    run_checked(['systemctl','is-active','--quiet',unit+'.timer'],timeout=10)


def timer_cancel(txid):
    run_checked(['systemctl','stop',timer_unit(txid)+'.timer'],timeout=10)


def dns_transaction(mode,txid=None):
    if os.geteuid()!=0:fail('Operazione DNS riservata a root')
    data=pending_read()
    if not data:return {'changed':False,'state':'idle','note':'Nessuna modifica DNS in attesa'}
    if mode=='watchdog' and (not txid or not secrets.compare_digest(str(data['txid']),txid)):
        return {'changed':False,'state':'different-transaction'}
    if mode=='recover-boot':
        # A transient systemd-run timer is lost on restart. Restore *any*
        # unconfirmed config before dnscrypt-proxy is allowed to start.
        cfg=Path(data['config']);file_is_safe(cfg)
        backup=BACKUP/data['backup']
        if backup.is_symlink() or not backup.is_file() or backup.stat().st_uid!=0 or backup.stat().st_mode&0o077:
            fail('Boot recovery: snapshot DNS mancante o non sicuro')
        write_atomic_secure(cfg,backup.read_bytes(),cfg.stat())
        PENDING.unlink()
        # Do not call systemctl or perform DNS queries from an early boot unit.
        # dnscrypt-proxy starts afterward with the restored configuration.
        return {'changed':True,'state':'reverted','reason':'boot-recover'}
    if mode=='confirm':
        if time.time()>=data['until']:fail('Conferma DNS scaduta: lascia intervenire il watchdog')
        cfg=Path(data['config']);file_is_safe(cfg)
        binary=shutil.which('dnscrypt-proxy')
        if not binary:fail('dnscrypt-proxy non disponibile per conferma')
        validate_candidate(binary,cfg)
        run_checked(['systemctl','is-active','--quiet','dnscrypt-proxy'],timeout=10)
        # Durable commit order: removing the pending marker first makes an
        # already scheduled watchdog harmless even if this process is killed
        # between the unlink and stopping the timer. The reverse order could
        # strand a pending transaction with no functional watchdog.
        PENDING.unlink()
        timer_cancel(data['txid'])
        return {'changed':False,'state':'confirmed'}
    if mode=='watchdog' and time.time()<data['until']:
        # A timer with very early execution is not allowed to rewrite config.
        fail('Watchdog DNS anticipato: verificare systemd timer')
    cfg=Path(data['config']);file_is_safe(cfg)
    backup=BACKUP/data['backup']
    if backup.is_symlink() or not backup.is_file() or backup.stat().st_uid!=0 or backup.stat().st_mode&0o077:
        fail('Snapshot DNS non disponibile o non sicuro')
    meta=cfg.stat()
    write_atomic_secure(cfg,backup.read_bytes(),meta)
    run_checked(['systemctl','restart','dnscrypt-proxy'],30)
    PENDING.unlink()
    if mode!='watchdog': timer_cancel(data['txid'])
    return {'changed':True,'state':'reverted','reason':mode}


def pending_public():
    state=pending_read()
    if not state:return {'state':'idle'}
    return {'state':'pending','seconds_remaining':max(0,state['until']-int(time.time())),
            'rollback':'automatic'}


def apply(plan):
    if os.geteuid()!=0:fail('Applicazione consentita solo a root')
    binary=shutil.which('dnscrypt-proxy')
    if not binary:fail('dnscrypt-proxy non installato')
    cfg=locate_config();file_is_safe(cfg)
    cfg_stat=cfg.stat()
    if shutil.which('systemctl') is None or subprocess.run(['systemctl','is-active','--quiet','dnscrypt-proxy'],timeout=8,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode!=0:
        fail('Il servizio dnscrypt-proxy non risulta attivo: nessuna modifica')
    for item in (plan['primary'],plan['secondary']):probe_stamp(item)
    if pending_read():fail('Modifica DNS precedente non confermata: completa o ripristina prima')
    previous=cfg.read_bytes();replaced=patch_config(previous.decode('utf-8'),plan).encode()
    if previous==replaced:return {'changed':False,'note':'Configurazione già applicata'}
    if without_unsupported_doh(previous.decode('utf-8'))[1]==0:
        validate_candidate(binary,cfg)
    if BACKUP.is_symlink() or (BACKUP.exists() and ((BACKUP.stat().st_mode&0o022) or BACKUP.stat().st_uid!=0)):
        fail('Directory backup non sicura')
    BACKUP.mkdir(parents=True,exist_ok=True,mode=0o700);os.chmod(BACKUP,0o700)
    backup=BACKUP/('dnscrypt.'+datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f')+'.toml')
    with backup.open('xb') as f:f.write(previous)
    backup.chmod(0o600)
    txid=secrets.token_hex(16)
    pending_write({'txid':txid,'config':str(cfg),'backup':backup.name,
                   'until':int(time.time())+ROLLBACK_SECONDS-5})
    try:
        timer_arm(txid)
    except BaseException:
        # Fail closed: cannot touch DNS without an independent rollback timer.
        PENDING.unlink(missing_ok=True)
        raise
    def write_atomic(blob): write_atomic_secure(cfg,blob,cfg_stat)
    try:
        write_atomic(replaced)
        validate_candidate(binary,cfg)
        run_checked(['systemctl','restart','dnscrypt-proxy'],30)
        # Require *each* pinned upstream to answer independently, not just one
        # healthy member of a load-balanced pair.
        for resolver in ('primary','secondary'):
            single=replaced.decode('utf-8').replace(
                "server_names = ['iptm-pinned-primary', 'iptm-pinned-secondary']",
                "server_names = ['iptm-pinned-"+resolver+"']",1)
            test_fd,test_name=tempfile.mkstemp(prefix='.iptm-resolver-test-',dir=str(cfg.parent))
            try:
                with os.fdopen(test_fd,'wb') as test_file:
                    os.fchmod(test_file.fileno(),0o600)
                    test_file.write(single.encode('utf-8'))
                run_checked([binary,'-resolve','example.org','-config',test_name],35)
            finally:
                if os.path.exists(test_name):os.unlink(test_name)
    except BaseException:
        # Keep watchdog if immediate restoration is not fully verified.
        try:
            write_atomic(previous)
            run_checked(['systemctl','restart','dnscrypt-proxy'],30)
            PENDING.unlink()
            timer_cancel(txid)
        except BaseException as restore_error:
            print('IPTM DNS rollback failed: '+type(restore_error).__name__,file=sys.stderr,flush=True)
        raise
    candidates=sorted(BACKUP.glob('dnscrypt.*.toml'),key=lambda p:p.stat().st_mtime,reverse=True)
    for stale in candidates[10:]:
        if stale.is_file() and not stale.is_symlink():stale.unlink()
    return {'changed':True,'backup':str(backup),'resolver_count':2,'pinned_stamps_configured':True,
            'pending_confirmation':True,'rollback_seconds':ROLLBACK_SECONDS-5,
            'note':'DNSCrypt in prova; verifica LAN e conferma entro la scadenza oppure verrà ripristinato.'}

def compatibility_repair(apply_changes=False):
    """Repair the precise IPTM-injected unsupported TOML key; no other edits.

    As with a resolver change, an armed watchdog and a confirmation are required.
    """
    if os.geteuid()!=0:fail('Riparazione DNSCrypt riservata a root')
    cfg=locate_config();file_is_safe(cfg)
    raw=cfg.read_bytes()
    if len(raw)>1048576:fail('Configurazione DNSCrypt troppo grande')
    replacement,count=without_unsupported_doh(raw.decode('utf-8'))
    if not count:return {'changed':False,'compatible':True,'note':'Nessuna direttiva incompatibile rilevata'}
    binary=shutil.which('dnscrypt-proxy')
    if not binary:fail('dnscrypt-proxy non disponibile')
    fd,name=tempfile.mkstemp(prefix='.iptm-dns-check-',suffix='.toml',dir=str(cfg.parent))
    try:
        with os.fdopen(fd,'wb') as stream:
            os.fchmod(stream.fileno(),0o600);stream.write(replacement.encode())
        validate_candidate(binary,Path(name))
    finally:
        if os.path.exists(name):os.unlink(name)
    if not apply_changes:return {'changed':False,'compatible_after_repair':True,
        'note':'Rimuove solo doh_check_cert_hashes_on_connect, mantenendo gli stamp DoH'}
    if pending_read():fail('È in corso una transazione DNS: confermare o ripristinare prima')
    BACKUP.mkdir(parents=True,exist_ok=True,mode=0o700)
    if BACKUP.is_symlink() or BACKUP.stat().st_uid!=0 or BACKUP.stat().st_mode&0o077:
        fail('Directory backup DNSCrypt non protetta')
    backup=BACKUP/('dnscrypt.'+datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f')+'.toml')
    with backup.open('xb') as stream:
        stream.write(raw);stream.flush();os.fsync(stream.fileno())
    backup.chmod(0o600)
    txid=secrets.token_hex(16)
    pending_write({'txid':txid,'config':str(cfg),'backup':backup.name,
                   'until':int(time.time())+ROLLBACK_SECONDS-5})
    try:timer_arm(txid)
    except BaseException:
        PENDING.unlink(missing_ok=True);raise
    metadata=cfg.stat()
    try:
        write_atomic_secure(cfg,replacement.encode('utf-8'),metadata)
        validate_candidate(binary,cfg)
        run_checked(['systemctl','restart','dnscrypt-proxy'],30)
    except BaseException:
        try:
            write_atomic_secure(cfg,raw,metadata)
            run_checked(['systemctl','restart','dnscrypt-proxy'],30)
            PENDING.unlink(missing_ok=True);timer_cancel(txid)
        except BaseException as restore_error:
            print('IPTM DNS rollback failed: '+type(restore_error).__name__,file=sys.stderr,flush=True)
        raise
    return {'changed':True,'pending_confirmation':True,'rollback_seconds':ROLLBACK_SECONDS-5,
            'note':'Direttiva incompatibile rimossa; verificare DNS e confermare prima del rollback'}

def status():
    content=''
    cfg=next((str(x) for x in CONFIG_CANDIDATES if x.is_file()),None)
    managed=False
    if cfg:
        try:
            config_path=Path(cfg)
            if config_path.is_file() and not config_path.is_symlink() and config_path.stat().st_size<=1024*1024:
                content=config_path.read_text(errors='replace')
                managed=('# IPTM_DNS_GUARD_BEGIN' in content and '# IPTM_DNS_GUARD_END' in content)
        except OSError:
            pass
    return {'version':VERSION,'config':cfg,'configured_by_iptm':managed,
     'obsolete_doh_option':bool(cfg and 'doh_check_cert_hashes_on_connect' in content),
     'recommended_presets':{'primary_stamp':PRESET_PRIMARY,'secondary_stamp':PRESET_SECONDARY,
       'primary_name':'Quad9 Secure (9.9.9.9, anti-malware)',
       'secondary_name':'RESTENA DoH (158.64.1.29, senza filtraggio)',
       'source':PRESET_SOURCE,'checked':'2026-11-19',
       'note':'Le dichiarazioni no-log sono dei fornitori e non certificazioni; i pin possono cambiare.'},
     'dnscrypt_installed':shutil.which('dnscrypt-proxy') is not None,
     'suricata_installed':shutil.which('suricata') is not None,
     'anti_dpi_installed':shutil.which('nfqws') is not None or Path('/opt/zapret/nfq/nfqws').is_file(),
     'dns_automatic_fallback':'configurabile con due DoH statici e pin certificati',
     'sni':'richiede Suricata, TLS ClientHello in chiaro; ECH rende opaco il nome reale',
     'dpi':'anteprima solo; nessuna modifica automatica a NFQUEUE o iptables'}


def sni_events(path=EVE):
    """Observe TLS metadata already recorded by Suricata; no packet capture."""
    if path.is_symlink() or not path.is_file():
        return {'available':False,'events':[],'note':'Registro Suricata EVE non disponibile'}
    st=path.stat()
    if st.st_size>512*1024*1024 or not stat.S_ISREG(st.st_mode):
        return {'available':False,'events':[],'note':'Registro troppo grande/non regolare'}
    with path.open('rb') as file:
        file.seek(max(0,st.st_size-512*1024))
        if file.tell():file.readline() # discard partial first JSON row
        rows=file.readlines()
    events=[]
    for raw in rows[-1000:]:
        if len(raw)>32768:continue
        try:item=json.loads(raw)
        except (ValueError,UnicodeDecodeError):continue
        if item.get('event_type')!='tls' or not isinstance(item.get('tls'),dict):continue
        tls=item['tls'];name=str(tls.get('sni') or '').lower()
        if not HOST_RE.fullmatch(name):continue
        events.append({'timestamp':str(item.get('timestamp',''))[:40],
            'source':str(item.get('src_ip',''))[:45],'destination':str(item.get('dest_ip',''))[:45],
            'sni_visible':name,'confidence':'outer-only: ECH can conceal actual hostname'})
    return {'available':True,'events':events[-40:],
      'note':'Dati già acquisiti da Suricata EVE; nessuna nuova cattura o modifica di regole'}

def main():
    if len(sys.argv)<2 or sys.argv[1] not in ('status','events','preview','apply','confirm','revert','watchdog','recover-boot','compat-preview','compat-apply'):
        fail('Uso: status|events|preview|apply|confirm|revert|watchdog')
    mode=sys.argv[1]
    if (mode=='watchdog' and (len(sys.argv)!=3 or not re.fullmatch('[a-f0-9]{32}',sys.argv[2]))) or (mode!='watchdog' and len(sys.argv)!=2):
        fail('Argomenti DNS Guard non validi')
    if mode in ('confirm','revert','watchdog','recover-boot'):
        fd=os.open(LOCK,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        try:
            owner=os.fstat(fd)
            if owner.st_uid!=0 or (owner.st_mode&0o077):fail('Lock DNS Guard non sicuro')
            fcntl.flock(fd,fcntl.LOCK_EX)
            return dns_transaction(mode,sys.argv[2] if mode=='watchdog' else None)
        finally:os.close(fd)
    if mode=='status':
        result=status()
        result['transaction']=pending_public()
        return result
    if mode=='events':return sni_events()
    if mode in ('compat-preview','compat-apply'):
        fd=os.open(LOCK,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX)
            return compatibility_repair(mode=='compat-apply')
        finally:os.close(fd)
    payload=json.load(sys.stdin)
    if not isinstance(payload,dict):fail('Configurazione JSON non valida')
    plan=validate(payload,require_stamps=(mode=='apply'))
    if mode=='preview':
        return {'ok':True,'primary':plan['primary'],'secondary':plan['secondary'],
                'fallback':'Solo resolver cifrati autenticati; nessun fallback DNS in chiaro per le query normali',
                'bootstrap_plain_dns':plan['bootstrap'],'suricata_rules_preview':suricata_rules(plan),
                'anti_dpi':dpi_preview(plan),'notes':['Il comando preview non modifica iptables né DNS.',
                'Per bloccare SNI serve Suricata IPS inline correttamente configurato.',
                'ECH/QUIC e TLS frammentato possono impedire visibilità SNI.']}
    fd=os.open(LOCK,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        owner=os.fstat(fd)
        if owner.st_uid!=0 or (owner.st_mode&0o077):fail('Lock DNS Guard non sicuro')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        return apply(plan)
    finally:os.close(fd)

if __name__=='__main__':
    try:print(json.dumps({'ok':True,'result':main()},ensure_ascii=False))
    except (PolicyError,ValueError,OSError,subprocess.TimeoutExpired) as ex:
        print(json.dumps({'ok':False,'error':str(ex)},ensure_ascii=False));sys.exit(1)
