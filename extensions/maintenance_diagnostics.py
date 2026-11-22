#!/usr/bin/env python3
"""IPTM diagnostic center: bounded, redacted, read-only probes and dry-run model.

Only own diagnostic artifacts can be deleted; NEVER vacuum the system journal.
Network-risk checks are read-only and explicitly opt-in. There is no
virtual rollback: the simulator never mutates live state.
"""
from __future__ import annotations
import collections, datetime as dt, fcntl, hashlib, ipaddress, itertools, json, math, os, pathlib, re, stat, subprocess, sys, tempfile, time, uuid, shutil, tomllib

ROOT=pathlib.Path('/var/lib/iptm-diagnostics')
RELEASE=pathlib.Path(__file__).resolve().parent.parent
STATE=ROOT/'state.json'
SECRET=re.compile(r'(?i)(password|passwd|token|secret|apikey|api[_-]?key|authorization|private[_ -]?key|cookie|psk|credential)(\s*[:=]\s*|\s+)([^\s,;]+)')
BEARER=re.compile(r'(?i)(bearer\s+)\S+')
JSON_SECRET=re.compile(r'(?i)([\"\'](?:password|passwd|access_token|refresh_token|api[_-]?key|token|secret|authorization|cookie|private_key|psk)[\"\']\s*:\s*[\"\'])[^\"\']*([\"\'])')
QUERYSECRET=re.compile(r'(?i)([?&](?:token|key|api_key|password|secret|access_token)=)[^&\s]+')
URLCRED=re.compile(r'(?i)(https?://)[^\s/@]+:[^\s/@]+@')
IP=re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
MAC=re.compile(r'(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b')
HOSTS=['IPTM','iptables-manager','php','pihole','pihole-FTL','dnscrypt','unbound','crowdsec','suricata','speedtest','nfqws','zapret','ip6tables','iptables','sudo','systemd']
UNIT_LIST=('pihole-FTL.service','dnscrypt-proxy.service','unbound.service','crowdsec.service','suricata.service','iptm-dns-boot-recover.service','iptm-sqm-calibrate.timer')
LIMIT=120000

def clean(text,limit=400):
    s=str(text)[:min(limit*3,40000)].replace('\x00',' ').replace('\r',' ')
    s=URLCRED.sub(r'\1[REDACTED]@',s)
    s=BEARER.sub(r'\1[REDACTED]',s)
    s=JSON_SECRET.sub(r'\1[REDACTED]\2',s)
    s=QUERYSECRET.sub(r'\1[REDACTED]',s)
    s=SECRET.sub(lambda m:m.group(1)+m.group(2)+'[REDACTED]',s)
    s=MAC.sub('[MAC]',IP.sub('[IP]',s))
    s=re.sub(r'(?i)(/etc/(?:shadow|ssh/ssh_host_\S+|.*\.key))','[SENSITIVE_PATH]',s)
    return s[:limit]

def ensure():
    if os.geteuid()!=0:raise ValueError('privilegi root richiesti')
    if ROOT.is_symlink() or ROOT.parent.is_symlink():raise ValueError('Directory diagnostica symlink')
    ROOT.mkdir(mode=0o700,parents=True,exist_ok=True)
    st=ROOT.stat()
    if st.st_uid!=0 or not stat.S_ISDIR(st.st_mode) or st.st_mode&0o077:raise ValueError('Directory diagnostica non protetta')

def locked():
    """Serialize start/clear; isolated from simulated state and never touches network."""
    ensure()
    lock=ROOT/".ops.lock"
    flags=os.O_CREAT|os.O_RDWR|getattr(os,"O_NOFOLLOW",0)
    fd=os.open(lock,flags,0o600)
    if os.fstat(fd).st_uid!=0 or os.fstat(fd).st_mode&0o077:
        os.close(fd);raise ValueError("Lock diagnostica non protetto")
    fcntl.flock(fd,fcntl.LOCK_EX)
    return fd

def atomic(p,data):
    ensure()
    if p.is_symlink():raise ValueError('File diagnostico simbolico')
    fd,temp=tempfile.mkstemp(dir=ROOT,prefix='.iptm-')
    try:
        with os.fdopen(fd,'w',encoding='utf-8') as f:
            os.fchmod(f.fileno(),0o600);json.dump(data,f,ensure_ascii=False,sort_keys=True);f.flush();os.fsync(f.fileno())
        os.replace(temp,p)
    finally:
        if os.path.exists(temp):os.unlink(temp)

def read(p):
    if p.is_symlink() or not p.is_file() or p.stat().st_size>2_000_000:return None
    if p.stat().st_uid!=0 or p.stat().st_mode&0o077:return None
    try:return json.loads(p.read_text(encoding='utf-8'))
    except (OSError,ValueError):return None

def probe(args,timeout=3,maxsize=2400):
    try:
        p=subprocess.run(args,stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=timeout,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
        return {'exit':p.returncode,'output':clean((p.stdout+'\n'+p.stderr)[:maxsize],maxsize)}
    except (OSError,subprocess.TimeoutExpired) as e:return {'exit':124,'output':clean(type(e).__name__)}

def system_info():
    out={'kernel':clean(os.uname().release,120),'architecture':clean(os.uname().machine,60),'time_utc':dt.datetime.now(dt.timezone.utc).isoformat(),
         'boot_id_prefix':'','system':'DietPi/Debian (non verificato)','services':{},'packages':{}}
    p=pathlib.Path('/etc/os-release')
    if p.is_file():
        for line in p.read_text(errors='replace')[:4096].splitlines():
            if line.startswith('PRETTY_NAME='):out['system']=clean(line.split('=',1)[1].strip('"'),120)
    boot=pathlib.Path('/proc/sys/kernel/random/boot_id')
    if boot.is_file():out['boot_id_prefix']=clean(boot.read_text()[:8],10)
    for unit in UNIT_LIST:
        r=probe(['/usr/bin/systemctl','show',unit,'--no-pager','--property=LoadState,ActiveState,SubState'],2,360)
        out['services'][unit]=r['output'].strip() if r['exit']==0 else 'stato non disponibile'
    for pkg in ('pihole-FTL','unbound','dnscrypt-proxy','crowdsec','suricata','iptables','nftables'):
        r=probe(['/usr/bin/dpkg-query','-W','-f=${Version}',pkg],2,180)
        out['packages'][pkg]=r['output'].strip() if r['exit']==0 else 'non verificato'
    out['cpu_memory']=probe(['/usr/bin/uptime'],2,220)['output']
    out['memory']=probe(['/usr/bin/free','-h'],2,360)['output']
    out['cpu_cores']=probe(['/usr/bin/nproc'],2,80)['output'].strip()
    recover=probe(['/usr/bin/systemctl','show','iptm-dns-boot-recover.service','--property=Type,Result,ExecMainStatus,ActiveState'],3,400)
    out['dns_boot_recover']=recover['output'].strip() if recover['exit']==0 else 'stato non disponibile'
    out['disk']=probe(['/usr/bin/df','-P','/'],2,260)['output']
    return out

def incidents():
    """Recent journald and explicitly allowlisted web/PHP error files, redacted."""
    rows=[]
    r=probe(['/usr/bin/journalctl','--since=-7 days','-p','emerg..err','--no-pager','-o','short-iso','-n','1200'],8,LIMIT)
    if r['exit']==0:
        for line in r['output'].splitlines()[:1200]:
            if any(x.lower() in line.lower() for x in HOSTS):rows.append(('journalctl',line))
    paths=('/var/log/lighttpd/error.log','/var/log/apache2/error.log','/var/log/nginx/error.log',
           '/var/log/php-fpm.log','/var/log/php8.2-fpm.log','/var/log/php8.3-fpm.log')
    for path in paths:
        p=pathlib.Path(path)
        if p.is_symlink() or not p.is_file() or p.stat().st_size>30*1024*1024:continue
        try:
            with p.open('rb') as stream:
                stream.seek(max(0,p.stat().st_size-250000))
                recent=stream.read(250001).decode('utf-8',errors='replace')
            for line in recent.splitlines()[-500:]:
                if ('error' in line.lower() or 'fatal' in line.lower() or 'IPTM' in line) and any(x.lower() in line.lower() for x in HOSTS):
                    rows.append((p.name,line))
        except (OSError,ValueError):continue
    counts=collections.OrderedDict()
    for source,line in rows[:1800]:
        ISO=re.search(r'\d{4}-\d{2}-\d{2}',line[:48])
        DAY=re.search(r'(?i)(\d{1,2})/([a-z]{3})/(\d{4})',line[:48])
        day=ISO.group(0) if ISO else 'sconosciuto'
        if DAY and not ISO:
            try:day=dt.datetime.strptime(DAY.group(0),'%d/%b/%Y').date().isoformat()
            except ValueError:pass
        if day != 'sconosciuto':
            try:
                if (dt.datetime.now(dt.timezone.utc).date()-dt.date.fromisoformat(day)).days>7:continue
            except ValueError:continue
        body=clean(line,430)
        inc=re.search(r'\bIPTM POST ([0-9a-f]{8,16})\b',body,re.I)
        incident=inc.group(1) if inc else ''
        sig=re.sub(r'\b[0-9a-f]{8,16}\b','[INCIDENT]',body,flags=re.I)
        sig=re.sub(r'\d+','#',sig)
        key=(day,hashlib.sha256((source+sig).encode()).hexdigest()[:12]);
        program=next((x for x in HOSTS if x.lower() in body.lower()),'web/php')
        if key not in counts:counts[key]={'id':key[1],'day':day,'count':0,'example':body,'source':source,'program':program,'incident':incident}
        counts[key]['count']+=1
    byday=collections.defaultdict(list)
    for obj in counts.values():byday[obj['day']].append(obj)
    return {'days':[{'date':d,'total':sum(x['count'] for x in rec),'entries':rec} for d,rec in sorted(byday.items(),reverse=True)],
            'count':len(rows),'source':'journalctl + log PHP/web noti','note':'Raccolta limitata e redatta, alcuni servizi potrebbero non avere un log disponibile'}

def catalog():
    src=RELEASE/'modules/00_bootstrap.php'
    content=src.read_text(encoding='utf-8')
    region=content.split('const SEC_FIELDS = [',1)[1].split('const BUILTIN =',1)[0]
    keys=re.findall(r"'([a-z][a-z0-9_]*)'\s*=>\s*'([a-z][a-z0-9_:.-]*)'",region)
    if len(keys)<100:raise ValueError('Catalogo simulazione non disponibile')
    # Duplicates from section-local and non-option dicts are harmless; name must be unique.
    seen=set();result=[]
    for name,typ in keys:
        if name in seen:continue
        seen.add(name)
        danger=bool(re.search(r'(drop|deny|lockout|spoof|block|ssh|mgmt|dns|wan|lan|nat|route|forward|rpfilter|knock|v6|ipv6|firewall|final)',name))
        result.append({'id':name,'type':typ,'risk':'network' if danger else 'normal'})
    return result

def schema_probe(typ):
    """Pure in-memory format/boundary probes; does NOT run IPTM business handlers."""
    if typ=='b':
        samples=[False,True]
        if not all(type(v) is bool for v in samples):raise ValueError('Boolean test failed')
        return 'boolean: false/true verificati in memoria'
    if typ.startswith('n:'):
        fields=typ.split(':')
        if len(fields)!=3:raise ValueError('Range numerico non valido')
        low,high=map(int,fields[1:])
        if not (0<=low<=high<=100000000):raise ValueError('Limiti numerici fuori schema')
        if not (low-1<low<=high<high+1):raise ValueError('Boundaries incoerenti')
        return f'numerico: limiti {low}..{high} verificati in memoria'
    if typ=='port':
        if not (1<=1<=65535 and not (0>=1) and not (65536<=65535)):raise ValueError('Porta fuori intervallo')
        return 'porta TCP/UDP: estremi 1..65535 simulati'
    if typ=='ports':
        values=(22,53,443)
        if not all(1<=p<=65535 for p in values):raise ValueError('Port list invalida')
        return 'porte: 22,53,443 simulate, nessun socket aperto'
    if typ in ('nets','ip'):
        v=ipaddress.ip_network('192.0.2.0/24') if typ=='nets' else ipaddress.ip_address('192.0.2.1')
        if v.version!=4:raise ValueError('Address family non valida')
        return 'indirizzi IPv4 di documentazione validati in memoria'
    if typ=='macs':
        if not re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}','02:00:00:00:00:01'):raise ValueError('MAC di test non valido')
        return 'MAC locale fittizio verificato in memoria'
    if typ in ('if','ifs'):
        if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}','eth-test0'):raise ValueError('Interfaccia fittizia non valida')
        return 'interfaccia fittizia verificata; nessun dispositivo aperto'
    if typ in ('chain','setname','prefix'):
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,28}','IPTM_SIM'):raise ValueError('Identificatore non valido')
        return 'nome fittizio: validazione del formato'
    if typ in ('rate','lrate'):
        if not re.fullmatch(r'[1-9][0-9]*/(?:second|minute|hour)','10/second'):raise ValueError('Rate di test non valido')
        return 'rate fittizio: 10/second, nessun limitatore modificato'
    raise ValueError('Tipo di opzione non previsto dal modello: '+typ)

# Combination coverage is generated deterministically, not by running privileged
# handlers. This catches missing interactions in the model without pretending to
# enumerate 2**N states or to prove packet forwarding on the real gateway.

def pairwise_boolean_matrix(options):
    names=sorted({o['id'] for o in options if o.get('type')=='b'})
    if len(names)>512:raise ValueError('Troppi interruttori nel catalogo diagnostico')
    if not names:return [],0,0
    if len(names)==1:return [{names[0]:False},{names[0]:True}],0,0
    # Two constant rows cover 0/0 and 1/1. Distinct equal-weight bit columns
    # are incomparable and cover 0/1 and 1/0 for EVERY pair. Exact coverage,
    # with O(log N) scenarios instead of exponential enumeration.
    m=2
    while math.comb(m,m//2)<len(names):m+=1
    if m>18:raise ValueError('Catalogo fuori budget per combinazioni')
    columns=list(itertools.islice(itertools.combinations(range(m),m//2),len(names)))
    matrix=[{name:False for name in names},{name:True for name in names}]
    for pos in range(m):
        matrix.append({name:pos in columns[i] for i,name in enumerate(names)})
    pairs=len(names)*(len(names)-1)//2
    # This construction guarantees all four values for each distinct pair.
    return matrix,pairs,pairs*4

def _field_samples(typ):
    """Two representative categories per field. They do NOT claim to cover
    every integer, string, list or networking boundary value.
    """
    if typ=='b':return (False,True)
    if typ.startswith('n:'):
        _,lo,hi=typ.split(':');return (int(lo),int(hi))
    return ('empty','provided')

def pairwise_field_matrix(options):
    fields=sorted({o['id']:o['type'] for o in options}.items())
    # Same covering construction as Boolean pairs; numeric/text fields use
    # representative categories instead of enumerating unbounded values.
    bits,pairs,coverage=pairwise_boolean_matrix([{'id':name,'type':'b'} for name,_ in fields])
    scenarios=[]
    for row in bits:
        scenarios.append({name:_field_samples(typ)[int(row[name])] for name,typ in fields})
    return scenarios,pairs,coverage

def critical_triple_summary(options):
    declared={o['id'] for o in options}
    # Real dependency families chosen for operational blast radius. Never
    # execute changes for any of the eight on/off assignments.
    triples=(
      ('dns_redirect','dot_block','quic_block'),
      ('final_drop','lockout_on','ssh_acc'),
      ('nat_masq','dns_redirect','lan_out_fwd'),
      ('crowdsec','cs_set_match','docker_accept'),
      ('wg_on','rpfilter','bogon_wan'),
      ('guest_on','iso_on','mac_only'),
      ('raw_drop','raw_invalid','final_drop'),
      ('dmz_on','closeports','egress_smtp'),
      ('icmp_limit','dos','lan_cl'),
      ('dns_redirect','guest_on','dhcp_accept'))
    found=[triplet for triplet in triples if set(triplet)<=declared]
    if len(found)!=len(triples):
        return diagnostic_result('combo:critical_triples','normal','unknown',
            'Una o più dipendenze critiche non sono nel catalogo di questa release','combinatorial/model')
    total=sum(len(list(itertools.product((False,True),repeat=3))) for _ in found)
    return diagnostic_result('combo:critical_triples','normal','pass',
        f'{len(found)} gruppi di 3 funzioni a rischio, {total} scenari di schema coperti; NON provati su firewall/DNS reali.',
        'combinatorial/model')

def _safe_settings():
    path=DRAFT_DIR/'settings.json'
    if DRAFT_DIR.is_symlink() or not DRAFT_DIR.is_dir():return None,'Archivio impostazioni non disponibile'
    try:
        fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_CLOEXEC',0))
        try:
            st=os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_size>2_000_000 or st.st_mode&0o002:
                return None,'Impostazioni non regolari, eccessive o accessibili in scrittura a tutti'
            with os.fdopen(os.dup(fd),'rb') as handle: raw=handle.read(2_000_001)
            if not raw or len(raw)>2_000_000:return None,'File impostazioni vuoto o eccessivo'
            val=json.loads(raw)
            if not isinstance(val,dict):return None,'Impostazioni non strutturate come oggetto'
            return val,None
        finally:os.close(fd)
    except (FileNotFoundError,PermissionError):return None,'Impostazioni salvate non leggibili'
    except (OSError,ValueError,UnicodeError):return None,'Impostazioni salvate non decodificabili'

def _enabled(value):
    return value is True or value==1 or value=='1' or value=='true'

def settings_combination_results(settings):
    # Each condition tests a declared dependency, NOT what a live controller
    # would do. Never include settings values, IPs, MACs or credentials in logs.
    checks=[]
    def add(name,trigger,requirements,label):
        if not trigger:
            status='skipped';detail='Combinazione non abilitata nelle impostazioni attuali'
        elif all(requirements.values()):
            status='pass';detail='Dipendenze configurate: '+label+' (efficacia live non verificata)'
        else:
            status='warning';detail='Combinazione incompleta: '+', '.join(k for k,ok in requirements.items() if not ok)+'; '+label
        checks.append(diagnostic_result('combo:'+name,'normal',status,detail,'model/saved-settings'))
    on=lambda x:_enabled(settings.get(x,0))
    valid=lambda x:bool(str(settings.get(x,'')).strip())
    add('nat_wan_lan',on('nat_masq'),{'WAN definita':valid('wan_if'),'LAN definite':valid('lan_nets')},'NAT + interfacce + LAN')
    add('dns_redirect_local',on('dns_redirect'),{'IP DNS disponibile':valid('dns_ip'),'LAN definite':valid('lan_nets')},'Redirect DNS + resolver locale')
    add('antispoof_sources',on('spoof_on'),{'interfaccia antispoof':valid('spoof_if'),'sottoreti antispoof':valid('spoof_nets')},'Antispoof e zone di origine')
    add('mac_allowlist',on('mac_only'),{'MAC consentiti':valid('mac_allow')},'MAC-only e inventario')
    add('guest_network',on('guest_on'),{'reti ospiti':valid('guest_nets'),'porte consentite':valid('guest_ports')},'Rete guest e DNS/DHCP')
    add('isolation_network',on('iso_on'),{'reti da isolare':valid('iso_nets')},'Isolamento IoT per sottorete')
    add('dmz',on('dmz_on'),{'indirizzo destinazione DMZ':valid('dmz_ip')},'DMZ e IP di destinazione')
    add('ssh_access',on('ssh_acc'),{'reti SSH consentite':valid('ssh_nets'),'porta SSH positiva':str(settings.get('ssh_acc_port','')).isdigit() and int(settings['ssh_acc_port'])>0},'SSH e ACL')
    add('wireguard',on('wg_on'),{'interfaccia WireGuard':valid('wg_if'),'porta WireGuard positiva':str(settings.get('wg_port','')).isdigit() and int(settings['wg_port'])>0},'WireGuard e firewall')
    add('port_knocking',on('knock_on'),{'porte sequenza':valid('knock_ports'),'porta bersaglio':valid('knock_target')},'Port knocking e accesso amministrativo')
    add('ui_protection',on('lockout_on'),{'porte gestione disponibili':valid('mgmt_ports'),'reti UI limitate':valid('ui_nets')},'Protezione UI: non bloccare l’accesso admin')
    sqm=settings.get('sqm') if isinstance(settings.get('sqm'),dict) else {}
    sqm_on=_enabled(sqm.get('on',0)); auto=_enabled(sqm.get('auto',0)) or _enabled(sqm.get('autocal',0))
    add('sqm_auto',auto,{'CAKE attivo':sqm_on,'interfaccia shaping':bool(sqm.get('iface')),
         'download valido':isinstance(sqm.get('down'),(int,float)) and sqm.get('down')>0,
         'upload valido':isinstance(sqm.get('up'),(int,float)) and sqm.get('up')>0},'Autocalibrazione Ookla e ultimo profilo CAKE')
    if on('final_drop') and on('lockout_on'):
        checks.append(diagnostic_result('combo:final_drop_lockout','network','warning',
            'DROP finale + lockout amministrativo: prima di applicare verifica ACL/porte, accesso SSH alternativo e watchdog di rollback','model/saved-settings'))
    if on('wg_on') and on('rpfilter'):
        checks.append(diagnostic_result('combo:wireguard_rpfilter','network','warning',
            'WireGuard + rpfilter: verificare eventuali instradamenti asimmetrici','model/saved-settings'))
    if on('dns_redirect') and on('dot_block') and on('quic_block'):
        checks.append(diagnostic_result('combo:anti_bypass_triple','network','unknown',
            'Redirect DNS + blocco DoT + QUIC: schema coerente, ma DoH e percorso DNS dei client non provati; verifica la navigazione da un client reale dopo un’applicazione con rollback','model/saved-settings'))
    v6=settings.get('v6') if isinstance(settings.get('v6'),dict) else {}
    if _enabled(v6.get('on')):
        disabled=ipv6_disabled_state()
        checks.append(diagnostic_result('combo:ipv6_policy_kernel','network',
           'warning' if disabled is True else ('unknown' if disabled is None else 'pass'),
           'Policy IPv6 richiesta ma IPv6 disabilitato nel kernel' if disabled is True else
           ('Stato IPv6 non verificabile' if disabled is None else 'IPv6 kernel abilitato; regole non applicate'),
           'model/kernel-read-only'))
    return checks

def combined_real_checks():
    """Read-only cross-subsystem checks. Never alter iptables or service state."""
    settings,error=_safe_settings()
    if settings is None:
        return [diagnostic_result('combo:live_saved_consistency','network','unknown',
            'Impostazioni non leggibili: '+error,'preflight/read-only')]
    results=[]
    rc,route=_command(['/usr/sbin/ip','-j','-4','route','show','default'],4,maxsize=9000)
    if rc==0:
        try: devs={r.get('dev') for r in json.loads(route) if isinstance(r,dict)}
        except (ValueError,TypeError):devs=set()
        saved=str(settings.get('wan_if','')).strip()
        results.append(diagnostic_result('combo:wan_saved_default','network',
          'pass' if saved and saved in devs else ('warning' if saved and devs else 'unknown'),
          'WAN salvata coincide con la route predefinita' if saved and saved in devs else
          ('WAN salvata diversa dalla route IPv4 predefinita' if saved and devs else 'WAN/route non confrontabili'),
          'preflight/read-only'))
    else:results.append(diagnostic_result('combo:wan_saved_default','network','unknown','Route IPv4 non leggibile','preflight/read-only'))
    if _enabled(settings.get('dns_redirect')):
        ports=_local_ports()
        ups=_pihole_upstreams()
        dnsip=bool(str(settings.get('dns_ip','')).strip())
        good=(ports is not None and 53 in ports and isinstance(ups,list) and
              any(re.search(r'(?:127\.0\.0\.1|::1)[#:](?:5335)\b',str(v)) for v in ups))
        results.append(diagnostic_result('combo:redirect_pihole_unbound','network',
          'pass' if dnsip and good else ('warning' if ports is not None and ups is not None else 'unknown'),
          'DNS redirect abilitato: IP DNS + listener 53 + upstream Unbound coerenti' if dnsip and good else
          'Controllare IP redirect, ascolto Pi-hole e upstream Unbound; catena non dimostrata',
          'preflight/read-only'))
    else:results.append(diagnostic_result('combo:redirect_pihole_unbound','network','skipped',
          'DNS redirect non attivo nelle impostazioni','preflight/read-only'))
    policies=settings.get('iot_policies',[])
    if isinstance(policies,(list,dict)) and policies:
        draft,reason=_safe_draft('draft.rules')
        results.append(diagnostic_result('combo:iot_policy_draft','network',
          'warning' if draft is None and reason!='Nessuna bozza presente' else ('unknown' if draft is None else 'pass'),
          'Policy IoT presente ma bozza non verificabile' if draft is None and reason!='Nessuna bozza presente' else
          ('Policy IoT salvata; nessuna bozza da collaudare. Genera anteprima policy MAC in Zone di rete, poi ripeti preflight (nessuna applicazione live)' if draft is None else
           'Policy IoT salvata e bozza presente; validità firewall controllata separatamente'),
          'preflight/read-only'))
    else:results.append(diagnostic_result('combo:iot_policy_draft','network','skipped',
          'Nessuna policy IoT salvata da confrontare','preflight/read-only'))
    if _enabled(settings.get('crowdsec')):
        rc,state=_command(['/usr/bin/systemctl','is-active','crowdsec.service'],3,maxsize=100)
        results.append(diagnostic_result('combo:crowdsec_service','network','pass' if rc==0 and state.strip()=='active' else 'warning',
            'CrowdSec selezionato e servizio attivo; bouncer e catene da validare separatamente' if rc==0 and state.strip()=='active' else
            'CrowdSec abilitato nella bozza ma servizio non attivo/verificabile','preflight/read-only'))
    return results

def pairwise_summary(options):
    matrix,pairs,covered=pairwise_field_matrix(options)
    return diagnostic_result('combo:pairwise_fields','normal','pass' if covered==pairs*4 else 'failed',
         f'{len(matrix)} scenari astratti; {len(options)} campi, {pairs} coppie e {covered}/{pairs*4} combinazioni di due classi coperte. Solo schema, NON prova live.',
         'combinatorial/model')

def combined_checks():
    opts=catalog()
    out=[pairwise_summary(opts),critical_triple_summary(opts)]
    settings,error=_safe_settings()
    if settings is None:
        out.append(diagnostic_result('combo:saved_configuration','normal','unknown',
             error+'; impossibile giudicare i conflitti sulla configurazione salvata','model/read-only'))
    else:
        out.append(diagnostic_result('combo:saved_configuration','normal','pass',
             'Impostazioni lette in sola lettura; controllate dipendenze e conflitti senza mostrare dati sensibili','model/read-only'))
        out.extend(settings_combination_results(settings))
    return out

# Tier 2 and 3: real, non-destructive checks. Every action is a bounded,
# explicit argv invocation, never a shell fragment or live controller call.
# Only the optional namespace check creates a transient, isolated network namespace.
DRAFT_DIR=pathlib.Path('/var/lib/iptables-manager')
LEVELS=('schema','preflight','isolated')

def _safe_draft(name):
    if DRAFT_DIR.is_symlink() or not DRAFT_DIR.is_dir():return None,'Directory bozza assente/non attendibile'
    p=DRAFT_DIR/name
    try:
        fd=os.open(p,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_CLOEXEC',0))
        try:
            st=os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or not (0<st.st_size<=2_097_152):return None,'Bozza non regolare o oltre 2 MiB'
            with os.fdopen(os.dup(fd),'rb') as f:data=f.read(2_097_153)
            if len(data)>2_097_152 or b'\x00' in data:return None,'Dimensioni/contenuto della bozza non validi'
            return data,None
        finally:os.close(fd)
    except FileNotFoundError:return None,'Nessuna bozza presente'
    except (OSError,ValueError):return None,'Lettura sicura della bozza non disponibile'

def _command(argv, timeout=5, content=None, maxsize=1000):
    try:
        args={'stdout':subprocess.PIPE,'stderr':subprocess.PIPE,'timeout':timeout,
              'env':{'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'}}
        if content is None:args['stdin']=subprocess.DEVNULL
        else:args['input']=content
        result=subprocess.run(argv,**args)
        message=(result.stdout+b'\n'+result.stderr)[:maxsize].decode('utf-8','replace')
        return result.returncode,clean(message,maxsize)
    except subprocess.TimeoutExpired:return 124,'Timeout del controllo non distruttivo'
    except OSError:return 127,'Programma non disponibile'

def diagnostic_result(name, risk, status, message, mode='preflight/read-only'):
    if status not in ('pass','warning','unknown','failed','skipped'):status='unknown'
    return {'option':name,'risk':risk,'mode':mode,'result':status,'detail':clean(message,370)}

def ipv6_disabled_state():
    """Return True only for confirmed fully-disabled IPv6, never infer it from
    ip6tables-restore failures. Mirrors the privileged helper's v6cap logic.
    """
    path=pathlib.Path('/proc/sys/net/ipv6/conf')
    mod=pathlib.Path('/sys/module/ipv6/parameters/disable')
    cmd=pathlib.Path('/proc/cmdline')
    try:
        boot_disabled=(mod.is_file() and mod.read_text().strip()=='1') or (
            cmd.is_file() and bool(re.search(r'(?:^|\s)ipv6\.disable=1(?:\s|$)',cmd.read_text()[:4096])))
        if boot_disabled:
            iface=pathlib.Path('/proc/net/if_inet6')
            return True if not iface.exists() or iface.stat().st_size==0 else False
        required=[path/'all'/'disable_ipv6',path/'default'/'disable_ipv6']
        if not all(p.is_file() for p in required):return None
        value=[p.read_text().strip() for p in required]
        if any(x not in ('0','1') for x in value):return None
        if '0' in value:return False
        for p in path.glob('*/disable_ipv6'):
            if p.parent.name in ('all','default','lo'):continue
            v=p.read_text().strip()
            if v=='0':return False
            if v!='1':return None
        return True
    except (OSError,UnicodeError):return None

def firewall_candidate(family=4,namespace=False):
    name='draft.rules' if family==4 else 'draft6.rules'
    content,err=_safe_draft(name)
    check='firewall:draft_v'+str(family)+('_namespace' if namespace else '_syntax')
    mode='isolated/netns' if namespace else 'preflight/read-only'
    if content is None:return diagnostic_result(check,'network','skipped' if err=='Nessuna bozza presente' else 'unknown',err,mode)
    if family==6 and ipv6_disabled_state() is True:
        return diagnostic_result(check,'network','skipped',
            'IPv6 disabilitato esplicitamente nel kernel: bozza v6 non applicabile, test del backend evitato',mode)
    text=content.decode('utf-8','replace')
    count=len(re.findall(r'(?m)^-A ',text))
    mac_rules=re.findall(r'(?m)^-A .*--mac-source\s[^\n]*',text)
    mac_count=len(mac_rules)
    if family==4 and any(not re.search(r'(?:^|\s)-m\s+mac(?:\s|$)',line) for line in mac_rules):
        return diagnostic_result(check,'network','failed','Bozza IoT contiene --mac-source senza match -m mac',mode)
    extra=('; regole MAC '+str(mac_count)) if family==4 else ''
    command='/usr/sbin/iptables-restore' if family==4 else '/usr/sbin/ip6tables-restore'
    if namespace:
        unshare=shutil.which('unshare')
        if not unshare:return diagnostic_result(check,'network','unknown','unshare non installato: test namespace non eseguito',mode)
        # --test never commits rules, even inside the ephemeral namespace.
        args=[unshare,'--net','--',command,'--test']
    else:args=[command,'--test']
    rc,message=_command(args,7,content,1100)
    if namespace and rc!=0 and ('not permitted' in message.lower() or 'operation not permitted' in message.lower() or rc==127):
        return diagnostic_result(check,'network','unknown','Namespace non disponibile (permessi/capacità); nessun intervento sul firewall host',mode)
    if rc!=0:
        # iptables-restore --test still resolves set names. Network namespaces
        # do not clone the host ipset namespace; absence is an isolated-fixture
        # dependency, not evidence of malformed rule syntax. Keep the failure
        # visible as unknown, never as a pass and never mutate the host ipsets.
        if namespace and re.search(r'Set [A-Za-z0-9_.:-]{1,80} doesn.t exist',message,re.I):
            return diagnostic_result(check,'network','unknown',
                'Test isolato incompleto: ipset usato dalla bozza non presente nel namespace. Nessuna regola applicata; verificare le dipendenze ipset in un ambiente di prova.',mode)
        unavailable=rc in (124,127) or any(x in message.lower() for x in (
            'permission denied','operation not permitted','could not fetch rule set generation id'))
        # A missing legacy ip6tables filter table is not evidence that the
        # candidate syntax is wrong. The gateway may have IPv6 disabled.
        if family==6 and "unable to initialize table 'filter'" in message.lower():
            return diagnostic_result(check,'network','unknown',
                'Backend ip6tables-legacy senza tabella filter; verificare IPv6 e moduli kernel. Bozza non giudicabile.',mode)
        return diagnostic_result(check,'network','unknown' if unavailable else 'failed',
            f'Test iptables-restore --test non superato (exit {rc}); {message[:240]}',mode)
    # Syntax can be valid even if no packet would match. Don't claim forwarding works.
    return diagnostic_result(check,'network','pass',
        f'Bozza {family}: {count} regole, test kernel --test superato{extra}. Non prova connettività o efficacia MAC',mode)

def network_interfaces():
    rc,out=_command(['/usr/sbin/ip','-j','-d','link','show'],4,maxsize=45000)
    if rc:return diagnostic_result('network:interfaces','network','unknown','Inventario interfacce non disponibile: '+out[:120])
    try:
        arr=json.loads(out)
        names=[x.get('ifname') for x in arr if isinstance(x,dict) and isinstance(x.get('ifname'),str)]
        wan_present='bond0' in names
        info=f'Interfacce rilevate: {len(names)}; bond0 '+('presente' if wan_present else 'assente')
        return diagnostic_result('network:interfaces','network','pass',info+'; non verifica che bond0 sia la WAN')
    except (ValueError,TypeError):return diagnostic_result('network:interfaces','network','unknown','Output ip -j non interpretabile')

def forwarding_info():
    rc,out=_command(['/usr/sbin/ip','-j','-4','route','show','default'],4,maxsize=9000)
    if rc:return diagnostic_result('network:default_route','network','unknown','Route non disponibili')
    try:
        routes=json.loads(out)
        devs=[r.get('dev','?') for r in routes if isinstance(r,dict)]
    except (ValueError,TypeError):return diagnostic_result('network:default_route','network','unknown','Route JSON non interpretabili')
    f=pathlib.Path('/proc/sys/net/ipv4/ip_forward')
    try:fw=f.read_text().strip()
    except OSError:fw='?'
    return diagnostic_result('network:default_route','network','pass' if routes else 'warning',
        'Route predefinite '+str(len(routes))+' su '+','.join(devs[:4])+'; IPv4 forwarding='+fw+'; non prova il percorso client')

def _local_ports():
    rc,output=_command(['/usr/bin/ss','-H','-lntu'],4,maxsize=24000)
    if rc:return None
    # check only port existence; do not expose local socket addresses in output
    ports=set()
    for line in output.splitlines():
        fields=line.split()
        if len(fields)>=5:
            match=re.search(r':(\d{1,5})$',fields[4])
            if match:ports.add(int(match.group(1)))
    return ports

def _pihole_upstreams():
    p=pathlib.Path('/etc/pihole/pihole.toml')
    if p.is_symlink() or not p.is_file():return None
    try:
        if p.stat().st_size>800_000:return None
        with p.open('rb') as f:doc=tomllib.load(f)
        dns=doc.get('dns',{})
        values=dns.get('upstreams') if isinstance(dns,dict) else None
        return values if isinstance(values,list) else None
    except (OSError,ValueError,TypeError):return None

def _unbound_forward_local():
    # Conservative heuristic: includes may be nested or templates, so 'unknown'
    # when a local forwarder is not visible in managed snippets.
    files=[pathlib.Path('/etc/unbound/unbound.conf')]
    configdir=pathlib.Path('/etc/unbound/unbound.conf.d')
    if configdir.is_dir() and not configdir.is_symlink():files+=sorted(configdir.glob('*.conf'))[:50]
    found=False
    for p in files:
        try:
            if p.is_symlink() or p.stat().st_size>600000:continue
            txt=p.read_text(errors='replace')
        except OSError:continue
        # match forward-addr directives to localhost port 5053, no user secrets
        if re.search(r'(?m)^\s*forward-addr\s*:\s*(?:127\.0\.0\.1|::1)@5053\b',txt):found=True
    return found

def dns_config_preflight():
    checks=[];ports=_local_ports()
    if ports is None:
        checks.append(diagnostic_result('dns:listeners','normal','unknown','ss non disponibile; porte 53/5335/5053 non verificate'))
    else:
        present=[str(i) for i in (53,5335,5053) if i in ports]
        checks.append(diagnostic_result('dns:listeners','normal','pass' if len(present)==3 else 'warning',
            'Porte DNS in ascolto (qualunque interfaccia): '+(','.join(present) if present else 'nessuna')+'; non identifica processo o binding loopback'))
    ups=_pihole_upstreams()
    if ups is None:msg='Upstream Pi-hole non leggibili; non confermabile la catena'
    else:
        local=any(re.search(r'(?i)(?:127\.0\.0\.1|::1)[#:](?:5335)\b',str(x)) for x in ups)
        msg='Pi-hole punta a Unbound sulla porta 5335' if local else 'Pi-hole non risulta puntare a 5335; controlla modalità DNS selezionata'
    checks.append(diagnostic_result('dns:pihole_upstream','normal','unknown' if ups is None else ('pass' if local else 'warning'),msg))
    forward=_unbound_forward_local()
    checks.append(diagnostic_result('dns:unbound_forward','normal','pass' if forward else 'unknown',
        'Forward Unbound → DNSCrypt 5053 trovato' if forward else 'Forward Unbound → DNSCrypt non rilevato: può essere corretta una diversa architettura DNS'))
    rc,_=_command(['/usr/sbin/unbound-checkconf'],5,maxsize=450)
    checks.append(diagnostic_result('dns:unbound_syntax','normal','pass' if rc==0 else ('unknown' if rc in (124,127) else 'failed'),
        'unbound-checkconf: '+('OK' if rc==0 else f'controllo non riuscito (exit {rc})')))
    # Debian supports binary at either path; no service restart or request.
    dnscrypt=shutil.which('dnscrypt-proxy')
    if dnscrypt:
        rc,_=_command([dnscrypt,'-check','-config','/etc/dnscrypt-proxy/dnscrypt-proxy.toml'],5,maxsize=450)
        checks.append(diagnostic_result('dns:dnscrypt_syntax','normal','pass' if rc==0 else ('unknown' if rc in (124,127) else 'warning'),
            'dnscrypt-proxy -check: '+('OK' if rc==0 else f'non verificato (exit {rc}; percorso config da confermare)')))
    else:checks.append(diagnostic_result('dns:dnscrypt_syntax','normal','unknown','Binario dnscrypt-proxy non disponibile nel PATH'))
    return checks

def dns_loopback_probes():
    # Optional active but non-mutating-configuration DNS queries. The resolver
    # cache may be updated, so they are never run without the network opt-in.
    dig=shutil.which('dig')
    if not dig:return [diagnostic_result('dns:loopback_queries','network','unknown','dig non installato; query locali non disponibili')]
    answers=[]
    for name,port in (('pihole',53),('unbound',5335),('dnscrypt',5053)):
        rc,response=_command([dig,'+time=2','+tries=1','+short','@127.0.0.1','-p',str(port),'example.com','A'],4,maxsize=400)
        answered=(rc==0 and '[IP]' in response)
        answers.append(diagnostic_result('dns:'+name+'_query','network','pass' if answered else 'warning',
            name+' porta '+str(port)+(': risposta A ricevuta (non prova forwarding specifico/DNSSEC)' if answered else ': nessuna risposta A valida sul loopback (exit '+str(rc)+')')))
    return answers

def recovery_preflight():
    rc,out=_command(['/usr/bin/systemctl','show','iptm-dns-boot-recover.service',
        '--property=LoadState,ActiveState,Type,Result,ExecMainStatus,ExecMainStartTimestampMonotonic,UnitFileState'],5,maxsize=900)
    if rc:return diagnostic_result('dns:boot_recovery','normal','unknown','systemctl show non riuscito')
    props=dict(row.split('=',1) for row in out.splitlines() if '=' in row)
    if props.get('LoadState')!='loaded':return diagnostic_result('dns:boot_recovery','normal','warning','Servizio di recupero non caricato')
    starttime=props.get('ExecMainStartTimestampMonotonic','0')
    enabled=props.get('UnitFileState') in ('enabled','enabled-runtime')
    good=(props.get('Type')=='oneshot' and props.get('Result')=='success'
          and props.get('ExecMainStatus')=='0' and starttime.isdecimal()
          and int(starttime)>0 and enabled)
    message=(('oneshot completato correttamente' if good else 'esito boot non dimostrato')+'; '+
        'type='+props.get('Type','?')+', result='+props.get('Result','?')+', exit='+props.get('ExecMainStatus','?'))
    # Dead is expected for a successful oneshot; check it ran this boot and is enabled.
    return diagnostic_result('dns:boot_recovery','normal','pass' if good else 'warning',message)

def pending_firewall():
    p=DRAFT_DIR/'pending.json'
    if p.is_symlink():return diagnostic_result('firewall:rollback_pending','normal','warning','Pending firewall simbolico: verificare da console')
    return diagnostic_result('firewall:rollback_pending','normal','warning' if p.exists() else 'pass',
        'Rollback firewall pendente: NON procedere con apply' if p.exists() else 'Nessuna transazione firewall pendente rilevata')

def real_preflight_tests(level,include_network):
    tests=[('dns:config',False,lambda:dns_config_preflight()),
           ('dns:boot_recovery',False,lambda:[recovery_preflight()]),
           ('firewall:rollback_pending',False,lambda:[pending_firewall()])]
    if include_network:
        tests.extend([('network:interfaces',True,lambda:[network_interfaces()]),
                      ('network:default_route',True,lambda:[forwarding_info()]),
                      ('firewall:draft_v4',True,lambda:[firewall_candidate(4)]),
                      ('firewall:draft_v6',True,lambda:[firewall_candidate(6)]),
                      ('dns:loopback_queries',True,lambda:dns_loopback_probes())])
        tests.append(('combinations:live',True,combined_real_checks))
        if level=='isolated':
            tests.extend([('firewall:namespace_v4',True,lambda:[firewall_candidate(4,True)]),
                          ('firewall:namespace_v6',True,lambda:[firewall_candidate(6,True)])])
    return tests

def snapshot(payload):
    record={'ok':True,'system':system_info(),'incidents':incidents(),'runs':[]}
    for p in sorted(ROOT.glob('run-*.json'),reverse=True)[:10]:
        j=read(p)
        if isinstance(j,dict):record['runs'].append({k:j.get(k) for k in ('id','status','started','completed','total','passed','skipped','failed','warning','unknown','include_network','level')})
    record['state']=status()['state']
    return record

def status():
    st=read(STATE) or {'status':'idle','progress':0}
    if st.get('status')=='running' and time.time()-st.get('updated',0)>150:st.update(status='stale',message='Worker non risponde: verificare il journal e ripetere')
    rid=str(st.get('id',''))
    if re.fullmatch(r'[a-f0-9]{20}',rid):
        r=read(ROOT/('run-'+rid+'.json'))
        if r:st['run']=r
    return {'ok':True,'state':st}

def record_run(r):
    atomic(ROOT/('run-'+r['id']+'.json'),r)
    atomic(STATE,{k:r.get(k) for k in ('id','status','progress','updated','total','passed','skipped','failed','include_network','level','warning','unknown','message')})

def worker(rid,include_network,level='preflight'):
    ensure()
    if level not in LEVELS:raise ValueError('Livello diagnostico non valido')
    opts=catalog()
    basics=[{'id':'programs:service_inventory','risk':'normal','type':'read-only'},
            {'id':'dns:stack_inventory','risk':'normal','type':'read-only'},
            {'id':'qos:software_inventory','risk':'normal','type':'read-only'},
            {'id':'firewall:live_readonly','risk':'network','type':'read-only'}]+opts
    extras=real_preflight_tests(level,include_network) if level!='schema' else []
    if level!='schema':extras.append(('combinations:all',False,combined_checks))
    total=len(basics)+len(extras)
    option_ids={x['id'] for x in opts}
    r={'id':rid,'started':dt.datetime.now(dt.timezone.utc).isoformat(),
       'status':'running','updated':time.time(),'progress':0,'total':total,
       'passed':0,'skipped':0,'failed':0,'warning':0,'unknown':0,
       'level':level,'include_network':include_network,'results':[],'system':system_info(),
       'disclaimer':'Schema e matrice combinatoria in memoria + configurazione salvata in sola lettura; preflight e namespace quando selezionati. Non viene eseguita alcuna combinazione live e non è provata la connettività dei client.'}
    record_run(r)
    def emit(item,step,group=None):
        item.setdefault('elapsed_ms',round((time.monotonic()-step)*1000,1))
        if group:item['group']=group
        r['results'].append(item)
        result=item['result']
        if result=='pass':r['passed']+=1
        elif result=='skipped':r['skipped']+=1
        elif result=='failed':r['failed']+=1
        elif result=='warning':r['warning']+=1
        else:r['unknown']+=1
    try:
        for ix,test in enumerate(basics):
            before=time.monotonic()
            item={'option':test['id'],'risk':test['risk'],'mode':'schema/read-only','result':'pass','detail':'Check dichiarativo; non equivale a test end-to-end.'}
            if test['risk']=='network' and not include_network:
                item.update(result='skipped',detail='Opzione a rischio rete esclusa su richiesta')
            elif test['id']=='firewall:live_readonly':
                check=probe(['/usr/sbin/iptables-save'],4,500)
                item.update(result='pass' if check['exit']==0 else 'unknown',detail='Snapshot iptables di sola lettura: '+('OK' if check['exit']==0 else 'indisponibile'))
            elif test['id']=='programs:service_inventory':item.update(detail='Snapshot versioni/stati programmi senza avvio servizi')
            elif test['id']=='dns:stack_inventory':item.update(detail='Inventario DNS, non equivale a risoluzione corretta')
            elif test['id']=='qos:software_inventory':item.update(detail='Inventario QoS; CAKE invariato, nessuno speedtest')
            elif not re.fullmatch(r'[a-z][a-z0-9_]*',test['id']):item.update(result='failed',detail='Nome opzione fuori schema')
            elif test['id'] in option_ids:
                try:item['detail']=schema_probe(test['type'])+'; nessun controller live richiamato'
                except (ValueError,TypeError) as error:item.update(result='failed',detail=clean(error,180))
            emit(item,before,'schema')
            r['progress']=int((ix+1)/total*100);r['updated']=time.time();r['message']=test['id']
            if ix%5==0 or ix==len(basics)-1:record_run(r)
        for i,(check_id,network,check_func) in enumerate(extras):
            before=time.monotonic()
            try:items=check_func()
            except (OSError,ValueError,TypeError) as error:
                items=[diagnostic_result(check_id,'network' if network else 'normal','unknown','Probe non disponibile: '+type(error).__name__)]
            for item in items:emit(item,before,'combinations' if check_id.startswith('combinations:') else ('preflight' if level!='isolated' or 'namespace' not in check_id else 'isolated'))
            r['progress']=int((len(basics)+i+1)/total*100)
            r['updated']=time.time();r['message']=check_id
            record_run(r)
        r['status']='completed';r['completed']=dt.datetime.now(dt.timezone.utc).isoformat()
        r['total']=len(r['results'])
        r['message']='Diagnostica terminata: '+str(r['failed'])+' falliti, '+str(r['warning'])+' avvisi, '+str(r['unknown'])+' non verificabili; nessuna modifica live'
    except Exception as error:
        r['status']='failed';r['completed']=dt.datetime.now(dt.timezone.utc).isoformat()
        r['message']='Errore worker: '+clean(type(error).__name__,80);r['failed']+=1
    record_run(r)

def start(payload):
    fd=locked()
    try:
        current=status()['state']
        if current.get('status')=='running':return {'ok':False,'error':'Simulazione già in esecuzione'}
        include_network=bool(payload.get('include_network')) if isinstance(payload,dict) else False
        level=payload.get('level','preflight') if isinstance(payload,dict) else 'preflight'
        if level not in LEVELS:return {'ok':False,'error':'Livello di simulazione non valido'}
        rid=uuid.uuid4().hex[:20]
        atomic(STATE,{'id':rid,'status':'running','updated':time.time(),'progress':0,'message':'Worker in preparazione','include_network':include_network,'level':level})
        # Detached worker continues after PHP request returns. argv contains no user input.
        try:
            proc=subprocess.Popen([sys.executable,'-B',str(pathlib.Path(__file__).resolve()),'_worker',rid,'1' if include_network else '0',level],
                stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,close_fds=True,start_new_session=True)
        except OSError:
            atomic(STATE,{'id':rid,'status':'failed','updated':time.time(),'progress':0,'message':'Avvio worker non disponibile'})
            return {'ok':False,'error':'Impossibile avviare il worker'}
        return {'ok':True,'id':rid,'pid':proc.pid,'changes_live':False}
    finally:
        os.close(fd)

def clear():
    fd=locked()
    try:
        if status()['state'].get('status')=='running':return {'ok':False,'error':'Attendere il termine della simulazione'}
        count=0
        for p in list(ROOT.glob('run-*.json'))+[STATE]:
            if p.is_file() and not p.is_symlink():p.unlink();count+=1
        return {'ok':True,'cleared':count,'note':'Solo report IPTM eliminati; journald non viene cancellato'}
    finally:
        os.close(fd)

def main():
    ensure()
    action=sys.argv[1] if len(sys.argv)>=2 else ''
    if action=='_worker' and len(sys.argv)==5 and re.fullmatch(r'[a-f0-9]{20}',sys.argv[2]) and sys.argv[3] in ('0','1') and sys.argv[4] in LEVELS:
        worker(sys.argv[2],sys.argv[3]=='1',sys.argv[4]);return {'ok':True}
    if len(sys.argv)!=2:return {'ok':False,'error':'Numero argomenti errato'}
    if action in ('snapshot','status'):return snapshot({}) if action=='snapshot' else status()
    if action=='start':
        raw=sys.stdin.buffer.read(3000)
        return start(json.loads(raw) if raw else {})
    if action=='clear':return clear()
    return {'ok':False,'error':'Operazione non autorizzata'}

if __name__=='__main__':
    try:print(json.dumps(main(),ensure_ascii=False))
    except Exception as e:
        print(json.dumps({'ok':False,'error':clean(type(e).__name__+': '+str(e),180)},ensure_ascii=False));sys.exit(1)
