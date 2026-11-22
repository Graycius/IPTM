#!/usr/bin/env python3
"""IPTM maintenance engine: conservative Pi-hole DB imports and sysctl transactions.

All write operations are opt-in. Pi-hole changes are restricted to the supported
SQLite tables after schema inspection; sysctl changes are restricted to an
explicit allow-list and IPTM-owned configuration file.
"""
from __future__ import annotations
import argparse, atexit, csv, datetime, fcntl, ipaddress, json, os, pathlib, re, shutil, sqlite3, subprocess, sys, tempfile, time, urllib.request, urllib.parse, urllib.error
from contextlib import contextmanager
from typing import Optional, List

DATA = pathlib.Path('/var/lib/iptables-manager')
RETHINK_SCRIPT = pathlib.Path('/usr/local/lib/iptables-manager/web/releases/5.30.4/extensions/rethink_catalog.py')
DB_CANDIDATES = [pathlib.Path('/etc/pihole/gravity.db'), pathlib.Path('/var/lib/pihole/gravity.db')]
SYSCTL_FILE = pathlib.Path('/etc/sysctl.d/98-iptm-hardening.conf')
BACKUP_DIR = DATA / 'backups' / 'maintenance'

def ookla_speedtest_present() -> bool:
    """Match the measurement engine policy: a native Ookla executable is required."""
    binary = shutil.which('speedtest')
    if not binary:
        return False
    try:
        with pathlib.Path(binary).resolve(strict=True).open('rb') as handle:
            return handle.read(4) == b'\x7fELF'
    except (OSError, ValueError, RuntimeError):
        return False

def rotate_backup_files(folder: pathlib.Path, name_regex: str, keep: int = 10) -> int:
    """Prune only completed regular backup files, newest 10; no symlink traversal."""
    if not 1 <= keep <= 100: raise ValueError('retention invalid')
    folder=pathlib.Path(folder)
    if folder.is_symlink() or not folder.is_dir(): return 0
    match=re.compile(name_regex).fullmatch
    entries=[]
    with os.scandir(folder) as items:
        for item in items:
            if not match(item.name) or item.is_symlink(): continue
            try: st=item.stat(follow_symlinks=False)
            except OSError: continue
            if not (st.st_mode & 0o170000)==0o100000: continue
            entries.append((st.st_mtime_ns,item.name,st.st_ino))
    entries.sort(reverse=True)
    deleted=0
    for _,name,ino in entries[keep:]:
        target=folder/name
        try:
            st=target.lstat()
            if st.st_ino!=ino or not (st.st_mode & 0o170000)==0o100000: continue
            target.unlink();deleted+=1
        except FileNotFoundError:pass
    return deleted

# Curated seed catalogue. Entries are optional and disabled until explicitly selected.
# URLs are identifiers, not a claim that remote content has been audited or is currently reachable.
CATALOG = [
('StevenBlackUnified','https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts','General','Unified hosts list'),
('StevenBlackFakenews','https://raw.githubusercontent.com/StevenBlack/hosts/master/ alternates/fakenews/hosts','Misinformation','Optional category list'),
('OISDMalware','https://raw.githubusercontent.com/sjhgvr/oisd/main/domainswild_big.txt','Malware','OISD Big'),
('OISDSmall','https://raw.githubusercontent.com/sjhgvr/oisd/main/domainswild_small.txt','General','OISD Small'),
('HaGeZiPro','https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt','General','HaGeZi Pro'),
('HaGeZiNormal','https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/normal.txt','General','HaGeZi Normal'),
('HaGeZiMultiPro','https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/multi-pro.txt','General','HaGeZi Multi Pro'),
('HaGeZiTIF','https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/tif.txt','Threat intel','Threat intelligence feeds'),
('HaGeZiFake','https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/fake.txt','Scam','Fake and scam domains'),
('HaGeZiDynDNS','https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/dyndns.txt','Dynamic DNS','Dynamic DNS domains'),
('AdAway','https://adaway.org/hosts.txt','Advertising','AdAway hosts'),
('AdGuardDNS','https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt','Advertising','AdGuard DNS filter'),
('AdGuardTracking','https://adguardteam.github.io/HostlistsRegistry/assets/filter_3.txt','Tracking','AdGuard tracking protection'),
('AdGuardSocial','https://adguardteam.github.io/HostlistsRegistry/assets/filter_ ಸಾಮಾಜಿಕ.txt','Social','Optional social filter'),
('EasyList','https://easylist.to/easylist/easylist.txt','Advertising','EasyList'),
('EasyPrivacy','https://easylist.to/easylist/easyprivacy.txt','Tracking','EasyPrivacy'),
('EasyListCookie','https://secure.fanboy.co.nz/fanboy-cookiemonster.txt','Cookies','Cookie notices'),
('FanboyAnnoyance','https://easylist.to/easylist/fanboy-annoyance.txt','Annoyances','Fanboy annoyances'),
('PeterLowe','https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext','Advertising','Peter Lowe adservers'),
('DisconnectTracking','https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt','Tracking','Disconnect tracking'),
('DisconnectMalvertising','https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt','Malware','Disconnect malvertising'),
('URLHaus','https://urlhaus.abuse.ch/downloads/hostfile/','Malware','abuse.ch URLhaus'),
('PhishingArmy','https://phishing.army/download/phishing_army_blocklist.txt','Phishing','Phishing Army'),
('OpenPhish','https://openphish.com/feed.txt','Phishing','OpenPhish community feed'),
('CERTPL','https://hole.cert.pl/domains/v2/domains.txt','Malware','CERT Polska domains'),
('Spam404','https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt','Malware','Spam404 blacklist'),
('DandelionSproutAntiMalware','https://raw.githubusercontent.com/DandelionSprout/adfilt/master/AntiMalwareHosts.txt','Malware','Anti-malware hosts'),
('GoodbyeAds','https://raw.githubusercontent.com/jerryn70/GoodbyeAds/master/Hosts/GoodbyeAds.txt','Advertising','Goodbye Ads'),
('AnudeepAds','https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt','Advertising','Anudeep adservers'),
('StevenBlackFakeNews','https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews/hosts','Misinformation','StevenBlack fake news domains'),
('WindowsSpy','https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt','Telemetry','Windows telemetry'),
('WindowsSpyExtra','https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/extra.txt','Telemetry','Windows telemetry extra'),
('AppleTracking','https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/AdGuard/Apple/Apple.txt','Telemetry','Apple endpoints'),
('SamsungTracking','https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV.txt','IoT','Smart TV endpoints'),
('LGWebOS','https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/LGwebOS.txt','IoT','LG webOS endpoints'),
('Vizio','https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/Vizio.txt','IoT','Vizio TV endpoints'),
('AmazonFireTV','https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/AmazonFireTV.txt','IoT','Amazon Fire TV endpoints'),
('Roku','https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/Roku.txt','IoT','Roku endpoints'),
('Xiaomi','https://raw.githubusercontent.com/StevenBlack/hosts/master/ alternates/xiaomi/hosts','Telemetry','Xiaomi endpoints'),
('NoTrack','https://raw.githubusercontent.com/quidsup/notrack/master/trackers.txt','Tracking','NoTrack trackers'),
('Hblock','https://hblock.molinero.dev/hosts','General','Hblock hosts'),
('BlocklistProjectAds','https://blocklistproject.github.io/Lists/ads.txt','Advertising','Blocklist Project ads'),
('BlocklistProjectMalware','https://blocklistproject.github.io/Lists/malware.txt','Malware','Blocklist Project malware'),
('BlocklistProjectPhishing','https://blocklistproject.github.io/Lists/phishing.txt','Phishing','Blocklist Project phishing'),
('BlocklistProjectFraud','https://blocklistproject.github.io/Lists/fraud.txt','Scam','Blocklist Project fraud'),
('BlocklistProjectRansomware','https://blocklistproject.github.io/Lists/ransomware.txt','Malware','Blocklist Project ransomware'),
('BlocklistProjectRedirect','https://blocklistproject.github.io/Lists/redirect.txt','Tracking','Blocklist Project redirects'),
('MalwareDomainList','https://www.malwaredomainlist.com/hostslist/hosts.txt','Malware','Malware Domain List'),
('KADhosts','https://raw.githubusercontent.com/BlackJack8/iOSAdblockList/master/Hosts.txt','Advertising','KAD hosts'),
('Phishing.Database','https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/hosts','Phishing','Phishing Database'),
('ShadowWhispererAds','https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Ads','Advertising','ShadowWhisperer advertising'),
('ShadowWhispererMalware','https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Malware','Malware','ShadowWhisperer malware'),
('ShadowWhispererTracking','https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Tracking','Tracking','ShadowWhisperer tracking'),
]
# Fix accidental non-ASCII/placeholder URLs to valid stable feeds or remove by validation on catalog output.
CATALOG = [(i,u,c,d) for i,u,c,d in CATALOG if ' ' not in u and ' ' not in i]

# Regex opt-in per host/domain DNS, NON URL. Verificate sintatticamente e su esempi
# positivi/negativi; l'impatto reale va validato nel Pi-hole locale prima di attivare.
REGEX_CATALOG = [
('doubleclick','DoubleClick','doubleclick.net','Advertising','medium'),
('googlesyndication','Google Syndication','googlesyndication.com','Advertising','medium'),
('googleadservices','Google AdServices','googleadservices.com','Advertising','medium'),
('googleanalytics','Google Analytics','google-analytics.com','Analytics','medium'),
('googletagmanager','Google Tag Manager','googletagmanager.com','Analytics','high'),
('2mdn','2mdn','2mdn.net','Advertising','medium'),
('adnxs','AppNexus','adnxs.com','Advertising','medium'),
('adsrvr','The Trade Desk','adsrvr.org','Advertising','medium'),
('rubicon','Rubicon Project','rubiconproject.com','Advertising','medium'),
('pubmatic','PubMatic','pubmatic.com','Advertising','medium'),
('openx','OpenX','openx.net','Advertising','medium'),
('criteo','Criteo','criteo.com','Advertising','medium'),
('criteonet','Criteo Network','criteo.net','Advertising','medium'),
('taboola','Taboola','taboola.com','Advertising','medium'),
('outbrain','Outbrain','outbrain.com','Advertising','medium'),
('scorecard','Comscore','scorecardresearch.com','Analytics','medium'),
('quantserve','Quantcast','quantserve.com','Analytics','medium'),
('chartbeat','Chartbeat','chartbeat.net','Analytics','medium'),
('hotjar','Hotjar','hotjar.com','Analytics','medium'),
('mixpanel','Mixpanel','mixpanel.com','Analytics','medium'),
('segment','Segment','segment.io','Analytics','high'),
('branch','Branch','branch.io','Attribution','high'),
('appsflyer','AppsFlyer','appsflyer.com','Attribution','medium'),
('adjust','Adjust','adjust.com','Attribution','high'),
('amplitude','Amplitude','amplitude.com','Analytics','medium'),
('optimizely','Optimizely','optimizely.com','Analytics','high'),
('newrelic','New Relic','newrelic.com','Diagnostics','high'),
('sentry','Sentry','sentry.io','Diagnostics','high'),
('branchmetrics','Branch Metrics','branchmetrics.com','Attribution','medium'),
('amazonadsystem','Amazon Ads','amazon-adsystem.com','Advertising','medium'),
]

def regex_catalog():
    return [{'id':i, 'label':label, 'pattern':r'(^|\.)'+re.escape(domain)+r'$',
             'sample': 'sub.'+domain, 'category':cat, 'risk':risk, 'default_selected':False}
            for i,label,domain,cat,risk in REGEX_CATALOG]

DOMAIN_RE = re.compile(r'(?i)^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)(?:\.(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?))*\.?$')
SYSCTL_ALLOW = [
 re.compile(r'^(?:kernel\.(?:dmesg_restrict|kptr_restrict|sysrq|randomize_va_space)|fs\.(?:protected_hardlinks|protected_symlinks|suid_dumpable)|net\.core\.(?:bpf_jit_harden|default_qdisc|netdev_max_backlog|rmem_max|wmem_max|somaxconn|optmem_max)|net\.netfilter\.nf_conntrack_(?:tcp_loose|acct|tcp_timeout_established|max)|net\.ipv4\.(?:tcp_syncookies|icmp_echo_ignore_broadcasts|icmp_ignore_bogus_error_responses|tcp_rfc1337|tcp_fastopen|tcp_slow_start_after_idle|tcp_mtu_probing|tcp_window_scaling|tcp_timestamps|tcp_no_metrics_save|tcp_congestion_control|tcp_synack_retries|tcp_rmem|tcp_wmem)|net\.ipv[46]\.conf\.(?:all|default)\.(?:accept_source_route|accept_redirects|secure_redirects|send_redirects|log_martians)|net\.ipv4\.conf\.(?:all|default)\.(?:rp_filter|arp_ignore|arp_announce|arp_filter|arp_notify))$')
]

def emit(obj): print(json.dumps(obj, ensure_ascii=False, separators=(',',':')))
def root_required():
    if os.geteuid()!=0: raise SystemExit('operazione privilegiata: eseguire come root/iptm-helper')
@contextmanager
def exclusive_lock(path):
    pathlib.Path(path).parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    fd=os.open(path,os.O_CREAT|os.O_RDWR,0o600)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        yield
    except BlockingIOError:
        raise ValueError('operazione già in corso: lock occupato')
    finally:
        try: fcntl.flock(fd,fcntl.LOCK_UN)
        except OSError: pass
        os.close(fd)

def backup_file(path: pathlib.Path):
    if not path.exists(): return None
    BACKUP_DIR.mkdir(parents=True,exist_ok=True,mode=0o700)
    dest=BACKUP_DIR/(path.name+'.'+datetime.datetime.now().strftime('%Y%m%d-%H%M%S')+f'.{os.getpid()}.bak')
    shutil.copy2(path,dest); os.chmod(dest,0o600); return dest

def parse_lines(path: Optional[str], stdin_ok=False) -> List[str]:
    if path == '-': raw=sys.stdin.read().splitlines()
    elif path: raw=pathlib.Path(path).read_text(encoding='utf-8-sig').splitlines()
    else: raw=[]
    out=[]
    for n,line in enumerate(raw,1):
        s=line.strip()
        if not s or s.startswith(('#',';')): continue
        if '\x00' in s or len(s)>2048: raise ValueError(f'riga {n}: input non valido')
        out.append(s)
    return out

def parse_domains(path):
    if not path: return []
    p=pathlib.Path(path)
    if path == '-': raw=sys.stdin.read()
    else:
        if p.stat().st_size > 5*1024*1024: raise ValueError('file import oltre 5 MiB')
        raw=p.read_text(encoding='utf-8-sig')
    vals=[]
    if p.suffix.lower()=='.json' and path!='-':
        obj=json.loads(raw)
        if isinstance(obj,dict): obj=obj.get('domains',obj.get('whitelist',obj.get('allow',[])))
        if not isinstance(obj,list): raise ValueError('JSON whitelist deve contenere un array di domini')
        source=[]
        for item in obj:
            if isinstance(item,dict):
                value=next((item[k] for k in ('domain','name','value','hostname') if k in item),None)
                if value is None: raise ValueError('oggetto JSON senza campo domain/name/value')
                source.append(str(value))
            else: source.append(str(item))
    elif p.suffix.lower()=='.csv' and path!='-':
        rows=list(csv.reader(raw.splitlines()))
        source=[]
        header=[x.strip().lower() for x in rows[0]] if rows else []
        domain_col=next((i for i,x in enumerate(header) if x in ('domain','domains','whitelist','address','hostname','name')),None)
        start=1 if domain_col is not None else 0
        for row in rows[start:]:
            if not row: continue
            if domain_col is not None and domain_col < len(row): candidate=row[domain_col].strip()
            else:
                candidates=[c.strip() for c in row if c.strip() and not c.strip().isdigit() and c.strip().lower() not in ('allow','deny','whitelist','blacklist')]
                candidate=next((c for c in candidates if DOMAIN_RE.fullmatch(c.rstrip('.').lower())), candidates[0] if candidates else '')
            if candidate: source.append(candidate)
    else: source=raw.splitlines()
    for line in source:
        s=line.strip()
        if not s or s.startswith(('#',';','!')): continue
        if s.startswith('||'): s=s[2:].split('^',1)[0]
        elif s.startswith('0.0.0.0 ') or s.startswith('127.0.0.1 '): s=s.split()[1]
        elif s.startswith('address=/') and s.endswith('/'):
            s=s[len('address=/'):-1]
        else: s=s.split()[0]
        s=s.rstrip('.').lower()
        if not DOMAIN_RE.fullmatch(s): raise ValueError(f'dominio non valido: {s[:120]}')
        vals.append(s)
    return sorted(set(vals))

def parse_regex(path: Optional[str]) -> List[str]:
    if not path: return []
    vals=[]
    for line in parse_lines(path):
        s=line.strip()
        if len(s)>512: raise ValueError('regex oltre 512 caratteri')
        if s.startswith('/') and s.endswith('/') and len(s)>2: s=s[1:-1]
        # Python syntax check is conservative; Pi-hole/FTL may use PCRE2 semantics.
        try: re.compile(s)
        except re.error as e: raise ValueError(f'regex non valida: {s[:100]} ({e})')
        if re.search(r'\([^)]*[+*][^)]*\)[+*{]',s): raise ValueError(f'regex potenzialmente costosa: {s[:100]}')
        vals.append(s)
    return sorted(set(vals))

def find_db(explicit: Optional[str]) -> pathlib.Path:
    if explicit:
        p=pathlib.Path(explicit)
        if not p.is_file(): raise ValueError('database non trovato')
        return p
    for p in DB_CANDIDATES:
        if p.is_file(): return p
    raise ValueError('gravity.db non trovato: Pi-hole non installato o percorso non standard')

def table_columns(conn, table):
    return {r[1] for r in conn.execute(f'PRAGMA table_info("{table}")')}

def compensate_pihole_import(db, records, pihole_cli, with_adlists):
    """Revert ONLY rows created by this import, not concurrent FTL changes.

    If a Pi-hole refresh fails after the DB commit, deleting only exact
    newly-inserted rows is safer than replacing a live SQLite database from a
    snapshot. Errors are returned explicitly and never reported as success.
    """
    if not records:
        return {'compensated':True,'dns_consistent':True,'remaining':0}
    conn=sqlite3.connect(str(db),timeout=15,isolation_level=None)
    remaining=0
    try:
        conn.execute('BEGIN IMMEDIATE')
        for table,rowid,ident,kind in records:
            if table=='domainlist':
                c=conn.execute('DELETE FROM domainlist WHERE rowid=? AND domain=? AND type=?',
                               (rowid,ident,kind))
            elif table=='adlist':
                c=conn.execute('DELETE FROM adlist WHERE rowid=? AND address=?',
                               (rowid,ident))
            else: raise ValueError('Tipo compensazione Pi-hole sconosciuto')
            if c.rowcount != 1: remaining+=1
        conn.execute('COMMIT')
    except BaseException:
        conn.execute('ROLLBACK')
        raise
    finally: conn.close()
    # An unsuccessful first gravity run may have updated partial on-disk state.
    # Force a supported resync after compensating the exact inserted records.
    command=[pihole_cli,'-g'] if with_adlists else [pihole_cli,'reloaddns']
    try:
        result=subprocess.run(command,capture_output=True,text=True,timeout=300 if with_adlists else 60)
        synced=result.returncode==0
    except (OSError,subprocess.TimeoutExpired): synced=False
    return {'compensated':remaining==0,'dns_consistent':synced and remaining==0,
            'remaining':remaining}


def import_pihole(args):
    db=find_db(args.db); allow=parse_domains(args.whitelist); allow_rx=parse_regex(args.allow_regex); deny_rx=parse_regex(args.deny_regex)
    selected=[]
    if len(args.adlists or []) > 50: raise ValueError('massimo 50 adlist per importazione')
    for ident in args.adlists or []:
        if ident not in {x[0] for x in CATALOG}: raise ValueError(f'ID adlist sconosciuto: {ident}')
        selected.append(next(x for x in CATALOG if x[0]==ident))
    plan={'database':str(db),'whitelist_exact':len(allow),'whitelist_regex':len(allow_rx),'deny_regex':len(deny_rx),'adlists':len(selected),'adlist_ids':[x[0] for x in selected], 'apply':bool(args.apply)}
    if not args.apply: emit({'ok':True,'mode':'dry-run','plan':plan,'warning':'Nessuna modifica eseguita. Rivedere il piano e ripetere con --apply.'}); return 0
    root_required()
    if not any((allow,allow_rx,deny_rx,selected)): raise ValueError('nessuna modifica richiesta')
    # Never commit a database change if the supported Pi-hole CLI is unavailable.
    pihole_cli=shutil.which('pihole')
    if not pihole_cli: raise ValueError('CLI ufficiale pihole non disponibile: nessuna modifica eseguita')
    # Hold one process-wide lock through both the SQLite commit and gravity refresh.
    BACKUP_DIR.mkdir(parents=True,exist_ok=True,mode=0o700)
    op_fd=os.open(BACKUP_DIR/'pihole-operation.lock',os.O_CREAT|os.O_RDWR,0o600)
    try: fcntl.flock(op_fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError: os.close(op_fd); raise ValueError('operazione Pi-hole già in corso')
    def _release_op_lock():
        try: fcntl.flock(op_fd,fcntl.LOCK_UN); os.close(op_fd)
        except OSError: pass
    atexit.register(_release_op_lock)
    # Gravity DB is SQLite. Validate schema before opening a write transaction.
    BACKUP_DIR.mkdir(parents=True,exist_ok=True,mode=0o700)
    lock_path=BACKUP_DIR/'pihole-import.lock'
    lock_fd=os.open(lock_path,os.O_CREAT|os.O_RDWR,0o600)
    try: fcntl.flock(lock_fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError: os.close(lock_fd); raise ValueError('import Pi-hole già in corso')
    conn=sqlite3.connect(str(db),timeout=15,isolation_level=None)
    conn.execute('PRAGMA busy_timeout=15000')
    try:
        tables={r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if (allow or allow_rx or deny_rx) and 'domainlist' not in tables: raise ValueError('schema non supportato: tabella domainlist assente')
        if selected and 'adlist' not in tables: raise ValueError('schema non supportato: tabella adlist assente')
        dc=table_columns(conn,'domainlist') if 'domainlist' in tables else set()
        ac=table_columns(conn,'adlist') if 'adlist' in tables else set()
        if 'domain' not in dc or 'type' not in dc: raise ValueError('schema domainlist non riconosciuto')
        if 'address' not in ac and selected: raise ValueError('schema adlist non riconosciuto')
        # SQLite online backup includes committed WAL content; raw file copies do not.
        backup=BACKUP_DIR/(db.name+'.'+datetime.datetime.now().strftime('%Y%m%d-%H%M%S')+f'.{os.getpid()}.bak')
        bconn=sqlite3.connect(str(backup))
        try: conn.backup(bconn)
        finally: bconn.close()
        os.chmod(backup,0o600)
        now=int(time.time()); inserted={'whitelist_exact':0,'whitelist_regex':0,'deny_regex':0,'adlists':0}; skipped=0
        inserted_records=[]
        conn.execute('BEGIN IMMEDIATE')
        try:
            def add_domain(value, typ, comment):
                nonlocal skipped
                where='domain=? AND type=?'; row=conn.execute(f'SELECT 1 FROM domainlist WHERE {where} LIMIT 1',(value,typ)).fetchone()
                if row: skipped+=1; return
                data={'type':typ,'domain':value,'comment':comment,'enabled':1,'date_added':now,'date_modified':now}
                data={k:v for k,v in data.items() if k in dc}
                cols=','.join('"'+k+'"' for k in data); marks=','.join('?' for _ in data)
                row=conn.execute(f'INSERT INTO domainlist ({cols}) VALUES ({marks})',tuple(data.values()))
                inserted_records.append(('domainlist',row.lastrowid,value,typ))
                return True
            for d in allow:
                if add_domain(d,0,'Imported by IPTM'): inserted['whitelist_exact']+=1
            for r in allow_rx:
                if add_domain(r,2,'Imported by IPTM regex allow'): inserted['whitelist_regex']+=1
            for r in deny_rx:
                if add_domain(r,3,'Imported by IPTM regex deny'): inserted['deny_regex']+=1
            for ident,url,category,desc in selected:
                if conn.execute('SELECT 1 FROM adlist WHERE address=? LIMIT 1',(url,)).fetchone(): skipped+=1; continue
                data={'address':url,'enabled':1,'comment':f'IPTM catalog: {ident} — {desc}','date_added':now,'date_modified':now,'number':0,'invalid_domains':0,'abp_entries':0,'status':0}
                data={k:v for k,v in data.items() if k in ac}
                cols=','.join('"'+k+'"' for k in data); marks=','.join('?' for _ in data)
                row=conn.execute(f'INSERT INTO adlist ({cols}) VALUES ({marks})',tuple(data.values()))
                inserted_records.append(('adlist',row.lastrowid,url,None))
                inserted['adlists']+=1
            conn.execute('COMMIT')
        except Exception:
            conn.execute('ROLLBACK'); raise
    finally:
        conn.close()
        try: fcntl.flock(lock_fd,fcntl.LOCK_UN); os.close(lock_fd)
        except OSError: pass
    # Reconcile the committed DB with the running Pi-hole service. A failed
    # refresh is NOT a successful import. Compensate only inserted records;
    # never overwrite gravity.db (FTL may concurrently write to its WAL).
    refresh_error=None
    try:
        if inserted['adlists']:
            r=subprocess.run([pihole_cli,'-g'],capture_output=True,text=True,timeout=300)
            if r.returncode: refresh_error='gravity-refresh-exit-'+str(r.returncode)
        elif any(inserted.values()):
            r=subprocess.run([pihole_cli,'reloaddns'],capture_output=True,text=True,timeout=60)
            if r.returncode: refresh_error='dns-reload-exit-'+str(r.returncode)
    except (OSError,subprocess.TimeoutExpired):
        refresh_error='service-refresh-unavailable'
    if refresh_error:
        try:
            recovered=compensate_pihole_import(db,inserted_records,pihole_cli,inserted['adlists']>0)
        except (sqlite3.Error,OSError,ValueError):
            recovered={'compensated':False,'dns_consistent':False,'remaining':len(inserted_records)}
        emit({'ok':False,'committed':not recovered['compensated'],
              'partial':not recovered['dns_consistent'],
              'compensation':recovered,'inserted':inserted,'duplicates':skipped,
              'refresh':'failed','reason':refresh_error,
              'manual_recovery_required':not recovered['dns_consistent'],
              'backup_dir':str(BACKUP_DIR)})
        return 1
    rotate_backup_files(BACKUP_DIR, re.escape(db.name)+r'\.\d{8}-\d{6}\.\d+\.bak')
    emit({'ok':True,'committed':True,'inserted':inserted,'duplicates':skipped,'refresh':'completed','backup_dir':str(BACKUP_DIR)})
    return 0

def import_pihole_json(args):
    """Accept a bounded JSON payload on stdin for the authenticated web UI."""
    raw=sys.stdin.read(24*1024*1024+1)
    if len(raw)>24*1024*1024: raise ValueError('payload import oltre 24 MiB')
    payload=json.loads(raw or '{}')
    if not isinstance(payload,dict): raise ValueError('payload JSON non valido')
    allowed={'whitelist','whitelist_format','allow_regex','deny_regex','adlists','apply'}
    if set(payload)-allowed: raise ValueError('campi payload non riconosciuti')
    for k in ('whitelist','allow_regex','deny_regex'):
        v=payload.get(k,'')
        if not isinstance(v,str) or len(v)>5*1024*1024: raise ValueError(f'campo {k} non valido o troppo grande')
    fmt=payload.get('whitelist_format','txt')
    if not isinstance(fmt,str) or fmt not in ('txt','csv','json'):
        raise ValueError('formato whitelist non supportato (solo txt/csv/json)')
    ids=payload.get('adlists',[])
    if not isinstance(ids,list) or len(ids)>50 or any(not isinstance(x,str) or len(x)>32 for x in ids):
        raise ValueError('selezione adlist non valida')
    if len(ids)!=len(set(ids)): raise ValueError('adlist duplicate nella selezione')
    temps=[]
    try:
        paths={}
        for key,suffix in [('whitelist','.'+fmt),('allow_regex','.txt'),('deny_regex','.txt')]:
            value=payload.get(key,'')
            if value.strip():
                fd,name=tempfile.mkstemp(prefix='iptm-pihole-',suffix=suffix)
                os.fchmod(fd,0o600)
                with os.fdopen(fd,'w',encoding='utf-8') as f: f.write(value)
                temps.append(name); paths[key]=name
            else: paths[key]=None
        ns=argparse.Namespace(db=None,whitelist=paths['whitelist'],allow_regex=paths['allow_regex'],deny_regex=paths['deny_regex'],adlists=ids,apply=payload.get('apply') is True)
        return import_pihole(ns)
    finally:
        for name in temps:
            try: os.unlink(name)
            except OSError: pass

def catalog_cmd(_args):
    emit({'count':len(CATALOG),'lists':[{'id':i,'url':u,'category':c,'description':d,'default_selected':False} for i,u,c,d in CATALOG], 'regex_patterns':regex_catalog()}); return 0

def canon_sysctl(key): return key.lstrip('-').replace('.', '/')
def scan_sysctl():
    roots=['/etc/sysctl.d','/run/sysctl.d','/usr/local/lib/sysctl.d','/usr/lib/sysctl.d','/lib/sysctl.d']
    selected={}; files=[]
    for root in roots:
        for p in sorted(pathlib.Path(root).glob('*.conf')) if pathlib.Path(root).exists() else []:
            if p.name not in selected: selected[p.name]=p
            files.append(str(p))
    effective=list(selected.values())
    if pathlib.Path('/etc/sysctl.conf').is_file(): effective.append(pathlib.Path('/etc/sysctl.conf'))
    entries=[]
    for p in effective:
        try:
            for no,line in enumerate(p.read_text(errors='replace').splitlines(),1):
                s=line.strip()
                if not s or s.startswith(('#',';')): continue
                m=re.match(r'^(-?)([A-Za-z0-9_./*-]+)\s*=\s*(.*?)\s*$',s)
                if m: entries.append({'key':canon_sysctl(m.group(2)),'raw_key':m.group(2),'value':m.group(3),'file':str(p),'line':no,'ignore_errors':bool(m.group(1))})
        except OSError: pass
    grouped={}
    for e in entries: grouped.setdefault(e['key'],[]).append(e)
    conflicts=[{'key':k,'definitions':v,'winner':v[-1]} for k,v in grouped.items() if len(v)>1]
    return {'files_scanned':files,'effective_files':[str(p) for p in effective],'keys':len(grouped),'duplicate_or_override_keys':len(conflicts),'conflicts':conflicts}

def sysctl_audit(_args): emit({'ok':True,**scan_sysctl()}); return 0

def validate_sysctl(lines):
    out=[]
    for n,line in enumerate(lines,1):
        m=re.fullmatch(r'([A-Za-z0-9_.]+)\s*=\s*(\S(?:.*\S)?)',line)
        if not m: raise ValueError(f'riga {n}: formato sysctl non valido')
        key,val=m.groups()
        if not any(p.fullmatch(key) for p in SYSCTL_ALLOW): raise ValueError(f'chiave non consentita: {key}')
        if len(val)>128 or any(c in val for c in '\n\r\x00'): raise ValueError(f'valore non valido per {key}')
        if key.endswith(('tcp_rmem','tcp_wmem')):
            nums=val.split()
            if len(nums)!=3 or not all(x.isdigit() for x in nums): raise ValueError(f'tripletta non valida: {key}')
        elif not re.fullmatch(r'[A-Za-z0-9_.-]+',val): raise ValueError(f'valore non valido: {key}')
        out.append((key,val))
    keys=[k for k,_ in out]
    if len(keys)!=len(set(keys)): raise ValueError('chiavi duplicate nel payload')
    return out

def sysctl_apply(args):
    lines=parse_lines(args.file)
    pairs=validate_sysctl(lines)
    if not pairs:
        emit({'ok':False,'error':'Nessuna assegnazione sysctl fornita. Inserisci almeno una riga nel formato chiave = valore; il testo di esempio non viene applicato.','mode':'apply' if args.apply else 'dry-run'})
        return 2
    # The web UI is often used on kernels without selected optional modules,
    # or with IPv6 entirely disabled. Report EACH missing key before writing.
    missing=[k for k,_ in pairs if not (pathlib.Path('/proc/sys')/k.replace('.', '/')).exists()]
    available=[(k,v) for k,v in pairs if k not in missing]
    if not args.apply:
        emit({'ok':bool(available),'mode':'dry-run','target':str(SYSCTL_FILE),
              'keys':available,'skipped_unsupported':missing,
              'error':('Nessuna delle chiavi richieste è disponibile nel kernel: '+', '.join(missing)) if not available else None,
              'warning':'Nessuna modifica eseguita. Le chiavi non disponibili non saranno applicate.'})
        return 0 if available else 2
    if not available:
        emit({'ok':False,'error':'Nessuna chiave sysctl applicabile sul kernel corrente: '+', '.join(missing)+'. Nessun file o valore runtime modificato.',
              'skipped_unsupported':missing})
        return 2
    root_required(); SYSCTL_FILE.parent.mkdir(parents=True,exist_ok=True)
    lock_fd=os.open('/run/lock/iptm-sysctl-maintenance.lock',os.O_CREAT|os.O_RDWR,0o600)
    try: fcntl.flock(lock_fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError: os.close(lock_fd); raise ValueError('operazione sysctl già in corso')
    old_runtime={}; skipped=[]
    for k,_ in pairs:
        proc_path=pathlib.Path('/proc/sys')/k.replace('.', '/')
        if not proc_path.exists():
            skipped.append(k); continue
        r=subprocess.run(['sysctl','-n',k],capture_output=True,text=True)
        if r.returncode: raise ValueError(f'impossibile leggere il valore runtime di {k}: {(r.stderr or r.stdout).strip()}')
        old_runtime[k]=r.stdout.strip()
    pairs=[(k,v) for k,v in pairs if k in old_runtime]
    if not pairs:
        emit({'ok':False,'error':'Nessuna chiave sysctl applicabile sul kernel corrente: '+', '.join(skipped)+'. Nessun file o valore runtime modificato.',
              'skipped_unsupported':skipped})
        return 2
    # Il profilo BBR può richiedere il caricamento del modulo prima del set.
    if any(k=='net.ipv4.tcp_congestion_control' and v=='bbr' for k,v in pairs):
        subprocess.run(['modprobe','-q','tcp_bbr'],capture_output=True,text=True)
    backup=backup_file(SYSCTL_FILE)
    fd,tmp=tempfile.mkstemp(prefix='.iptm-sysctl-',dir=str(SYSCTL_FILE.parent))
    try:
        with os.fdopen(fd,'w') as f:
            f.write('# Managed by IPTM maintenance engine. Do not edit while IPTM is applying changes.\n')
            for k,v in pairs: f.write(f'{k} = {v}\n')
            f.flush(); os.fsync(f.fileno())
        os.chmod(tmp,0o600); os.chown(tmp,0,0)
        applied=[]; committed=False
        try:
            for k,v in pairs:
                r=subprocess.run(['sysctl','-q','-w',f'{k}={v}'],capture_output=True,text=True,timeout=10)
                if r.returncode: raise RuntimeError(f'{k}: {(r.stderr or r.stdout).strip()}')
                applied.append(k)
            os.replace(tmp,SYSCTL_FILE); committed=True
            dfd=os.open(str(SYSCTL_FILE.parent),os.O_DIRECTORY); os.fsync(dfd); os.close(dfd)
        except Exception:
            if committed:
                if backup and backup.exists():
                    restore_tmp=str(SYSCTL_FILE)+'.restore.'+str(os.getpid()); shutil.copy2(backup,restore_tmp); os.replace(restore_tmp,SYSCTL_FILE)
                else:
                    try: SYSCTL_FILE.unlink()
                    except FileNotFoundError: pass
            for k in reversed(applied):
                old=old_runtime.get(k)
                if old is not None: subprocess.run(['sysctl','-q','-w',f'{k}={old}'],capture_output=True,timeout=10)
            raise
        rotate_backup_files(BACKUP_DIR, re.escape(SYSCTL_FILE.name)+r'\.\d{8}-\d{6}\.\d+\.bak')
        emit({'ok':True,'applied':len(pairs),'skipped_unsupported':skipped,'file':str(SYSCTL_FILE),'backup':str(backup) if backup else None}); return 0
    except Exception as e:
        try: os.unlink(tmp)
        except OSError: pass
        emit({'ok':False,'error':str(e),'backup':str(backup) if backup else None}); return 1
    finally:
        try: fcntl.flock(lock_fd,fcntl.LOCK_UN); os.close(lock_fd)
        except OSError: pass

def sysctl_verify(_args):
    data=[]
    for e in scan_sysctl().get('conflicts',[]): pass
    if SYSCTL_FILE.is_file():
        for line in SYSCTL_FILE.read_text(errors='replace').splitlines():
            s=line.strip()
            if not s or s.startswith('#'): continue
            m=re.match(r'^([A-Za-z0-9_.]+)\s*=\s*(.*?)\s*$',s)
            if m:
                k,v=m.groups(); r=subprocess.run(['sysctl','-n',k],capture_output=True,text=True)
                actual=r.stdout.strip() if r.returncode==0 else None
                data.append({'key':k,'configured':v,'runtime':actual,'match':actual==v})
    emit({'ok':all(x['match'] for x in data),'file':str(SYSCTL_FILE),'values':data}); return 0 if all(x['match'] for x in data) else 1


class PiholeApiError(ValueError):
    pass

class LocalPiholeAPI:
    """Pi-hole v6 API on an IP-literal loopback address only. No redirects/proxies."""
    def __init__(self, base, password=''):
        uri=urllib.parse.urlsplit(base)
        try:
            host=ipaddress.ip_address(uri.hostname or '')
        except ValueError:
            raise PiholeApiError('Endpoint API: usa soltanto 127.0.0.1 o [::1]')
        if not host.is_loopback or uri.scheme!='http' or uri.username or uri.password or uri.query or uri.fragment or uri.path.rstrip('/') not in ('','/api'):
            raise PiholeApiError('Sono consentite solo API Pi-hole HTTP su loopback, senza credenziali nell’URL')
        port=uri.port or 80
        if port not in (80,8080,8081,8053,8088,8089): raise PiholeApiError('Porta API locale non consentita')
        hostname='[::1]' if host.version==6 else str(host)
        self.base=f'http://{hostname}:{port}/api'
        self.sid=None
        self.password=password
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self,*_): raise PiholeApiError('Redirect API rifiutato')
        self.opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())

    def call(self, method, resource, data=None, timeout=8, json_required=True):
        if not resource.startswith('/') or '://' in resource or '#' in resource:
            raise PiholeApiError('Percorso API non valido')
        headers={'Accept':'application/json'}
        if data is not None: headers['Content-Type']='application/json'
        if self.sid: headers['X-FTL-SID']=self.sid
        body=None if data is None else json.dumps(data,separators=(',',':')).encode('utf-8')
        req=urllib.request.Request(self.base+resource,data=body,headers=headers,method=method)
        try:
            with self.opener.open(req,timeout=timeout) as resp:
                if resp.status<200 or resp.status>=300: raise PiholeApiError('HTTP '+str(resp.status))
                raw=resp.read((8*1024*1024 if json_required else 256*1024)+1)
                if len(raw)>(8*1024*1024 if json_required else 256*1024): raise PiholeApiError('Risposta API troppo grande')
                if json_required:
                    result=json.loads(raw or b'{}')
                    if not isinstance(result,dict): raise PiholeApiError('JSON API inatteso')
                    return result
                return {'status':resp.status, 'output_tail':raw[-1600:].decode('utf-8','replace')}
        except urllib.error.HTTPError as ex:
            # Never print auth responses, session IDs, application passwords or server traces.
            if ex.code == 401 and resource == '/auth':
                raise PiholeApiError('Pi-hole HTTP 401: password non accettata. Genera una password applicativa in Pi-hole v6 e ripeti la verifica; nessuna lista modificata') from None
            if ex.code == 401:
                raise PiholeApiError('Pi-hole HTTP 401: sessione assente, scaduta o non autorizzata; nessuna lista modificata') from None
            raise PiholeApiError('API Pi-hole HTTP '+str(ex.code)) from None
        except (urllib.error.URLError, TimeoutError, ConnectionError, json.JSONDecodeError) as ex:
            raise PiholeApiError('API locale non raggiungibile o risposta non valida ('+type(ex).__name__+')') from None

    def __enter__(self):
        try:
            if self.password:
                result=self.call('POST','/auth',{'password':self.password})
                session=result.get('session',{})
                if not isinstance(session,dict) or not session.get('valid') or not isinstance(session.get('sid'),str):
                    raise PiholeApiError('Autenticazione Pi-hole non riuscita')
                self.sid=session['sid']
            # Do not confuse v5 admin/api.php or a reverse-proxy error page with the v6 API.
            version=self.call('GET','/info/version')
            if not any(k in version for k in ('version','core','ftl','web')):
                raise PiholeApiError('Versione API Pi-hole v6 non riconosciuta; database non modificato')
            return self
        except BaseException:
            # __exit__ is not called when __enter__ itself raises.
            self.__exit__(None,None,None)
            raise

    def __exit__(self,*_):
        if self.sid:
            try: self.call('DELETE','/auth',json_required=False,timeout=3)
            except Exception: pass
            self.sid=None


def _api_entries(payload, key, max_entries=40000):
    if not isinstance(payload,dict) or not isinstance(payload.get(key),list):
        raise PiholeApiError('Risposta API Pi-hole non compatibile: '+key)
    data=payload[key]
    if len(data)>max_entries: raise PiholeApiError('Troppi record nella risposta API: interrompo')
    return [x for x in data if isinstance(x,dict)]


def get_rethink_imports(ids):
    if not ids:return []
    import importlib.util
    path=RETHINK_SCRIPT
    if not path.is_file() or path.is_symlink() or path.stat().st_uid!=0 or path.stat().st_mode & 0o022:
        raise PiholeApiError('Modulo RethinkDNS mancante o non sicuro')
    spec=importlib.util.spec_from_file_location('iptm_rethink_verified',str(path))
    if spec is None or spec.loader is None:raise PiholeApiError('Modulo RethinkDNS non leggibile')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    try:return module.get_importable(ids)
    except Exception as exc:raise PiholeApiError('RethinkDNS: '+str(exc))

def _api_parse_fields(payload):
    whitelist=payload.get('whitelist','')
    fmt=payload.get('whitelist_format','txt')
    if not isinstance(whitelist,str) or len(whitelist)>1048576 or fmt not in ('txt','csv','json'):
        raise PiholeApiError('Whitelist o formato non valido')
    ids=payload.get('adlists',[])
    rxids=payload.get('regex_ids',[])
    rdids=payload.get('rethink_ids',[])
    if (not isinstance(ids,list) or len(ids)>50 or len(ids)!=len(set(ids)) or
        not all(isinstance(x,str) for x in ids) or
        not isinstance(rxids,list) or len(rxids)>30 or len(rxids)!=len(set(rxids)) or
        not all(isinstance(x,str) for x in rxids) or
        not isinstance(rdids,list) or len(set(rdids))!=len(rdids) or
        not all(isinstance(x,str) and re.fullmatch(r'rd[a-f0-9]{16}',x) for x in rdids)):
        raise PiholeApiError('Selezione adlist/regex non valida')
    catalogue={x[0]:x for x in CATALOG}
    presets={x['id']:x for x in regex_catalog()}
    if any(k not in catalogue for k in ids) or any(k not in presets for k in rxids):
        raise PiholeApiError('ID adlist/regex sconosciuto')
    def read_format(raw, suffix, parser):
        if not isinstance(raw,str) or len(raw)>1048576: raise PiholeApiError('Input regex non valido')
        if not raw.strip(): return []
        with tempfile.TemporaryDirectory(prefix='iptm-ph-') as folder:
            path=pathlib.Path(folder)/('input.'+suffix)
            path.write_text(raw,encoding='utf-8')
            return parser(str(path))
    allow=read_format(whitelist,fmt,parse_domains)
    ra=read_format(payload.get('allow_regex',''),'txt',parse_regex)
    rd=read_format(payload.get('deny_regex',''),'txt',parse_regex)
    rd=sorted(set(rd).union(presets[k]['pattern'] for k in rxids))
    return allow,ra,rd,[(k,catalogue[k][1]) for k in ids]+get_rethink_imports(rdids)


def compensate_pihole_api(api, delta, applied, gravity_started=False):
    """Best-effort selective REST compensation, NOT a global API transaction.

    Only removes records the current import created and whose marker still
    matches IPTM. Never restores a full snapshot over concurrent user changes.
    Fail closed if Pi-hole becomes unreadable or any marker changes.
    """
    outcome={'attempted':True,'removed':{k:0 for k in delta},
             'complete':False,'manual_recovery':True,'gravity_may_have_changed':bool(gravity_started)}
    planned={k:delta[k][:applied.get(k,0)] for k in ('whitelist','allow_regex','deny_regex','adlists')}
    routes={'whitelist':('allow','exact'),'allow_regex':('allow','regex'),'deny_regex':('deny','regex')}
    try:
        now_domains=_api_entries(api.call('GET','/domains'),'domains')
        now_lists=_api_entries(api.call('GET','/lists'),'lists')
        for key,(kind,typ) in routes.items():
            for item in planned[key]:
                matches=[row for row in now_domains if row.get('domain')==item and
                         row.get('kind')==typ and row.get('type')==kind]
                if not matches:
                    # POST may not have taken effect; absent entry is safe.
                    continue
                if len(matches)!=1 or matches[0].get('comment')!='IPTM import (opt-in)':
                    raise PiholeApiError('Record cambiato durante il recupero: '+key)
                path='/domains/'+kind+'/'+typ+'/'+urllib.parse.quote(item,safe='')
                api.call('DELETE',path,json_required=False,timeout=15)
                outcome['removed'][key]+=1
        for ident,url in planned['adlists']:
            matches=[row for row in now_lists if row.get('address')==url]
            if not matches: continue
            if len(matches)!=1 or matches[0].get('comment')!='IPTM catalog: '+ident:
                raise PiholeApiError('Adlist cambiata durante il recupero')
            api.call('DELETE','/lists/'+urllib.parse.quote(url,safe='')+'?type=block',json_required=False,timeout=15)
            outcome['removed']['adlists']+=1
        final_domains=_api_entries(api.call('GET','/domains'),'domains')
        final_lists=_api_entries(api.call('GET','/lists'),'lists')
        domains_present=any(row.get('domain')==item and row.get('kind')==typ and row.get('type')==kind
                            for key,(kind,typ) in routes.items() for item in planned[key] for row in final_domains)
        lists_present=any(row.get('address')==url for _,url in planned['adlists'] for row in final_lists)
        outcome['complete']=not domains_present and not lists_present and not gravity_started
        outcome['manual_recovery']=not outcome['complete']
    except Exception as ex:
        outcome['recovery_error']=type(ex).__name__
    return outcome


def pihole_api_json(_args):
    raw=sys.stdin.buffer.read(3*1024*1024+1)
    if len(raw)>3*1024*1024: raise PiholeApiError('Payload oltre 3 MiB')
    payload=json.loads(raw.decode('utf-8') or '{}')
    if not isinstance(payload,dict): raise PiholeApiError('Payload JSON non valido')
    mode=payload.get('mode','import')
    if mode not in ('read','import'): raise PiholeApiError('Operazione API non valida')
    base=payload.get('api_url','http://127.0.0.1')
    password=payload.get('password','')
    if not isinstance(base,str) or len(base)>90 or not isinstance(password,str) or len(password)>256:
        raise PiholeApiError('Parametri autenticazione non validi')
    if not password:
        # Password fetched only by the root worker: never returned to the web session.
        import importlib.util
        credential_script=pathlib.Path('/usr/local/lib/iptables-manager/web/releases/5.30.4/extensions/pihole_credentials.py')
        if credential_script.is_symlink() or not credential_script.is_file():
            raise PiholeApiError('Archivio credenziali IPTM non installato')
        st=credential_script.stat()
        if st.st_uid!=0 or st.st_mode&0o022:raise PiholeApiError('Archivio credenziali non sicuro')
        spec=importlib.util.spec_from_file_location('iptm_pihole_credentials',credential_script)
        if spec is None or spec.loader is None:raise PiholeApiError('Archivio credenziali non disponibile')
        mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
        try:password=mod.get_password()
        except mod.SecretError:raise PiholeApiError('Credenziale Pi-hole memorizzata non accessibile')
    with LocalPiholeAPI(base,password) as api:
        current=_api_entries(api.call('GET','/domains'),'domains')
        existing_lists=_api_entries(api.call('GET','/lists'),'lists')
        if mode=='read':
            exact=sorted({x['domain'] for x in current if x.get('type')=='allow' and x.get('kind')=='exact' and isinstance(x.get('domain'),str)})
            allow_rx=sorted({x['domain'] for x in current if x.get('type')=='allow' and x.get('kind')=='regex' and isinstance(x.get('domain'),str)})
            deny_rx=sorted({x['domain'] for x in current if x.get('type')=='deny' and x.get('kind')=='regex' and isinstance(x.get('domain'),str)})
            # Only catalog membership/status is exposed to the admin browser.
            # Preserve unknown status when Pi-hole doesn't include `enabled`.
            def status_of(row):
                enabled=row.get('enabled',None)
                if enabled is True or enabled == 1: return 'active'
                if enabled is False or enabled == 0: return 'disabled'
                return 'present'
            def list_key(address):
                if not isinstance(address,str): return ''
                u=urllib.parse.urlsplit(address.strip())
                if u.scheme.lower() not in ('http','https') or not u.netloc: return ''
                host=(u.hostname or '').lower()
                try: port=u.port
                except ValueError: return ''
                if not host: return ''
                suffix=':'+str(port) if port else ''
                path=u.path.rstrip('/')
                return u.scheme.lower()+'://'+host+suffix+path+('?' + u.query if u.query else '')
            known_lists={}
            for row in existing_lists:
                key=list_key(row.get('address'))
                if key: known_lists[key]=status_of(row)
            catalog_lists={ident:known_lists.get(list_key(url),'new') for ident,url,*_ in CATALOG}
            known_regex={}
            for row in current:
                if row.get('kind')=='regex' and row.get('type')=='deny' and isinstance(row.get('domain'),str):
                    known_regex[row['domain']]=status_of(row)
            catalog_regex={row['id']:known_regex.get(row['pattern'],'new') for row in regex_catalog()}
            # Use the *same* canonical URL matcher used by the standard adlists.
            # A source may be currently unavailable but still installed in Pi-hole;
            # report that distinction instead of falsely calling it 'new'.
            rethink_status={}
            try:
                import importlib.util
                if RETHINK_SCRIPT.is_file() and not RETHINK_SCRIPT.is_symlink():
                    st=RETHINK_SCRIPT.stat()
                    if st.st_uid==0 and not (st.st_mode & 0o022):
                        spec=importlib.util.spec_from_file_location('iptm_rethink_status',str(RETHINK_SCRIPT))
                        if spec is not None and spec.loader is not None:
                            module=importlib.util.module_from_spec(spec)
                            spec.loader.exec_module(module)
                            cached=module.cache_read()
                            for row in cached.get('lists',[]):
                                if isinstance(row,dict) and isinstance(row.get('id'),str):
                                    rethink_status[row['id']]=known_lists.get(list_key(row.get('url')),'new')
            except (OSError,ValueError,ImportError,KeyError,TypeError):
                pass  # Unreadable catalog must not erase the valid Pi-hole API read.
            emit({'ok':True,'mode':'read','source':'Pi-hole v6 API localhost',
                  'whitelist':exact,'allow_regex':allow_rx,'deny_regex':deny_rx,
                  'catalog_status':{'adlists':catalog_lists,'regex':catalog_regex,'rethink':rethink_status},
                  'counts':{'whitelist':len(exact),'allow_regex':len(allow_rx),'deny_regex':len(deny_rx),
                            'adlists':len(existing_lists)}})
            return 0
        allow,ra,rd,lists=_api_parse_fields(payload)
        def existing(kind,typ):
            return {x['domain'] for x in current if x.get('kind')==kind and x.get('type')==typ and isinstance(x.get('domain'),str)}
        delta={'whitelist':sorted(set(allow)-existing('exact','allow')),
               'allow_regex':sorted(set(ra)-existing('regex','allow')),
               'deny_regex':sorted(set(rd)-existing('regex','deny')),
               'adlists':[(ident,url) for ident,url in lists if url not in {x.get('address') for x in existing_lists}]}
        high=len(lists)>10
        plan={'requested':{'whitelist':len(allow),'allow_regex':len(ra),'deny_regex':len(rd),'adlists':len(lists)},
              'new':{k:len(v) for k,v in delta.items()},
              'already_present':{k:len(v)-len(delta[k]) for k,v in [('whitelist',allow),('allow_regex',ra),('deny_regex',rd),('adlists',lists)]},
              'adlist_ids':[a for a,_ in lists],
              'risk':'alto: molte adlist, aggiornamento gravity rinviato e nuove liste disattivate' if high else 'normale',
              'warning':'30 regex: solo test sintattici/di esempio, nessuna attivazione automatica degli elenchi; validare gli effetti reali'}
        if payload.get('apply') is not True:
            emit({'ok':True,'mode':'dry-run','api':'v6','plan':plan,'changed':False}); return 0
        root_required()
        if high and payload.get('confirm_large') is not True:
            raise PiholeApiError('Oltre 10 adlist: conferma espressamente l’aggiunta in staging disabilitato')
        if not any(delta.values()):
            emit({'ok':True,'mode':'no-op','plan':plan,'changed':False}); return 0
        # Prevent a gravity refresh on critically low-resource DietPi hosts.
        if delta['adlists'] and not high and payload.get('gravity') is True:
            try:
                available_kb=next((int(x.split()[1]) for x in pathlib.Path('/proc/meminfo').read_text().splitlines() if x.startswith('MemAvailable:')),0)
                free_bytes=shutil.disk_usage('/etc/pihole').free
            except (OSError,ValueError):
                raise PiholeApiError('Risorse per Gravity non verificabili: aggiorna Gravity manualmente')
            if available_kb<131072 or free_bytes<268435456:
                raise PiholeApiError('Memoria disponibile inferiore a 128 MiB o disco libero inferiore a 256 MiB: Gravity non avviato')
        deadline=time.monotonic()+180
        with exclusive_lock(BACKUP_DIR/'pihole-api.lock'):
            BACKUP_DIR.mkdir(parents=True,exist_ok=True,mode=0o700)
            # Reject concurrent edits between initial read and write (including another IPTM request).
            # Pi-hole FTL remains authoritative; these calls do not promise global atomicity.
            now_domains=_api_entries(api.call('GET','/domains'),'domains')
            now_lists=_api_entries(api.call('GET','/lists'),'lists')
            if now_domains!=current or now_lists!=existing_lists:
                raise PiholeApiError('Liste Pi-hole modificate durante l’anteprima: ripeti importazione, nessuna scrittura effettuata')
            # Snapshot for manual recovery only: Pi-hole API has no multi-resource transaction.
            fd,name=tempfile.mkstemp(prefix='pihole-api-before-',suffix='.json',dir=BACKUP_DIR)
            os.fchmod(fd,0o600)
            try:
                with os.fdopen(fd,'w',encoding='utf-8') as f:
                    json.dump({'domains':current,'lists':existing_lists},f,ensure_ascii=False)
                    f.flush(); os.fsync(f.fileno())
            except BaseException:
                pathlib.Path(name).unlink(missing_ok=True); raise
            applied={k:0 for k in delta}
            try:
                for k,path in (('whitelist','/domains/allow/exact'),('allow_regex','/domains/allow/regex'),('deny_regex','/domains/deny/regex')):
                    for value in delta[k]:
                        if time.monotonic()>deadline: raise PiholeApiError('Tempo massimo import raggiunto: verifica le voci aggiunte')
                        api.call('POST',path,{'domain':value,'comment':'IPTM import (opt-in)','enabled':True,'groups':[0]})
                        applied[k]+=1
                for ident,url in delta['adlists']:
                    if time.monotonic()>deadline: raise PiholeApiError('Tempo massimo import raggiunto: verifica le voci aggiunte')
                    # Restrict catalog addresses to HTTPS. Never forward arbitrary file:// URLs.
                    if urllib.parse.urlsplit(url).scheme!='https': raise PiholeApiError('URL adlist non HTTPS')
                    api.call('POST','/lists?type=block',{'address':url,'comment':'IPTM catalog: '+ident,
                                                          'enabled':not high,'groups':[0]})
                    applied['adlists']+=1
                # Gravity is intentionally NOT automatically launched for big bulk selections.
                # Small selections can be processed with the official v6 API action.
                gravity='deferred'
                gravity_started=False
                if applied['adlists'] and not high and payload.get('gravity') is True:
                    gravity_started=True
                    api.call('POST','/action/gravity',{},timeout=180,json_required=False)
                    gravity='requested'
            except Exception as exc:
                # A failed API write may already have reached FTL before the
                # timeout. Record the outcome and compensate only verified
                # IPTM-created entries, never the entire pre-import snapshot.
                recovery=compensate_pihole_api(api,delta,applied,locals().get('gravity_started',False))
                emit({'ok':False,'committed':any(applied.values()),'partial':applied,'snapshot':name,
                      'recovery':recovery,'error':str(exc),
                      'note':'REST non transazionale: verificare Pi-hole. Interventi esterni, timeout e aggiornamento Gravity possono richiedere recupero manuale.'})
                return 1
            rotate_backup_files(BACKUP_DIR, r'pihole-api-before-.*\.json')
            emit({'ok':True,'mode':'applied','api':'v6','changed':True,'inserted':applied,
                  'staged_disabled':high,'gravity':gravity,'snapshot':name,
                  'note':'Nessuna modifica ad entry preesistenti; nessuna transazione globale garantita dall’API.'})
            return 0

# Crash-recoverable application file replacement journal. The stable rescue copy
# is installed and enabled *before* the updater begins replacing application files.
UPDATE_COMPONENTS = (
    '/usr/local/sbin/iptm-helper',
    '/usr/local/lib/iptables-manager/iptm-maintenance.py',
    '/usr/local/lib/iptables-manager/iptm-traffic-av.py',
    '/usr/local/lib/iptables-manager/iptm-security.py',
    '/usr/local/lib/iptables-manager/iptm-iot-warden.py',
    '/usr/local/lib/iptables-manager/iptm-dns-bundle.py',
    '/usr/local/lib/iptables-manager/iptm-crowdsec-audit.py',
)

def _sync_dir(path):
    fd = os.open(str(path), os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)

def _update_paths(web):
    if not re.fullmatch(r'/[A-Za-z0-9._/-]+/iptables-manager\.php', str(web)) or '..' in pathlib.PurePosixPath(str(web)).parts:
        raise ValueError('Percorso PHP non autorizzato')
    return [pathlib.Path(web)] + [pathlib.Path(p) for p in UPDATE_COMPONENTS]

def _update_txn(operation, state_dir, paths=None):
    import hashlib, stat
    state = pathlib.Path(state_dir)
    if not state.is_absolute() or '..' in state.parts or state.is_symlink():
        raise ValueError('Percorso journal non valido')
    if operation == 'stage':
        state.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(state,0o700)
    if not state.is_dir() or state.is_symlink():
        raise ValueError('Directory journal mancante o non sicura')
    directory_stat=os.stat(state)
    if directory_stat.st_mode & 0o022 or (os.geteuid()==0 and directory_stat.st_uid!=0):
        raise ValueError('Directory journal non di root o scrivibile da terzi')
    marker = state / 'pending.json'
    backups = state / 'snapshot'
    if operation == 'stage':
        if marker.exists() or marker.is_symlink():
            raise ValueError('Esiste una transazione incompleta: esegui recovery prima di aggiornare')
        if paths is None: raise ValueError('Percorsi non disponibili')
        if backups.exists():
            if backups.is_symlink(): raise ValueError('Snapshot non sicuro')
            shutil.rmtree(backups)
        backups.mkdir(mode=0o700)
        records=[]
        for i,target in enumerate(paths):
            target=pathlib.Path(target)
            if target.is_symlink(): raise ValueError(f'Link simbolico non consentito: {target}')
            if not target.exists():
                records.append({'target':str(target),'present':False})
                continue
            st=target.stat()
            if not stat.S_ISREG(st.st_mode): raise ValueError(f'File non regolare: {target}')
            if st.st_size>8*1024*1024: raise ValueError(f'File troppo grande: {target}')
            dest=backups / f'{i:02d}.bak'
            shutil.copyfile(target,dest)
            with dest.open('rb') as fp: os.fsync(fp.fileno())
            data=dest.read_bytes()
            records.append({'target':str(target),'present':True,'backup':dest.name,
                            'sha256':hashlib.sha256(data).hexdigest(),
                            'mode':stat.S_IMODE(st.st_mode),'uid':st.st_uid,'gid':st.st_gid})
        _sync_dir(backups)
        payload={'format':'iptm.update.v1','phase':'pending','files':records}
        temp=state / '.pending.new'
        with temp.open('w',encoding='utf-8') as fp:
            json.dump(payload,fp,sort_keys=True)
            fp.flush(); os.fsync(fp.fileno())
        os.chmod(temp,0o600); os.replace(temp,marker); _sync_dir(state)
        return {'ok':True,'phase':'pending','files':len(records)}
    if not marker.exists():
        return {'ok':True,'phase':'none'}
    if marker.is_symlink() or marker.stat().st_size>65536 or (os.geteuid()==0 and marker.stat().st_uid!=0):
        raise ValueError('Journal non sicuro')
    payload=json.loads(marker.read_text(encoding='utf-8'))
    if payload.get('format')!='iptm.update.v1' or payload.get('phase')!='pending':
        raise ValueError('Journal sconosciuto')
    records=payload.get('files')
    if not isinstance(records,list) or len(records)>16:
        raise ValueError('Numero di file journal invalido')
    if operation == 'recover':
        # Check all copies before modifying any target; idempotent on power loss.
        for row in records:
            target=pathlib.Path(row['target'])
            if not target.is_absolute() or '..' in target.parts or target.is_symlink():
                raise ValueError('Target recovery non valido')
            if row.get('present'):
                name=row.get('backup','')
                if not re.fullmatch(r'[0-9]{2}\.bak',name): raise ValueError('Backup name invalid')
                source=backups/name
                if not source.is_file() or source.is_symlink() or hashlib.sha256(source.read_bytes()).hexdigest()!=row['sha256']:
                    raise ValueError(f'Snapshot corrotto: {name}')
        for row in records:
            target=pathlib.Path(row['target'])
            if not row.get('present'):
                if target.exists() and not target.is_symlink(): target.unlink()
                continue
            data=(backups/row['backup']).read_bytes()
            fd,tmp=tempfile.mkstemp(prefix='.iptm-rescue-',dir=str(target.parent))
            try:
                with os.fdopen(fd,'wb') as fp:
                    fp.write(data); fp.flush(); os.fsync(fp.fileno())
                os.chown(tmp,int(row['uid']),int(row['gid']))
                os.chmod(tmp,int(row['mode']))
                os.replace(tmp,target); _sync_dir(target.parent)
                if hashlib.sha256(target.read_bytes()).hexdigest()!=row['sha256']:
                    raise ValueError(f'Ripristino non verificato: {target}')
            finally:
                if os.path.exists(tmp): os.unlink(tmp)
    elif operation=='commit':
        # Do not remove the recovery marker until every new on-disk file and
        # directory entry is durable. Otherwise a power cut just after commit
        # could resurrect a mixture of old and new application files.
        for row in records:
            target=pathlib.Path(row['target'])
            if not target.is_file() or target.is_symlink():
                raise ValueError(f'File applicativo non presente: {target}')
            with target.open('rb') as fp: os.fsync(fp.fileno())
            _sync_dir(target.parent)
    else:
        raise ValueError('Operazione non prevista')
    marker.unlink(); _sync_dir(state)
    if backups.is_dir() and not backups.is_symlink(): shutil.rmtree(backups)
    return {'ok':True,'phase':'recovered' if operation=='recover' else 'committed','files':len(records)}

def update_recovery_cli(args):
    if os.geteuid()!=0:
        raise ValueError('Richiesti privilegi root')
    if args.operation=='stage':
        if not args.web: raise ValueError('Percorso web obbligatorio')
        paths=_update_paths(args.web)
    else: paths=None
    result=_update_txn(args.operation,args.state,paths)
    emit(result)
    return 0

# ---- Non-mutating platform inspection (the same engine is used by the web UI) ----
def preflight_checks(root: pathlib.Path = pathlib.Path('/'), *, probe_commands: bool = True):
    """Bounded read-only inspection. Each check provides actionable status.

    `root` allows fixtures and chroot-like checks, but commands are never run
    against a fixture root. No secrets or contents of credentials are returned.
    """
    root = pathlib.Path(root)
    checks = []
    def add(name, status, detail):
        checks.append({'name': name, 'status': status, 'detail': detail[:320]})
    def path(name):
        return root / name.lstrip('/')
    def command(name, args=(), seconds=3):
        binary = shutil.which(name) if probe_commands else None
        if not binary: return None
        try:
            return subprocess.run([binary, *args], capture_output=True,
                                  text=True, timeout=seconds, check=False)
        except (OSError, subprocess.TimeoutExpired):
            return None

    expected = {
        '/usr/local/sbin/iptm-helper': 0o755,
        '/usr/local/lib/iptables-manager/iptm-maintenance.py': 0o644,
        '/etc/iptables-manager.conf': 0o600,
        '/etc/iptables-manager.web.json': 0o644,
    }
    for filename, nominal_mode in expected.items():
        f = path(filename)
        if not f.exists():
            if filename.endswith('.web.json'):
                add('Configurazione web opzionale', 'ok', 'Assente: valori predefiniti in uso')
            else: add(filename, 'warn', 'File assente: verifica installazione e percorso')
            continue
        try:
            st = f.lstat()
            if not f.is_file() or f.is_symlink():
                add(filename, 'error', 'File non regolare o collegamento simbolico')
            elif st.st_uid != 0 or st.st_mode & 0o022:
                add(filename, 'error', 'File non di root o scrivibile da gruppo/altri: verifica proprietà e permessi')
            elif filename.endswith('.conf') and (st.st_mode & 0o077):
                add(filename, 'warn', 'Configurazione privilegiata leggibile da altri utenti: raccomandato 0600')
            else: add(filename, 'ok', 'File regolare, root-owned, non modificabile da altri')
        except OSError:
            add(filename, 'error', 'Permessi impossibili da leggere')

    # Validate privileged config without sourcing or executing it. Failures in
    # this file otherwise prevent the legacy helper from running at all.
    config = path('/etc/iptables-manager.conf')
    if config.is_file() and not config.is_symlink():
        try:
            import shlex
            raw = config.read_text('utf-8')
            allowed = {'POST_SERVICES','POST_SCRIPT','SQM_IF','SQM_UP','SQM_DOWN',
                       'SURICATA_YAML','BACKEND_WANTED','SQM_DIFFSERV','SQM_ACK',
                       'SQM_NAT','SQM_OVERHEAD','SQM_WASH','SQM_AUTOCAL'}
            errors = []
            for lineno, line in enumerate(raw.splitlines(), 1):
                if not line.strip() or line.lstrip().startswith('#'): continue
                match = re.fullmatch(r'\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*',line)
                if not match:
                    errors.append(lineno); continue
                key, expression = match.groups()
                if key not in allowed: continue
                try: words = shlex.split(expression, posix=True)
                except ValueError: errors.append(lineno); continue
                if len(words)!=1 or len(words[0])>2048 or any(ord(ch)<32 for ch in words[0]) \
                   or any(ch in words[0] for ch in '`$;|&<>'):
                    errors.append(lineno)
                elif key in ('SQM_UP','SQM_DOWN') and not re.fullmatch(r'[0-9]{0,6}',words[0]):
                    errors.append(lineno)
                elif key in ('SQM_ACK','SQM_NAT','SQM_WASH','SQM_AUTOCAL') and words[0] not in ('','0','1'):
                    errors.append(lineno)
                elif key == 'SQM_IF' and words[0] and not re.fullmatch(r'[A-Za-z0-9_.-]{1,15}',words[0]):
                    errors.append(lineno)
                elif key == 'BACKEND_WANTED' and words[0] not in ('','legacy','nft'):
                    errors.append(lineno)
            if errors:
                add('Sintassi configurazione helper', 'error', 'Assegnazioni non valide alle righe '
                    +', '.join(str(n) for n in errors[:12])+'. Non eseguire il file come shell; correggere la sintassi.')
            else: add('Sintassi configurazione helper', 'ok', 'Valori verificati come dati, nessuna esecuzione shell')
        except (OSError, UnicodeError):
            add('Sintassi configurazione helper','error','File non leggibile o non UTF-8')

    for filename in ['/var/lib/iptables-manager/settings.json',
                     '/etc/iptables-manager.web.json']:
        f = path(filename)
        if not f.exists(): continue
        try:
            if f.stat().st_size > 8 * 1024 * 1024:
                add('JSON '+filename, 'error', 'Oltre 8 MiB: non analizzato')
            elif not isinstance(json.loads(f.read_text('utf-8')), dict):
                add('JSON '+filename, 'error', 'La radice JSON deve essere un oggetto')
            else: add('JSON '+filename, 'ok', 'Sintassi e oggetto JSON validi')
        except (OSError, ValueError, UnicodeError):
            add('JSON '+filename, 'error', 'JSON illeggibile o non valido: ripristina dal backup')

    for flag, name in [('pending.json', 'Transazione firewall pendente'),
                       ('update/update.lock', 'Lock aggiornamento presente')]:
        f = path('/var/lib/iptables-manager') / flag
        if flag.endswith('lock'):
            # Lock file existence alone is NOT an active lock.
            if f.exists(): add(name, 'ok', 'Lock presente su disco; non significa aggiornamento attivo')
            continue
        if f.exists(): add(name, 'warn', 'Confermare o ripristinare prima di aggiornare / cambiare rete')
        else: add(name, 'ok', 'Nessuna transazione pendente rilevata')
    if path('/var/lib/iptm/ipv6-control/pending.json').exists():
        add('Transazione IPv6', 'warn', 'Confermare o ripristinare la modifica IPv6 prima di aggiornare')

    # Cross-service consistency: static, read-only inspection of actual files.
    # Never change DNS, firewall or SQM based on inferred configuration alone.
    try:
        import tomllib
        pihole=path('/etc/pihole/pihole.toml')
        if pihole.is_file() and not pihole.is_symlink():
            with pihole.open('rb') as f: pi=tomllib.load(f)
            upstreams=pi.get('dns',{}).get('upstreams',[])
            if isinstance(upstreams,list):
                upstreams=[str(v) for v in upstreams if isinstance(v,str)]
                if any(re.fullmatch(r'(?:127\.0\.0\.1|\[?::1\]?)#?53',x) for x in upstreams):
                    add('Catena DNS Pi-hole', 'error', 'Upstream sulla stessa porta 53 del resolver locale: possibile loop DNS; configurazione NON modificata')
                elif any(re.fullmatch(r'127\.0\.0\.1#5335',x) for x in upstreams):
                    unbound_dir=path('/etc/unbound/unbound.conf.d')
                    texts=[]
                    if unbound_dir.is_dir() and not unbound_dir.is_symlink():
                        for item in sorted(unbound_dir.glob('*.conf'))[:80]:
                            if item.is_file() and not item.is_symlink() and item.stat().st_size<=2_000_000:
                                texts.append(item.read_text('utf-8',errors='replace'))
                    merged='\n'.join(texts)
                    if re.search(r'^\s*forward-addr\s*:\s*(?:127\.0\.0\.1|::1)@?53\s*(?:#.*)?$',merged,re.M):
                        add('Catena DNS Pi-hole → Unbound', 'error', 'Pi-hole usa Unbound :5335, ma Unbound inoltra a DNS :53 locale: possibile ciclo di inoltro')
                    else: add('Catena DNS Pi-hole → Unbound','ok','Upstream 127.0.0.1:5335: nessun ciclo verso :53 nei frammenti Unbound esaminati')
                elif any(re.fullmatch(r'127\.0\.0\.1#5053',x) for x in upstreams):
                    add('Catena DNS Pi-hole → DNSCrypt','ok','Upstream locale 5053 configurato; verificare stato listener e DNSSEC separatamente')
    except (OSError,ValueError,UnicodeError,AttributeError,TypeError) as exc:
        add('Catena DNS Pi-hole', 'warn', 'Configurazione non analizzabile in sola lettura: '+str(type(exc).__name__))

    try:
        conf=path('/etc/iptables-manager.conf'); settings=path('/var/lib/iptables-manager/settings.json')
        if conf.is_file() and settings.is_file() and not conf.is_symlink() and not settings.is_symlink():
            raw=conf.read_text('utf-8'); cfg={}
            for name in ('SQM_IF','SQM_UP','SQM_DOWN'):
                m=re.search(r'^\s*'+name+r'\s*=\s*([A-Za-z0-9_.-]{1,20})\s*$',raw,re.M)
                if m:cfg[name]=m.group(1)
            qs=json.loads(settings.read_text('utf-8')).get('sqm',{})
            if isinstance(qs,dict) and qs.get('on') and all(x in cfg for x in ('SQM_IF','SQM_UP','SQM_DOWN')):
                if (qs.get('iface')!=cfg['SQM_IF'] or str(qs.get('up'))!=cfg['SQM_UP'] or str(qs.get('down'))!=cfg['SQM_DOWN']):
                    add('Coerenza SQM helper/UI','warn','Limiti SQM diversi tra settings.json e configurazione helper: confrontare con tc e sincronizzare dalla pagina QoS')
                else:add('Coerenza SQM helper/UI','ok','Interfaccia e limiti salvati coincidono; verificare comunque i rate effettivi con tc')
    except (OSError,ValueError,UnicodeError,AttributeError,TypeError):pass

    if probe_commands and root == pathlib.Path('/'):
        required = ('python3', 'php', 'bash', 'sudo', 'ip', 'tc', 'iptables',
                    'iptables-save', 'iptables-restore', 'ip6tables', 'ipset', 'unzip',
                    'curl', 'ss', 'systemctl', 'flock')
        for name in required:
            present = shutil.which(name) is not None
            # IPv6 and optional kernel features may be intentionally disabled.
            status = 'ok' if present else ('warn' if name in ('ip6tables', 'ipset') else 'error')
            add('Binario '+name, status, 'Disponibile' if present else 'Assente dal PATH: installa o correggi il percorso')
        for name in ('pihole-FTL', 'unbound', 'dnscrypt-proxy', 'crowdsec',
                     'cscli', 'suricata', 'suricata-update', 'speedtest'):
            present = ookla_speedtest_present() if name == 'speedtest' else bool(shutil.which(name))
            add('Integrazione '+name, 'ok' if present else 'warn',
                'Binario disponibile' if present else 'Opzionale, non installato o non nel PATH')
        ookla_ready = ookla_speedtest_present()
        add('Motore speedtest', 'ok' if ookla_ready else 'warn',
            'Motore Ookla rilevato' if ookla_ready else 'Motore ufficiale non disponibile; aggiornamento automatico QoS non sicuro')
        for name in ('pihole-FTL', 'unbound', 'dnscrypt-proxy', 'crowdsec',
                     'suricata', 'crowdsec-firewall-bouncer'):
            if not shutil.which('systemctl'): break
            r = command('systemctl', ('is-active', name+'.service'), seconds=3)
            active = r and r.returncode == 0 and r.stdout.strip() == 'active'
            add('Servizio '+name, 'ok' if active else 'warn',
                'Attivo' if active else 'Inattivo/non installato: verifica se richiesto dalla tua configurazione')
        for filename in ('/etc/iptables/rules.v4', '/etc/iptables/rules.v6'):
            f = path(filename)
            tool = 'iptables-restore' if filename.endswith('v4') else 'ip6tables-restore'
            if f.exists() and f.is_file() and shutil.which(tool):
                try:
                    with f.open('rb') as inp:
                        r = subprocess.run([tool, '--test'], stdin=inp,
                                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                           timeout=4, check=False)
                    ok = (r.returncode == 0)
                    add('Sintassi '+filename, 'ok' if ok else 'warn',
                        'Test restore superato' if ok else 'Test fallito: confronta backend e stato IPv6; nessuna regola applicata')
                except (OSError, subprocess.TimeoutExpired):
                    add('Sintassi '+filename, 'warn', 'Test restore non completato')
            elif f.exists(): add('Sintassi '+filename, 'warn', 'Restore non disponibile, regole non testate')
        conf = path('/etc/iptables-manager.conf')
        if conf.exists():
            try:
                t = conf.read_text('utf-8')[:50000]
                def get(k):
                    m = re.search(r'^\s*'+re.escape(k)+r'=([^\n]*)$', t, re.M)
                    return m.group(1).strip(' \"\'') if m else ''
                if get('SQM_AUTOCAL') == '1':
                    speed = ookla_speedtest_present()
                    add('Calibrazione CAKE automatica', 'ok' if speed else 'warn',
                        'Speedtest bidirezionale disponibile' if speed else 'Installa il motore ufficiale Ookla; curl non misura upload e non deve modificare CAKE')
                    if not get('SQM_IF') or not get('SQM_UP') or not get('SQM_DOWN'):
                        add('Profilo CAKE', 'warn', 'Interfaccia o velocità non configurate: non applicare automaticamente')
            except (OSError, UnicodeError):
                add('Configurazione SQM', 'warn', 'File illeggibile; cambiare opzioni bloccato in sicurezza')
        ftl = shutil.which('pihole-FTL')
        if ftl:
            port = command('pihole-FTL', ('--config','webserver.port'), seconds=4)
            if port and port.returncode == 0:
                val = port.stdout.strip().splitlines()[-1][:160] if port.stdout.strip() else '(vuoto)'
                add('Pi-hole FTL webserver.port', 'ok',
                    'Valore letto: '+val+'; confronta con le porte in ascolto e le regole INPUT')
            else: add('Pi-hole FTL webserver.port', 'warn',
                      'Non leggibile: controlla sudo pihole-FTL --config webserver.port e il file pihole.toml')
            sockets = command('ss', ('-H','-tln'), seconds=3)
            if sockets and sockets.returncode == 0:
                ports = set(re.findall(r':(\d+)(?:\s|$)', sockets.stdout))
                found = sorted(ports & {'80','443','8089','8080','8443'},key=int)
                add('Pi-hole / web porte TCP', 'ok' if found else 'warn',
                    'Porte tra 80/443/8089/8080/8443 in ascolto: '+(', '.join(found) if found else 'nessuna')+
                    '. Verifica quale processo possiede la porta con ss -ltnp')
        elif path('/etc/pihole/pihole.toml').exists():
            add('Pi-hole FTL', 'warn', 'Configurazione presente, ma binario FTL assente dal PATH')
        try:
            available = re.search(r'MemAvailable:\s*(\d+)',path('/proc/meminfo').read_text())
            if available and int(available.group(1)) < 131072:
                add('Memoria libera', 'warn', 'Meno di 128 MiB disponibili: limitare test e scansioni concorrenti')
        except (OSError, ValueError): pass
    return {'ok': True, 'readonly': True, 'checks': checks,
            'counts': {name:sum(c['status']==name for c in checks) for name in ('ok','warn','error')}}


def preflight_cli(args):
    emit(preflight_checks())
    return 0

def main():
    ap=argparse.ArgumentParser(description='IPTM maintenance engine')
    sub=ap.add_subparsers(dest='cmd',required=True)
    sub.add_parser('pihole-catalog')
    sub.add_parser('rethink-catalog')
    sub.add_parser('rethink-refresh')
    sub.add_parser('pihole-import-json')
    sub.add_parser('pihole-api-json')
    pi=sub.add_parser('pihole-import'); pi.add_argument('--db'); pi.add_argument('--whitelist'); pi.add_argument('--allow-regex'); pi.add_argument('--deny-regex'); pi.add_argument('--adlists',action='append'); pi.add_argument('--apply',action='store_true')
    sa=sub.add_parser('sysctl-audit')
    sy=sub.add_parser('sysctl-apply'); sy.add_argument('--file',required=True); sy.add_argument('--apply',action='store_true')
    sub.add_parser('sysctl-verify')
    sub.add_parser('preflight')
    ur=sub.add_parser('update-recovery'); ur.add_argument('operation',choices=['stage','recover','commit']); ur.add_argument('--state',required=True); ur.add_argument('--web')
    a=ap.parse_args()
    try:
        if a.cmd in ('rethink-catalog','rethink-refresh'):
            import subprocess
            ext=str(RETHINK_SCRIPT)
            return subprocess.call(['/usr/bin/python3','-B',ext,'list' if a.cmd=='rethink-catalog' else 'refresh'],timeout=90)
        if a.cmd=='pihole-catalog': return catalog_cmd(a)
        if a.cmd=='pihole-import-json': return import_pihole_json(a)
        if a.cmd=='pihole-api-json': return pihole_api_json(a)
        if a.cmd=='pihole-import': return import_pihole(a)
        if a.cmd=='sysctl-audit': return sysctl_audit(a)
        if a.cmd=='sysctl-apply': return sysctl_apply(a)
        if a.cmd=='sysctl-verify': return sysctl_verify(a)
        if a.cmd=='preflight': return preflight_cli(a)
        if a.cmd=='update-recovery': return update_recovery_cli(a)
    except Exception as e:
        emit({'ok':False,'error':str(e)}); return 2
    return 2
if __name__=='__main__': raise SystemExit(main())
