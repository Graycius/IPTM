#!/usr/bin/env python3
"""IPTM security-stack operator: CrowdSec feeds and Suricata rule operations.

CLI is root-only, machine-readable; previews have no side effects to either engine.
Only explicit approved local sources are accepted for feed downloads. Web requests
are never performed by the admin PHP process. CLI invocation is strictly argv.
"""

from command_transport import capture
import fcntl, hashlib, ipaddress, json, os, pathlib, re, shutil, subprocess, sys, tempfile, time, urllib.request

BASE=pathlib.Path('/var/lib/iptm-security-stack')
LOCK=BASE/'lock'
PLAN=BASE/'plan.json'
MAX_BYTES=3*1024*1024
MAX_ENTRIES=25000
TTL=900
SOURCE=re.compile(r'^[a-zA-Z0-9_-]+/[a-zA-Z0-9_.-]+$')
URL=re.compile(r'^https://[A-Za-z0-9.-]+(?:/[A-Za-z0-9_./?&=%+~-]*)?$')
# Operator explicitly chooses a trusted HTTPS source. Block private/loopback redirect
# targets with DNS address verification; do not permit arbitrary URLs from a browser.
ALLOWED_HOSTS={'raw.githubusercontent.com','github.com','www.spamhaus.org','iplists.firehol.org','blocklist.de','rules.emergingthreats.net'}
class StackError(Exception): pass

def check_root():
    if os.geteuid(): raise StackError('richiede root')
def safe_dir():
    if BASE.is_symlink(): raise StackError('directory simbolica')
    BASE.mkdir(parents=True,exist_ok=True,mode=0o700)
    s=BASE.stat()
    if s.st_uid or s.st_mode&0o077: raise StackError('directory non root:0700')
def write_json(path,obj):
    from command_transport import durable_json
    durable_json(path,obj)


def read_plan():
    from command_transport import read_private_json
    import math
    try:v=read_private_json(PLAN,limit=MAX_BYTES+65536)
    except (OSError,ValueError,UnicodeError) as exc:raise StackError('Piano non protetto') from exc
    if v is None:raise StackError('Nessun piano')
    created=v.get('created')
    if type(created) not in (int,float) or not math.isfinite(created) or not 0<=time.time()-created<=TTL:raise StackError('Piano scaduto')
    digest=v.get('digest')
    if not isinstance(digest,str) or not re.fullmatch('[a-f0-9]{64}',digest):raise StackError('Digest del piano non valido')
    if v.get('type')=='crowdsec-feed':
        values=v.get('values')
        if not isinstance(values,list) or not 1<=len(values)<=MAX_ENTRIES or not all(isinstance(x,str) for x in values):raise StackError('Feed non valido')
        raw=('\n'.join(values)+'\n').encode()
        parsed,_=parse_feed(raw)
        if sorted(parsed)!=values or hashlib.sha256(raw).hexdigest()!=digest:raise StackError('Feed modificato')
        if v.get('duration') not in ('1h','4h','12h','24h','48h') or not isinstance(v.get('reason'),str) or not re.fullmatch('[a-z0-9_-]{3,32}',v['reason']):raise StackError('Metadati feed non validi')
    elif v.get('type')=='suricata-source':
        if not isinstance(v.get('source'),str) or not SOURCE.fullmatch(v['source']) or type(v.get('enabled')) is not bool:raise StackError('Piano Suricata non valido')
        if hashlib.sha256(json.dumps({k:x for k,x in v.items() if k!='digest'},sort_keys=True).encode()).hexdigest()!=digest:raise StackError('Piano Suricata modificato')
    else:raise StackError('Tipo piano non valido')
    return v


def run(args,timeout=45,check=True):
    try:r=capture(args,timeout=timeout)
    except (OSError,subprocess.TimeoutExpired) as e:raise StackError('esecuzione non disponibile: '+str(e)) from e
    if check and r.returncode:raise StackError('comando fallito: '+(r.stderr or r.stdout)[-350:])
    return r

def inventory():
    result={}
    for cmd in ['cscli','crowdsec','crowdsec-firewall-bouncer','suricata','suricata-update','suricatasc','evebox','nmcli']:
        result[cmd]=shutil.which(cmd)
    for unit in ['crowdsec','crowdsec-firewall-bouncer','suricata','NetworkManager']:
        try:
            status=run(['systemctl','is-active',unit],timeout=3,check=False).stdout.strip()
            result[unit+'_status']=status if status in ('active','inactive','failed','activating','deactivating','reloading','maintenance','unknown') else 'unknown'
        except StackError:
            result[unit+'_status']='unknown'
    return {'ok':True,'components':result,'third_party_gui':'optional-not-embedded'}

def parse_feed(contents):
    if len(contents)>MAX_BYTES:raise StackError('feed troppo grande')
    entries=set(); invalid=0; excluded=0
    for line in contents.decode('utf-8','replace').splitlines():
        val=line.split('#',1)[0].strip()
        if not val:continue
        # Only one IP or network per line, not hostnames or shell scripts.
        if not re.fullmatch(r'[0-9a-fA-F:.\/]{3,49}',val):invalid+=1;continue
        try:net=ipaddress.ip_network(val,strict=False)
        except ValueError:invalid+=1;continue
        if not net.is_global or net.is_multicast or net.is_reserved or net.is_loopback or net.is_link_local:
            excluded+=1;continue
        if net.version==4 and net.prefixlen<16 or net.version==6 and net.prefixlen<48:
            excluded+=1;continue
        entries.add(str(net.network_address) if net.prefixlen==net.max_prefixlen else str(net))
        if len(entries)>MAX_ENTRIES:raise StackError('feed supera limite sicuro')
    return sorted(entries),{'unique':len(entries),'invalid':invalid,'excluded':excluded}

def download(url):
    from urllib.parse import urlparse
    import socket
    u=urlparse(url)
    if not URL.fullmatch(url) or u.hostname not in ALLOWED_HOSTS or u.username or u.password or u.port:
        raise StackError('URL HTTPS non approvato')
    # Reject local DNS results; urllib can follow redirects, so disable them.
    for item in socket.getaddrinfo(u.hostname,443,type=socket.SOCK_STREAM):
        if not ipaddress.ip_address(item[4][0]).is_global:raise StackError('destinazione non pubblica')
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,*a,**k):raise StackError('redirect HTTPS non consentito')
    opener=urllib.request.build_opener(NoRedirect())
    with opener.open(urllib.request.Request(url,headers={'User-Agent':'IPTM-security-stack/1.0'}),timeout=12) as response:
        if response.status!=200:raise StackError('HTTP '+str(response.status))
        contents=response.read(MAX_BYTES+1)
    if len(contents)>MAX_BYTES:raise StackError('dimensione eccessiva')
    return contents

def stage_feed(payload):
    if not isinstance(payload,dict) or set(payload)-{'urls','duration','reason','local_files'}:
        raise StackError('schema feed inatteso')
    urls=payload.get('urls',[]);files=payload.get('local_files',[])
    if not isinstance(urls,list) or not isinstance(files,list) or len(urls)+len(files)<1 or len(urls)+len(files)>8:
        raise StackError('scegliere 1..8 feed')
    duration=payload.get('duration','4h')
    if duration not in ('1h','4h','12h','24h','48h'):raise StackError('durata non supportata')
    reason=payload.get('reason','iptm-feed')
    if not re.fullmatch(r'[a-z0-9_-]{3,32}',reason):raise StackError('etichetta non valida')
    entries=set();sources=[];totals={'invalid':0,'excluded':0}
    for url in urls:
        if not isinstance(url,str):raise StackError('URL non valido')
        vals,stats=parse_feed(download(url));sources.append(url);entries.update(vals)
        for k in totals:totals[k]+=stats[k]
    for path in files:
        if not isinstance(path,str):raise StackError('percorso importazione non valido')
        base=pathlib.Path('/var/lib/iptables-manager/imports')
        p=pathlib.Path(path)
        # Reject traversal and symlinked ancestors, not just a symlink at leaf.
        if not p.is_absolute() or '..' in p.parts or p.parent != base:
            raise StackError('file fuori area importazioni')
        if any(node.is_symlink() for node in (base.parent,base,p)):
            raise StackError('percorso importazione simbolico')
        fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            import stat
            meta=os.fstat(fd)
            if not stat.S_ISREG(meta.st_mode) or meta.st_size>MAX_BYTES or meta.st_uid != 0 or meta.st_mode & 0o022:
                raise StackError('file importazione non valido o modificabile da altri')
            with os.fdopen(fd,'rb',closefd=False) as handle:
                raw=handle.read(MAX_BYTES+1)
        finally:os.close(fd)
        vals,stats=parse_feed(raw);sources.append(path);entries.update(vals)
        for k in totals:totals[k]+=stats[k]
    if not entries:raise StackError('nessun indirizzo pubblico valido')
    if len(entries)>MAX_ENTRIES:raise StackError('troppe voci')
    canonical='\n'.join(sorted(entries))+'\n'
    digest=hashlib.sha256(canonical.encode()).hexdigest()
    state={'type':'crowdsec-feed','created':time.time(),'digest':digest,'duration':duration,'reason':reason,
           'sources':sources,'values':sorted(entries),'stats':totals}
    write_json(PLAN,state)
    return {'ok':True,'sha256':digest,'total':len(entries),'sources':sources,'sample':sorted(entries)[:12],**totals,
            'expires_seconds':TTL,'applied':False}

def crowd_apply(digest):
    p=read_plan()
    if p.get('type')!='crowdsec-feed' or p.get('digest')!=digest:raise StackError('SHA piano diverso')
    if shutil.which('cscli') is None:raise StackError('cscli mancante')
    if not re.fullmatch('[a-f0-9]{64}',digest):raise StackError('hash non valido')
    # CSV explicitly carries scope, to avoid misinterpreting CIDRs as IPv4 values.
    f=tempfile.NamedTemporaryFile(mode='w',suffix='.csv',dir=BASE,delete=False)
    path=f.name
    try:
        os.fchmod(f.fileno(),0o600)
        f.write('duration,reason,scope,type,value\n')
        for item in p['values']:
            f.write(','.join([p['duration'],p['reason'],'range' if '/' in item else 'ip','ban',item])+'\n')
        f.flush();os.fsync(f.fileno());f.close()
        result=run(['cscli','decisions','import','-i',path,'--format','csv'],timeout=90)
        count=len(p['values']);p.pop('values',None);p['applied_at']=time.time();write_json(BASE/'last-import.json',p)
        PLAN.unlink()
        return {'ok':True,'count':count,'result':result.stdout[-600:]}
    finally:
        f.close()
        pathlib.Path(path).unlink(missing_ok=True)

def suricata_sources():
    if not shutil.which('suricata-update'):raise StackError('suricata-update mancante')
    r=run(['suricata-update','list-sources','--enabled'],timeout=20,check=False)
    return {'ok':r.returncode==0,'sources':r.stdout[-12000:],'error':r.stderr[-400:]}

def stage_suricata(payload):
    if not isinstance(payload,dict) or set(payload)!={'source','enabled'} or type(payload['enabled']) is not bool:
        raise StackError('schema sorgente non valido')
    if not isinstance(payload['source'],str) or not SOURCE.fullmatch(payload['source']):
        raise StackError('nome fonte non valido')
    p={'type':'suricata-source','created':time.time(),'source':payload['source'],'enabled':payload['enabled']}
    digest=hashlib.sha256(json.dumps(p,sort_keys=True).encode()).hexdigest();p['digest']=digest
    write_json(PLAN,p)
    return {'ok':True,'sha256':digest,'operation':'enable-source' if payload['enabled'] else 'disable-source',
            'source':payload['source'],'applied':False}

def suricata_apply(digest):
    p=read_plan()
    if p.get('type')!='suricata-source' or p['digest']!=digest:raise StackError('SHA sorgente diverso')
    if not shutil.which('suricata-update') or not shutil.which('suricata'):
        raise StackError('Suricata e suricata-update obbligatori')
    action='enable-source' if p['enabled'] else 'disable-source'
    # Record prior enabled state and preserve the generated ruleset before changing sources.
    previous=run(['suricata-update','list-sources','--enabled'],timeout=20,check=False)
    if previous.returncode:raise StackError('stato fonti Suricata non verificabile')
    previously_enabled=p['source'] in previous.stdout
    original=pathlib.Path('/var/lib/suricata/rules/suricata.rules')
    if original.is_symlink():raise StackError('ruleset con link simbolico: aggiornamento rifiutato')
    original_bytes=original.read_bytes() if original.is_file() else None
    if original_bytes is not None and len(original_bytes)>30*1024*1024:raise StackError('ruleset troppo grande per rollback locale')
    try:
        run(['suricata-update',action,p['source']],timeout=50)
        # --no-reload never restarts Suricata. Validate generated rules before reload.
        run(['suricata-update','--no-reload'],timeout=150)
        run(['suricata','-T','-c','/etc/suricata/suricata.yaml'],timeout=100)
    except Exception:
        try:
            opposite='enable-source' if previously_enabled else 'disable-source'
            run(['suricata-update',opposite,p['source']],timeout=50,check=False)
            if original_bytes is not None:
                tmp=BASE/'rules-rollback.tmp'
                with tmp.open('wb') as fh:
                    os.fchmod(fh.fileno(),0o600);fh.write(original_bytes);fh.flush();os.fsync(fh.fileno())
                os.replace(tmp,original)
            elif original.is_file():original.unlink()
        except OSError as e:
            raise StackError('ripristino regole incompleto: '+str(e)) from e
        raise
    PLAN.unlink()
    return {'ok':True,'validated':True,'reload':'manual','source':p['source']}

def main(argv):
    check_root();safe_dir()
    from command_transport import domain_lock
    with domain_lock(LOCK):
        if argv==['status']:return inventory()
        if argv==['suricata-sources']:return suricata_sources()
        if argv in (['crowdsec-stage'],['suricata-stage']):
            contents=sys.stdin.buffer.read(8193)
            if len(contents)>8192:raise StackError('JSON troppo grande')
            obj=json.loads(contents)
            return stage_feed(obj) if argv[0]=='crowdsec-stage' else stage_suricata(obj)
        if len(argv)==2 and argv[0] in ('crowdsec-apply','suricata-apply'):
            if not re.fullmatch(r'[a-f0-9]{64}',argv[1]):raise StackError('hash errato')
            return crowd_apply(argv[1]) if argv[0]=='crowdsec-apply' else suricata_apply(argv[1])
        if argv==['plan']:
            p=read_plan();return {k:v for k,v in p.items() if k!='values'}
        raise StackError('comando sconosciuto')
def coordinated_main(args):
    from command_transport import driver_admission
    with driver_admission('security_stack',args):
        return main(args)

if __name__=='__main__':
    try:print(json.dumps(coordinated_main(sys.argv[1:]),ensure_ascii=False))
    except (StackError,ValueError,KeyError,OSError) as e:
        print(json.dumps({'ok':False,'error':str(e)},ensure_ascii=False));sys.exit(1)
