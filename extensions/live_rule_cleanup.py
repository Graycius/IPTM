#!/usr/bin/env python3
"""Conservative *runtime* iptables cleanup for IPTM-owned custom chains.

Only adjacent bit-identical duplicate append rules in IPTM_* chains are eligible.
Never flush tables or touch third-party chains; perform a fresh exact snapshot check
before each deletion. All operations are logged with a root-only snapshot.
"""
from __future__ import annotations
import fcntl, hashlib, json, os, pathlib, re, subprocess, sys, time

BASE=pathlib.Path('/var/lib/iptm-live-rule-cleanup')
TABLES=('filter','nat','mangle','raw','security')
CHAIN=re.compile(r'^IPTM_[A-Za-z0-9_]{1,24}$')
APPEND=re.compile(r'^-A (IPTM_[A-Za-z0-9_]{1,24}) (.+)$')
class CleanupError(Exception): pass

def command(*args):
    try: p=subprocess.run(args,capture_output=True,text=True,timeout=20,check=False)
    except (OSError,subprocess.TimeoutExpired) as e:raise CleanupError(str(e)) from e
    if p.returncode: raise CleanupError('Comando non riuscito: '+str(args[0])+': '+p.stderr[-280:])
    return p.stdout

def digest(x):return hashlib.sha256(x.encode()).hexdigest()

def candidates(snapshot):
    """Only consecutive identical rules in explicit IPTM-owned *user chains*."""
    table=None; index={}; last_line=None; findings=[]
    for line in snapshot.splitlines():
        if line.startswith('*'):
            table=line[1:];index={};last_line=None;continue
        if line=='COMMIT':table=None;last_line=None;continue
        if table not in TABLES: continue
        if line.startswith(':'):
            current=line.split()[0][1:]
            last_line=None
            if CHAIN.fullmatch(current):index[current]=0
            continue
        m=APPEND.fullmatch(line)
        if not m or m[1] not in index:
            last_line=None
            continue
        chain=m[1];index[chain]+=1
        if last_line==line:
            findings.append({'table':table,'chain':chain,'number':index[chain],'rule':line})
        last_line=line
    return findings

def snapshot():
    out={'v4':command('iptables-save')}
    try:out['v6']=command('ip6tables-save')
    except CleanupError:
        flag=pathlib.Path('/proc/sys/net/ipv6/conf/all/disable_ipv6')
        if flag.exists() and flag.read_text().strip()=='1':
            # Full IPv6 disable is an explicit IPTM mode; no v6 rules can be scanned.
            return out
        raise
    return out

def plan(current):
    found=[dict(family=fam,**item) for fam,snap in current.items() for item in candidates(snap)]
    hashes={fam:digest(snap) for fam,snap in current.items()}
    if len(found)>200:raise CleanupError('Troppe regole candidate: analisi manuale necessaria')
    payload={'hashes':hashes,'findings':found}
    payload['plan_sha256']=digest(json.dumps(payload,sort_keys=True))
    return payload

def ensure_root():
    if os.geteuid()!=0:raise CleanupError('root richiesto')
    if BASE.is_symlink():raise CleanupError('directory di stato non sicura')
    BASE.mkdir(parents=True,exist_ok=True,mode=0o700)
    os.chmod(BASE,0o700)
    if BASE.stat().st_uid:raise CleanupError('directory di stato non root')

def apply(expected):
    if not re.fullmatch('[a-f0-9]{64}',expected):raise CleanupError('SHA256 non valido')
    ensure_root()
    with (BASE/'lock').open('a+') as lock:
        os.chmod(BASE/'lock',0o600);fcntl.flock(lock,fcntl.LOCK_EX)
        before=snapshot();p=plan(before)
        if p['plan_sha256']!=expected:raise CleanupError('Il firewall è cambiato: rigenerare anteprima')
        if not p['findings']:return {'ok':True,'removed':0}
        stamp=str(int(time.time()))+'-'+expected[:12]
        for fam,data in before.items():
            dest=BASE/(stamp+'-'+fam+'.rules')
            with dest.open('x') as out:os.fchmod(out.fileno(),0o600);out.write(data);out.flush();os.fsync(out.fileno())
        # Delete bottom-to-top, retaining the first rule of each identical pair.
        selected=sorted(p['findings'],key=lambda x:(x['family'],x['table'],x['chain'],-x['number']))
        removed=[]
        for item in selected:
            fam,table,chain,n=item['family'],item['table'],item['chain'],item['number']
            tool='iptables' if fam=='v4' else 'ip6tables'
            try:
                # Live verification under the same iptables global xtables lock.
                live=snapshot()[fam]
                present=[f for f in candidates(live) if f['table']==table and f['chain']==chain and f['number']==n and f['rule']==item['rule']]
                if not present:
                    raise CleanupError('Firewall mutato durante la pulizia; operazione interrotta')
                command(tool,'-w','5','-t',table,'-D',chain,str(n))
                removed.append(item)
            except Exception as exc:
                # Only reinsert rules if their exact position is still available;
                # never restore a whole machine-wide ruleset over third-party changes.
                failures=[]
                for old in reversed(removed):
                    try:
                        import shlex
                        argv=shlex.split(old['rule'])
                        command('iptables' if old['family']=='v4' else 'ip6tables','-w','5','-t',old['table'],'-I',old['chain'],str(old['number']),*argv[2:])
                    except Exception as rollback_error:failures.append(str(rollback_error))
                raise CleanupError('Pulizia arrestata: '+str(exc)+ ('; ripristino parziale: '+str(failures) if failures else '; ripristino tentato'))
        report={'ok':True,'removed':len(removed),'snapshots':stamp,'details':removed}
        log=BASE/(stamp+'.json');log.write_text(json.dumps(report,indent=2));log.chmod(0o600)
        return report

def main(argv):
    if len(argv)==1 and argv[0]=='scan':
        ensure_root();return dict(ok=True,**plan(snapshot()))
    if len(argv)==2 and argv[0]=='apply':return apply(argv[1])
    raise CleanupError('uso: scan | apply SHA256')

if __name__=='__main__':
    try:print(json.dumps(main(sys.argv[1:]),ensure_ascii=False))
    except (CleanupError,ValueError) as ex:print(json.dumps({'ok':False,'error':str(ex)}));sys.exit(1)
