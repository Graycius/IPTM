#!/usr/bin/env python3
"""Root-only opt-in explicit proxy policy for local mitmproxy/ClamAV.

This NEVER routes or intercepts a device transparently. Each client must opt in
by configuring its proxy and trusting a locally generated CA if HTTPS is needed.
"""
import ipaddress,json,os,pathlib,re,stat,subprocess,sys,tempfile,time
POLICY=pathlib.Path('/etc/iptables-manager/traffic-optin.json')
BK=pathlib.Path('/var/lib/iptables-manager/backups/traffic-optin')

def validate(payload):
    if not isinstance(payload,dict):raise ValueError('Formato non valido')
    ips=payload.get('clients',[]);hosts=payload.get('hosts',[]);ports=payload.get('ports',[])
    if not isinstance(ips,list) or not 1<=len(ips)<=32 or not isinstance(hosts,list) or not 1<=len(hosts)<=32:
        raise ValueError('Seleziona almeno un client e un dominio, max 32 ciascuno')
    if not isinstance(ports,list) or not ports or not set(ports).issubset({80,443}):
        raise ValueError('Seleziona HTTP 80, HTTPS 443 o entrambi')
    clean_ips=[]
    for ip in ips:
        if not isinstance(ip,str):raise ValueError('Client non valido')
        obj=ipaddress.ip_address(ip)
        if obj.version!=4 or not obj.is_private or obj.is_loopback or obj.is_multicast or obj.is_unspecified:
            raise ValueError('Sono ammessi soltanto indirizzi IPv4 privati dei client LAN')
        clean_ips.append(str(obj))
    clean_hosts=[]
    for host in hosts:
        if not isinstance(host,str) or not re.fullmatch(r'(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}',host.strip().lower()):
            raise ValueError('Dominio destinazione non valido')
        clean_hosts.append(host.strip().lower())
    return {'clients':sorted(set(clean_ips)),'hosts':sorted(set(clean_hosts)),'ports':sorted(set(ports)),
            'mode':'explicit-local','log_content':False,'version':1}

def secure(path,dir=False):
    if path.is_symlink():raise ValueError('Percorso simbolico non sicuro')
    if path.exists():
        st=path.stat()
        if st.st_uid!=0 or st.st_mode&0o022 or (not path.is_dir() if dir else not path.is_file()):
            raise ValueError('Percorso file o directory non sicuro')

def action(mode):
    secure(POLICY);secure(POLICY.parent,True);secure(BK,True)
    if mode=='show':
        print(json.dumps({'ok':True,'policy':json.loads(POLICY.read_text()) if POLICY.is_file() else None}));return
    if os.geteuid()!=0:raise ValueError('Richiede root')
    raw=sys.stdin.buffer.read(16384)
    if len(raw)>8192:raise ValueError('Profilo troppo grande')
    profile=validate(json.loads(raw))
    if mode=='preview':
        print(json.dumps({'ok':True,'profile':profile,'changed':not POLICY.exists() or json.loads(POLICY.read_text())!=profile}));return
    old=POLICY.read_bytes() if POLICY.exists() else None
    new=json.dumps(profile,sort_keys=True,separators=(',',':')).encode('utf-8')
    if new==old:print(json.dumps({'ok':True,'changed':False}));return
    POLICY.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
    BK.mkdir(mode=0o700,parents=True,exist_ok=True);os.chmod(BK,0o700)
    if old is not None:
        save=BK/('policy-'+str(time.time_ns())+'.json')
        with save.open('xb') as f:f.write(old)
        save.chmod(0o600)
    temp=None
    try:
        with tempfile.NamedTemporaryFile(mode='wb',dir=POLICY.parent,prefix='.iptm-proxy-',delete=False) as f:
            os.fchmod(f.fileno(),0o600);f.write(new);f.flush();os.fsync(f.fileno());temp=pathlib.Path(f.name)
        os.replace(temp,POLICY);temp=None
        if subprocess.run(['systemctl','is-active','--quiet','iptm-traffic-proxy.service'],timeout=10).returncode==0:
            subprocess.run(['systemctl','restart','iptm-traffic-proxy.service'],timeout=30,check=True)
    except BaseException:
        if temp is not None:temp.unlink(missing_ok=True)
        if old is None:POLICY.unlink(missing_ok=True)
        else:
            with tempfile.NamedTemporaryFile(mode='wb',dir=POLICY.parent,delete=False) as f:
                f.write(old);os.fchmod(f.fileno(),0o600);restore=pathlib.Path(f.name)
            os.replace(restore,POLICY)
        try:subprocess.run(['systemctl','try-restart','iptm-traffic-proxy.service'],timeout=30,check=False)
        except Exception:pass
        raise
    backups=sorted(BK.glob('policy-*.json'),key=lambda x:x.stat().st_mtime_ns,reverse=True)
    for file in backups[10:]:
        if file.is_file() and not file.is_symlink():file.unlink()
    print(json.dumps({'ok':True,'changed':True,'note':'Applicata policy al proxy esplicito, non modificato il firewall.'}))

if __name__=='__main__':
    try:
        if len(sys.argv)!=2 or sys.argv[1] not in ('preview','apply','show'):raise ValueError('Uso: preview|apply|show')
        action(sys.argv[1])
    except Exception as exc:
        print(json.dumps({'ok':False,'error':str(exc)}));sys.exit(2)
