#!/usr/bin/env python3
"""Guarded forwarding-only NFQUEUE trial with explicit, rollback-protected boot persistence.

Persistence is opt-in only after the administrator confirms a live trial. A boot
job rechecks profile hashes and local routing before installing rules; an
independent timer disables persistence after boot failures.
"""
from __future__ import annotations
import fcntl, hashlib, json, os, pathlib, re, secrets, subprocess, sys, time

STATE=pathlib.Path('/run/iptm-antidpi-live.json')
LOCK=pathlib.Path('/run/lock/iptm-antidpi-live.lock')
CHAIN='IPTM_DPI_TRIAL'
UNIT='iptm-antidpi-trial'
GRACE=120
# The independent systemd timer must invoke the very same verified release.
SCRIPT=str(pathlib.Path(__file__).resolve())
ENGINE_MOD_DIR=pathlib.Path(__file__).resolve().parent
PERSIST_DIR=pathlib.Path('/var/lib/iptm-antidpi')
PERSIST=PERSIST_DIR/'persistent.json'
UNIT_FILE=pathlib.Path('/etc/systemd/system/iptm-antidpi-persist.service')
BOOT_HEALTH_DELAY=20

class TrialError(Exception): pass

def _safe_error(raw):
    # Best-effort redaction; never expose arbitrary subprocess output to the web UI.
    line=re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', raw.decode('utf-8','replace'))
    line=next((v.strip() for v in line.splitlines() if v.strip()), '')[:240]
    line=re.sub(r'(?i)(password|passwd|token|secret|api[_-]?key)\s*[:=]\s*\S+',r'\1=[redacted]',line)
    line=re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b','[IP]',line)
    return ''.join(ch for ch in line if ch.isprintable())

def cmd(argv,timeout=12,check=True,stage=None):
    try:
        run=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,timeout=timeout,check=False)
    except (OSError,subprocess.TimeoutExpired) as e:
        raise TrialError((stage or pathlib.Path(argv[0]).name)+': esecuzione non disponibile ('+type(e).__name__+')')
    if check and run.returncode:
        detail=_safe_error(run.stderr or run.stdout)
        if 'file_open_test' in detail and 'Permission denied' in detail:
            detail='file_open_test: accesso negato dopo la riduzione dei privilegi; verifica permessi su hostlist, Lua e directory parent'
        raise TrialError((stage or pathlib.Path(argv[0]).name)+': exit '+str(run.returncode) + (', dettaglio: '+detail if detail else ', nessun dettaglio restituito'))
    return run.returncode

def secure_file(p):
    if p.is_symlink() or not p.is_file() or p.stat().st_uid!=0 or p.stat().st_mode&0o022:
        raise TrialError('File non protetto o mancante: '+p.name)

def current():
    if STATE.is_symlink():raise TrialError('Stato Anti-DPI non sicuro')
    if not STATE.exists():return None
    st=STATE.stat()
    if not STATE.is_file() or st.st_uid!=0 or st.st_mode&0o077 or st.st_size>4096:
        raise TrialError('Stato Anti-DPI non protetto')
    j=json.loads(STATE.read_text())
    if not isinstance(j,dict) or not re.fullmatch('[a-f0-9]{24}',str(j.get('token',''))):
        raise TrialError('Stato Anti-DPI non valido')
    return j

def persistent():
    if PERSIST_DIR.is_symlink():raise TrialError('Directory persistenza Anti-DPI non sicura')
    if not PERSIST.exists():return None
    if PERSIST.is_symlink() or not PERSIST.is_file() or PERSIST.stat().st_uid!=0 or PERSIST.stat().st_mode & 0o077 or PERSIST.stat().st_size>4096:
        raise TrialError('Persistenza Anti-DPI non protetta')
    data=json.loads(PERSIST.read_text())
    if not isinstance(data,dict) or data.get('engine') not in ('zapret2','classic') or not re.fullmatch('[a-f0-9]{64}',str(data.get('config_sha',''))):
        raise TrialError('Persistenza Anti-DPI non valida')
    return data

def config_digest(cfg):
    return hashlib.sha256(json.dumps(cfg,sort_keys=True,separators=(',',':')).encode('utf-8')).hexdigest()

def persist_atomic(data):
    if PERSIST_DIR.is_symlink():raise TrialError('Directory persistenza simbolica')
    PERSIST_DIR.mkdir(parents=True,exist_ok=True,mode=0o700)
    # The source-download worker may have created /var/lib/iptm-antidpi
    # through mkdir(parents=True), using the umask-derived mode 0755.
    # Repair only this IPTM-owned root directory; never follow symlinks,
    # chown arbitrary objects or loosen any existing permissions.
    current_dir=PERSIST_DIR.lstat()
    if not PERSIST_DIR.is_dir() or current_dir.st_uid!=0:
        raise TrialError('Directory persistenza non protetta: proprietario non root')
    if current_dir.st_mode & 0o077:
        os.chmod(PERSIST_DIR,0o700,follow_symlinks=False)
    current_dir=PERSIST_DIR.lstat()
    if current_dir.st_uid!=0 or current_dir.st_mode&0o077:
        raise TrialError('Directory persistenza non protetta: chmod 0700 non riuscito')
    if PERSIST.is_symlink():raise TrialError('File persistenza simbolico')
    tmp=PERSIST_DIR/('.pending-'+secrets.token_hex(8))
    fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,'w') as file:
            json.dump(data,file,sort_keys=True);file.flush();os.fsync(file.fileno())
        os.replace(tmp,PERSIST)
    finally:tmp.unlink(missing_ok=True)

def unit_content():
    return ("[Unit]\nDescription=IPTM Anti-DPI persistent boot (rollback-protected)\n"
            "Wants=network-online.target\nAfter=network-online.target netfilter-persistent.service iptables.service\n"
            "[Service]\nType=oneshot\nTimeoutStartSec=85\n"
            "ExecStart=/usr/local/sbin/iptm-helper anti-dpi-live boot\n"
            "[Install]\nWantedBy=multi-user.target\n")

def persistence_enable(state):
    if not state or state.get('status')!='confirmed':
        raise TrialError('Conferma prima una prova Anti-DPI funzionante')
    cfg,_=config(state['engine'])
    if state.get('config_sha')!=config_digest(cfg):
        raise TrialError('Profilo modificato dopo la prova: ripeti preflight e conferma')
    cmd(['systemctl','is-active','--quiet',UNIT+'.service'],8)
    cmd(['iptables','-t','mangle','-C','FORWARD','-j',CHAIN],8)
    if UNIT_FILE.is_symlink():raise TrialError('Unità persistente simbolica non consentita')
    if UNIT_FILE.exists():
        if not UNIT_FILE.is_file() or UNIT_FILE.stat().st_uid!=0 or UNIT_FILE.stat().st_mode&0o022 or UNIT_FILE.read_text()!=unit_content():
            raise TrialError('Unità persistente già esistente e differente: intervento manuale necessario')
    else:
        tmp=UNIT_FILE.with_name('.iptm-antidpi-'+secrets.token_hex(8))
        fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644)
        try:
            with os.fdopen(fd,'w') as file:
                file.write(unit_content());file.flush();os.fsync(file.fileno())
            os.replace(tmp,UNIT_FILE)
        finally:tmp.unlink(missing_ok=True)
    cmd(['systemctl','daemon-reload'],20)
    cmd(['systemctl','enable',UNIT_FILE.name],20)
    persist_atomic({'engine':state['engine'],'config_sha':config_digest(cfg),'enabled':True,'enabled_at':int(time.time())})
    return {'ok':True,'persistent':True,'note':'Attivo ora e abilitato per i prossimi boot; ogni avvio ripete controlli e rollback se fallisce. Nessuna garanzia di navigazione dei client senza test reale.'}

def persistence_disable():
    # Fail closed even if systemctl cannot disable the unit: the boot worker
    # rechecks this persisted intent and will refuse to activate.
    current_persist=persistent()
    if current_persist:
        current_persist['enabled']=False
        persist_atomic(current_persist)
    cmd(['systemctl','disable',UNIT_FILE.name],15,check=False)
    return {'ok':True,'persistent':False}

def boot_recover():
    intent=persistent()
    if not intent or not intent.get('enabled'):
        return {'ok':True,'skipped':True,'reason':'persistenza non abilitata'}
    if current():
        return {'ok':True,'skipped':True,'reason':'Antidpi già in esecuzione'}
    cfg,_=config(intent['engine'])
    if config_digest(cfg)!=intent['config_sha']:
        persistence_disable()
        raise TrialError('Profilo cambiato dopo conferma: persistenza disabilitata, nessuna regola applicata')
    try:
        return apply_start(intent['engine'],boot=True)
    except BaseException:
        persistence_disable()
        raise

def confirm_trial(state):
    if not state or state.get('status')!='pending' or int(time.time())>=state['until']:
        raise TrialError('Prova scaduta: attendi rollback o arresta')
    cmd(['systemctl','is-active','--quiet',UNIT+'.service'],8)
    cmd(['iptables','-t','mangle','-C','FORWARD','-j',CHAIN],8)
    state['status']='confirmed'
    temp=STATE.with_name('.iptm-antidpi-confirmed-'+state['token'])
    fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,'w') as f:
            json.dump(state,f,sort_keys=True);f.flush();os.fsync(f.fileno())
        os.replace(temp,STATE)
    finally:temp.unlink(missing_ok=True)
    cmd(['systemctl','stop',timer(state['token'])+'.timer'],8,check=False)
    return {'ok':True,'state':'confirmed','persistent':bool(persistent() and persistent().get('enabled'))}

def confirm_boot(state):
    if not state or not state.get('boot') or state.get('status')!='pending':return {'ok':True,'skipped':True}
    intent=persistent()
    try:
        if not intent or not intent.get('enabled') or intent['engine']!=state['engine']:
            raise TrialError('Persistenza non confermata al riavvio')
        cfg,_=config(state['engine'])
        if config_digest(cfg)!=intent['config_sha']:
            raise TrialError('Configurazione cambiata al riavvio')
        # Health confirms only LOCAL prerequisites; never pretend to prove
        # censorship circumvention, client connectivity, or remote DPI.
        cmd(['ip','link','show','dev',cfg['wan_if']],6,stage='WAN boot')
        cmd(['systemctl','is-active','--quiet',UNIT+'.service'],8)
        cmd(['iptables','-t','mangle','-C','FORWARD','-j',CHAIN],8)
        result=confirm_trial(state)
        result['boot_local_health']=True
        return result
    except BaseException:
        try:cleanup(state)
        finally:persistence_disable()
        raise

def write_state(data):
    fd=os.open(STATE,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,'w') as f:
            json.dump(data,f,sort_keys=True)
            f.flush();os.fsync(f.fileno())
    except BaseException:
        STATE.unlink(missing_ok=True);raise

def config(engine):
    if engine=='zapret2':
        sys.path.insert(0,str(ENGINE_MOD_DIR))
        import zapret2_manager as tool
        cfg=tool.config_read()
        binary=tool.BIN
        if not cfg:raise TrialError('Salva prima il profilo Zapret2')
        secure_file(binary)
        tool.prepare_runtime_hostlist(cfg)
        secure_file(tool.HOSTLIST)
        lua=tool.BASE/'lua'
        lib=lua/'zapret-lib.lua';antidpi=lua/'zapret-antidpi.lua'
        secure_file(lib);secure_file(antidpi)
        argv=[str(binary),*tool.nfqws_args(cfg)]
    elif engine=='classic':
        sys.path.insert(0,str(ENGINE_MOD_DIR))
        import zapret_manager as tool
        cfg=tool.read_config()
        if not cfg:raise TrialError('Salva prima il profilo Zapret classico')
        binary=tool.BIN
        secure_file(binary);secure_file(tool.HOSTLIST)
        argv=[str(binary),'--qnum='+str(cfg['queue']),
              '--dpi-desync='+cfg['strategy'],'--hostlist='+str(tool.HOSTLIST)]
    else:raise TrialError('Motore Anti-DPI non consentito')
    return cfg,argv

def route_and_tools(cfg):
    wan=cfg['wan_if']
    if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}',wan):raise TrialError('WAN non valida')
    cmd(['ip','link','show','dev',wan],5,stage='Interfaccia WAN')
    # Not just an existing interface: it must be the default route on the gateway.
    route=subprocess.run(['ip','-4','route','show','default'],capture_output=True,text=True,timeout=5)
    if route.returncode!=0 or not any(re.search(r'\bdev\s+'+re.escape(wan)+r'\b',line)
                                        for line in route.stdout.splitlines()):
        raise TrialError('WAN non presente sulla route IPv4 di default: Anti-DPI non applicabile qui')
    if pathlib.Path('/proc/sys/net/ipv4/ip_forward').read_text().strip()!='1':
        raise TrialError('Il sistema non è un gateway IPv4 (ip_forward disabilitato)')
    cmd(['iptables','-t','mangle','-S','FORWARD'],10,stage='Catena iptables mangle/FORWARD')
    cmd(['systemctl','--version'],5,stage='systemctl')
    cmd(['systemd-run','--version'],5,stage='systemd-run')
    if cmd(['iptables','-t','mangle','-S',CHAIN],5,False)==0:
        raise TrialError('Esiste una catena Anti-DPI non gestita: recupero manuale prima di attivare')

def preview(engine):
    cfg,argv=config(engine)
    secure_file(pathlib.Path(SCRIPT))
    route_and_tools(cfg)
    if engine=='zapret2':
        cmd([argv[0],'--dry-run',*argv[1:]],10,stage='nfqws2 --dry-run')
    # Old versions of nfqws do not consistently support --dry-run.
    return {'ok':True,'ready':True,'engine':engine,'wan':cfg['wan_if'],
            'clients':len(cfg['clients']),'domains':len(cfg['domains']),
            'note':'Preflight CLI e WAN. Nessun pacchetto è stato processato: prova vera solo dopo attivazione temporanea.'}

def timer(token):return 'iptm-antidpi-revert-'+token

def remove_chain():
    # Delete only the exact jump belonging to this plugin; never flush FORWARD.
    if cmd(['iptables','-t','mangle','-S',CHAIN],5,False)!=0:return
    for _ in range(4):
        if cmd(['iptables','-t','mangle','-C','FORWARD','-j',CHAIN],5,False)!=0:break
        cmd(['iptables','-w','3','-t','mangle','-D','FORWARD','-j',CHAIN])
    cmd(['iptables','-w','3','-t','mangle','-F',CHAIN])
    cmd(['iptables','-w','3','-t','mangle','-X',CHAIN])

def cleanup(state):
    errors=[]
    try:remove_chain()
    except TrialError as e:errors.append(str(e))
    try:cmd(['systemctl','stop',UNIT+'.service'],15,check=False)
    except TrialError as e:errors.append(str(e))
    if errors:raise TrialError('Ripristino Anti-DPI incompleto: '+'; '.join(errors))
    STATE.unlink(missing_ok=True)

def apply_start(engine,boot=False):
    if current():raise TrialError('Prova precedente in corso: confermare o arrestare')
    preview(engine)
    cfg,argv=config(engine)
    token=secrets.token_hex(12)
    state={'token':token,'engine':engine,'started':int(time.time()),
           'until':int(time.time())+GRACE,'status':'pending','boot':bool(boot),'config_sha':config_digest(cfg)}
    write_state(state)
    try:
        # Timer is independent; arm BEFORE any live rule or daemon is started.
        secure_file(pathlib.Path(SCRIPT))
        cmd(['systemd-run','--quiet','--unit='+timer(token),'--on-active='+str(GRACE)+'s',
             '/usr/bin/python3','-B',SCRIPT,'watchdog',token],15)
        cmd(['systemctl','is-active','--quiet',timer(token)+'.timer'],8)
        cmd(['systemd-run','--quiet','--unit='+UNIT,'--property=Restart=on-failure',
             '--property=RestartSec=2s','--',*argv],20)
        cmd(['systemctl','is-active','--quiet',UNIT+'.service'],8)
        cmd(['iptables','-w','3','-t','mangle','-N',CHAIN])
        for subnet in cfg['clients']:
            cmd(['iptables','-w','3','-t','mangle','-A',CHAIN,'-s',subnet,'-o',cfg['wan_if'],
                '-p','tcp','-m','multiport','--dports','80,443', '-m','connbytes',
                '--connbytes','1:6','--connbytes-dir','original',
                '--connbytes-mode','packets','-j','NFQUEUE','--queue-num',str(cfg['queue']),
                '--queue-bypass'])
        cmd(['iptables','-w','3','-t','mangle','-I','FORWARD','1','-j',CHAIN])
        if boot:
            cmd(['systemd-run','--quiet','--unit=iptm-antidpi-boot-health-'+token,
                 '--on-active='+str(BOOT_HEALTH_DELAY)+'s',
                 '/usr/local/sbin/iptm-helper','anti-dpi-live','boot-health',token],15)
    except BaseException:
        try:cleanup(state)
        except TrialError:pass # independent timer still armed to retry
        raise
    return {'ok':True,'state':'pending','rollback_seconds':GRACE,
            'engine':engine,'note':'NFQUEUE attiva temporaneamente SOLO sul FORWARD; conferma dopo una prova LAN.'}

def main(op,engine=None,token=None):
    if os.geteuid()!=0:raise TrialError('Richiesti privilegi root')
    LOCK.parent.mkdir(parents=True,exist_ok=True)
    fd=os.open(LOCK,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        if os.fstat(fd).st_uid!=0 or os.fstat(fd).st_mode&0o077:raise TrialError('Lock non protetto')
        fcntl.flock(fd,fcntl.LOCK_EX)
        state=current()
        if op=='status':
            persisted=persistent()
            return {'ok':True,'state':state['status'] if state else 'inactive',
                    'engine':state['engine'] if state else None,
                    'persistent':bool(persisted and persisted.get('enabled')),
                    'persistent_engine':persisted['engine'] if persisted and persisted.get('enabled') else None,
                    'seconds_remaining':max(0,state['until']-int(time.time())) if state and state['status']=='pending' else 0}
        if op=='preflight':return preview(engine)
        if op=='start':return apply_start(engine)
        if op=='boot':return boot_recover()
        if op=='boot-health':return confirm_boot(state) if state and state['token']==token else {'ok':True,'skipped':True}
        if op=='persist-enable':return persistence_enable(state)
        if op=='persist-disable':return persistence_disable()
        if op=='watchdog':
            if not state or state['token']!=token or state['status']=='confirmed':return {'ok':True,'changed':False}
            cleanup(state)
            if state.get('boot'):persistence_disable()
            return {'ok':True,'changed':True,'reverted':True}
        if op=='stop':
            persistence_disable()
            if state:cleanup(state)
            return {'ok':True,'state':'inactive','persistent':False}
        if op=='confirm':return confirm_trial(state)
        raise TrialError('Operazione non supportata')
    finally:os.close(fd)

if __name__=='__main__':
    try:
        a=sys.argv[1:]
        if len(a) not in (1,2,3):raise TrialError('Argomenti non validi')
        action=a[0]
        if action in ('preflight','start') and len(a)==2 and a[1] in ('zapret2','classic'):
            result=main(action,engine=a[1])
        elif action in ('watchdog','boot-health') and len(a)==2 and re.fullmatch('[a-f0-9]{24}',a[1]):
            result=main(action,token=a[1])
        elif action in ('status','stop','confirm','boot','persist-enable','persist-disable') and len(a)==1:result=main(action)
        else:raise TrialError('Argomenti non autorizzati')
        print(json.dumps(result))
    except (TrialError,OSError,ValueError,subprocess.TimeoutExpired) as e:
        print(json.dumps({'ok':False,'error':str(e)}));sys.exit(1)
