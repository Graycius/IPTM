#!/usr/bin/env python3
"""Generic NetworkManager profile editor for IPTM.

Produces new *inactive*, *autoconnect-disabled* cloned profiles rather than
mutating a live connection. Supports full NM setting/property namespace through
nmcli with strict argument separation. Live activation stays with the existing
IPTM network-runtime guarded trial (not a second competing network manager).
"""
import fcntl, hashlib, json, os, pathlib, re, secrets, subprocess, sys, tempfile, time

BASE=pathlib.Path('/var/lib/iptm-nm-editor')
STAGE=BASE/'plan.json';LOCK=BASE/'lock';TRIAL=BASE/'trial.json';LAST=BASE/'last.json'
SCRIPT='/usr/local/lib/iptables-manager/web/releases/5.30.1/extensions/nm_control.py'
UUID=re.compile(r'^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$')
PROP=re.compile(r'^[a-z][a-z0-9-]*\.[a-z][a-z0-9-]*$')
NAME=re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$')
DENY={'connection.uuid','connection.id','connection.interface-name','connection.autoconnect',
      'connection.permissions','connection.zone','connection.secondaries','connection.master',
      'connection.slave-type'}
class NmError(Exception):pass

def run(args,check=True,timeout=30):
    try:r=subprocess.run(args,capture_output=True,text=True,timeout=timeout,stdin=subprocess.DEVNULL)
    except (OSError,subprocess.TimeoutExpired) as e:raise NmError('nmcli non disponibile: '+str(e)) from e
    if check and r.returncode:raise NmError((r.stderr or r.stdout)[-500:])
    return r

def dguard():
    if BASE.is_symlink():raise NmError('directory simbolica')
    BASE.mkdir(exist_ok=True,parents=True,mode=0o700)
    s=BASE.stat()
    if s.st_uid or s.st_mode&0o077:raise NmError('directory non sicura')

def atomic(path,obj):
    fd,tmp=tempfile.mkstemp(dir=BASE,prefix='.nm-')
    try:
        with os.fdopen(fd,'w') as f:
            os.fchmod(f.fileno(),0o600);json.dump(obj,f,sort_keys=True);f.flush();os.fsync(f.fileno())
        os.replace(tmp,path)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)

def existing():
    rows=run(['nmcli','-t','-f','UUID,TYPE,DEVICE,NAME','connection','show'],check=False)
    if rows.returncode:raise NmError('NetworkManager non disponibile')
    # IPv6 colons in escaped names cannot be parsed with split; UUIDs are stable
    # use only UUID column and read each other value by UUID during inventory.
    uuids=[]
    for line in rows.stdout.splitlines():
        value=line.partition(':')[0]
        if UUID.fullmatch(value):uuids.append(value.lower())
    return uuids

def inventory():
    profiles=[]
    for uuid in existing():
        r=run(['nmcli','-g','connection.id,connection.type,connection.interface-name,connection.autoconnect',
               'connection','show',uuid],check=False)
        profiles.append({'uuid':uuid,'properties':r.stdout.strip().splitlines()[:4]})
    dev=run(['nmcli','-t','-f','DEVICE,TYPE,STATE,CONNECTION','device','status'],check=False)
    return {'ok':True,'profiles':profiles,'devices':dev.stdout[:18000]}

def sanitize(raw):
    if not isinstance(raw,dict) or set(raw)!={'uuid','properties'}:raise NmError('schema non valido')
    uuid=raw['uuid']
    if not isinstance(uuid,str) or not UUID.fullmatch(uuid):raise NmError('UUID non valido')
    props=raw['properties']
    if not isinstance(props,dict) or not 1<=len(props)<=48:raise NmError('1-48 proprietà')
    out={}
    for key,val in props.items():
        if not isinstance(key,str) or not PROP.fullmatch(key) or key in DENY:raise NmError('proprietà non permessa: '+str(key))
        if not isinstance(val,str) or len(val)>1024 or any(ord(c)<32 for c in val) or '\x00' in val:
            raise NmError('valore non valido: '+key)
        out[key]=val
    return {'uuid':uuid.lower(),'properties':out}

def stage(raw):
    obj=sanitize(raw)
    if obj['uuid'] not in existing():raise NmError('profilo inesistente')
    props=obj['properties']
    controller=props.get('connection.controller')
    port_type=props.get('connection.port-type')
    if controller is not None or port_type is not None:
        if controller is None or port_type is None:
            raise NmError('controller e port-type devono essere impostati insieme')
        if controller=='' and port_type=='':
            # Explicit detach is prepared only as a new inactive clone.
            pass
        elif UUID.fullmatch(controller or '') and port_type in ('bond','bridge'):
            if controller.lower()==obj['uuid']:
                raise NmError('un profilo non può controllare se stesso')
            if controller.lower() not in existing():
                raise NmError('controller NetworkManager inesistente')
            remote=run(['nmcli','-g','connection.type','connection','show',controller]).stdout.strip()
            if remote!=port_type:
                raise NmError('tipo controller diverso dal port-type selezionato')
        else:
            raise NmError('controller richiede UUID bond/bridge valido oppure entrambi i campi vuoti')
    identity='iptm-'+secrets.token_hex(6)
    obj.update({'name':identity,'created':time.time(),'state':'staged'})
    digest=hashlib.sha256(json.dumps(obj,sort_keys=True).encode()).hexdigest()
    obj['digest']=digest
    atomic(STAGE,obj)
    return {'ok':True,'sha256':digest,'preview':obj,'mutated':False}

def read_stage():
    if STAGE.is_symlink() or not STAGE.is_file() or STAGE.stat().st_uid or STAGE.stat().st_mode&0o077:
        raise NmError('piano non disponibile o non sicuro')
    obj=json.loads(STAGE.read_text())
    if time.time()-obj.get('created',0)>900:raise NmError('piano scaduto')
    return obj

def apply(digest):
    obj=read_stage()
    if digest!=obj['digest']:raise NmError('hash del piano non corrisponde')
    if obj['uuid'] not in existing():raise NmError('connessione origine modificata')
    ctrl=obj['properties'].get('connection.controller','')
    typ=obj['properties'].get('connection.port-type','')
    if ctrl:
        if ctrl.lower() not in existing() or run(['nmcli','-g','connection.type','connection','show',ctrl]).stdout.strip()!=typ:
            raise NmError('controller cambiato dopo anteprima; clone non creato')
    name=obj['name']
    # Clone is a full NetworkManager snapshot. Original is unchanged.
    run(['nmcli','connection','clone',obj['uuid'],name])
    clone_id=run(['nmcli','-g','connection.uuid','connection','show',name]).stdout.strip()
    if not UUID.fullmatch(clone_id):raise NmError('UUID clone non verificabile; verificare manualmente')
    try:
        run(['nmcli','connection','modify',clone_id,'connection.autoconnect','no'])
        args=['nmcli','connection','modify',clone_id]
        for key,value in obj['properties'].items():args.extend([key,value])
        run(args)
        # Make certain NetworkManager did not auto-activate the newly cloned profile.
        running=run(['nmcli','-t','-f','UUID','connection','show','--active'],check=False).stdout
        if clone_id in running:raise NmError('clone attivato inatteso; controllo manuale urgente')
    except Exception:
        run(['nmcli','connection','delete',clone_id],check=False)
        raise
    obj['state']='created-inactive';obj['clone_uuid']=clone_id;atomic(BASE/'last.json',obj)
    STAGE.unlink()
    return {'ok':True,'original_uuid':obj['uuid'],'clone_uuid':clone_id,'active':False,
            'message':'Profilo completo creato e mantenuto inattivo; attivazione tramite guard di rete'}

def delete_clone(uuid):
    last=BASE/'last.json'
    if last.is_symlink() or not last.is_file():raise NmError('nessun profilo IPTM')
    obj=json.loads(last.read_text())
    if uuid!=obj.get('clone_uuid'):raise NmError('UUID non di proprietà IPTM')
    active=run(['nmcli','-t','-f','UUID','connection','show','--active'],check=False).stdout
    if uuid in active:raise NmError('non cancellare una connessione attiva')
    run(['nmcli','connection','delete',uuid]);last.unlink()
    return {'ok':True,'deleted':uuid}

DBUS_SERVICE='org.freedesktop.NetworkManager'
DBUS_OBJECT='/org/freedesktop/NetworkManager'
DBUS_IFACE='org.freedesktop.NetworkManager'
DBUS_PATH=re.compile(r'^/org/freedesktop/NetworkManager/(?:Devices|Checkpoint|Checkpoints)/[0-9]+$')

def buscall(method,signature,*args):
    result=run(['busctl','--system','call',DBUS_SERVICE,DBUS_OBJECT,DBUS_IFACE,method,signature,*map(str,args)])
    return result.stdout.strip()

def buspath(output):
    m=re.fullmatch(r'o\s+"?([^"\s]+)"?',output)
    if not m or not DBUS_PATH.fullmatch(m.group(1)):
        raise NmError('risposta D-Bus con path inatteso: '+output[:80])
    return m.group(1)

def trial_state():
    if not TRIAL.exists():return {'ok':True,'state':'empty'}
    if TRIAL.is_symlink() or TRIAL.stat().st_uid or TRIAL.stat().st_mode&0o077:
        raise NmError('trial non protetta')
    obj=json.loads(TRIAL.read_text())
    return {'ok':True,**{k:v for k,v in obj.items() if k not in ('token','created')}}

def activate_clone(uuid,iface):
    if not UUID.fullmatch(uuid) or not NAME.fullmatch(iface) or iface=='lo':raise NmError('UUID/ifname invalidi')
    if not LAST.is_file() or LAST.is_symlink():raise NmError('nessun clone creato da IPTM')
    last=json.loads(LAST.read_text())
    if last.get('clone_uuid')!=uuid:raise NmError('solo il clone IPTM può essere attivato')
    state=trial_state()
    if state.get('state') in ('starting','pending') and state.get('deadline',0)>time.time():
        raise NmError('prova NM già in corso')
    d=run(['nmcli','-t','-f','DEVICE','device','status'],check=False)
    if d.returncode or iface not in d.stdout.splitlines():raise NmError('dispositivo non presente in NetworkManager')
    if run(['systemctl','is-active','NetworkManager'],check=False).stdout.strip()!='active':
        raise NmError('NetworkManager non attivo')
    dev=buspath(buscall('GetDeviceByIpIface','s',iface))
    # NetworkManager owns the timeout independent of the web process.
    # Include all managed devices so bonds, bridges and port migrations can
    # recover together instead of rolling back only the selected WAN.
    listing=buscall('GetDevices','')
    devices=re.findall(r'/org/freedesktop/NetworkManager/Devices/[0-9]+',listing)
    devices=list(dict.fromkeys(d for d in devices if DBUS_PATH.fullmatch(d)))
    if dev not in devices or not devices or len(devices)>64:
        raise NmError('inventario checkpoint D-Bus incompleto')
    checkpoint=buspath(buscall('CheckpointCreate','aouu',len(devices),*devices,180,0))
    token=secrets.token_hex(12)
    obj={'state':'starting','token':token,'uuid':uuid,'interface':iface,
         'checkpoint':checkpoint,'created':time.time(),'deadline':time.time()+180}
    atomic(TRIAL,obj)
    try:
        run(['nmcli','--wait','30','connection','up',uuid,'ifname',iface],timeout=45)
    except Exception:
        try:buscall('CheckpointRollback','o',checkpoint)
        finally:
            obj['state']='rolled-back-or-failed';atomic(TRIAL,obj)
        raise
    obj['state']='pending';atomic(TRIAL,obj)
    return {'ok':True,'state':'pending','token':token,'deadline':obj['deadline'],
            'note':'NetworkManager D-Bus checkpoint: rollback automatico in 180 secondi'}

def trial_change(token,mode):
    if not re.fullmatch('[a-f0-9]{24}',token):raise NmError('token non valido')
    if not TRIAL.is_file() or TRIAL.is_symlink():raise NmError('nessuna transazione NM')
    state=json.loads(TRIAL.read_text())
    if state.get('token')!=token or state.get('state')!='pending':raise NmError('transazione NM non confermabile')
    if mode=='confirmed' and time.time()>state.get('deadline',0)-15:
        raise NmError('checkpoint in scadenza: non confermare')
    if mode=='confirmed':
        active=run(['nmcli','-t','-f','UUID','connection','show','--active']).stdout
        if state['uuid'] not in active.splitlines():
            raise NmError('profilo attivo non verificato: checkpoint ancora ripristinabile')
        buscall('CheckpointDestroy','o',state['checkpoint'])
    else:
        buscall('CheckpointRollback','o',state['checkpoint'])
    state['state']=mode if mode=='confirmed' else 'rolled-back'
    state['finished_at']=time.time();atomic(TRIAL,state)
    return {'ok':True,'state':state['state']}

def main(args):
    if os.geteuid():raise NmError('root richiesto')
    dguard()

    fd=os.open(LOCK,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'r+') as f:
        fcntl.flock(f,fcntl.LOCK_EX)
        if args==['inventory']:return inventory()
        if args==['trial-status']:return trial_state()
        if args==['stage']:
            raw=sys.stdin.buffer.read(16385)
            if len(raw)>16384:raise NmError('JSON troppo grande')
            return stage(json.loads(raw))
        if len(args)==2 and args[0]=='apply' and re.fullmatch('[a-f0-9]{64}',args[1]):return apply(args[1])
        if len(args)==2 and args[0]=='delete-inactive' and UUID.fullmatch(args[1]):return delete_clone(args[1])
        if args==['preview']:return {k:v for k,v in read_stage().items() if k!='state'}
        if len(args)==3 and args[0]=='activate-trial':return activate_clone(args[1],args[2])
        if len(args)==2 and args[0] in ('confirm-trial','revert-trial'):
            return trial_change(args[1],'confirmed' if args[0]=='confirm-trial' else 'reverting')
        raise NmError('comando sconosciuto')
if __name__=='__main__':
    try:print(json.dumps(main(sys.argv[1:]),ensure_ascii=False))
    except (NmError,OSError,ValueError,TypeError,KeyError) as e:
        print(json.dumps({'ok':False,'error':str(e)},ensure_ascii=False));sys.exit(1)
