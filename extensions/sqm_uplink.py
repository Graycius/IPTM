#!/usr/bin/env python3
"""IPTM 5.4.3: guarded egress-only CAKE trial on a single uplink.

Conservative: never replaces a non-default qdisc, never autocalibrates an
already shaped link, never touches IFB ingress or any other interface.
Console root only for mutation; a systemd timer expires unconfirmed trials.
"""
from __future__ import annotations
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile
import time

VERSION='5.30.4'
BASE=Path('/var/lib/iptm-sqm-uplink')
STATE=BASE/'state.json'
LOCK=BASE/'lock'
SCRIPT=f'/usr/local/lib/iptables-manager/web/releases/{VERSION}/extensions/sqm_uplink.py'
UNIT=Path('/etc/systemd/system/iptm-sqm-uplink-recover.service')
TIMER='iptm-sqm-uplink-expire'
OWN_HANDLE='5ca1:'
TTL=180
NIC=re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$')
TOKEN=re.compile(r'^[a-f0-9]{24}$')
DEFAULT_QDISCS={'fq_codel','pfifo_fast'}

class SQMError(RuntimeError):pass

def as_root():
    if os.geteuid()!=0:raise SQMError('Operazione consentita soltanto a root')

def tty():
    try:f=os.open('/dev/tty',os.O_RDONLY|os.O_NOCTTY)
    except OSError as exc:raise SQMError('Serve una console root fisica/interattiva') from exc
    else:os.close(f)

def command(args,*,check=True,runner=None):
    cmd=runner or subprocess.run
    try:
        out=cmd(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                text=True,timeout=10,check=False)
    except (OSError,subprocess.TimeoutExpired) as exc:raise SQMError('Comando non disponibile') from exc
    if check and out.returncode:
        raise SQMError('Comando fallito: '+args[0]+' '+str(out.stderr)[:140])
    return out

def result_json(args,runner=None):
    try:obj=json.loads(command(args,runner=runner).stdout)
    except (TypeError,ValueError) as exc:raise SQMError('Risposta JSON non valida') from exc
    if not isinstance(obj,list):raise SQMError('Lista JSON richiesta')
    return obj

def private_dir():
    if BASE.is_symlink():raise SQMError('Directory simbolica vietata')
    BASE.mkdir(parents=True,mode=0o700,exist_ok=True)
    st=BASE.stat()
    if st.st_uid!=0 or st.st_mode&0o077:raise SQMError('Directory deve essere root:0700')

def read_state():
    if not STATE.exists() and not STATE.is_symlink():return None
    if STATE.is_symlink() or not STATE.is_file() or STATE.stat().st_uid!=0 or STATE.stat().st_mode&0o077:
        raise SQMError('Stato transazione non protetto')
    try:return json.loads(STATE.read_text())
    except (ValueError,UnicodeError) as exc:raise SQMError('Stato danneggiato') from exc

def save(state):
    private_dir()
    fd,path=tempfile.mkstemp(dir=BASE,prefix='.state-',suffix='.tmp')
    try:
        with os.fdopen(fd,'w') as stream:
            os.fchmod(stream.fileno(),0o600)
            json.dump(state,stream,sort_keys=True)
            stream.flush();os.fsync(stream.fileno())
        os.replace(path,STATE)
    finally:
        if os.path.exists(path):os.unlink(path)

def inspect(dev,runner=None):
    if not isinstance(dev,str) or not NIC.fullmatch(dev) or dev=='lo':raise SQMError('Nome NIC non valido')
    links=result_json(['ip','-j','link','show','dev',dev],runner)
    if len(links)!=1 or links[0].get('ifname')!=dev:raise SQMError('NIC non esistente')
    if links[0].get('master'):
        raise SQMError('Qdisc su porta slave non consentita')
    qdiscs=result_json(['tc','-j','qdisc','show','dev',dev],runner)
    root=[q for q in qdiscs if q.get('root') is True or q.get('parent')=='root']
    if len(root)!=1 or root[0].get('kind') not in DEFAULT_QDISCS:
        raise SQMError('Qdisc esistente non standard: non si sostituisce la policy di un altro gestore')
    return {'interface':dev,'ifindex':links[0].get('ifindex'),'mac':links[0].get('address'),
            'previous_qdisc':root[0].get('kind')}

def profile(dev,rate,runner=None):
    if type(rate) is not int or not 1<=rate<=10000:raise SQMError('Bandwidth 1..10000 Mbit richiesto')
    cfg=inspect(dev,runner)
    cfg['upload_mbit']=rate
    return cfg

def install_guard(*,runner=None):
    as_root();tty()
    old=read_state()
    if old and old.get('status') in ('pending','confirmed') and old.get('version')!=VERSION:
        raise SQMError('Worker di altra release già attivo')
    if UNIT.exists() or UNIT.is_symlink():
        if UNIT.is_symlink() or 'Description=IPTM SQM uplink boot recovery' not in UNIT.read_text():
            raise SQMError('Unit systemd sconosciuta')
    if runner is None and not Path(SCRIPT).is_file():raise SQMError('Worker installato non corrisponde alla release')
    content=('[Unit]\nDescription=IPTM SQM uplink boot recovery\nAfter=network-online.target\n'
             '[Service]\nType=oneshot\nExecStart=/usr/bin/python3 -B '+SCRIPT+' boot-recover\n'
             '[Install]\nWantedBy=multi-user.target\n')
    fd,path=tempfile.mkstemp(dir=UNIT.parent,prefix='.iptm-sqm-')
    try:
        with os.fdopen(fd,'w') as stream:
            os.fchmod(stream.fileno(),0o644);stream.write(content);stream.flush();os.fsync(stream.fileno())
        os.replace(path,UNIT)
    finally:
        if os.path.exists(path):os.unlink(path)
    command(['systemctl','daemon-reload'],runner=runner)
    command(['systemctl','enable',UNIT.name],runner=runner)
    return {'installed':True}

def guard_ready(runner=None):
    if UNIT.is_symlink() or not UNIT.is_file() or SCRIPT not in UNIT.read_text():
        raise SQMError('Guard non installato')
    p=command(['systemctl','is-enabled',UNIT.name],runner=runner,check=False)
    if p.returncode or p.stdout.strip()!='enabled':raise SQMError('Guard disabilitato')

def rollback(state,*,runner=None):
    as_root()
    if state.get('version')!=VERSION:raise SQMError('Journal di altra release')
    if state.get('schema')==2:return _group_rollback(state,runner=runner)
    dev=state['interface']
    links=result_json(['ip','-j','link','show','dev',dev],runner)
    if not links or links[0].get('ifindex')!=state.get('ifindex') or links[0].get('address')!=state.get('mac'):
        state['status']='rollback-incomplete';save(state)
        raise SQMError('Identità NIC modificata: nessun comando distruttivo')
    qdiscs=result_json(['tc','-j','qdisc','show','dev',dev],runner)
    roots=[q for q in qdiscs if q.get('root') is True or q.get('parent')=='root']
    if len(roots)!=1 or (roots[0].get('kind')!='cake' or roots[0].get('handle')!=OWN_HANDLE):
        state['status']='rollback-incomplete';save(state)
        raise SQMError('Qdisc gestita esternamente: non eliminata')
    command(['tc','qdisc','del','dev',dev,'root'],runner=runner)
    command(['systemctl','stop',TIMER+'.timer'],runner=runner,check=False)
    state['status']='rolled-back';save(state)
    return {'status':'rolled-back'}

def apply(dev,rate,*,runner=None):
    as_root();tty();guard_ready(runner)
    state=read_state()
    if state and state.get('status') in ('pending','confirmed','rollback-incomplete'):
        raise SQMError('Esiste già una configurazione SQM attiva')
    cfg=profile(dev,rate,runner)
    if type(cfg['ifindex']) is not int or not cfg['mac']:
        raise SQMError('Identità NIC non verificata')
    stamp=int(time.time())
    state={'schema':1,'version':VERSION,'status':'pending','created':stamp,'deadline':stamp+TTL,
           'token':secrets.token_hex(12),**cfg}
    save(state)
    try:
        command(['systemd-run','--unit='+TIMER,'--on-active='+str(TTL)+'s','--collect',
                 '/usr/bin/python3','-B',SCRIPT,'expire'],runner=runner)
        # A default root qdisc can be restored by deleting our CAKE qdisc.
        command(['tc','qdisc','replace','dev',dev,'root','handle',OWN_HANDLE,'cake','bandwidth',str(rate)+'mbit',
                 'besteffort','nat'],runner=runner)
        current=result_json(['tc','-j','qdisc','show','dev',dev],runner)
        if not any(q.get('kind')=='cake' and q.get('root') is True and q.get('handle')==OWN_HANDLE for q in current):
            raise SQMError('CAKE non confermato dopo installazione')
    except Exception:
        try:
            qdiscs=result_json(['tc','-j','qdisc','show','dev',dev],runner)
            if any(q.get('kind')=='cake' and q.get('root') is True and q.get('handle')==OWN_HANDLE for q in qdiscs):
                rollback(state,runner=runner)
            else:
                state['status']='rolled-back';save(state)
                command(['systemctl','stop',TIMER+'.timer'],runner=runner,check=False)
        except Exception:
            # Journal remains pending/rollback-incomplete for watchdog recovery.
            pass
        raise
    return {'status':'pending','token':state['token'],'deadline':state['deadline'],
            'interface':dev,'upload_mbit':rate}

def confirm(token,*,runner=None):
    as_root();tty();state=read_state()
    if not state or state.get('status')!='pending' or not TOKEN.fullmatch(token) or state['token']!=token:
        raise SQMError('Token non valido')
    if int(time.time())>=state['deadline']:return rollback(state,runner=runner)
    state['status']='confirmed';save(state)
    command(['systemctl','stop',TIMER+'.timer'],runner=runner,check=False)
    return {'status':'confirmed', 'profiles':[{k:p[k] for k in ('interface','upload_mbit')} for p in state['profiles']]} if state.get('schema')==2 else {'status':'confirmed','upload_mbit':state['upload_mbit']}

def boot_recover(*,runner=None):
    as_root();state=read_state()
    if not state:return {'status':'empty'}
    if state.get('version')!=VERSION:raise SQMError('Journal di altra release')
    if state.get('schema')==2:return group_boot_recover(state,runner=runner)
    if state.get('status')=='pending':
        # If pending changes vanished on reboot, there is nothing to remove.
        dev=state['interface']
        qdiscs=result_json(['tc','-j','qdisc','show','dev',dev],runner)
        if any(q.get('kind')=='cake' and q.get('root') is True and q.get('handle')==OWN_HANDLE for q in qdiscs):
            return rollback(state,runner=runner)
        state['status']='rolled-back';save(state);return {'status':'rolled-back'}
    if state.get('status')=='confirmed':
        # Fail closed rather than replacing a foreign qdisc after reboot.
        if profile(state['interface'],state['upload_mbit'],runner)['ifindex']!=state['ifindex']:
            raise SQMError('Interfaccia cambiata al boot')
        command(['tc','qdisc','replace','dev',state['interface'],'root','handle',OWN_HANDLE,'cake','bandwidth',
                 str(state['upload_mbit'])+'mbit','besteffort','nat'],runner=runner)
        return {'status':'reapplied'}
    return {'status':state['status']}

def _group_profiles(state):
    profiles=state.get('profiles')
    if not isinstance(profiles,list) or not 2<=len(profiles)<=4:
        raise SQMError('Gruppo CAKE: 2-4 interfacce richieste')
    if len({p.get('interface') for p in profiles})!=len(profiles):
        raise SQMError('Gruppo CAKE: interfacce duplicate')
    return profiles


def _owned_root(dev, runner=None):
    roots=[q for q in result_json(['tc','-j','qdisc','show','dev',dev],runner)
           if q.get('root') is True or q.get('parent')=='root']
    return roots[0] if len(roots)==1 else None


def _group_rollback(state, *, runner=None):
    """Per-NIC ownership checks: never delete a foreign replacement qdisc."""
    as_root();errors=[]
    if state.get('version')!=VERSION:
        raise SQMError('Journal CAKE di altra release')
    for p in _group_profiles(state):
        dev=p['interface']
        try:
            live=result_json(['ip','-j','link','show','dev',dev],runner)
            if len(live)!=1 or live[0].get('ifindex')!=p['ifindex'] or live[0].get('address')!=p['mac']:
                errors.append(dev+': identità NIC cambiata');continue
            root=_owned_root(dev,runner)
            if root and root.get('kind')=='cake' and root.get('handle')==OWN_HANDLE:
                command(['tc','qdisc','del','dev',dev,'root'],runner=runner)
            elif root and root.get('kind') in DEFAULT_QDISCS:
                # Other members may not have been reached before apply failed.
                continue
            else:
                errors.append(dev+': qdisc diversa, non rimossa')
        except (SQMError,KeyError) as ex:
            errors.append(dev+': '+str(ex)[:80])
    command(['systemctl','stop',TIMER+'.timer'],runner=runner,check=False)
    state['status']='rollback-incomplete' if errors else 'rolled-back'
    state['errors']=errors;save(state)
    return {'status':state['status'],'errors':errors}


def apply_multi(pairs, *, runner=None):
    """One guarded transaction for independent egress CAKE rates per uplink.

    No ingress/IFB, automatic speedtest, qdisc overwrite or route change.
    """
    as_root();tty();guard_ready(runner)
    current=read_state()
    if current and current.get('status') in ('pending','confirmed','rollback-incomplete'):
        raise SQMError('Configurazione SQM già attiva')
    if not isinstance(pairs,list) or not 2<=len(pairs)<=4:
        raise SQMError('Attesi 2-4 uplink, uno per interfaccia')
    if len({p[0] for p in pairs})!=len(pairs):raise SQMError('Interfaccia WAN ripetuta')
    profiles=[profile(dev,rate,runner) for dev,rate in pairs]
    for p in profiles:
        if type(p.get('ifindex')) is not int or not p.get('mac'):
            raise SQMError('Identità NIC non verificata')
    ts=int(time.time())
    state={'schema':2,'version':VERSION,'status':'pending','created':ts,'deadline':ts+TTL,
           'token':secrets.token_hex(12),'profiles':profiles}
    _group_profiles(state);save(state)
    try:
        command(['systemd-run','--unit='+TIMER,'--on-active='+str(TTL)+'s','--collect',
                 '/usr/bin/python3','-B',SCRIPT,'expire'],runner=runner)
        for p in profiles:
            dev=p['interface'];rate=p['upload_mbit']
            command(['tc','qdisc','replace','dev',dev,'root','handle',OWN_HANDLE,'cake',
                     'bandwidth',str(rate)+'mbit','besteffort','nat'],runner=runner)
            root=_owned_root(dev,runner)
            if not root or root.get('kind')!='cake' or root.get('handle')!=OWN_HANDLE:
                raise SQMError('CAKE non verificato su '+dev)
    except Exception:
        try:_group_rollback(state,runner=runner)
        except Exception:pass
        raise
    return {'status':'pending','interfaces':[{k:p[k] for k in ('interface','upload_mbit')} for p in profiles],
            'token':state['token'],'deadline':state['deadline']}


def group_boot_recover(state, *, runner=None):
    """Restore only qdiscs we own, only if unchanged NIC identity."""
    as_root();profiles=_group_profiles(state)
    if state.get('status')=='pending':return _group_rollback(state,runner=runner)
    if state.get('status')!='confirmed':return {'status':state.get('status','unknown')}
    for p in profiles:
        dev=p['interface']
        live=result_json(['ip','-j','link','show','dev',dev],runner)
        if len(live)!=1 or live[0].get('ifindex')!=p['ifindex'] or live[0].get('address')!=p['mac']:
            raise SQMError('Uplink modificato al boot: '+dev)
        root=_owned_root(dev,runner)
        if root and root.get('kind')=='cake' and root.get('handle')==OWN_HANDLE:continue
        if not root or root.get('kind') not in DEFAULT_QDISCS:
            raise SQMError('CAKE esterno su '+dev+': niente sovrascritture')
        command(['tc','qdisc','replace','dev',dev,'root','handle',OWN_HANDLE,'cake',
                 'bandwidth',str(p['upload_mbit'])+'mbit','besteffort','nat'],runner=runner)
    return {'status':'reapplied','interfaces':[p['interface'] for p in profiles]}


# Recovery for one exact legacy 950-Mbit CAKE state from the user's old build.
# This is NOT a general qdisc importer. Unknown root settings are a hard stop.
RECON_DIR=Path('/var/lib/iptm-sqm-reconcile')
RECON_STATE=RECON_DIR/'state.json'
RECON_UNIT=Path('/etc/systemd/system/iptm-sqm-reconcile-recover.service')
RECON_TIMER='iptm-sqm-reconcile-expire'
RECON_ROOT='5ca6:'
RECON_IFB='5ca7:'
ORPHAN_ROOT=re.compile(r'^qdisc cake [0-9a-fA-F]+: root refcnt [0-9]+ bandwidth 950Mbit besteffort triple-isolate nat wash ack-filter split-gso rtt 100ms raw overhead 0\s*$')

def rec_previous_valid(value):
    return isinstance(value,str) and len(value)<512 and bool(ORPHAN_ROOT.fullmatch(value.strip()))

def rec_config(path=Path('/etc/iptables-manager.conf')):
    import shlex
    if path.is_symlink() or not path.is_file():raise SQMError('Configurazione IPTM non sicura')
    if path.stat().st_uid!=0 or path.stat().st_mode&0o022:raise SQMError('Configurazione IPTM modificabile da altri')
    raw=path.read_text()[:65536];data={}
    for row in raw.splitlines():
        m=re.fullmatch(r'\s*(SQM_IF|SQM_UP|SQM_DOWN|SQM_DIFFSERV|SQM_ACK|SQM_NAT|SQM_OVERHEAD|SQM_WASH)\s*=\s*(.*?)\s*',row)
        if m:
            values=shlex.split(m.group(2))
            if len(values)!=1:raise SQMError('Parametro QoS non valido')
            data[m.group(1)]=values[0]
    iface=data.get('SQM_IF','');up=data.get('SQM_UP','');down=data.get('SQM_DOWN','')
    if not NIC.fullmatch(iface) or not up.isdigit() or not down.isdigit() or not (1<=int(up)<=10000 and 1<=int(down)<=10000):
        raise SQMError('Profili QoS non verificabili')
    ds=data.get('SQM_DIFFSERV','diffserv4');ov=data.get('SQM_OVERHEAD','ethernet')
    if ds not in ('diffserv3','diffserv4','diffserv8','besteffort') or ov!='ethernet':
        raise SQMError('Riconciliazione iniziale supportata soltanto per overhead ethernet')
    if data.get('SQM_ACK','1') not in ('1','ack-filter') or data.get('SQM_NAT','1') not in ('1','nat'):
        raise SQMError('Riconciliazione iniziale richiede nat e ack-filter')
    if data.get('SQM_WASH','0') not in ('0','1'):raise SQMError('Wash non valido')
    return {'iface':iface,'up':int(up),'down':int(down),'diffserv':ds,'wash':data.get('SQM_WASH','0')=='1'}

def rec_file():
    if RECON_DIR.is_symlink():raise SQMError('Directory SQM reconcile symlink')
    RECON_DIR.mkdir(parents=True,exist_ok=True,mode=0o700)
    if RECON_DIR.stat().st_uid!=0 or RECON_DIR.stat().st_mode&0o077:
        raise SQMError('Directory SQM reconcile non protetta')

def rec_read():
    if not RECON_STATE.exists() and not RECON_STATE.is_symlink():return None
    if RECON_STATE.is_symlink() or RECON_STATE.stat().st_uid!=0 or RECON_STATE.stat().st_mode&0o077:
        raise SQMError('Journal SQM reconcile non sicuro')
    state=json.loads(RECON_STATE.read_bytes())
    if not isinstance(state,dict) or state.get('version')!=VERSION:
        raise SQMError('Journal SQM reconcile appartenente ad altra release')
    return state

def rec_write(state):
    rec_file();fd,tmp=tempfile.mkstemp(dir=RECON_DIR,prefix='.state-',suffix='.json')
    try:
        with os.fdopen(fd,'w') as f:
            os.fchmod(f.fileno(),0o600);json.dump(state,f,sort_keys=True);f.flush();os.fsync(f.fileno())
        os.replace(tmp,RECON_STATE)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)

def rec_qdisc(dev):
    return command(['tc','qdisc','show','dev',dev],check=False).stdout.strip()

def rec_check():
    cfg=rec_config();dev=cfg['iface']
    links=result_json(['ip','-j','link','show','dev',dev])
    if len(links)!=1 or links[0].get('ifname')!=dev or links[0].get('master'):
        raise SQMError('Interfaccia QoS non verificabile o porta slave')
    root=rec_qdisc(dev)
    if not rec_previous_valid(root):
        raise SQMError('CAKE reale non coincide con il vecchio stato 950: nessuna modifica')
    if command(['ip','link','show','dev','ifb-sqm'],check=False).returncode==0:
        raise SQMError('ifb-sqm presente: non sovrascrivere un IFB esistente')
    if ' ingress ' in root or ' clsact ' in root:
        raise SQMError('Ingress gia presente: niente riconciliazione')
    return {'profile':cfg,'previous':root,'ifindex':links[0].get('ifindex'),'mac':links[0].get('address')}

def rec_verify(state):
    dev=state['profile']['iface'];root=rec_qdisc(dev)
    if not re.search(r'qdisc cake '+RECON_ROOT+r' root .*?bandwidth '+str(state['profile']['up'])+r'Mbit',root):
        raise SQMError('CAKE uplink non corrisponde al target')
    if not re.search(r'qdisc cake '+RECON_IFB+r' root .*?bandwidth '+str(state['profile']['down'])+r'Mbit',rec_qdisc('ifb-sqm')):
        raise SQMError('IFB download non verificato')
    flt=command(['tc','filter','show','dev',dev,'parent','ffff:'],check=False).stdout
    if 'mirred' not in flt or 'redirect' not in flt or 'ifb-sqm' not in flt:
        raise SQMError('Redirect ingress verso IFB non verificato')

def rec_rollback(state):
    dev=state['profile']['iface'];errors=[]
    links=result_json(['ip','-j','link','show','dev',dev])
    if len(links)!=1 or links[0].get('ifindex')!=state['ifindex'] or links[0].get('address')!=state['mac']:
        state['status']='rollback-incomplete';rec_write(state)
        raise SQMError('Identita NIC cambiata: rollback automatico rifiutato')
    live=rec_qdisc(dev)
    if rec_previous_valid(live):
        # We may have crashed between IFB creation and WAN qdisc replacement.
        # Do not leave a stray device and do not delete a device if another
        # manager has installed a qdisc on it since our attempt.
        ifb=rec_qdisc('ifb-sqm')
        if ifb and not ('qdisc noqueue' in ifb or 'qdisc cake '+RECON_IFB in ifb):
            state['status']='rollback-incomplete';rec_write(state)
            raise SQMError('IFB non riconosciuto: intervento manuale')
        if command(['ip','link','show','dev','ifb-sqm'],check=False).returncode==0:
            result=command(['ip','link','del','ifb-sqm'],check=False)
            if result.returncode:
                state['status']='rollback-incomplete';rec_write(state)
                raise SQMError('IFB creato ma non rimosso')
        state['status']='rolled-back';rec_write(state);return {'status':'rolled-back','already_restored':True}
    if not re.search('qdisc cake '+RECON_ROOT+r' root ',live):
        state['status']='rollback-incomplete';rec_write(state)
        raise SQMError('La qdisc non appartiene a questa transazione: rollback rifiutato')
    ifb=rec_qdisc('ifb-sqm')
    if ifb and not ('qdisc noqueue' in ifb or re.search('qdisc cake '+RECON_IFB+r' root ',ifb)):
        state['status']='rollback-incomplete';rec_write(state)
        raise SQMError('IFB modificato dopo la creazione: rollback rifiutato')
    # A crash may occur after the new root but before ingress/IFB creation.
    # Only delete ingress if it was installed; don't misreport a harmless
    # absent qdisc as rollback failure.
    listing=rec_qdisc(dev)
    if re.search(r'qdisc (?:ingress|clsact) ',listing):
        output=command(['tc','qdisc','del','dev',dev,'ingress'],check=False)
        if output.returncode:errors.append('tc ingress')
    output=command(['tc','qdisc','replace','dev',dev,'root','cake','bandwidth','950Mbit',
                   'besteffort','triple-isolate','nat','wash','ack-filter','split-gso','rtt','100ms','raw','overhead','0'],check=False)
    if output.returncode:errors.append('tc restore-root')
    if command(['ip','link','show','dev','ifb-sqm'],check=False).returncode==0:
        output=command(['ip','link','del','ifb-sqm'],check=False)
        if output.returncode:errors.append('ip delete-ifb')
    state['status']='rollback-incomplete' if errors else 'rolled-back'
    state['errors']=errors;rec_write(state)
    return {'status':state['status'],'errors':errors}

def rec_guard():
    tty()
    if RECON_UNIT.is_symlink():raise SQMError('Recovery unit symlink')
    if RECON_UNIT.exists() and 'Description=IPTM SQM reconcile recovery' not in RECON_UNIT.read_text():
        raise SQMError('Unita recovery non di IPTM')
    unit='[Unit]\nDescription=IPTM SQM reconcile recovery\nAfter=local-fs.target\n[Service]\nType=oneshot\nExecStart=/usr/bin/python3 -B '+SCRIPT+' reconcile boot-recover\n[Install]\nWantedBy=multi-user.target\n'
    fd,tmp=tempfile.mkstemp(prefix='.iptm-sqm-reconcile-',dir=RECON_UNIT.parent)
    try:
        with os.fdopen(fd,'w') as f:
            os.fchmod(f.fileno(),0o644);f.write(unit);f.flush();os.fsync(f.fileno())
        os.replace(tmp,RECON_UNIT)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)
    command(['systemctl','daemon-reload']);command(['systemctl','enable',RECON_UNIT.name])
    return {'status':'guard-installed'}

def rec_apply():
    tty();rec_file()
    if read_state() and read_state().get('status') in ('pending','confirmed','rollback-incomplete'):
        raise SQMError('Esiste una transazione SQM uplink in corso')
    old=rec_read()
    if old and old.get('status') in ('pending','rollback-incomplete'):
        raise SQMError('Ripristinare prima la transazione SQM precedente')
    if command(['systemctl','is-enabled',RECON_UNIT.name],check=False).returncode:
        raise SQMError('Recovery boot non installato: eseguire install-guard')
    # No simultaneous trial or background calibration may change the same qdisc.
    for marker in (Path('/run/iptm-sqm-safe/active'), Path('/run/iptm-sqm-probe/active')):
        if marker.exists() or marker.is_symlink():
            raise SQMError('Prova SQM precedente in corso: confermare o annullare prima')
    if command(['systemctl','is-active','--quiet','iptm-sqm-calibrate.service'],check=False).returncode==0:
        raise SQMError('Calibrazione SQM in corso: nessuna modifica')
    data=rec_check();profile=data['profile'];dev=profile['iface']
    if not isinstance(data['ifindex'],int) or not data['mac']:raise SQMError('Identita NIC incompleta')
    now=int(time.time());state={'version':VERSION,'status':'pending','created':now,'deadline':now+180,
        'token':secrets.token_hex(12),'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),**data}
    rec_write(state)
    try:
        command(['systemd-run','--unit='+RECON_TIMER,'--on-active=180s','--collect',
                 '/usr/bin/python3','-B',SCRIPT,'reconcile','expire'])
    except Exception:
        state['status']='rolled-back';rec_write(state);raise
    try:
        command(['modprobe','ifb']);command(['modprobe','sch_cake'])
        command(['ip','link','add','ifb-sqm','type','ifb'])
        command(['ip','link','set','ifb-sqm','up'])
        opts=['bandwidth',str(profile['up'])+'mbit',profile['diffserv'],'nat','ack-filter','ethernet']
        if profile['wash']:opts.append('wash')
        command(['tc','qdisc','replace','dev',dev,'root','handle',RECON_ROOT,'cake']+opts)
        command(['tc','qdisc','add','dev',dev,'handle','ffff:','ingress'])
        command(['tc','filter','add','dev',dev,'parent','ffff:','protocol','all','u32',
                 'match','u32','0','0','action','mirred','egress','redirect','dev','ifb-sqm'])
        command(['tc','qdisc','replace','dev','ifb-sqm','root','handle',RECON_IFB,'cake',
                 'bandwidth',str(profile['down'])+'mbit',profile['diffserv'],'nat','ethernet'])
        rec_verify(state)
    except Exception:
        try: rec_rollback(state)
        except Exception: pass
        raise
    return {'status':'pending','token':state['token'],'seconds':180,'profile':profile}

def rec_main(argv):
    as_root()
    if argv==['install-guard']:return rec_guard()
    if argv==['preview']:return rec_check()
    if argv==['status']:
        x=rec_read() or {'status':'empty'}
        return {'status':x['status'],'profile':x.get('profile'),'seconds_left':max(0,x.get('deadline',0)-int(time.time()))}
    if argv==['apply']:return rec_apply()
    if argv in (['expire'],['boot-recover']):
        state=rec_read()
        if state and state.get('status')=='pending':
            if argv==['boot-recover']:
                current=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
                if state.get('boot_id')!=current:
                    # Transient qdiscs and IFBs vanish at reboot. A different
                    # service may already have started: don't overwrite it.
                    current_root=rec_qdisc(state['profile']['iface'])
                    if any('qdisc '+kind+' ' in current_root for kind in ('fq_codel','mq','noqueue','fq')):
                        state['status']='rolled-back';rec_write(state)
                        return {'status':'rolled-back','reboot':True}
                    state['status']='rollback-incomplete';rec_write(state)
                    raise SQMError('Qdisc al boot non riconosciuta, ripristino non automatico')
            return rec_rollback(state)
        return {'status':'idle' if not state else state['status']}
    if len(argv)==2 and argv[0] in ('confirm','rollback'):
        tty()
        if not TOKEN.fullmatch(argv[1]):raise SQMError('Token SQM non valido')
        state=rec_read()
        if not state or state.get('status')!='pending' or state.get('token')!=argv[1]:
            raise SQMError('Transazione SQM non valida')
        if argv[0]=='rollback' or int(time.time())>=state['deadline']:
            return rec_rollback(state)
        rec_verify(state)
        state['status']='confirmed';rec_write(state)
        command(['systemctl','stop',RECON_TIMER+'.timer'],check=False)
        return {'status':'confirmed','interface':state['profile']['iface']}
    raise SQMError('Comando reconcile sconosciuto')

def main(argv):
    as_root();private_dir()
    fd=os.open(LOCK,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'r+') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        if argv and argv[0]=='reconcile':return rec_main(argv[1:])
        return _locked_main(argv)


def _locked_main(argv):
    if argv==['status']:
        state=read_state() or {'status':'empty'}
        return {'version':VERSION,'status':state['status'],'interface':state.get('interface'),'upload_mbit':state.get('upload_mbit'), 'profiles':[{k:v.get(k) for k in ('interface','upload_mbit')} for v in state.get('profiles',[])]}
    if argv==['install-guard']:return install_guard()
    if argv and argv[0] in ('preview-multi','apply-multi'):
        if len(argv)<5 or len(argv)>9 or len(argv)%2!=1:
            raise SQMError('Uso: apply-multi NIC1 MBIT1 NIC2 MBIT2 [NIC3 MBIT3 ...]')
        pairs=[]
        for idx in range(1,len(argv),2):
            if not argv[idx+1].isdigit():raise SQMError('Rate numerico richiesto')
            pairs.append((argv[idx],int(argv[idx+1])))
        if argv[0]=='preview-multi':
            return {'profiles':[profile(dev,rate) for dev,rate in pairs]}
        return apply_multi(pairs)
    if len(argv)==3 and argv[0] in ('preview','apply'):
        dev=argv[1]
        if not argv[2].isdigit():raise SQMError('Rate numerico richiesto')
        rate=int(argv[2])
        if argv[0]=='preview':return profile(dev,rate)
        return apply(dev,rate)
    if len(argv)==2 and argv[0] in ('confirm','rollback'):
        tty()
        if not TOKEN.fullmatch(argv[1]):raise SQMError('Token non valido')
        state=read_state()
        if not state or state.get('token')!=argv[1]:raise SQMError('Token diverso dalla transazione')
        return confirm(argv[1]) if argv[0]=='confirm' else rollback(state)
    if argv==['expire']:
        state=read_state()
        return rollback(state) if state and state.get('status')=='pending' else {'status':'idle'}
    if argv==['boot-recover']:return boot_recover()
    raise SQMError('Comando sconosciuto')

if __name__=='__main__':
    try:print(json.dumps(main(sys.argv[1:]),ensure_ascii=False))
    except (SQMError,ValueError,OSError,KeyError) as exc:
        print(json.dumps({'ok':False,'error':str(exc)},ensure_ascii=False));sys.exit(1)
