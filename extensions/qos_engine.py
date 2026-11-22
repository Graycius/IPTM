#!/usr/bin/env python3
"""IPTM CAKE/IFB bidirectional guarded transaction engine.

Only claims completely unowned kernel topology; no blind tc qdisc replace.
A separately supervised systemd watchdog restores unconfirmed trials.
Deliberately does not estimate internet bandwidth from NIC link speed.
"""
from __future__ import annotations
import fcntl, hashlib, json, os, pathlib, re, secrets, subprocess, sys, tempfile, time

VERSION='5.20.25'
BASE=pathlib.Path('/var/lib/iptm-qos-engine')
LOCK=BASE/'lock';STAGE=BASE/'stage.json';STATE=BASE/'active.json'
UNIT=pathlib.Path('/etc/systemd/system/iptm-qos-watchdog.service')
SCRIPT=f'/usr/local/lib/iptables-manager/web/releases/{VERSION}/extensions/qos_engine.py'
POLICY_ACTIVE=pathlib.Path('/var/lib/iptm-qos-policy/active.json')
CALIB=BASE/'calibration.json'
CALIB_LOG=BASE/'calibration-history.json'
ADAPT=BASE/'adaptive.json'
ADAPT_UNIT=pathlib.Path('/etc/systemd/system/iptm-qos-adaptive.service')
ADAPT_TIMER=pathlib.Path('/etc/systemd/system/iptm-qos-adaptive.timer')
CALIB_UNIT='iptm-qos-calibration'
AUTO_STATE=BASE/'auto-calibration.json'
AUTO_SERVICE=pathlib.Path('/etc/systemd/system/iptm-qos-auto-calibration.service')
AUTO_TIMER=pathlib.Path('/etc/systemd/system/iptm-qos-auto-calibration.timer')
NIC=re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$')
TOKEN=re.compile(r'^[a-f0-9]{24}$')
HEX=re.compile(r'^[a-f0-9]{64}$')
DIFFSERV={'besteffort','diffserv3','diffserv4','diffserv8'}
DEFAULT={'fq_codel','pfifo_fast','noqueue','mq'}
class QosError(Exception):pass

def run(args,*,check=True,timeout=10):
    try:r=subprocess.run(args,capture_output=True,text=True,stdin=subprocess.DEVNULL,timeout=timeout)
    except (OSError,subprocess.TimeoutExpired) as e:raise QosError('comando non disponibile: '+str(e)) from e
    if check and r.returncode:raise QosError((r.stderr or r.stdout)[-350:]+' ['+args[0]+']')
    return r

def jcmd(args):
    try:v=json.loads(run(args).stdout)
    except json.JSONDecodeError as e:raise QosError('JSON di tc/ip non valido') from e
    if not isinstance(v,list):raise QosError('risposta attesa come lista')
    return v

def guard_root():
    if os.geteuid():raise QosError('root richiesto')
    if BASE.is_symlink():raise QosError('directory link simbolico')
    BASE.mkdir(parents=True,mode=0o700,exist_ok=True)
    s=BASE.stat()
    if s.st_uid or s.st_mode&0o077:raise QosError('directory non root:0700')

def atom(path,obj):
    fd,p=tempfile.mkstemp(dir=BASE,prefix='.qos-')
    try:
        with os.fdopen(fd,'w') as out:
            os.fchmod(out.fileno(),0o600);json.dump(obj,out,sort_keys=True);out.flush();os.fsync(out.fileno())
        os.replace(p,path)
    finally:
        if os.path.exists(p):os.unlink(p)

def read(path):
    if path.is_symlink():raise QosError('stato simbolico')
    if not path.exists():return None
    s=path.stat()
    if not path.is_file() or s.st_uid or s.st_mode&0o077:raise QosError('stato non protetto')
    v=json.loads(path.read_text())
    if not isinstance(v,dict):raise QosError('stato JSON non valido')
    return v

def identity(iface):
    links=jcmd(['ip','-j','link','show','dev',iface])
    if len(links)!=1 or links[0].get('ifname')!=iface:raise QosError('interfaccia non verificabile')
    return {'ifindex':links[0].get('ifindex'),'mac':links[0].get('address')}

def inspect(iface):
    if not isinstance(iface,str) or not NIC.fullmatch(iface) or iface=='lo':raise QosError('interfaccia non valida')
    ident=identity(iface)
    roots=[q for q in jcmd(['tc','-j','qdisc','show','dev',iface]) if q.get('root') is True or q.get('parent')=='root']
    ing=[q for q in jcmd(['tc','-j','qdisc','show','dev',iface]) if q.get('kind') in ('ingress','clsact')]
    if len(roots)!=1 or roots[0].get('kind') not in DEFAULT or ing:
        audit=topology_report(iface)
        raise QosError(audit['reason']+' (root='+str(audit['root_kind'])+', handle='+str(audit['root_handle'])+'). Non è stata modificata alcuna qdisc.')
    if not isinstance(ident['ifindex'],int) or not ident['mac']:raise QosError('identità fisica incompleta')
    return {'interface':iface,**ident,'original_root':roots[0]['kind']}

def foreign_qos_owner(iface):
    """Conservative read-only check of the known external systemd CAKE owner.

    An inactive but enabled oneshot can reclaim bond0 on the next boot.
    Never stop, disable or alter the unit; reject stage/apply until the
    operator migrates the owner through an independent console.
    """
    path=pathlib.Path('/etc/systemd/system/qos.service')
    if not path.exists() and not path.is_symlink():
        return {'detected':False,'blocking':False}
    result={'detected':True,'unit':'qos.service','blocking':True,
            'reason':'Unità qos.service presente: proprietà da verificare'}
    if path.is_symlink() or not path.is_file():
        result['reason']='qos.service non è un file regolare: migrazione manuale richiesta'
        return result
    try:
        unit=path.read_text(encoding='utf-8')
        start=re.search(r'(?m)^ExecStart\s*=\s*(.+)$',unit)
        stop=re.search(r'(?m)^ExecStop\s*=\s*(.+)$',unit)
        if start:result['exec_start']=start.group(1).strip()[:256]
        if stop:result['exec_stop']=stop.group(1).strip()[:256]
        # Only attribute a specific interface when the command explicitly names it.
        result['matches_interface']=bool(start and re.search(r'\bdev\s+'+re.escape(iface)+r'\b',start.group(1)))
        if not result['matches_interface']:
            result['blocking']=False
            result['reason']='qos.service non punta alla interfaccia selezionata'
            return result
        active=run(['systemctl','is-active','qos.service'],check=False,timeout=5)
        enabled=run(['systemctl','is-enabled','qos.service'],check=False,timeout=5)
        result['active']=active.stdout.strip()
        result['enabled']=enabled.stdout.strip()
        result['exec_stop_removes_root']=bool(stop and re.search(
            r'\btc\s+qdisc\s+del\s+dev\s+'+re.escape(iface)+r'\s+root\b',stop.group(1)))
        # Anything other than confirmed inactive + disabled remains unsafe.
        result['blocking']=result['active'] not in ('inactive','failed') or result['enabled'] not in ('disabled','masked')
        result['reason']=('qos.service ancora attivo o abilitato al boot' if result['blocking']
                          else 'qos.service inattivo e disabilitato; verificare comunque qdisc/IFB')
    except (OSError,QosError,UnicodeError) as exc:
        result['blocking']=True
        result['reason']='Impossibile verificare qos.service: '+str(exc)[:150]
    return result

def topology_report(iface):
    """Read-only and explicit ownership audit; never deletes a foreign qdisc."""
    if not isinstance(iface,str) or not NIC.fullmatch(iface) or iface=='lo':
        raise QosError('interfaccia non valida')
    ident=identity(iface)
    qdiscs=jcmd(['tc','-j','qdisc','show','dev',iface])
    roots=[q for q in qdiscs if q.get('root') is True or q.get('parent')=='root']
    ingress=[q for q in qdiscs if q.get('kind') in ('ingress','clsact')]
    root=roots[0] if len(roots)==1 else None
    saved=read(STATE)
    proven=bool(saved and saved.get('version')==VERSION and saved.get('interface')==iface and saved.get('ifindex')==ident.get('ifindex')
                and saved.get('mac')==ident.get('mac') and root and
                root.get('kind')=='cake' and root.get('handle')=='5ca1:' and
                saved.get('state') in ('confirmed','pending'))
    owner=foreign_qos_owner(iface)
    free=bool(root and root.get('kind') in DEFAULT and not ingress) and not owner.get('blocking')
    kind=(root or {}).get('kind','unknown')
    reason=('Libera: qdisc di sistema compatibile' if free else
            'CAKE IPTM già gestito' if proven else
            'CAKE precedente rilevato: disattivare il vecchio shaping tramite il suo gestore e rigenerare anteprima' if kind=='cake' else
            'Ingress/clsact già presente: verificare il gestore attuale prima di migrare' if ingress else
            'Topologia sconosciuta: migrazione automatica vietata')
    return {'ok':True,'interface':iface,'ifindex':ident.get('ifindex'),'root_kind':kind,
            'root_handle':(root or {}).get('handle'),'ingress_kinds':[x.get('kind') for x in ingress],
            'free':free,'owned':proven,'can_stage':free,'reason':reason,
            'external_owner':owner,
            'migration':'Non rimuovere qdisc con tc qdisc del. Spegnere prima i servizi QoS concorrenti e verificare da console.'}

def validate(obj):
    if not isinstance(obj,dict) or set(obj)-{'interface','up_mbit','down_mbit','diffserv','nat','wash','ack_filter','overhead','timeout'}:
        raise QosError('schema QoS non valido')
    iface=obj.get('interface')
    if not isinstance(iface,str) or not NIC.fullmatch(iface):raise QosError('interfaccia richiesta')
    for key in ('up_mbit','down_mbit'):
        if type(obj.get(key)) is not int or not 1<=obj[key]<=10000:raise QosError(key+' non valido')
    if obj.get('diffserv','diffserv4') not in DIFFSERV:raise QosError('diffserv non valido')
    for key in ('nat','wash','ack_filter'):
        if type(obj.get(key,False)) is not bool:raise QosError(key+' booleano richiesto')
    if type(obj.get('overhead',0)) is not int or not -64<=obj.get('overhead',0)<=256:
        raise QosError('overhead fuori limite')
    if type(obj.get('timeout',180)) is not int or not 60<=obj.get('timeout',180)<=600:
        raise QosError('timeout 60..600 s richiesto')
    return {'interface':iface,'up_mbit':obj['up_mbit'],'down_mbit':obj['down_mbit'],
            'diffserv':obj.get('diffserv','diffserv4'),'nat':obj.get('nat',False),
            'wash':obj.get('wash',False),'ack_filter':obj.get('ack_filter',False),
            'overhead':obj.get('overhead',0),'timeout':obj.get('timeout',180)}

def ifb_name(iface):
    return 'ifbip'+hashlib.sha256(iface.encode()).hexdigest()[:9]

def plan(raw):
    obj=validate(raw)
    if (read(STATE) or {}).get('state') in ('pending','applying','rollback-failed','confirmed'):
        raise QosError('profilo QoS attivo o in transazione')
    if run(['systemctl','is-active','iptm-sqm-calibrate.timer'],check=False).stdout.strip()=='active':
        raise QosError('timer SQM precedente attivo: disabilitarlo prima di migrare')
    owner=foreign_qos_owner(obj['interface'])
    if owner.get('blocking'):raise QosError('Migrazione richiesta: '+owner['reason'])
    info=inspect(obj['interface'])
    try:existing=jcmd(['ip','-j','link','show','dev',ifb_name(obj['interface'])])
    except QosError:existing=[]
    if existing:raise QosError('IFB già presente: non assumere proprietà')
    obj.update(info);obj['ifb']=ifb_name(obj['interface']);obj['created']=int(time.time());obj['version']=VERSION
    digest=hashlib.sha256(json.dumps(obj,sort_keys=True).encode()).hexdigest()
    obj['digest']=digest;atom(STAGE,obj)
    return {'ok':True,'sha256':digest,'preview':obj,'applied':False}

def guard_install():
    previous=read(STATE)
    if previous and previous.get('version') not in (None,VERSION) and previous.get('state') in ('applying','pending','confirmed','rollback-failed'):
        raise QosError('Watchdog della release precedente con QoS attivo: completare la migrazione dalla console prima di sostituirlo')
    if UNIT.is_symlink():raise QosError('systemd unit simbolica')
    if UNIT.exists() and 'Description=IPTM QoS independent rollback watchdog' not in UNIT.read_text():
        raise QosError('unità esistente non riconosciuta')
    if not pathlib.Path(SCRIPT).is_file():raise QosError('script release non installato: '+SCRIPT)
    unit=f'''[Unit]\nDescription=IPTM QoS independent rollback watchdog\nAfter=network.target\n[Service]\nType=simple\nExecStart=/usr/bin/python3 -B {SCRIPT} watchdog\nRestart=always\nRestartSec=2\nNoNewPrivileges=true\n[Install]\nWantedBy=multi-user.target\n'''
    fd,p=tempfile.mkstemp(dir=UNIT.parent,prefix='.iptm-qos-')
    try:
        with os.fdopen(fd,'w') as out:out.write(unit);out.flush();os.fsync(out.fileno())
        os.chmod(p,0o644);os.replace(p,UNIT)
    finally:
        if os.path.exists(p):os.unlink(p)
    run(['systemctl','daemon-reload'],timeout=20);run(['systemctl','enable',UNIT.name],timeout=20);
    run(['systemctl','restart',UNIT.name],timeout=20);
    if run(['systemctl','is-active',UNIT.name],check=False).stdout.strip()!='active':
        raise QosError('watchdog non attivo')
    return {'ok':True,'watchdog':'active'}

def guard_ready():
    if not UNIT.is_file() or UNIT.is_symlink() or SCRIPT not in UNIT.read_text():
        raise QosError('installare watchdog indipendente')
    if run(['systemctl','is-active',UNIT.name],check=False).stdout.strip()!='active':
        raise QosError('watchdog non attivo')
    if run(['systemctl','is-enabled',UNIT.name],check=False).stdout.strip()!='enabled':
        raise QosError('watchdog non abilitato al riavvio')

def cake_opts(mbits,cfg):
    args=['bandwidth',str(mbits)+'mbit',cfg['diffserv']]
    for key,flag in [('nat','nat'),('wash','wash'),('ack_filter','ack-filter')]:
        if cfg[key]:args.append(flag)
    if cfg['overhead']:
        args.extend(['overhead',str(cfg['overhead'])])
    return args

def qroots(dev):
    return [q for q in jcmd(['tc','-j','qdisc','show','dev',dev]) if q.get('root') is True or q.get('parent')=='root']

def owned(state):
    iface=state['interface'];ifb=state['ifb']
    ident=identity(iface)
    if ident['ifindex']!=state['ifindex'] or ident['mac']!=state['mac']:
        raise QosError('WAN sostituita, rimozione automatica bloccata')
    r=run(['ip','-j','link','show','dev',ifb],check=False)
    link=json.loads(r.stdout) if r.returncode==0 else []
    index=link[0].get('ifindex') if link else None
    if index is not None and not state.get('ifb_ifindex'):
        raise QosError('proprietà IFB non dimostrata: rimozione automatica vietata')
    if state.get('ifb_ifindex') and index!=state['ifb_ifindex']:
        raise QosError('IFB sostituita, rimozione automatica bloccata')
    roots=qroots(iface)
    if roots and roots[0].get('kind')=='cake' and roots[0].get('handle')!='5ca1:':
        raise QosError('root WAN acquisita da altro software')
    ifbr=qroots(ifb) if index is not None else []
    if ifbr and ifbr[0].get('kind')=='cake' and ifbr[0].get('handle')!='5ca2:':
        raise QosError('root IFB acquisita da altro software')

def restore(state):
    if state.get('version')!=VERSION:raise QosError('stato di altra release')
    try:owned(state)
    except QosError:
        state['state']='rollback-failed';atom(STATE,state);raise
    iface=state['interface'];ifb=state['ifb']
    # Only delete ingress if IPTM added it and the filter still targets our IFB.
    if state.get('ingress_added'):
        expected=1+int(state.get('ingress_policy_count',0))
        # If an outside manager added actions, protect its filters. The
        # independent watchdog records rollback-failed for manual recovery.
        if not ingress_filters_verified(iface,ifb,expected-1,partial=state.get('state')=='applying'):
            state['state']='rollback-failed';atom(STATE,state)
            raise QosError('ingress modificato da altro servizio; rollback manuale necessario')
        run(['tc','qdisc','del','dev',iface,'ingress'],check=False)
    roots=qroots(iface)
    if roots and roots[0].get('handle')=='5ca1:':
        run(['tc','qdisc','del','dev',iface,'root'])
    links=run(['ip','link','show','dev',ifb],check=False)
    if links.returncode==0 and state.get('ifb_ifindex'):run(['ip','link','del','dev',ifb])
    state['state']='rolled-back';state['restored_at']=time.time();atom(STATE,state)
    # QoS teardown never depends on systemd availability, but disable the
    # adaptive timer best-effort to prevent a stale job after rollback.
    try:
        adaptive=read(ADAPT)
        if adaptive and adaptive.get('enabled'):
            adaptive['enabled']=False;atom(ADAPT,adaptive)
            if ADAPT_TIMER.is_file() and not ADAPT_TIMER.is_symlink():
                run(['systemctl','disable','--now',ADAPT_TIMER.name],check=False)
    except (QosError,OSError):pass
    return {'ok':True,'state':'rolled-back','interface':iface}

def ingress_policy(iface):
    """Load only verifiably owned DSCP rules, otherwise use plain IFB ingress.

    CAKE shaping and the IFB catch-all redirect work without an optional
    classification profile. A stale DSCP *ownership* record must never cause
    CAKE to fail after qdiscs were created. We do not adopt, restore, remove
    or rewrite the mismatching iptables chain. Unsafe/malformed state still
    fails closed, rather than silently trusting attacker-supplied rules.

    Remote service port is source port on ingress; a local source CIDR becomes
    destination CIDR. Status is persisted for the UI and the watchdog.
    """
    file=POLICY_ACTIVE
    if file.is_symlink():
        raise QosError('profilo DSCP simbolico: controllo manuale richiesto')
    if not file.exists():return [],'not-configured'
    st=file.stat()
    if not file.is_file() or st.st_uid or (st.st_mode & 0o077):
        raise QosError('profilo DSCP persistente non protetto')
    import importlib.util
    policy_file=pathlib.Path(__file__).with_name('qos_policy.py')
    spec=importlib.util.spec_from_file_location('iptm_qos_policy_ingress',policy_file)
    policy=importlib.util.module_from_spec(spec);spec.loader.exec_module(policy)
    raw=json.loads(file.read_text())
    if not isinstance(raw,dict):raise QosError('profilo DSCP non valido')
    if raw.get('interface')!=iface:return [],'other-interface'
    normalized=policy.validate_active(raw)
    if not policy.matches_owned(raw):
        # The on-disk profile is not proof of live kernel ownership. Preserve
        # both the foreign chain and network connectivity. DSCP classification
        # is disabled only for this CAKE transaction (not firewall egress).
        return [],'unverified'
    rules=[dict(item,dscp=policy.DSCP[item['priority']])
           for item in normalized['rules']
           if item.get('direction','both') in ('both','download') and policy.DSCP[item['priority']]]
    return rules,'verified'

def ingress_flower_args(iface,ifb,rule,order):
    """Preserve ECN on IPv4; checksum fix precedes redirect into IFB.

    A terminal mirred redirect means the generic catch-all runs only for
    packets that did not match an application-specific rule.
    """
    if order<0 or order>39:raise QosError('ordine ingresso non valido')
    if rule['protocol'] not in ('tcp','udp') or not 1<=rule['port']<=65535:
        raise QosError('porta ingresso non valida')
    dscp=rule['dscp']
    if type(dscp)!=int or not 0<=dscp<=63:raise QosError('DSCP ingresso non valido')
    args=['tc','filter','add','dev',iface,'parent','ffff:','protocol','ip',
          'pref',str(100+order),'flower','ip_proto',rule['protocol'],
          'src_port',str(rule['port'])]
    if rule['source']:args+=['dst_ip',rule['source']]
    args+=['action','pedit','ex','munge','ip','dsfield','set',hex(dscp<<2),
           'retain','0xfc','pipe','action','csum','ip4h','pipe',
           'action','mirred','egress','redirect','dev',ifb]
    return args

def ingress_filters_verified(iface,ifb,expected,partial=False):
    out=run(['tc','filter','show','dev',iface,'parent','ffff:']).stdout
    priorities={int(x) for x in re.findall(r'\bpref (\d+)\b',out)}
    wanted={500}|{100+n for n in range(expected)}
    if not (priorities <= wanted if partial else priorities == wanted):return False
    for pref in sorted(priorities):
        detail=run(['tc','filter','show','dev',iface,'parent','ffff:',
                    'pref',str(pref)]).stdout
        if ifb not in detail or 'mirred' not in detail:return False
    return True

def install_topology(obj):
    """Apply only the fully-owned two-direction CAKE topology to default root.

    The state file must already identify the new transaction and boot.
    """
    iface=obj['interface'];ifb=obj['ifb']
    # Inspect the optional policy before any kernel mutation. Unknown ownership
    # means no ingress DSCP filters, but CAKE/IFB still gets its catch-all.
    rules,policy_status=ingress_policy(iface)
    obj['ingress_policy_status']=policy_status
    obj['ingress_policy_count']=len(rules)
    atom(STATE,obj)
    run(['ip','link','add','dev',ifb,'type','ifb'])
    obj['ifb_ifindex']=identity(ifb)['ifindex'];atom(STATE,obj)
    run(['ip','link','set','dev',ifb,'up'])
    run(['tc','qdisc','replace','dev',ifb,'root','handle','5ca2:','cake']+cake_opts(obj['down_mbit'],obj))
    run(['tc','qdisc','replace','dev',iface,'root','handle','5ca1:','cake']+cake_opts(obj['up_mbit'],obj))
    run(['tc','qdisc','add','dev',iface,'handle','ffff:','ingress'])
    obj['ingress_added']=True;atom(STATE,obj)
    # Optional application-aware ingress classification must be installed
    # before the catch-all; any unsupported tc action aborts the entire trial.
    for n,rule in enumerate(rules):run(ingress_flower_args(iface,ifb,rule,n))
    run(['tc','filter','add','dev',iface,'parent','ffff:','protocol','all','pref','500',
         'u32','match','u32','0','0','action','mirred','egress','redirect','dev',ifb])
    if qroots(iface)[0].get('handle')!='5ca1:' or qroots(ifb)[0].get('handle')!='5ca2:':
        raise QosError('verifica CAKE root non superata')
    if not ingress_filters_verified(iface,ifb,len(rules)):
        raise QosError('IFB redirect o filtri applicativi non verificati')
    return True

def activate(digest):
    guard_ready()
    obj=read(STAGE)
    if not obj or not HEX.fullmatch(digest) or obj.get('digest')!=digest or time.time()-obj.get('created',0)>600:
        raise QosError('piano non valido o scaduto')
    if (read(STATE) or {}).get('state') in ('applying','pending','confirmed','rollback-failed'):
        raise QosError('un altro profilo è già attivo')
    owner=foreign_qos_owner(obj['interface'])
    if owner.get('blocking'):raise QosError('Gestore QoS esterno riattivato: '+owner['reason'])
    cur=inspect(obj['interface'])
    if cur['ifindex']!=obj['ifindex'] or cur['mac']!=obj['mac']:
        raise QosError('WAN modificata dopo anteprima')
    ifb=obj['ifb'];iface=obj['interface']
    if run(['ip','link','show','dev',ifb],check=False).returncode==0:
        raise QosError('IFB già esistente')
    obj['state']='applying';obj['token']=secrets.token_hex(12);obj['applied_at']=time.time()
    obj['deadline']=time.time()+obj['timeout'];obj['boot_id']=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    obj['owner_pid']=os.getpid();obj['ingress_added']=False
    atom(STATE,obj)
    try:
        install_topology(obj)
        obj['state']='pending';atom(STATE,obj);STAGE.unlink(missing_ok=True)
        return {'ok':True,'state':'pending','token':obj['token'],'deadline':obj['deadline'],
                'interface':iface,'ifb':ifb,'up_mbit':obj['up_mbit'],'down_mbit':obj['down_mbit'],
                'ingress_policy_status':obj['ingress_policy_status'],
                'ingress_policy_count':obj['ingress_policy_count']}
    except Exception:
        # Independent watcher will retry if direct cleanup fails.
        try:restore(obj)
        except Exception:pass
        raise

def verified_ingress_for_state(obj):
    """Verify owned IFB redirect and the exact number of ingress policy filters.

    Refuse a confirmation when another process removed or altered the filter
    topology after the initially successful installation.
    """
    count=obj.get('ingress_policy_count')
    if type(count) is not int or not 0 <= count <= 40 or obj.get('ingress_added') is not True:
        raise QosError('stato filtri ingresso incompleto')
    if not ingress_filters_verified(obj['interface'], obj['ifb'], count):
        raise QosError('redirect IFB o filtri DSCP modificati: conferma rifiutata')
    return True

def confirm(token):
    obj=read(STATE)
    if not obj or obj.get('token')!=token or obj.get('state')!='pending':raise QosError('nessuna prova da confermare')
    if time.time()>=obj['deadline']:return restore(obj)
    owned(obj)
    if qroots(obj['interface'])[0].get('handle')!='5ca1:' or qroots(obj['ifb'])[0].get('handle')!='5ca2:':
        raise QosError('stato CAKE non verificabile')
    verified_ingress_for_state(obj)
    obj['state']='confirmed';obj['confirmed_at']=time.time();atom(STATE,obj)
    return {'ok':True,'state':'confirmed','interface':obj['interface']}

def status():
    obj=read(STATE)
    if not obj:return {'ok':True,'state':'empty'}
    result={k:v for k,v in obj.items() if k not in ('token','owner_pid','mac')}
    result['ok']=True
    if obj['state'] in ('pending','confirmed'):
        try:
            owned(obj);result['verified']=(qroots(obj['interface'])[0].get('handle')=='5ca1:' and
                                             qroots(obj['ifb'])[0].get('handle')=='5ca2:' and
                                             verified_ingress_for_state(obj))
        except (QosError,IndexError):result['verified']=False
    return result

def resume_confirmed_after_boot(obj,boot_id):
    """Restore an accepted profile after reboot only on the same physical WAN.

    Never steal an ingress/qdisc from another manager; if the NIC is not yet
    ready watchdog retries. Do not touch a new NIC with the previous name.
    """
    if obj.get('boot_id')==boot_id:return False
    if obj.get('state')!='confirmed':return False
    if run(['systemctl','is-active','iptm-sqm-calibrate.timer'],check=False).stdout.strip()=='active':
        return False
    try:info=inspect(obj['interface'])
    except QosError:return False
    if info.get('mac')!=obj.get('mac'):return False
    if run(['ip','link','show','dev',obj['ifb']],check=False).returncode==0:
        return False
    obj.update(info)
    obj.pop('ifb_ifindex',None)
    obj['state']='applying';obj['owner_pid']=os.getpid()
    obj['applied_at']=time.time();obj['deadline']=time.time()+120
    obj['boot_id']=boot_id;obj['ingress_added']=False
    atom(STATE,obj)
    try:
        install_topology(obj)
        obj['state']='confirmed';obj['resumed_at']=time.time();atom(STATE,obj)
        return True
    except Exception:
        # The independent supervisor still owns the transaction and will
        # restore if direct cleanup cannot be completed.
        try:restore(obj)
        except Exception:pass
        return False

def watchdog():
    # Separate long-lived unit. Boot different => roll back all unconfirmed trials.
    while True:
        fd=os.open(LOCK,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'r+') as f:
            fcntl.flock(f,fcntl.LOCK_EX)
            obj=read(STATE)
            if obj and obj.get('state')=='confirmed':
                resume_confirmed_after_boot(obj,pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip())
            if obj and obj.get('state') in ('applying','pending'):
                expired=(time.time()>=obj.get('deadline',0) or
                         obj.get('boot_id')!=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip())
                if obj['state']=='applying' and time.time()-obj.get('applied_at',0)>15:
                    try:os.kill(obj.get('owner_pid',0),0)
                    except (ProcessLookupError,PermissionError):expired=True
                if expired:
                    try:restore(obj)
                    except Exception as e:print('IPTM watchdog rollback: '+str(e),file=sys.stderr,flush=True)
        time.sleep(2)

def calibration_status():
    current=read(CALIB)
    previous=read(CALIB_LOG)
    if current and current.get('state')=='running' and time.time()-current.get('started',0)>1000:
        current=dict(current,state='stale',error='calibrazione scaduta; controllare il journal di systemd')
    return {'ok':True,'calibration':current or {'state':'idle'},'last_valid':previous}

def calibration_start(iface):
    # Read-only benchmarking does not require or install the QoS mutation watchdog.
    audit=topology_report(iface)
    cur=read(CALIB)
    if cur and cur.get('state')=='running' and time.time()-cur.get('started',0)<1000:
        raise QosError('calibrazione già in esecuzione')
    active=read(STATE)
    if active and active.get('state') in ('applying','pending','rollback-failed'):
        raise QosError('calibrazione vietata durante prova o rollback QoS')
    run(['systemctl','is-active','network-online.target'],check=False)
    measurement={'state':'running','job_id':secrets.token_hex(12),'started':time.time(),'attempts':0,
                 'interface':iface,'ifindex':audit['ifindex'],'root_kind':audit['root_kind'],
                 'can_propose':audit['free'],'root_handle':audit['root_handle'],
                 'note':'Solo misura; nessuna modifica a tc, IFB o limiti attivi'}
    atom(CALIB,measurement)
    try:
        run(['systemd-run','--unit='+CALIB_UNIT,'--collect','--property=Type=exec',
             '--property=RuntimeMaxSec=900',
             '/usr/bin/python3','-B',SCRIPT,'calibrate-worker'])
    except Exception:
        atom(CALIB,dict(measurement,state='failed',error='avvio servizio calibrazione non riuscito'))
        raise
    return {'ok':True,'state':'running','note':measurement['note']}

def speedtest_measurement():
    """Independent Ookla runner; reject Python wrappers using the same command name."""
    import shutil
    path=shutil.which('speedtest')
    if not path:raise QosError('ookla:not-installed')
    executable=pathlib.Path(path).resolve(strict=True)
    if not executable.is_file():raise QosError('ookla:not-official-binary')
    with executable.open('rb') as binary:
        if binary.read(4)!=b'\x7fELF':raise QosError('ookla:not-official-binary')
    # Ookla 1.2.x can abort with std::logic_error when invoked from systemd
    # without USER/LOGNAME/XDG_CONFIG_HOME. Match the successful root CLI
    # invocation and disable interactive progress in JSON mode.
    environment=os.environ.copy()
    environment.update({'HOME':'/root','USER':'root','LOGNAME':'root',
                        'LANG':'C.UTF-8','LC_ALL':'C.UTF-8',
                        'XDG_CONFIG_HOME':'/root/.config'})
    try:
        result=subprocess.run([str(executable),'--accept-license','--accept-gdpr',
                               '--progress=no','--format=json'],
                              capture_output=True,text=True,stdin=subprocess.DEVNULL,
                              timeout=200,env=environment)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise QosError('ookla:execution-failed: '+type(exc).__name__) from exc
    if result.returncode:
        raise QosError('ookla:exit-'+str(result.returncode)+': '+
                       (result.stderr or result.stdout)[-350:])
    payload=result.stdout
    if len(payload)>256000:raise QosError('ookla:output-too-large')
    obj=json.loads(payload)
    if not isinstance(obj,dict) or obj.get('error') or obj.get('type')=='error':
        raise QosError('ookla:invalid-result')
    dl=float(obj['download']['bandwidth'])*8/1e6
    ul=float(obj['upload']['bandwidth'])*8/1e6
    import math
    if not math.isfinite(dl) or not math.isfinite(ul) or not 1<=dl<=10000 or not 1<=ul<=10000:
        raise QosError('ookla:invalid-bidirectional-speed')
    return {'download_mbit':round(dl,2),'upload_mbit':round(ul,2),'engine':'ookla'}


def calibration_proposal(samples,old):
    """Independently approve an improved and stable direction; preserve the other.

    A stale, absent, noisy or lower result cannot reduce a previously approved
    limit. A change is at most +10% per run (anti-noise); never over 10Gbit.
    Automatic approval here persists the recommendation, *not* a new qdisc.
    """
    import math,statistics
    if not samples:raise QosError('nessuna misura disponibile')
    for sample in samples:
        for key in ('download_mbit','upload_mbit'):
            if key in sample:
                try:value=float(sample[key])
                except (TypeError,ValueError,OverflowError):raise QosError('misura non valida')
                if not math.isfinite(value) or value<=0:raise QosError('misura nulla o non valida')
    previous=(old or {}).get('proposal') or {}
    proposal={};decisions={};measurements={}
    for direction in ('down','up'):
        key=direction+'_mbit'
        values=[]
        for sample in samples:
            try:value=float(sample['download_mbit' if direction=='down' else 'upload_mbit'])
            except (KeyError,TypeError,ValueError,OverflowError):continue
            if math.isfinite(value) and 1<=value<=10000:values.append(value)
        old_value=previous.get(key)
        old_value=old_value if type(old_value) is int and 1<=old_value<=10000 else None
        stable=len(values)>=2 and max(values)/min(values)<=1.20
        measurements[direction]={'count':len(values),'stable':stable}
        if stable:
            candidate=max(1,int(statistics.median(values)*0.92))
            if old_value is None:
                proposal[key]=candidate;decisions[direction]='approved-first-valid'
            elif candidate>old_value:
                proposal[key]=min(candidate,old_value+max(1,int(old_value*.10)),10000)
                decisions[direction]='approved-improvement'
            else:
                proposal[key]=old_value;decisions[direction]='kept-not-improved'
        elif old_value is not None:
            proposal[key]=old_value;decisions[direction]='kept-insufficient-data'
        else:
            decisions[direction]='not-approved'
    approved=[d for d,v in decisions.items() if v.startswith('approved')]
    return {'proposal':proposal if len(proposal)==2 else None,
            'direction_decisions':decisions,'quality':measurements,
            'auto_approved':approved,'kept_previous':not bool(approved),
            'reason':('Limiti migliori approvati per '+', '.join(approved) if approved
                      else 'Nessun miglioramento bidirezionale attendibile; limiti conservati')}


def calibration_worker():
    """Measurements run lock-free, but commit is serialized and job-id checked."""
    doc=read(CALIB)
    if not doc or doc.get('state')!='running' or not TOKEN.fullmatch(str(doc.get('job_id',''))):
        raise QosError('job calibrazione non verificabile')
    samples=[];errors=[]
    try:
        for attempt in range(2):
            try:samples.append(speedtest_measurement())
            except QosError as exc:errors.append(str(exc))
        fd=os.open(LOCK,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'r+') as f:
            fcntl.flock(f,fcntl.LOCK_EX)
            latest=read(CALIB)
            if not latest or latest.get('job_id')!=doc['job_id'] or latest.get('state')!='running':
                raise QosError('job sostituito: risultati ignorati')
            old=read(CALIB_LOG)
            if old and old.get('interface')!=doc['interface']:old=None
            result=calibration_proposal(samples,old)
            active=read(STATE)
            reason=None
            if not doc.get('can_propose'):
                reason='QoS già attivo: Speedtest sotto shaping non prova maggiore capacità della linea'
            elif active and active.get('state') in ('confirmed','applying','pending','rollback-failed'):
                reason='Transazione o profilo CAKE intervenuto durante la misura'
            else:
                try:
                    audit=topology_report(doc['interface'])
                    if (audit['ifindex']!=doc['ifindex'] or audit['root_kind']!=doc['root_kind']
                        or audit['root_handle']!=doc['root_handle'] or not audit['free']):
                        reason='WAN o qdisc cambiate durante la misura'
                except QosError:reason='WAN non verificabile al termine del test'
            if reason:
                result={'proposal':(old or {}).get('proposal'),'auto_approved':[],
                        'direction_decisions':{'down':'kept','up':'kept'},
                        'kept_previous':True,'reason':reason}
            latest.update(state='completed',finished=time.time(),attempts=2,
                          samples=samples,errors=errors,**result)
            if result.get('proposal') and result.get('auto_approved'):
                atom(CALIB_LOG,{'proposal':result['proposal'],'interface':doc['interface'],
                                'ifindex':doc['ifindex'],'measured_at':time.time(),
                                'source':'ookla','auto_approved':result['auto_approved']})
            atom(CALIB,latest)
        return {'ok':True,'state':'completed','auto_approved':result.get('auto_approved',[])}
    except Exception as exc:
        fd=os.open(LOCK,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'r+') as f:
            fcntl.flock(f,fcntl.LOCK_EX)
            latest=read(CALIB)
            if latest and latest.get('job_id')==doc['job_id'] and latest.get('state')=='running':
                atom(CALIB,dict(latest,state='failed',finished=time.time(),error=str(exc)[:350]))
        raise


def auto_units_install():
    if not pathlib.Path(SCRIPT).is_file():raise QosError('Motore QoS non installato')
    units={AUTO_SERVICE:f"""[Unit]\nDescription=IPTM QoS hourly independent calibration\nAfter=network-online.target\n[Service]\nType=oneshot\nExecStart=/usr/bin/python3 -B {SCRIPT} auto-tick\nNoNewPrivileges=true\n[Install]\nWantedBy=multi-user.target\n""",
           AUTO_TIMER:"""[Unit]\nDescription=IPTM QoS hourly independent calibration timer\n[Timer]\nOnBootSec=20min\nOnUnitInactiveSec=1h\nPersistent=true\nUnit=iptm-qos-auto-calibration.service\n[Install]\nWantedBy=timers.target\n"""}
    for path,contents in units.items():
        if path.is_symlink():raise QosError('unità auto-calibrazione simbolica')
        if path.exists() and 'Description=IPTM QoS hourly independent calibration' not in path.read_text():
            raise QosError('unità auto-calibrazione non verificata')
        fd,tmp=tempfile.mkstemp(dir=path.parent,prefix='.iptm-auto-')
        try:
            with os.fdopen(fd,'w') as f:
                os.fchmod(f.fileno(),0o644);f.write(contents);f.flush();os.fsync(f.fileno())
            os.replace(tmp,path)
        finally:
            if os.path.exists(tmp):os.unlink(tmp)
    run(['systemctl','daemon-reload'])
    run(['systemctl','enable','--now',AUTO_TIMER.name])
    if run(['systemctl','is-active',AUTO_TIMER.name],check=False).stdout.strip()!='active':
        raise QosError('Timer automatico non attivo')

def auto_enable():
    if run(['systemctl','is-active','iptm-sqm-calibrate.timer'],check=False).stdout.strip()=='active':
        raise QosError('disabilitare prima il timer SQM storico')
    auto_units_install()
    atom(AUTO_STATE,{'enabled':True,'activated_at':time.time(),'version':VERSION})
    return {'ok':True,'enabled':True,'interval':'1h','mode':'independent-unshaped-only'}

def auto_disable():
    if AUTO_TIMER.exists():
        if AUTO_TIMER.is_symlink() or 'Description=IPTM QoS hourly independent calibration' not in AUTO_TIMER.read_text():
            raise QosError('timer sconosciuto')
        run(['systemctl','disable','--now',AUTO_TIMER.name])
    atom(AUTO_STATE,{'enabled':False,'version':VERSION})
    return {'ok':True,'enabled':False}

def auto_status():
    return {'ok':True,'config':read(AUTO_STATE) or {'enabled':False},
            'calibration':calibration_status()}

def auto_tick():
    """Do not run shaped speedtests. RTT controller handles online adjustments."""
    if not (read(AUTO_STATE) or {}).get('enabled'):
        return {'ok':True,'started':False,'reason':'disabilitato'}
    if run(['systemctl','is-active','iptm-sqm-calibrate.timer'],check=False).stdout.strip()=='active':
        return {'ok':True,'started':False,'reason':'legacy-timer-active'}
    active=read(STATE)
    if active and active.get('state') in ('confirmed','pending','applying','rollback-failed'):
        return {'ok':True,'started':False,'reason':'CAKE attivo: evitare speedtest sotto shaping'}
    routes=jcmd(['ip','-j','-4','route','show','default'])
    if not routes:raise QosError('nessuna WAN IPv4 di default')
    routes=sorted(routes,key=lambda r:r.get('metric',0))
    interface=routes[0].get('dev','')
    if not NIC.fullmatch(interface):raise QosError('interfaccia default non verificata')
    audit=topology_report(interface)
    if not audit['free']:return {'ok':True,'started':False,'reason':'qdisc non libera'}
    return calibration_start(interface)

def latency_measurement(iface):
    """WAN-bound ICMP probe. Failure or ambiguity means NO rate change."""
    samples=[]
    for target in ('1.1.1.1','9.9.9.9'):
        try:
            result=run(['ping','-n','-I',iface,'-c','2','-W','1',target],check=False,timeout=6)
        except QosError:continue
        if result.returncode:continue
        vals=[float(x) for x in re.findall(r'\btime=([0-9]+(?:\.[0-9]+)?)',result.stdout)]
        if len(vals)==2 and 0<min(vals) and max(vals)<1000:
            samples.append(sum(vals)/len(vals))
    if not samples:raise QosError('ICMP RTT non attendibile: limiti invariati')
    return min(samples)

def adaptive_decision(latency,base,current,baseline,high,low):
    """Bounded controller: never recompute original rate from shaped speedtests.

    Three high-RTT samples to reduce; two quiet samples to recover. Each
    direction stays within 85-100% of the last user-confirmed rate.
    """
    if type(base)!=int or base<1 or type(current)!=int or current<1:
        raise QosError('velocità adattiva non valida')
    if not isinstance(latency,(int,float)) or not 0<latency<1000:
        raise QosError('latenza non valida')
    if baseline is None:baseline=latency
    baseline=min(float(baseline),latency)
    high=high+1 if latency>baseline+30 else 0
    low=low+1 if latency<baseline+12 else 0
    min_rate=max(1,int(base*.85))
    rate=min(base,max(min_rate,current))
    if high>=3:
        rate=max(min_rate,int(rate*.97));high=0
    elif low>=2:
        rate=min(base,max(rate+1,int(rate*1.02)));low=0
    return rate,baseline,high,low

def adaptive_units_install():
    if not pathlib.Path(SCRIPT).is_file():raise QosError('release QoS non installata')
    files={ADAPT_UNIT:f'''[Unit]\nDescription=IPTM QoS adaptive RTT controller\nAfter=network-online.target\n[Service]\nType=oneshot\nExecStart=/usr/bin/python3 -B {SCRIPT} adaptive-tick\nNoNewPrivileges=true\n[Install]\nWantedBy=multi-user.target\n''',
           ADAPT_TIMER:'''[Unit]\nDescription=IPTM QoS adaptive RTT timer\n[Timer]\nOnBootSec=2min\nOnUnitInactiveSec=1min\nAccuracySec=10s\nUnit=iptm-qos-adaptive.service\n[Install]\nWantedBy=timers.target\n'''}
    for path,contents in files.items():
        if path.is_symlink():raise QosError('unità adattiva simbolica')
        if path.exists() and 'Description=IPTM QoS adaptive RTT' not in path.read_text():
            raise QosError('unità adattiva non appartenente a IPTM')
        fd,tmp=tempfile.mkstemp(dir=path.parent,prefix='.iptm-qos-adapt-')
        try:
            with os.fdopen(fd,'w') as f:
                os.fchmod(f.fileno(),0o644);f.write(contents);f.flush();os.fsync(f.fileno())
            os.replace(tmp,path)
        finally:
            if os.path.exists(tmp):os.unlink(tmp)
    run(['systemctl','daemon-reload'])
    run(['systemctl','enable','--now',ADAPT_TIMER.name])
    if run(['systemctl','is-active',ADAPT_TIMER.name],check=False).stdout.strip()!='active':
        raise QosError('timer RTT non attivo')

def adapt_enable():
    state=read(STATE)
    if not state or state.get('state')!='confirmed':raise QosError('CAKE deve essere confermato')
    owned(state);guard_ready()
    current=read(ADAPT)
    if current and current.get('enabled'):
        if current.get('interface')==state['interface'] and current.get('base_up')==state['up_mbit'] and current.get('base_down')==state['down_mbit']:
            return {'ok':True,'enabled':True,'already_active':True}
        raise QosError('regolatore già associato a un altro profilo')
    if state.get('up_mbit',0)<1 or state.get('down_mbit',0)<1:
        raise QosError('limiti confermati incompleti')
    adaptive_units_install()
    config={'enabled':True,'interface':state['interface'],'ifb':state['ifb'],
            'boot_id':state['boot_id'],'base_up':state['up_mbit'],'base_down':state['down_mbit'],
            'up':state['up_mbit'],'down':state['down_mbit'],
            'baseline':None,'high':0,'low':0,'samples':0,'trial':None,'next_direction':'down',
            'counters':None,'last_change':0,'last_tick':0}
    atom(ADAPT,config)
    return {'ok':True,'enabled':True,'bounded':'85%-100%','interval':'60s'}

def adaptive_qdisc_bytes(dev):
    """Return actual CAKE byte counters, or None when this iproute2 lacks them."""
    roots=[q for q in jcmd(['tc','-j','-s','qdisc','show','dev',dev])
           if q.get('kind')=='cake' and (q.get('root') is True or q.get('parent')=='root')]
    if len(roots)!=1:return None
    root=roots[0]
    value=root.get('bytes',root.get('bytes_sent'))
    if value is None and isinstance(root.get('stats'),dict):
        value=(root['stats'].get('basic') or {}).get('bytes')
    return value if type(value) is int and value>=0 else None


def adapt_change_one(state,direction,rate):
    """Only change a qdisc that is still owned by the confirmed IPTM profile."""
    if direction not in ('up','down') or type(rate) is not int or rate<1:
        raise QosError('regolazione direzione/rate non valida')
    owned(state)
    dev=state['interface'] if direction=='up' else state['ifb']
    handle='5ca1:' if direction=='up' else '5ca2:'
    roots=qroots(dev)
    if len(roots)!=1 or roots[0].get('kind')!='cake' or roots[0].get('handle')!=handle:
        raise QosError('CAKE non di proprietà: modifica vietata')
    run(['tc','qdisc','change','dev',dev,'root','handle',handle,'cake']+cake_opts(rate,state))


def adapt_tick():
    """Test one independent direction at a time; rollback on bad RTT or idle test.

    No speculative increase above the last operator-confirmed rates. A shaped
    speedtest is never used as evidence that the physical line is faster.
    """
    cfg=read(ADAPT)
    if not cfg or not cfg.get('enabled'):return {'ok':True,'changed':False,'reason':'disabilitato'}
    state=read(STATE)
    if not state or state.get('state')!='confirmed' or state['interface']!=cfg['interface'] or state['ifb']!=cfg['ifb']:
        return {'ok':True,'changed':False,'reason':'profilo CAKE non confermato'}
    owned(state)
    if qroots(state['interface'])[0].get('handle')!='5ca1:' or qroots(state['ifb'])[0].get('handle')!='5ca2:':
        raise QosError('qdisc CAKE non verificabili')
    boot_id=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    if cfg['boot_id']!=boot_id:
        cfg.update(boot_id=boot_id,up=state['up_mbit'],down=state['down_mbit'],
                   baseline=None,high=0,low=0,samples=0,trial=None,counters=None)
    if cfg['base_up']!=state['up_mbit'] or cfg['base_down']!=state['down_mbit']:
        raise QosError('limiti massimi variati: ricreare il regolatore')
    now=time.time();rtt=latency_measurement(state['interface'])
    counter={'up':adaptive_qdisc_bytes(state['interface']),
             'down':adaptive_qdisc_bytes(state['ifb'])}
    earlier=cfg.get('counters') if isinstance(cfg.get('counters'),dict) else {}
    previous_tick=float(cfg.get('last_tick') or 0)
    elapsed=max(0,now-previous_tick)
    traffic={key:(counter[key]-earlier[key]) if type(counter[key]) is int and type(earlier.get(key)) is int and counter[key]>=earlier[key] else 0
             for key in ('up','down')}
    trial=cfg.get('trial')
    if isinstance(trial,dict):
        direction=trial['direction']
        # An interrupted change can be only a partial trial. Restoring prior
        # rate is safe and idempotent even if the process died before tc change.
        sufficient=(elapsed>=20 and traffic[direction]>=1_000_000)
        improved=(sufficient and rtt<=float(trial['initial_rtt'])+2.0)
        if not improved:
            try:adapt_change_one(state,direction,int(trial['old_rate']))
            except QosError:
                cfg['recovery_needed']=True;atom(ADAPT,cfg)
                raise QosError('rollback regolazione RTT fallito: intervento richiesto')
            cfg[direction]=trial['old_rate']
        cfg.update(trial=None,last_tick=now,last_rtt=round(rtt,2),counters=counter,
                   samples=cfg.get('samples',0)+1,last_verification='approved' if improved else 'rolled-back')
        atom(ADAPT,cfg)
        return {'ok':True,'changed':False,'trial':cfg['last_verification'],
                'rtt_ms':rtt,'direction':direction}
    cfg['samples']=cfg.get('samples',0)+1
    cfg['baseline']=min(cfg.get('baseline') or rtt,rtt)
    direction=cfg.get('next_direction','down')
    cfg['next_direction']='up' if direction=='down' else 'down'
    base=cfg['base_'+direction]
    current=cfg[direction]
    if elapsed>=20 and traffic[direction]>=1_000_000 and current<base and rtt<=cfg['baseline']+8:
        candidate=min(base,max(current+1,int(current*1.01)))
        cfg['trial']={'direction':direction,'old_rate':current,'new_rate':candidate,
                      'initial_rtt':rtt,'started_at':now}
        # Persist journal before touching kernel. A crash is resolved next tick.
        atom(ADAPT,cfg)
        try:adapt_change_one(state,direction,candidate)
        except QosError:
            cfg['trial']=None;atom(ADAPT,cfg);raise
        cfg[direction]=candidate
        cfg.update(last_change=now,last_rtt=round(rtt,2),last_tick=now,counters=counter)
        atom(ADAPT,cfg)
        return {'ok':True,'changed':True,'trial':'pending','direction':direction,
                'old_mbit':current,'candidate_mbit':candidate,'rtt_ms':rtt}
    cfg.update(last_rtt=round(rtt,2),last_tick=now,counters=counter)
    atom(ADAPT,cfg)
    return {'ok':True,'changed':False,'reason':'nessun recupero verificabile',
            'rtt_ms':rtt,'direction':direction,'traffic_bytes':traffic[direction]}

def adapt_disable():
    cfg=read(ADAPT)
    if ADAPT_TIMER.exists():
        if ADAPT_TIMER.is_symlink() or 'Description=IPTM QoS adaptive RTT timer' not in ADAPT_TIMER.read_text():
            raise QosError('timer non di proprietà IPTM')
        run(['systemctl','disable','--now',ADAPT_TIMER.name])
    state=read(STATE)
    restored=False
    if state and state.get('state')=='confirmed' and cfg and cfg.get('interface')==state['interface']:
        owned(state)
        if qroots(state['interface'])[0].get('handle')!='5ca1:' or qroots(state['ifb'])[0].get('handle')!='5ca2:':
            raise QosError('topologia CAKE cambiata: limiti non toccati')
        run(['tc','qdisc','change','dev',state['interface'],'root','handle','5ca1:','cake']+cake_opts(state['up_mbit'],state))
        run(['tc','qdisc','change','dev',state['ifb'],'root','handle','5ca2:','cake']+cake_opts(state['down_mbit'],state))
        restored=True
    if cfg:
        cfg.update(enabled=False,trial=None,up=(state or {}).get('up_mbit',cfg.get('up')),
                   down=(state or {}).get('down_mbit',cfg.get('down')))
        atom(ADAPT,cfg)
    return {'ok':True,'enabled':False,'base_restored':restored}

def main(args):
    guard_root()
    if args==['watchdog']:
        watchdog();return {'ok':True}
    # Calibrating takes minutes; do not hold the QoS state lock while measuring.
    if args==['calibrate-worker']:return calibration_worker()
    fd=os.open(LOCK,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'r+') as f:
        fcntl.flock(f,fcntl.LOCK_EX)
        if args==['status']:
            result=status();cfg=read(ADAPT)
            result['adaptive']={k:v for k,v in (cfg or {}).items() if k in
                ('enabled','up','down','last_rtt','last_tick','base_up','base_down','samples')}
            return result
        if args==['adaptive-tick']:return adapt_tick()
        if args==['auto-tick']:return auto_tick()
        if args==['auto-enable']:return auto_enable()
        if args==['auto-disable']:return auto_disable()
        if args==['auto-status']:return auto_status()
        if args==['adaptive-enable']:return adapt_enable()
        if args==['adaptive-disable']:return adapt_disable()
        if len(args)==2 and args[0]=='inspect':return topology_report(args[1])
        if len(args)==2 and args[0]=='calibrate-start':return calibration_start(args[1])
        if args==['calibrate-status']:return calibration_status()
        if args==['install-guard']:return guard_install()
        if args==['stage']:
            data=sys.stdin.buffer.read(8193)
            if len(data)>8192:raise QosError('JSON troppo grande')
            return plan(json.loads(data))
        if len(args)==2 and args[0]=='apply':return activate(args[1])
        if len(args)==2 and args[0]=='confirm' and TOKEN.fullmatch(args[1]):return confirm(args[1])
        if len(args)==2 and args[0]=='rollback' and TOKEN.fullmatch(args[1]):
            obj=read(STATE)
            if not obj or obj.get('token')!=args[1]:raise QosError('token differente')
            return restore(obj)
        if args==['disable']:
            obj=read(STATE)
            if not obj or obj.get('state')!='confirmed':raise QosError('nessun profilo confermato')
            return restore(obj)
        raise QosError('comando sconosciuto')
if __name__=='__main__':
    try:print(json.dumps(main(sys.argv[1:]),ensure_ascii=False))
    except (QosError,OSError,ValueError,KeyError,TypeError,IndexError) as exc:
        print(json.dumps({'ok':False,'error':str(exc)},ensure_ascii=False));sys.exit(1)
