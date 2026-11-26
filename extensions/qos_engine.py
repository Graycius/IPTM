#!/usr/bin/env python3
"""IPTM CAKE/IFB bidirectional guarded transaction engine.

Only claims completely unowned kernel topology; no blind tc qdisc replace.
A separately supervised systemd watchdog restores unconfirmed trials.
Deliberately does not estimate internet bandwidth from NIC link speed.
"""
from __future__ import annotations

from command_transport import durable_replace

from command_transport import capture
import fcntl, hashlib, json, os, pathlib, re, secrets, subprocess, sys, tempfile, time

VERSION='6.0.8'
BASE=pathlib.Path('/var/lib/iptm-qos-engine')
LOCK=BASE/'lock';STAGE=BASE/'stage.json';STATE=BASE/'active.json'
UNIT=pathlib.Path('/etc/systemd/system/iptm-qos-watchdog.service')
SCRIPT=f'/usr/local/lib/iptables-manager/web/releases/{VERSION}/extensions/qos_engine.py'
POLICY_ACTIVE=pathlib.Path('/var/lib/iptm-qos-policy/active.json')
CALIB=BASE/'calibration.json'
UNSHAPED=BASE/'unshaped-calibration.json'
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
    try:r=capture(args,timeout=timeout)
    except (OSError,subprocess.TimeoutExpired) as e:raise QosError('comando non disponibile: '+str(e)) from e
    if check and r.returncode:raise QosError((r.stderr or r.stdout)[-350:]+' ['+args[0]+']')
    return r

def jcmd(args):
    try:v=json.loads(run(args).stdout)
    except json.JSONDecodeError as e:raise QosError('JSON di tc/ip non valido') from e
    if not isinstance(v,list) or not all(isinstance(row,dict) for row in v):
        raise QosError('risposta tc/ip non valida: attesa lista di oggetti')
    return v

def guard_root():
    if os.geteuid():raise QosError('root richiesto')
    if BASE.is_symlink():raise QosError('directory link simbolico')
    BASE.mkdir(parents=True,mode=0o700,exist_ok=True)
    s=BASE.stat()
    if s.st_uid or s.st_mode&0o077:raise QosError('directory non root:0700')

def atom(path,obj):
    from command_transport import durable_json
    durable_json(path,obj)


def read(path):
    from command_transport import read_private_json
    try:return read_private_json(path,limit=2097152)
    except (OSError,ValueError,UnicodeError) as exc:raise QosError('Documento di stato non protetto o non valido: '+str(exc)) from exc


def identity(iface):
    links=jcmd(['ip','-j','link','show','dev',iface])
    if len(links)!=1 or not isinstance(links[0],dict) or links[0].get('ifname')!=iface:raise QosError('interfaccia non verificabile')
    return {'ifindex':links[0].get('ifindex'),'mac':links[0].get('address')}

def inspect(iface):
    if not isinstance(iface,str) or not NIC.fullmatch(iface) or iface=='lo':raise QosError('interfaccia non valida')
    ident=identity(iface)
    qdiscs=jcmd(['tc','-j','qdisc','show','dev',iface])
    roots=[q for q in qdiscs if q.get('root') is True or q.get('parent')=='root']
    ing=[q for q in qdiscs if q.get('kind') in ('ingress','clsact')]
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
    if (read(STATE) or {}).get('state') in ('pending','applying','rollback-failed','rolling-back','confirmed'):
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
    if previous and previous.get('version') not in (None,VERSION) and previous.get('state') in ('applying','pending','confirmed','rollback-failed','rolling-back'):
        raise QosError('Watchdog della release precedente con QoS attivo: completare la migrazione dalla console prima di sostituirlo')
    if UNIT.is_symlink():raise QosError('systemd unit simbolica')
    if UNIT.exists() and 'Description=IPTM QoS independent rollback watchdog' not in UNIT.read_text():
        raise QosError('unità esistente non riconosciuta')
    if not pathlib.Path(SCRIPT).is_file():raise QosError('script release non installato: '+SCRIPT)
    unit=f'''[Unit]\nDescription=IPTM QoS independent rollback watchdog\nAfter=network.target\n[Service]\nType=simple\nExecStart=/usr/bin/python3 -B {SCRIPT} watchdog\nRestart=always\nRestartSec=2\nNoNewPrivileges=true\n[Install]\nWantedBy=multi-user.target\n'''
    durable_replace(UNIT, unit.encode(), mode=0o644)
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

def validate_confirmed_state(state, iface=None):
    """Do not dereference untrusted persisted JSON before validating ownership.

    Damaged/legacy state must fail closed without touching tc or systemd.
    """
    if not isinstance(state,dict) or state.get('state')!='confirmed' or state.get('version')!=VERSION:
        raise QosError('Profilo CAKE confermato non valido o di altra release')
    for name in ('interface','ifb'):
        if not isinstance(state.get(name),str) or not NIC.fullmatch(state[name]):
            raise QosError('Interfaccia CAKE salvata non valida: '+name)
    if iface is not None and state['interface']!=iface:
        raise QosError('WAN scelta differente dal profilo attivo')
    for name in ('up_mbit','down_mbit','ifindex','ifb_ifindex'):
        val=state.get(name)
        if type(val) is not int or not 1 <= val <= (10000 if name.endswith('_mbit') else 2**31-1):
            raise QosError('Parametro CAKE salvato mancante o non valido: '+name)
    if not isinstance(state.get('mac'),str) or not re.fullmatch(r'[A-Fa-f0-9:.-]{11,32}',state['mac']):
        raise QosError('Identità fisica WAN incompleta')
    if type(state.get('ingress_policy_count')) is not int or not 0<=state['ingress_policy_count']<=40:
        raise QosError('Inventario filtri ingress incompleto')
    if state.get('ingress_added') is not True:
        raise QosError('Proprietà ingress non dimostrata')
    return state


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
    if index is not None and state.get('ifb_ifindex') and index!=state['ifb_ifindex']:
        raise QosError('IFB sostituita, rimozione automatica bloccata')
    roots=qroots(iface)
    if roots and roots[0].get('kind')=='cake' and roots[0].get('handle')!='5ca1:':
        raise QosError('root WAN acquisita da altro software')
    ifbr=qroots(ifb) if index is not None else []
    if ifbr:
        if len(ifbr)!=1:raise QosError('root IFB ambigua')
        q=ifbr[0]
        if q.get('kind')=='cake':
            if q.get('handle')!='5ca2:':raise QosError('root IFB acquisita da altro software')
        elif q.get('kind') not in DEFAULT or q.get('handle') not in ('0:',None) or state.get('rollback_from',state.get('state'))!='applying':
            raise QosError('root IFB esterna: rimozione vietata')

def rollback_topology(state):
    """Idempotent compensation: verify current ownership before each deletion.

    A missing previously-owned object is already removed, not a conflict.
    Persist progress so an interrupted rollback can resume without deleting
    an independently installed ingress or a replacement interface.
    """
    iface,ifb=state['interface'],state['ifb']
    owned(state)
    ingress=[q for q in jcmd(['tc','-j','qdisc','show','dev',iface])
             if q.get('kind') in ('ingress','clsact')]
    if state.get('ingress_added'):
        if ingress:
            if len(ingress)!=1 or ingress[0].get('kind')!='ingress' or ingress[0].get('handle')!='ffff:':
                raise QosError('ingress sostituito: rimozione vietata')
            expected=int(state.get('ingress_policy_count',0))
            if not ingress_filters_verified(iface,ifb,expected,partial=state.get('rollback_from')=='applying'):
                raise QosError('ingress modificato da altro servizio')
            run(['tc','qdisc','del','dev',iface,'ingress'])
            if any(q.get('kind') in ('ingress','clsact') for q in jcmd(['tc','-j','qdisc','show','dev',iface])):
                raise QosError('ingress ancora presente: IFB conservata')
        state['ingress_added']=False;atom(STATE,state)
    elif ingress:
        # Unknown ingress could refer to the IFB. Do not destroy its target.
        raise QosError('ingress non attribuibile a IPTM: rollback sospeso')
    owned(state)
    roots=qroots(iface)
    if any(q.get('handle')=='5ca1:' for q in roots):
        if len(roots)!=1 or roots[0].get('kind')!='cake':
            raise QosError('handle WAN ora assegnato a qdisc esterna')
        run(['tc','qdisc','del','dev',iface,'root'])
        if any(q.get('handle')=='5ca1:' for q in qroots(iface)):
            raise QosError('root CAKE ancora presente')
    owned(state)
    links=run(['ip','link','show','dev',ifb],check=False)
    if links.returncode==0:
        if not state.get('ifb_ifindex'):raise QosError('IFB non attribuibile a IPTM')
        run(['ip','link','del','dev',ifb])
        if run(['ip','link','show','dev',ifb],check=False).returncode==0:
            raise QosError('IFB ancora presente dopo rimozione')
    state['ifb_ifindex']=None;atom(STATE,state)


def restore(state):
    if state.get('version')!=VERSION:raise QosError('stato di altra release')
    if (read(UNSHAPED) or {}).get('state')=='pending':
        raise QosError('Prova senza shaping in corso: attendere ripristino dei limiti CAKE')
    if state.get('state')=='rolled-back':return {'ok':True,'state':'rolled-back','interface':state['interface']}
    if state.get('state') not in ('applying','pending','confirmed','rollback-failed','rolling-back'):
        raise QosError('stato non ripristinabile')
    if state.get('state')=='confirmed':validate_confirmed_state(state)
    state.setdefault('rollback_from',state['state']);state['state']='rolling-back'
    state['rollback_attempt_at']=time.time();atom(STATE,state)
    try:rollback_topology(state)
    except (QosError,OSError,ValueError,KeyError,TypeError,IndexError) as exc:
        state['state']='rollback-failed';state['rollback_error']=str(exc)[:240]
        atom(STATE,state);raise
    state['state']='rolled-back';state['restored_at']=time.time();state.pop('rollback_error',None);atom(STATE,state)
    try:
        adaptive=read(ADAPT)
        if adaptive and adaptive.get('enabled'):
            adaptive['enabled']=False;atom(ADAPT,adaptive)
            if ADAPT_TIMER.is_file() and not ADAPT_TIMER.is_symlink():
                run(['systemctl','disable','--now',ADAPT_TIMER.name],check=False)
    except (QosError,OSError):pass
    return {'ok':True,'state':'rolled-back','interface':state['interface']}

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

def topology_commands(obj, rules):
    """Pure, ordered command plan shared by activation and boot restoration."""
    iface,ifb=obj['interface'],obj['ifb']
    if not NIC.fullmatch(iface) or not NIC.fullmatch(ifb) or iface==ifb or iface=='lo':
        raise QosError('topologia non valida')
    return [
        ('ifb-create',['ip','link','add','dev',ifb,'type','ifb']),
        ('ifb-up',['ip','link','set','dev',ifb,'up']),
        ('down',['tc','qdisc','replace','dev',ifb,'root','handle','5ca2:','cake']+cake_opts(obj['down_mbit'],obj)),
        ('up',['tc','qdisc','replace','dev',iface,'root','handle','5ca1:','cake']+cake_opts(obj['up_mbit'],obj)),
        ('ingress',['tc','qdisc','add','dev',iface,'handle','ffff:','ingress']),
        *[('filter',ingress_flower_args(iface,ifb,rule,n)) for n,rule in enumerate(rules)],
        ('redirect',['tc','filter','add','dev',iface,'parent','ffff:','protocol','all','pref','500',
                    'u32','match','u32','0','0','action','mirred','egress','redirect','dev',ifb]),
    ]


def verify_cake_roots(obj):
    for dev,handle in ((obj['interface'],'5ca1:'),(obj['ifb'],'5ca2:')):
        roots=qroots(dev)
        if len(roots)!=1 or roots[0].get('kind')!='cake' or roots[0].get('handle')!=handle:
            raise QosError('root CAKE non verificabile: '+dev)
    return True


def install_topology(obj):
    iface,ifb=obj['interface'],obj['ifb']
    rules,policy_status=ingress_policy(iface)
    commands=topology_commands(obj,rules) # validate all filters before mutation
    obj['ingress_policy_status']=policy_status
    obj['ingress_policy_count']=len(rules)
    atom(STATE,obj)
    for step,argv in commands:
        # Bind all steps to the same interface identity. Revalidation does not
        # replace kernel ownership checks below and never mutates the network.
        current=identity(iface)
        if current['ifindex']!=obj.get('ifindex') or current['mac']!=obj.get('mac'):
            raise QosError('WAN sostituita durante installazione')
        # Verify the actual identity and ownership again before each destructive claim.
        if step in ('ifb-up','down','filter','redirect'):
            if identity(ifb)['ifindex']!=obj.get('ifb_ifindex'):
                raise QosError('IFB sostituita durante installazione')
        if step=='down':
            roots=qroots(ifb)
            if len(roots)!=1 or roots[0].get('kind') not in DEFAULT or roots[0].get('handle') not in ('0:',None):
                raise QosError('root IFB non libera')
        # Recheck WAN immediately before claiming root/ingress.
        if step=='up':
            cur=inspect(iface)
            if cur['ifindex']!=obj['ifindex'] or cur['mac']!=obj['mac']:
                raise QosError('WAN sostituita durante installazione')
            if cur['original_root']!=obj['original_root']:
                raise QosError('root WAN cambiata dopo anteprima')
            roots=qroots(iface)
            if len(roots)!=1 or roots[0].get('handle') not in ('0:',None):
                raise QosError('root WAN non predefinita')
        if step=='ingress':
            roots=qroots(iface)
            if len(roots)!=1 or roots[0].get('handle')!='5ca1:' or roots[0].get('kind')!='cake':
                raise QosError('root WAN non posseduta')
            if any(q.get('kind') in ('ingress','clsact') for q in jcmd(['tc','-j','qdisc','show','dev',iface])):
                raise QosError('ingress acquisito da altro servizio')
        run(argv)
        if step=='ifb-create':obj['ifb_ifindex']=identity(ifb)['ifindex'];atom(STATE,obj)
        if step=='ingress':obj['ingress_added']=True;atom(STATE,obj)
    verify_cake_roots(obj)
    if not ingress_filters_verified(iface,ifb,len(rules)):
        raise QosError('IFB redirect o filtri applicativi non verificati')
    return True

def activate(digest):
    guard_ready()
    obj=read(STAGE)
    if not obj or not HEX.fullmatch(digest) or obj.get('digest')!=digest or time.time()-obj.get('created',0)>600:
        raise QosError('piano non valido o scaduto')
    if (read(STATE) or {}).get('state') in ('applying','pending','confirmed','rollback-failed','rolling-back'):
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
    verify_cake_roots(obj)
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
        from command_transport import domain_lock
        with domain_lock(LOCK):
            obj=read(STATE)
            unshaped=read(UNSHAPED)
            if unshaped and unshaped.get('state')=='pending':
                expired=(time.time()>=float(unshaped.get('deadline',0)) or
                         unshaped.get('boot_id')!=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip())
                if expired:
                    try:
                        restore_cake_after_calibration(unshaped)
                        calibration=read(CALIB)
                        if calibration and calibration.get('state')=='running' and calibration.get('job_id')==unshaped.get('job_id'):
                            atom(CALIB,dict(calibration,state='aborted',error='watchdog: ripristino dei limiti CAKE per timeout/riavvio'))
                    except Exception as exc:
                        print('IPTM CAKE unlimited recovery: '+str(exc),file=sys.stderr,flush=True)
            if obj and obj.get('state')=='confirmed':
                resume_confirmed_after_boot(obj,pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip())
            if obj and obj.get('state') in ('rolling-back','rollback-failed') and time.time()-obj.get('rollback_attempt_at',0)>=30:
                try:restore(obj)
                except Exception as e:print('IPTM watchdog ripristino sospeso: '+str(e),file=sys.stderr,flush=True)
            if obj and obj.get('state') in ('applying','pending'):
                expired=(time.time()>=obj.get('deadline',0) or
                         obj.get('boot_id')!=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip())
                if obj['state']=='applying' and time.time()-obj.get('applied_at',0)>15:
                    pid=obj.get('owner_pid')
                    if type(pid) is not int or pid<=1:expired=True
                    else:
                        try:os.kill(pid,0)
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

def interface_idle(iface, *, duration=0.5, threshold_bps=131072):
    """Protect legitimate traffic from speedtest saturation (read-only NIC counters).

    Return False on unreadable/invalid statistics: never assume a NIC is idle
    if counters are unavailable. Traffic may begin later; recheck in worker.
    """
    if not isinstance(iface,str) or not NIC.fullmatch(iface):return False
    directory=pathlib.Path('/sys/class/net')/iface/'statistics'
    def counter():
        try:
            return tuple(int((directory/name).read_text()) for name in ('rx_bytes','tx_bytes'))
        except (OSError,ValueError):return None
    first=counter()
    if first is None:return False
    time.sleep(duration)
    last=counter()
    if last is None or any(n<a for n,a in zip(last,first)):return False
    return sum(b-a for a,b in zip(first,last))/duration < threshold_bps

def root_cake_text(dev, handle):
    roots=qroots(dev)
    if len(roots)!=1 or roots[0].get('kind')!='cake' or roots[0].get('handle')!=handle:
        raise QosError('proprietà CAKE persa su '+dev)
    return run(['tc','-d','qdisc','show','dev',dev]).stdout


def check_cake_bandwidth(dev,handle,rate=None):
    """Verify CAKE rate from tc detail, never infer it from configured settings."""
    output=root_cake_text(dev,handle)
    if rate is None:
        if not re.search(r'\bbandwidth\s+unlimited\b',output,re.I):
            raise QosError('CAKE unlimited non verificabile su '+dev)
    else:
        rx=r'\bbandwidth\s+'+re.escape(str(rate))+r'(?:Mbit|Mbit/s|Mbits)\b'
        if not re.search(rx,output,re.I):
            raise QosError('limite CAKE originale non verificabile su '+dev)
    return True


def set_unlimited(state):
    owned(state)
    if not verified_ingress_for_state(state):raise QosError('filtro IFB non verificato')
    for dev,handle in ((state['interface'],'5ca1:'),(state['ifb'],'5ca2:')):
        opts=cake_opts(1,state)
        opts[0:2]=['bandwidth','unlimited']
        run(['tc','qdisc','change','dev',dev,'root','handle',handle,'cake']+opts)
        check_cake_bandwidth(dev,handle)


def restore_cake_after_calibration(journal):
    """Idempotent rollback of the two bandwidth limits, including crashed workers.

    The independent QoS watchdog calls this on expiry or reboot. It never
    deletes a qdisc or creates an interface, and refuses foreign ownership.
    """
    if journal.get('version')!=VERSION:raise QosError('Journal di altra release: recupero non consentito')
    if journal.get('state')!='pending':return {'ok':True,'already_restored':True}
    state=read(STATE)
    validate_confirmed_state(state)
    if state.get('interface')!=journal.get('interface') or state.get('ifb')!=journal.get('ifb'):
        raise QosError('topologia differente: nessun cambio CAKE')
    for key in ('ifindex','ifb_ifindex','mac'):
        if key in journal and journal[key]!=state.get(key):
            raise QosError('identità fisica non corrispondente: '+key)
    if (journal.get('original_up') is not None and
        (type(journal['original_up']) is not int or journal['original_up']!=state['up_mbit'])):
        raise QosError('velocità upload modificata durante la calibrazione')
    if (journal.get('original_down') is not None and
        (type(journal['original_down']) is not int or journal['original_down']!=state['down_mbit'])):
        raise QosError('velocità download modificata durante la calibrazione')
    owned(state)
    errors=[]
    for dev,handle,rate in ((state['interface'],'5ca1:',state['up_mbit']),
                            (state['ifb'],'5ca2:',state['down_mbit'])):
        try:
            root_cake_text(dev,handle)
            run(['tc','qdisc','change','dev',dev,'root','handle',handle,'cake']+cake_opts(rate,state))
            check_cake_bandwidth(dev,handle,rate)
        except QosError as exc:errors.append(dev+': '+str(exc))
    if errors:
        journal['recovery_error']='; '.join(errors)[:320]
        atom(UNSHAPED,journal)
        raise QosError('Ripristino rate CAKE incompleto; watchdog manterrà il journal')
    journal.update(state='restored',restored_at=time.time())
    atom(UNSHAPED,journal)
    return {'ok':True,'restored':True}


def start_unshaped_calibration(iface,active,measurement):
    """Temporarily disables *bandwidth shaping* while retaining owned CAKE qdiscs.

    A standalone systemd watchdog restores both saved rates even if the
    worker or web connection fails. Never delete ingress/IFB to measure speed.
    """
    guard_ready()
    validate_confirmed_state(active,iface)
    owned(active)
    verified_ingress_for_state(active)
    if pathlib.Path('/var/lib/iptables-manager/pending.json').exists():
        raise QosError('Firewall in transazione; calibrazione proibita')
    if not interface_idle(iface):raise QosError('WAN occupata: calibrazione rinviata')
    old=read(UNSHAPED)
    if old and old.get('state')=='pending':raise QosError('un’altra prova senza shaping è ancora pendente')
    journal={'state':'pending','job_id':measurement['job_id'],'interface':iface,
             'ifb':active['ifb'],'original_up':active['up_mbit'],
             'original_down':active['down_mbit'],'ifindex':active['ifindex'],
             'ifb_ifindex':active['ifb_ifindex'],'mac':active['mac'],
             'boot_id':active.get('boot_id'),
             'started':time.time(),'deadline':time.time()+780,'version':VERSION}
    atom(UNSHAPED,journal)  # independent safety net BEFORE the first tc change
    atom(CALIB,measurement)
    try:
        set_unlimited(active)
        # Systemd supervised worker has its own timeout; restoration is
        # independent and never depends on the browser remaining connected.
        run(['systemd-run','--unit='+CALIB_UNIT,'--collect',
             '--property=Type=exec','--property=RuntimeMaxSec=700',
             '/usr/bin/python3','-B',SCRIPT,'calibrate-worker'],timeout=25)
    except Exception:
        try:restore_cake_after_calibration(journal)
        except QosError:pass  # watchdog retries; keep the journal
        atom(CALIB,dict(measurement,state='failed',error='Avvio prova senza shaping fallito; verifica recupero CAKE'))
        raise
    return {'ok':True,'state':'running','mode':'cake-bandwidth-unlimited',
            'note':'Limiti CAKE sospesi temporaneamente, watchdog indipendente armato'}


def calibration_start(iface):
    active=read(STATE)
    if active and active.get('state') in ('pending','applying','rollback-failed'):
        raise QosError('Prova CAKE/rollback in corso: misura vietata')
    running=read(CALIB)
    if running and running.get('state')=='running' and time.time()-running.get('started',0)<1000:
        raise QosError('calibrazione già in esecuzione')
    if not isinstance(iface,str) or not NIC.fullmatch(iface) or iface=='lo':
        raise QosError('WAN non valida')
    if run(['systemctl','is-active','iptm-sqm-calibrate.timer'],check=False).stdout.strip()=='active':
        raise QosError('Timer SQM concorrente da disattivare prima della calibrazione')
    if active and active.get('state')=='confirmed':
        validate_confirmed_state(active,iface)
        # Bandwidth unlimited is explicitly verified on both CAKE roots. The
        # qdiscs remain present to preserve connectivity; *shaping is off*.
        measurement={'state':'running','mode':'cake-bandwidth-unlimited',
                     'job_id':secrets.token_hex(12),'started':time.time(),
                     'attempts':0,'interface':iface,'ifindex':active['ifindex'],
                     'can_propose':True,
                     'note':'Banda misurata soltanto mentre i due CAKE sono unlimited'}
        return start_unshaped_calibration(iface,active,measurement)
    audit=topology_report(iface)
    if not audit['free']:raise QosError('WAN di proprietà di altro QoS: nessuna modifica')
    if not interface_idle(iface):raise QosError('WAN occupata: calibrazione rinviata')
    measurement={'state':'running','mode':'unshaped','job_id':secrets.token_hex(12),
                 'started':time.time(),'attempts':0,'interface':iface,
                 'ifindex':audit['ifindex'],'root_kind':audit['root_kind'],
                 'can_propose':True,'root_handle':audit['root_handle'],
                 'note':'Calibrazione con shaping non attivo; nessuna modifica a tc'}
    atom(CALIB,measurement)
    try:
        run(['systemd-run','--unit='+CALIB_UNIT,'--collect','--property=Type=exec',
             '--property=RuntimeMaxSec=700',
             '/usr/bin/python3','-B',SCRIPT,'calibrate-worker'],timeout=25)
    except Exception:
        atom(CALIB,dict(measurement,state='failed',error='avvio servizio calibrazione non riuscito'))
        raise
    return {'ok':True,'state':'running','mode':'unshaped','note':measurement['note']}

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
        result=capture([str(executable),'--accept-license','--accept-gdpr',
                               '--progress=no','--format=json'],
                              timeout=200,env=environment,stdout_limit=256000,stderr_limit=262144)
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


def _direction_proposal(samples, field, previous):
    """Pure decision: never lower approved rates from automatic measurements."""
    import math, statistics
    values=[]
    for sample in samples:
        if not isinstance(sample,dict):raise QosError('campione non valido')
        if field not in sample:continue
        if isinstance(sample[field],bool):raise QosError('misura booleana non valida')
        try:value=float(sample[field])
        except (TypeError,ValueError,OverflowError):raise QosError('misura non valida')
        if not math.isfinite(value) or value<=0:raise QosError('misura nulla o non valida')
        if 1<=value<=10000:values.append(value)
    old=previous if type(previous) is int and 1<=previous<=10000 else None
    stable=len(values)>=2 and max(values)/min(values)<=1.20
    quality={'count':len(values),'stable':stable};review=None
    if not stable:return old,('kept-insufficient-data' if old is not None else 'not-approved'),quality,review
    candidate=max(1,int(statistics.median(values)*0.92))
    if old is None:return candidate,'approved-first-valid',quality,review
    if candidate>old:return min(candidate,old+max(1,int(old*.10)),10000),'approved-improvement',quality,review
    if candidate==old:return old,'kept-unchanged',quality,review
    if candidate>=int(old*.75):return old,'review-decrease',quality,candidate
    return old,'kept-large-decrease-requires-manual-check',quality,review


def calibration_proposal(samples,old):
    if not isinstance(samples,(list,tuple)) or not samples:raise QosError('nessuna misura disponibile')
    if old is not None and not isinstance(old,dict):raise QosError('stato precedente non valido')
    previous=(old or {}).get('proposal') or {}
    if not isinstance(previous,dict):raise QosError('proposta precedente non valida')
    proposal={};decisions={};quality={};review={}
    for direction,field in (('down','download_mbit'),('up','upload_mbit')):
        key=direction+'_mbit';value,decision,metrics,suggestion=_direction_proposal(samples,field,previous.get(key))
        if value is not None:proposal[key]=value
        if suggestion is not None:review[key]=suggestion
        decisions[direction]=decision;quality[direction]=metrics
    approved=[key for key,value in decisions.items() if value.startswith('approved')] if len(proposal)==2 else []
    if len(proposal)!=2:
        for key in decisions:
            if decisions[key].startswith('approved'):decisions[key]='candidate-pending-other-direction'
    return {'proposal':proposal if len(proposal)==2 else None,'direction_decisions':decisions,'quality':quality,'review_candidates':review,'auto_approved':approved,'kept_previous':not bool(approved),'reason':('Limiti migliori approvati per '+', '.join(approved) if approved else 'Nessun miglioramento attendibile; limiti conservati')}


def calibration_worker():
    """Measurements run lock-free, but commit is serialized and job-id checked."""
    doc=read(CALIB)
    if not doc or doc.get('state')!='running' or not TOKEN.fullmatch(str(doc.get('job_id',''))):
        raise QosError('job calibrazione non verificabile')
    if not isinstance(doc.get('interface'),str) or not NIC.fullmatch(doc['interface']):
        raise QosError('interfaccia calibrazione mancante')
    samples=[];errors=[]
    try:
        for attempt in range(2):
            # Re-check immediately before each high-bandwidth measurement.
            # The existing sample is retained, but one sample cannot authorize
            # a new bidirectional profile.
            if not interface_idle(doc['interface']):
                errors.append('Rete occupata: misurazione sospesa per tutelare il traffico')
                break
            current=read(STATE)
            if doc.get('mode')=='cake-bandwidth-unlimited':
                journal=read(UNSHAPED)
                if (not journal or journal.get('state')!='pending' or
                    journal.get('job_id')!=doc['job_id'] or
                    time.time()>=journal.get('deadline',0)):
                    errors.append('Protezione unshaping scaduta; misura interrotta')
                    break
                try:
                    if not current or current.get('state')!='confirmed':
                        raise QosError('profilo CAKE non confermato')
                    owned(current)
                    check_cake_bandwidth(current['interface'],'5ca1:')
                    check_cake_bandwidth(current['ifb'],'5ca2:')
                except QosError:
                    errors.append('Banda CAKE unlimited non verificata; misura interrotta')
                    break
            elif current and current.get('state') in ('confirmed','pending','applying','rollback-failed'):
                errors.append('Shaping attivo durante la misura: misurazione interrotta')
                break
            try:samples.append(speedtest_measurement())
            except QosError as exc:errors.append(str(exc))
        from command_transport import domain_lock
        with domain_lock(LOCK):
            latest=read(CALIB)
            if not latest or latest.get('job_id')!=doc['job_id'] or latest.get('state')!='running':
                raise QosError('job sostituito: risultati ignorati')
            old=read(CALIB_LOG)
            if old and (old.get('interface')!=doc['interface'] or old.get('ifindex') not in (None,doc['ifindex'])):old=None
            active=read(STATE)
            reason=None
            if doc.get('mode')=='cake-bandwidth-unlimited':
                journal=read(UNSHAPED)
                if not journal or journal.get('job_id')!=doc['job_id']:
                    raise QosError('journal dei limiti CAKE mancante')
                if journal.get('state')!='pending' or time.time()>=float(journal.get('deadline',0)):
                    # The watchdog may have restored limits before a late
                    # speedtest finished. Do not accept potentially shaped data.
                    reason='Watchdog già intervenuto: misurazione non più non-shaped'
                else:
                    restore_cake_after_calibration(journal)
                # The underlying ifindex and confirmed ownership must still match.
                if not active or active.get('state')!='confirmed' or active.get('ifindex')!=doc['ifindex']:
                    reason='Topologia cambiata durante la misura'
            result=calibration_proposal(samples,old)
            if not doc.get('can_propose'):
                reason='QoS già attivo: Speedtest sotto shaping non prova maggiore capacità della linea'
            elif doc.get('mode')=='cake-bandwidth-unlimited':
                # Confirmed CAKE has already been restored; measurements were
                # captured only with unlimited bandwidth on both directions.
                if not samples or len(samples)<2:
                    reason='Campioni insufficienti nella finestra senza shaping'
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
            latest.update(state='completed',finished=time.time(),attempts=len(samples),
                          samples=samples,errors=errors,**result)
            if result.get('proposal') and result.get('auto_approved'):
                atom(CALIB_LOG,{'proposal':result['proposal'],'interface':doc['interface'],
                                'ifindex':doc['ifindex'],'measured_at':time.time(),
                                'source':'ookla','auto_approved':result['auto_approved']})
            atom(CALIB,latest)
        return {'ok':True,'state':'completed','auto_approved':result.get('auto_approved',[])}
    except Exception as exc:
        from command_transport import domain_lock
        with domain_lock(LOCK):
            latest=read(CALIB)
            if doc.get('mode')=='cake-bandwidth-unlimited':
                journal=read(UNSHAPED)
                if journal and journal.get('job_id')==doc['job_id'] and journal.get('state')=='pending':
                    try:restore_cake_after_calibration(journal)
                    except QosError:pass  # independent watchdog will retry
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
        durable_replace(path, contents.encode(), mode=0o644)
    run(['systemctl','daemon-reload'])
    run(['systemctl','enable','--now',AUTO_TIMER.name])
    if run(['systemctl','is-active',AUTO_TIMER.name],check=False).stdout.strip()!='active':
        raise QosError('Timer automatico non attivo')

def auto_enable():
    if run(['systemctl','is-active','iptm-sqm-calibrate.timer'],check=False).stdout.strip()=='active':
        raise QosError('disabilitare prima il timer SQM storico')
    auto_units_install()
    atom(AUTO_STATE,{'enabled':True,'activated_at':time.time(),'version':VERSION})
    return {'ok':True,'enabled':True,'interval':'1h','mode':'rtt-shaped-manual-unshaped-speedtest'}

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
    """Hourly passive RTT monitor; never start an unattended speedtest."""
    if (read(UNSHAPED) or {}).get('state')=='pending':
        return {'ok':True,'started':False,'reason':'calibrazione senza shaping in corso'}
    if not (read(AUTO_STATE) or {}).get('enabled'):
        return {'ok':True,'started':False,'reason':'disabilitato'}
    if run(['systemctl','is-active','iptm-sqm-calibrate.timer'],check=False).stdout.strip()=='active':
        return {'ok':True,'started':False,'reason':'legacy-timer-active'}
    active=read(STATE)
    if active and active.get('state') in ('confirmed','pending','applying','rollback-failed'):
        if active.get('state')!='confirmed':
            return {'ok':True,'started':False,'reason':'prova CAKE in corso; nessun test pesante'}
        owned(active)
        try: rtt=latency_measurement(active['interface'])
        except QosError as exc:
            result={'ok':True,'started':False,'mode':'rtt-only','reason':str(exc),'changed':False}
        else:
            result={'ok':True,'started':False,'mode':'rtt-only','rtt_ms':round(rtt,2),
                    'reason':'RTT verificato; i limiti CAKE non cambiano','changed':False}
        atom(AUTO_STATE,dict(read(AUTO_STATE) or {},last_check=time.time(),last_result=result))
        return result
    # Do not saturate a shared link on an automatic timer. Only an operator
    # can initiate two high-bandwidth Ookla measurements.
    result={'ok':True,'started':False,'changed':False,'mode':'passive-only',
            'reason':'Non viene eseguito alcuno speedtest automatico senza shaping'}
    atom(AUTO_STATE,dict(read(AUTO_STATE) or {},last_check=time.time(),last_result=result))
    return result

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

    Three high-RTT samples to reduce; two quiet samples to recover. The
    default runtime loop remains recovery-only; RTT is not proof of capacity.
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
        durable_replace(path, contents.encode(), mode=0o644)
    run(['systemctl','daemon-reload'])
    run(['systemctl','enable','--now',ADAPT_TIMER.name])
    if run(['systemctl','is-active',ADAPT_TIMER.name],check=False).stdout.strip()!='active':
        raise QosError('timer RTT non attivo')

def adapt_enable():
    if (read(UNSHAPED) or {}).get('state')=='pending':
        raise QosError('Regolatore RTT bloccato durante la calibrazione senza shaping')
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
    if (read(UNSHAPED) or {}).get('state')=='pending':
        raise QosError('Regolazione vietata durante la misura senza shaping')
    if direction not in ('up','down') or type(rate) is not int or rate<1:
        raise QosError('regolazione direzione/rate non valida')
    owned(state)
    dev=state['interface'] if direction=='up' else state['ifb']
    handle='5ca1:' if direction=='up' else '5ca2:'
    roots=qroots(dev)
    if len(roots)!=1 or roots[0].get('kind')!='cake' or roots[0].get('handle')!=handle:
        raise QosError('CAKE non di proprietà: modifica vietata')
    run(['tc','qdisc','change','dev',dev,'root','handle',handle,'cake']+cake_opts(rate,state))


def recovery_rtt_reference(samples, rtt):
    """Last 30 valid observations, robust lower quartile, no historical floor."""
    valid=[float(x) for x in (samples if isinstance(samples,list) else []) if type(x) in (int,float) and 0<x<1000]
    if type(rtt) not in (int,float) or not 0<rtt<1000: raise QosError('RTT non valido')
    valid=(valid+[float(rtt)])[-30:]
    ordered=sorted(valid)
    return valid,ordered[(len(ordered)-1)//4]

def adapt_tick():
    """Test one independent direction at a time; rollback on bad RTT or idle test.

    No speculative increase above the last operator-confirmed rates. A shaped
    speedtest is never used as evidence that the physical line is faster.
    """
    cfg=read(ADAPT)
    if not cfg or not cfg.get('enabled'):return {'ok':True,'changed':False,'reason':'disabilitato'}
    if (read(UNSHAPED) or {}).get('state')=='pending':
        return {'ok':True,'changed':False,'reason':'Calibrazione senza shaping in corso'}
    state=read(STATE)
    if not state or state.get('state')!='confirmed' or state['interface']!=cfg['interface'] or state['ifb']!=cfg['ifb']:
        return {'ok':True,'changed':False,'reason':'profilo CAKE non confermato'}
    owned(state)
    wan=qroots(state['interface']);ifb_roots=qroots(state['ifb'])
    if (len(wan)!=1 or len(ifb_roots)!=1 or
        wan[0].get('kind')!='cake' or wan[0].get('handle')!='5ca1:' or
        ifb_roots[0].get('kind')!='cake' or ifb_roots[0].get('handle')!='5ca2:'):
        raise QosError('qdisc CAKE non verificabili')
    boot_id=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    if cfg['boot_id']!=boot_id:
        cfg.update(boot_id=boot_id,up=state['up_mbit'],down=state['down_mbit'],
                   baseline=None,high=0,low=0,samples=0,trial=None,counters=None,rtt_window=[])
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
    cfg['rtt_window'],cfg['baseline']=recovery_rtt_reference(cfg.get('rtt_window'),rtt)
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
    if (read(UNSHAPED) or {}).get('state')=='pending':
        raise QosError('Disattivazione RTT vietata durante la misura senza shaping')
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
    from command_transport import domain_lock
    with domain_lock(LOCK):
        if args==['status']:
            result=status();cfg=read(ADAPT)
            result['unshaped_calibration']=(read(UNSHAPED) or {}).get('state')=='pending'
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
        if args==['traffic-inspect']:
            import importlib.util
            path=pathlib.Path(__file__).with_name('traffic_observer.py')
            if path.is_symlink() or not path.is_file():raise QosError('Osservatore non installato')
            spec=importlib.util.spec_from_file_location('iptm_traffic_observer',path)
            observer=importlib.util.module_from_spec(spec)
            spec.loader.exec_module(observer)
            return observer.status()
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
            if (read(UNSHAPED) or {}).get('state')=='pending':
                raise QosError('Disabilitazione proibita durante calibrazione senza shaping')
            obj=read(STATE)
            if not obj or obj.get('state')!='confirmed':raise QosError('nessun profilo confermato')
            return restore(obj)
        raise QosError('comando sconosciuto')
def coordinated_main(args):
    from command_transport import driver_admission
    with driver_admission('qos_engine',args):
        return main(args)


if __name__=='__main__':
    try:print(json.dumps(coordinated_main(sys.argv[1:]),ensure_ascii=False))
    except (QosError,OSError,ValueError,KeyError,TypeError,IndexError) as exc:
        print(json.dumps({'ok':False,'error':str(exc)},ensure_ascii=False));sys.exit(1)
