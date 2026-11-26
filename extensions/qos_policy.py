#!/usr/bin/env python3
"""IPTM-owned IPv4 DSCP profile for CAKE diffserv in both directions.

Egress is applied via mangle/POSTROUTING. The confirmed profile is independently
consumed by qos_engine to classify ingress with tc before IFB. Third-party
chains, access filters and NAT are not modified. Both directions require
explicit SHA256 staging and user approval; only a confirmed profile is used.
"""
from __future__ import annotations

from command_transport import durable_replace

from command_transport import capture
import fcntl, hashlib, ipaddress, json, os, pathlib, re, secrets, subprocess, sys, tempfile, time
BASE=pathlib.Path('/var/lib/iptm-qos-policy')
PLAN=BASE/'plan.json'; ACTIVE=BASE/'active.json'
IFACE=re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$')
TOKEN=re.compile(r'^[a-f0-9]{64}$')
CHAIN=re.compile(r'^IPTM_QP_[A-F0-9]{8}$')
VERSION='6.0.9'
UNIT=pathlib.Path('/etc/systemd/system/iptm-qos-policy-restore.service')
SCRIPT=f'/usr/local/lib/iptables-manager/web/releases/{VERSION}/extensions/qos_policy.py'
DSCP={'realtime':46,'interactive':34,'normal':0,'background':8}
class PolicyError(Exception):pass

def cmd(*argv,check=True):
    try:r=capture(argv,timeout=15)
    except (OSError,subprocess.TimeoutExpired) as exc:raise PolicyError('iptables non disponibile: '+str(exc)) from exc
    if check and r.returncode:raise PolicyError((r.stderr or r.stdout)[-250:])
    return r

def secure():
    if os.geteuid():raise PolicyError('root richiesto')
    if BASE.is_symlink():raise PolicyError('directory simbolica')
    BASE.mkdir(mode=0o700,parents=True,exist_ok=True)
    s=BASE.stat()
    if s.st_uid or s.st_mode&0o077:raise PolicyError('directory non root:0700')

def load(path):
    from command_transport import read_private_json
    try:return read_private_json(path,limit=2097152)
    except (OSError,ValueError,UnicodeError) as exc:raise PolicyError('Documento di stato non protetto o non valido: '+str(exc)) from exc


def save(path,obj):
    from command_transport import durable_json
    durable_json(path,obj)


def validate(payload):
    if not isinstance(payload,dict) or set(payload)!={'interface','rules'}:raise PolicyError('schema non valido')
    iface=payload['interface']
    if not isinstance(iface,str) or not IFACE.fullmatch(iface) or iface=='lo':raise PolicyError('WAN non valida')
    rules=payload['rules']
    if not isinstance(rules,list) or not 1<=len(rules)<=40:raise PolicyError('1..40 regole richieste')
    result=[]
    for r in rules:
        if not isinstance(r,dict) or set(r)-{'protocol','port','source','priority','direction'} or set(r)&{'protocol','port','priority'}!={'protocol','port','priority'}:
            raise PolicyError('regola inattesa')
        proto=r['protocol'];port=r['port'];priority=r['priority'];source=r.get('source','');direction=r.get('direction','both')
        if direction not in ('both','upload','download') or proto not in ('tcp','udp') or type(port)!=int or port<1 or port>65535 or priority not in DSCP:
            raise PolicyError('protocollo/porta/priorità non validi')
        if not isinstance(source,str):raise PolicyError('CIDR non valido')
        if source:
            try:network=ipaddress.ip_network(source,strict=False)
            except ValueError as e:raise PolicyError('CIDR non valido') from e
            if network.version!=4 or network.is_multicast or network.is_unspecified or network.is_loopback:raise PolicyError('CIDR IPv4 non consentito')
            source=str(network)
        result.append({'protocol':proto,'port':port,'source':source,'priority':priority,'direction':direction})
    seen=set()
    for rule in result:
        key=(rule['protocol'],rule['port'],rule['source'])
        for direction in (('upload','download') if rule['direction']=='both' else (rule['direction'],)):
            if (key,direction) in seen:
                raise PolicyError('regole sovrapposte nella stessa direzione')
            seen.add((key,direction))
    return {'interface':iface,'rules':result}

def signature(obj):return hashlib.sha256(json.dumps(obj,sort_keys=True,separators=(',',':')).encode()).hexdigest()

def ipt(*args,check=True):return cmd('iptables','-w','5','-t','mangle',*args,check=check)

def chain_exists(chain):return ipt('-S',chain,check=False).returncode==0

def links(iface,chain):
    """Canonical exact hook; any unexpected jump to chain is treated as foreign."""
    lines=ipt('-S','POSTROUTING').stdout.splitlines()
    exact=f'-A POSTROUTING -o {iface} -j {chain}'
    matching=[x for x in lines if re.search(r'(?:^| )-j '+re.escape(chain)+r'$',x)]
    return len(matching)==1 and matching[0]==exact

def matches_owned(active):
    if not active:return False
    chain=active.get('chain');iface=active.get('interface')
    if not (isinstance(chain,str) and CHAIN.fullmatch(chain) and isinstance(iface,str) and IFACE.fullmatch(iface) and chain_exists(chain) and links(iface,chain)):
        return False
    # The chain must contain precisely the expected number of policy rules;
    # refuse to modify or delete a chain altered by another actor.
    rules=ipt('-S',chain).stdout.splitlines()
    body=[r for r in rules if r.startswith('-A '+chain+' ')]
    return (len(body)==len(upload_rules(active.get('rules',[]))) and
            hashlib.sha256('\n'.join(body).encode()).hexdigest()==active.get('rules_digest'))

def validate_active(profile):
    """Reject compromised saved profiles before any privileged boot operation."""
    if not isinstance(profile,dict) or not CHAIN.fullmatch(str(profile.get('chain',''))):
        raise PolicyError('profilo salvato privo di catena IPTM valida')
    if not isinstance(profile.get('rules_digest'),str) or not TOKEN.fullmatch(profile['rules_digest']):
        raise PolicyError('digest del profilo salvato non valido')
    if not isinstance(profile.get('sha256'),str) or not TOKEN.fullmatch(profile['sha256']):
        raise PolicyError('SHA del profilo salvato non valido')
    profile_data=validate({'interface':profile.get('interface'),'rules':profile.get('rules')})
    if not isinstance(profile.get('created'),int) or profile['created'] < 1:
        raise PolicyError('timestamp del profilo non valido')
    return profile_data

def boot_restore():
    """Fail-closed restoration after a reboot; never adopt or flush foreign rules."""
    saved=load(ACTIVE)
    if not saved:return {'ok':True,'restored':False,'reason':'nessuna policy attiva'}
    data=validate_active(saved)
    name=saved['chain'];iface=data['interface']
    if cmd('ip','link','show','dev',iface,check=False).returncode:
        raise PolicyError('WAN salvata assente: nessuna modifica')
    if matches_owned(saved):
        return {'ok':True,'restored':False,'verified':True,'reason':'già attiva'}
    # A surviving or modified owned chain is ambiguous: do not repair in place.
    if chain_exists(name):
        raise PolicyError('catena già presente ma diversa dal profilo: nessuna modifica')
    # If a foreign service or an older profile still references an IPTM_QP chain,
    # abort instead of installing a second competing policy.
    post=ipt('-S','POSTROUTING').stdout.splitlines()
    if any(re.search(r'(?:^| )-j IPTM_QP_[A-F0-9]{8}(?: |$)',x) for x in post):
        raise PolicyError('hook policy già presente: nessuna modifica')
    # Existing orphan IPTM_QP chains must not be silently overwritten.
    all_chains=ipt('-S').stdout.splitlines()
    if any(re.match(r'^-N IPTM_QP_[A-F0-9]{8}(?: |$)',x) for x in all_chains):
        raise PolicyError('catena policy orfana presente: nessuna modifica')
    ipt('-N',name)
    hooked=False
    try:
        for rule in upload_rules(data['rules']):
            ipt('-A',name,*rule_args(rule))
        body=[r for r in ipt('-S',name).stdout.splitlines() if r.startswith('-A '+name+' ')]
        digest=hashlib.sha256('\n'.join(body).encode()).hexdigest()
        if digest != saved['rules_digest'] or len(body)!=len(upload_rules(data['rules'])):
            raise PolicyError('regole ricostruite diverse dal profilo salvato')
        ipt('-A','POSTROUTING','-o',iface,'-j',name)
        hooked=True
        if not matches_owned(saved):raise PolicyError('ripristino non verificato')
        return {'ok':True,'restored':True,'verified':True,'interface':iface}
    except Exception:
        if hooked:ipt('-D','POSTROUTING','-o',iface,'-j',name,check=False)
        ipt('-F',name,check=False);ipt('-X',name,check=False)
        raise

def install_boot_service():
    """Explicitly managed one-shot unit; no user-controlled command interpolation."""
    if not pathlib.Path(SCRIPT).is_file():
        raise PolicyError('release QoS non installata: '+SCRIPT)
    if UNIT.is_symlink():raise PolicyError('unità di ripristino simbolica')
    marker='Description=IPTM QoS DSCP boot restore'
    if UNIT.exists() and marker not in UNIT.read_text():
        raise PolicyError('unità systemd non appartenente a IPTM')
    unit=("""[Unit]
Description=IPTM QoS DSCP boot restore
Wants=network-online.target
After=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 -B """+SCRIPT+""" restore-boot
NoNewPrivileges=true
[Install]
WantedBy=multi-user.target
""")
    durable_replace(UNIT, unit.encode(), mode=0o644)
    cmd('systemctl','daemon-reload')
    cmd('systemctl','enable',UNIT.name)
    if cmd('systemctl','is-enabled',UNIT.name,check=False).stdout.strip()!='enabled':
        raise PolicyError('persistenza QoS non abilitata')

def status():
    active=load(ACTIVE)
    unit_enabled=(UNIT.is_file() and not UNIT.is_symlink() and SCRIPT in UNIT.read_text() and
                  cmd('systemctl','is-enabled',UNIT.name,check=False).stdout.strip()=='enabled')
    return {'ok':True,'active':bool(active),'verified':matches_owned(active),'persistent':unit_enabled,'profile':active}

def stage(raw):
    data=validate(raw)
    data['created']=int(time.time());data['sha256']=signature(data)
    save(PLAN,data)
    return {'ok':True,'sha256':data['sha256'],'preview':data,'applied':False}

def upload_rules(rules):
    return [rule for rule in rules if rule.get('direction','both') in ('both','upload')]

def rule_args(r):
    args=['-p',r['protocol'],'--dport',str(r['port'])]
    if r['source']:args+=['-s',r['source']]
    # Only classify unmarked packets, preserving trusted upstream/app DSCP.
    args+=['-m','dscp','--dscp','0','-j','DSCP','--set-dscp',str(DSCP[r['priority']])]
    return args

def apply(sha):
    if not TOKEN.fullmatch(sha):raise PolicyError('SHA256 non valido')
    # A confirmed CAKE ingress filter set is a snapshot of this policy.
    # Never silently replace the outbound rules while inbound still uses
    # the previous version; require a guarded CAKE restart first.
    qos_state=pathlib.Path('/var/lib/iptm-qos-engine/active.json')
    if qos_state.exists() or qos_state.is_symlink():
        running=load(qos_state)
        if running and running.get('state') in ('pending','applying','confirmed','rollback-failed'):
            raise PolicyError('CAKE/IFB attivo: disabilitarlo in modo controllato prima di modificare le priorità')
    p=load(PLAN)
    if not p or p.get('sha256')!=sha or time.time()-p.get('created',0)>600:raise PolicyError('piano scaduto o cambiato')
    data=validate({'interface':p['interface'],'rules':p['rules']})
    old=load(ACTIVE)
    if old and not matches_owned(old):raise PolicyError('topologia della policy precedente cambiata: nessuna modifica')
    # Require the referenced egress interface to exist; no interface creation.
    install_boot_service()
    if cmd('ip','link','show','dev',data['interface'],check=False).returncode:raise PolicyError('WAN assente')
    new='IPTM_QP_'+secrets.token_hex(4).upper()
    if chain_exists(new):raise PolicyError('catena già esistente')
    ipt('-N',new)
    hooked=False
    old_detached=False
    try:
        for rule in upload_rules(data['rules']):ipt('-A',new,*rule_args(rule))
        ipt('-A','POSTROUTING','-o',data['interface'],'-j',new)
        hooked=True
        if not links(data['interface'],new):raise PolicyError('hook DSCP non verificato')
        body=[r for r in ipt('-S',new).stdout.splitlines() if r.startswith('-A '+new+' ')]
        if len(body)!=len(upload_rules(data['rules'])):raise PolicyError('numero regole installate incoerente')
        saved={'interface':data['interface'],'rules':data['rules'],'chain':new,'created':int(time.time()),
               'sha256':sha,'rules_digest':hashlib.sha256('\n'.join(body).encode()).hexdigest()}
        if old:
            ipt('-D','POSTROUTING','-o',old['interface'],'-j',old['chain'])
            old_detached=True
        save(ACTIVE,saved)
        PLAN.unlink(missing_ok=True)
        if old:
            # Post-commit cleanup is best effort; an unreferenced chain cannot
            # change traffic. Avoid reverting an already committed new policy.
            ipt('-F',old['chain'],check=False);ipt('-X',old['chain'],check=False)
        return {'ok':True,'active':saved,'verified':matches_owned(saved)}
    except Exception:
        if old_detached:
            ipt('-A','POSTROUTING','-o',old['interface'],'-j',old['chain'],check=False)
        if hooked:ipt('-D','POSTROUTING','-o',data['interface'],'-j',new,check=False)
        ipt('-F',new,check=False);ipt('-X',new,check=False)
        raise

def live_chain_rules(chain, snapshot):
    """Read live mangle rules; do not mistake a missing chain for an iptables failure."""
    if not any(line == '-N '+chain for line in snapshot):
        return None
    result=ipt('-S',chain)
    return [line for line in result.stdout.splitlines() if line.startswith('-A '+chain+' ')]


def references(chain, snapshot):
    """Find every jump/goto, not only the expected IPTM POSTROUTING hook."""
    import shlex
    refs=[]
    for line in snapshot:
        if not line.startswith('-A '):
            continue
        try:tokens=shlex.split(line)
        except ValueError:raise PolicyError('regole iptables non leggibili: nessuna modifica')
        if any(tokens[k] in ('-j','--jump','-g','--goto') and tokens[k+1]==chain
               for k in range(len(tokens)-1)):
            refs.append(line)
    return refs


def alternate_backend_present(chain):
    """Do not forget a policy merely because the iptables backend switched."""
    import shutil
    for binary in ('iptables-nft','iptables-legacy'):
        if not shutil.which(binary):continue
        r=cmd(binary,'-w','5','-t','mangle','-S',chain,check=False)
        if r.returncode==0:return binary
    return None


def retire_restore_unit():
    """Stop future restoration only for a recognizably IPTM-owned unit."""
    if UNIT.is_symlink():return 'unità di ripristino non verificata: conservata'
    if not UNIT.exists():return None
    try:content=UNIT.read_text()
    except (OSError,UnicodeError):return 'unità di ripristino non leggibile: conservata'
    if 'Description=IPTM QoS DSCP boot restore' not in content or 'qos_policy.py restore-boot' not in content:
        return 'unità di ripristino non riconosciuta: conservata'
    r=cmd('systemctl','disable',UNIT.name,check=False)
    if r.returncode:return 'unità di ripristino non disabilitata: controllare systemd'
    return None


def disable():
    """Idempotent, selective retirement of IPTM DSCP without flushing foreign rules.

    A saved digest is an integrity diagnostic, not proof that everything in a
    changed chain belongs to IPTM. Remove only rules described by the signed
    local IPTM profile, keep all unrecognized rules, and retire a now-stale
    state if iptables was reloaded without the chain. Never flush a chain.
    """
    qos_state=pathlib.Path('/var/lib/iptm-qos-engine/active.json')
    if qos_state.exists() or qos_state.is_symlink():
        running=load(qos_state)
        if running and running.get('state') in ('pending','applying','confirmed','rollback-failed'):
            raise PolicyError('CAKE/IFB attivo: disabilitarlo in modo controllato prima della rimozione DSCP')
    old=load(ACTIVE)
    if not old:return {'ok':True,'disabled':False,'reason':'già disattivato'}
    data=validate_active(old)
    chain=old['chain'];iface=data['interface']
    # A full successful listing proves the mangle backend is available; no
    # deletion of saved state on permissions/backend/iptables errors.
    snapshot=ipt('-S').stdout.splitlines()
    live=live_chain_rules(chain,snapshot)
    refs=references(chain,snapshot)
    if live is None:
        if refs:raise PolicyError('riferimento a catena non presente: verifica firewall richiesta')
        alternate=alternate_backend_present(chain)
        if alternate:raise PolicyError('profilo ancora presente nel backend '+alternate+': nessuna modifica')
        ACTIVE.unlink()
        warning=retire_restore_unit()
        result={'ok':True,'disabled':True,'stale':True,'removed_rules':0,
                'foreign_preserved':False,'reason':'profilo non presente nel firewall: stato ripulito'}
        if warning:result['warning']=warning
        return result

    # Only the exact IPTM rules from the validated local policy are eligible
    # for deletion; other rules and foreign hooks always remain untouched.
    removed=0
    for rule in upload_rules(data['rules']):
        args=rule_args(rule)
        if ipt('-C',chain,*args,check=False).returncode==0:
            ipt('-D',chain,*args)
            removed+=1
    # Refresh after each deletion; concurrent insertion of foreign rules is
    # never a reason to flush the chain.
    live=live_chain_rules(chain,ipt('-S').stdout.splitlines())
    if live is None:raise PolicyError('catena eliminata durante la disattivazione: verifica firewall richiesta')
    snapshot=ipt('-S').stdout.splitlines()
    refs=references(chain,snapshot)
    expected=f'-A POSTROUTING -o {iface} -j {chain}'
    foreign=bool(live or any(ref != expected for ref in refs) or refs.count(expected)>1)
    if not live:
        # Only the exact IPTM hook may be removed, and only when the chain no
        # longer contains any rule. This cannot interrupt third-party rules.
        if refs==[expected]:
            ipt('-D','POSTROUTING','-o',iface,'-j',chain)
            refs=references(chain,ipt('-S').stdout.splitlines())
        if not refs:
            # -X refuses to delete a nonempty or referenced chain; no -F.
            ipt('-X',chain)
        else:
            foreign=True
    ACTIVE.unlink()
    warning=retire_restore_unit()
    result={'ok':True,'disabled':True,'removed_rules':removed,
            'foreign_preserved':foreign,'reason':('regole IPTM rimosse; modifiche esterne conservate'
                  if foreign else 'policy IPTM rimossa')}
    if warning:result['warning']=warning
    return result

def main(args):
    secure()
    from command_transport import domain_lock
    with domain_lock(BASE/'lock'):
        if args==['status']:return status()
        if args==['restore-boot']:return boot_restore()
        if args==['stage']:
            raw=sys.stdin.buffer.read(12000)
            return stage(json.loads(raw))
        if len(args)==2 and args[0]=='apply':return apply(args[1])
        if args==['disable']:return disable()
        raise PolicyError('uso: status | stage | apply SHA256 | disable | restore-boot')

def coordinated_main(args):
    from command_transport import driver_admission
    with driver_admission('qos_policy',args):
        return main(args)


if __name__=='__main__':
    try:print(json.dumps(coordinated_main(sys.argv[1:]),ensure_ascii=False))
    except (PolicyError,OSError,ValueError,KeyError,json.JSONDecodeError) as e:
        print(json.dumps({'ok':False,'error':str(e)}));sys.exit(1)
