#!/usr/bin/env python3
"""IPTM 4.9.0: additive, console-only IPv4 /32 alias trial on an UNUSED spare NIC.

The only kernel mutation is `ip -4 address add/del` for a /32 label owned by
this transaction. No link, route, firewall, DHCP, DNS, Wi-Fi, manager or service
reconfiguration. Independent systemd timer and boot guard undo unconfirmed
trials. This is NOT a production secondary address or multi-WAN executor.
"""
from __future__ import annotations

import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time

import fabric_runtime as journal
from multinic_manager import inventory, read_profile, validate, ValidationError

VERSION = '5.20.25'
STATE_DIR = Path('/var/lib/iptm-alias-trial')
STATE = STATE_DIR/'state.json'
LOCK = STATE_DIR/'lock'
UNIT = Path('/etc/systemd/system/iptm-alias-boot-recover.service')
SCRIPT = f'/usr/local/lib/iptables-manager/web/releases/{VERSION}/extensions/network_alias_trial.py'
TIMER = 'iptm-alias-trial-revert'
TTL = 120
TOKEN = re.compile(r'^[a-f0-9]{24}$')
HASH = re.compile(r'^[a-f0-9]{64}$')
IFACE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$')
PRIVATE_V4 = tuple(ipaddress.ip_network(x) for x in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))

class AliasError(ValueError): pass


def command(argv, *, runner=None, check=True, timeout=12):
    result=(runner or subprocess.run)(argv,capture_output=True,text=True,timeout=timeout,check=False)
    if check and result.returncode:
        raise AliasError(f'{argv[0]} non riuscito: exit {result.returncode}; {result.stderr[:120]}')
    return result


def kernel(*, runner=None):
    def rows(cmd):
        try:
            data=json.loads(command(cmd,runner=runner).stdout)
            if not isinstance(data,list):raise ValueError()
            return data
        except (ValueError,TypeError) as exc:raise AliasError('Inventario iproute2 non leggibile') from exc
    return (rows(['ip','-j','-d','link','show']),
            rows(['ip','-j','-4','addr','show']),
            rows(['ip','-j','-4','route','show','table','all']))


def _owned(data, link_rows, addr_rows):
    name=data['interface'];link=next((x for x in link_rows if x.get('ifname')==name),None)
    if link is None or link.get('ifindex')!=data['ifindex'] or link.get('address','').lower()!=data['mac']:
        return False, 'NIC non identificabile: MAC/ifindex cambiato'
    address=next((x for x in addr_rows if x.get('ifname')==name),None)
    for entry in (address or {}).get('addr_info',[]):
        if (entry.get('family')=='inet' and entry.get('local')==data['address'] and
            entry.get('prefixlen')==32 and entry.get('label')==data['label']):
            return True, ''
    return False, 'IPv4/etichetta non più attribuibile al trial'


def _normalize(doc, live, observations):
    if not isinstance(doc,dict) or doc.get('status')!='draft' or doc.get('applied') is not False:
        raise AliasError('Occorre una bozza non applicata')
    try:valid=validate(doc['profile'],live)
    except (ValidationError,TypeError,KeyError) as exc:raise AliasError(f'Bozza incompatibile con hardware: {exc}') from exc
    profile=valid['profile']
    # Risky topology changes are never combined with an alias trial.
    fabric=profile['fabric']
    if any(fabric.get(k) for k in ('vlans','bridges','bonds','switches')):
        raise AliasError('Trial IPv4: non combinare con VLAN, bond, bridge o switch')
    candidates=[x for x in profile['nics'] if x.get('alias_address')]
    if len(candidates)!=1:raise AliasError('Selezionare esattamente un alias di prova')
    n=candidates[0];name=n['name'];alias=n['alias_address']
    if n['role']!='spare' or n['address'] or n['dhcp'] or n['gateway']:
        raise AliasError('Solo NIC fisica spare inutilizzata, senza IPv4/DHCP/gateway')
    if not IFACE.fullmatch(name) or len(name)+len(':iptm')>15:
        raise AliasError('Nome NIC troppo lungo per etichetta kernel IP')
    try:ip=ipaddress.IPv4Interface(alias)
    except (ValueError,TypeError) as exc:raise AliasError('Alias IPv4 non valido') from exc
    if ip.network.prefixlen != 32 or not any(ip.ip in net for net in PRIVATE_V4):
        raise AliasError('Trial limitato a IPv4 RFC1918 /32 (nessuna route connessa)')
    links,addrs,routes=observations
    link=next((x for x in links if x.get('ifname')==name),None)
    if not link or not isinstance(link.get('ifindex'),int) or link['ifindex']<=0 or not link.get('address'):
        raise AliasError('NIC non verificata tramite ifindex/MAC')
    if link.get('master') or (link.get('linkinfo') or {}).get('info_kind') in {'bridge','bond','vlan','veth','tun'}:
        raise AliasError('NIC non libera o controllata da bridge/bond/VLAN')
    if link.get('operstate','').upper()!='UP':
        raise AliasError('La scheda spare deve essere gia UP; IPTM non modifica link state')
    physical={x['name'] for x in live.get('interfaces',[]) if x.get('physical') is True}
    if name not in physical or len(physical)<2:
        raise AliasError('Servono almeno due NIC fisiche verificate; WAN principale non modificata')
    if any(row.get('ifname')==name and any(e.get('family')=='inet' for e in row.get('addr_info',[])) for row in addrs):
        raise AliasError('NIC gia con IPv4: prova additiva vietata')
    for row in addrs:
        for addr in row.get('addr_info',[]):
            if addr.get('family')!='inet':continue
            if addr.get('local')==str(ip.ip):raise AliasError('IPv4 gia presente in sistema')
            try:
                subnet=ipaddress.ip_interface(f"{addr['local']}/{addr['prefixlen']}").network
            except (KeyError,TypeError,ValueError) as exc:raise AliasError('Indirizzi kernel incompleti') from exc
            if ip.ip in subnet:
                raise AliasError('IPv4 dentro una subnet gia configurata sul gateway')
    for row in routes:
        if row.get('dev')==name and row.get('dst')=='default':
            raise AliasError('La scheda e un uplink WAN con route predefinita')
        dst=row.get('dst')
        if not dst or dst=='default':continue
        try:route_net=ipaddress.ip_network(dst,strict=False)
        except ValueError:continue
        if ip.ip in route_net:raise AliasError('Alias incluso in route IPv4 attiva')
    identity={'interface':name,'address':str(ip.ip),'prefix':32,'label':name+':iptm',
              'ifindex':link['ifindex'],'mac':link['address'].lower()}
    digest=hashlib.sha256(json.dumps(identity,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    return {'version':VERSION,'hash':digest,'mode':'ipv4-host-alias-only','target':identity,
            'ttl_seconds':TTL,'auto_confirm':False,'persistent':False,
            'untouched':['default route','existing addresses','iptables','DNS/DHCP','CAKE','network services','WAN primary'],
            'requires_console':True}


def plan(*,live=None,draft=None,runner=None,observations=None):
    return _normalize(draft if draft is not None else read_profile(),
                      live if live is not None else inventory(),
                      observations if observations is not None else kernel(runner=runner))


def atomic(doc):journal.atomic_state(doc, STATE)

def read():
    journal.secure_dir(STATE_DIR)
    if STATE.exists():
        st=STATE.lstat()
        if not STATE.is_file() or st.st_uid!=0 or st.st_mode & 0o077:
            raise AliasError('File di stato non root-only')
    doc=journal.state_read(STATE)
    if doc is not None and (doc.get('version')!=VERSION or doc.get('status') not in
        {'pending','confirmed','rolled-back','rollback-incomplete','rebooted-not-persistent'}):
        raise AliasError('Transazione da release diversa o stato sconosciuto')
    return doc

def _lock():return journal.locking(LOCK)


def boot_guard_install(*,runner=None,unit=None,script=SCRIPT):
    unit=unit or UNIT
    if not Path(script).is_file() and runner is None:raise AliasError('Script release non installato')
    if unit.parent.is_symlink() or unit.is_symlink():raise AliasError('Unità systemd non sicura')
    if unit.exists() and 'Description=IPTM Alias trial boot recovery' not in unit.read_text():
        raise AliasError('Unità systemd esistente sconosciuta')
    content=(f'[Unit]\nDescription=IPTM Alias trial boot recovery\nDefaultDependencies=no\n'
             'After=local-fs.target\nBefore=network-pre.target\nWants=network-pre.target\n'
             f'[Service]\nType=oneshot\nExecStart=/usr/bin/python3 -B {script} boot-recover\n'
             '[Install]\nWantedBy=sysinit.target\n')
    fd,tmp=tempfile.mkstemp(prefix='.iptm-alias-',dir=unit.parent)
    try:
        with os.fdopen(fd,'w') as f:
            f.write(content);f.flush();os.fsync(f.fileno());os.fchmod(f.fileno(),0o644)
        os.replace(tmp,unit)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)
    command(['systemctl','daemon-reload'],runner=runner)
    command(['systemctl','enable',unit.name],runner=runner)
    return {'ok':True,'unit':str(unit)}


def _guard_ready(*,runner=None):
    if UNIT.is_symlink() or not UNIT.is_file() or SCRIPT not in UNIT.read_text():
        raise AliasError('Prima installare il boot guard della release da console')
    result=command(['systemctl','is-enabled',UNIT.name],runner=runner,check=False)
    if result.returncode or result.stdout.strip()!='enabled':
        raise AliasError('Recupero boot non abilitato')
    if runner is None and not shutil.which('systemd-run'):
        raise AliasError('systemd-run assente')


def _arm(*,runner=None):
    command(['systemd-run',f'--unit={TIMER}',f'--on-active={TTL}s','--collect',
             '/usr/bin/python3','-B',SCRIPT,'expire'],runner=runner)

def _disarm(*,runner=None):command(['systemctl','stop',TIMER+'.timer'],runner=runner,check=False)


def _remove(doc,*,runner=None):
    try:link_rows,addr_rows,_=kernel(runner=runner)
    except (AliasError,OSError) as exc:return {'ok':False,'status':'rollback-incomplete','error':str(exc)}
    owned,reason=_owned(doc['target'],link_rows,addr_rows)
    if not owned:
        # An alias that disappeared is already safely absent; never touch any other address.
        present=any(x.get('ifname')==doc['target']['interface'] and
                    any(a.get('local')==doc['target']['address'] for a in x.get('addr_info',[])) for x in addr_rows)
        if not present:return {'ok':True,'status':'rolled-back','removed':False}
        return {'ok':False,'status':'rollback-incomplete','error':reason}
    target=doc['target']
    try:command(['ip','-4','addr','del',target['address']+'/32','dev',target['interface']],runner=runner)
    except AliasError as exc:return {'ok':False,'status':'rollback-incomplete','error':str(exc)}
    return {'ok':True,'status':'rolled-back','removed':True}


def rollback(doc,*,runner=None):
    result=_remove(doc,runner=runner)
    doc['status']=result['status'];doc['error']=result.get('error','')
    atomic(doc)
    return result


def apply(digest,*,runner=None,live=None,draft=None,observations=None):
    if not HASH.fullmatch(digest):raise AliasError('Hash piano non valido')
    _guard_ready(runner=runner)
    previous=read()
    if previous and previous.get('status') in {'pending','confirmed','rollback-incomplete'}:
        raise AliasError('Trial precedente non chiuso; usare rollback o reboot')
    proposal=plan(runner=runner,live=live,draft=draft,observations=observations)
    if proposal['hash']!=digest:raise AliasError('Bozza/hardware cambiato: rigenerare anteprima')
    now=int(time.time());doc={'schema':1,'version':VERSION,'token':secrets.token_hex(12),
                               'status':'pending','started':now,'deadline':now+TTL,
                               'target':proposal['target']}
    atomic(doc)  # Write durable rollback information BEFORE any mutation.
    try:_arm(runner=runner)
    except Exception:
        doc['status']='rolled-back';atomic(doc)
        raise
    try:
        # Race check: fail closed if interface addresses/routes changed while arming.
        again=plan(runner=runner,live=live,draft=draft)
        if again['hash']!=digest:raise AliasError('Stato cambiato mentre si armava il watchdog')
        x=doc['target']
        command(['ip','-4','addr','add',x['address']+'/32','dev',x['interface'],'label',x['label']],runner=runner)
        return {'ok':True,'status':'pending','token':doc['token'],'deadline':doc['deadline'],
                'address':x['address'],'interface':x['interface'],'persistent':False}
    except Exception as exc:
        result=rollback(doc,runner=runner)
        if result['ok']:_disarm(runner=runner)
        raise AliasError('Prova annullata: '+str(exc)+'; rollback='+result['status']) from exc


def action(op,code='',*,runner=None):
    if op not in {'status','preview','install-guard','apply','confirm','rollback','expire','boot-recover'}:
        raise AliasError('Operazione non consentita')
    if os.geteuid()!=0:raise AliasError('Comando solo root')
    if op in {'install-guard','apply','confirm','rollback'} and runner is None and not sys.stdin.isatty():
        raise AliasError('Richiesto terminale locale o SSH root, non HTTP')
    if op=='preview':return {'ok':True,'plan':plan(runner=runner)}
    if op=='status':
        state=read()
        if state:state={k:v for k,v in state.items() if k!='token'}
        return {'ok':True,'trial':state,'boot_guard_installed':UNIT.is_file() and not UNIT.is_symlink()}
    if op=='install-guard':return boot_guard_install(runner=runner)
    fd=_lock()
    try:
        if op=='apply':return apply(code,runner=runner)
        doc=read()
        if not doc:return {'ok':True,'status':'absent'}
        if op=='boot-recover':
            # Kernel aliases do not persist through reboot. Never mutate a link here.
            if doc['status'] in {'pending','confirmed'}:
                doc['status']='rebooted-not-persistent';atomic(doc)
            return {'ok':True,'status':doc['status']}
        if op in {'confirm','rollback'} and (not TOKEN.fullmatch(code) or code!=doc['token']):
            raise AliasError('Token di conferma errato')
        if op=='confirm':
            if doc['status']!='pending' or int(time.time())>=doc['deadline']:
                raise AliasError('Trial non confermabile: scaduto o non pendente')
            links,addrs,_=kernel(runner=runner)
            owned,reason=_owned(doc['target'],links,addrs)
            if not owned:raise AliasError('Alias non corrispondente: '+reason)
            doc['status']='confirmed';atomic(doc);_disarm(runner=runner)
            return {'ok':True,'status':'confirmed','persistent':False}
        if op=='expire' and doc['status']!='pending':return {'ok':True,'status':doc['status']}
        if op=='rollback' and doc['status'] not in {'pending','confirmed','rollback-incomplete'}:
            return {'ok':True,'status':doc['status']}
        result=rollback(doc,runner=runner)
        if result['ok']:_disarm(runner=runner)
        return result
    finally:
        fcntl.flock(fd,fcntl.LOCK_UN);os.close(fd)


def main(args):
    if len(args)==1 and args[0] in {'status','preview','install-guard','expire','boot-recover'}:
        return action(args[0])
    if len(args)==2 and args[0] in {'apply','confirm','rollback'}:
        return action(args[0],args[1])
    raise AliasError('Uso: net-alias status|preview|install-guard|apply HASH|confirm TOKEN|rollback TOKEN')

if __name__=='__main__':
    try:print(json.dumps(main(sys.argv[1:]),ensure_ascii=False,separators=(',',':')))
    except (AliasError,journal.TrialError,ValueError,OSError,subprocess.TimeoutExpired) as exc:
        print(json.dumps({'ok':False,'error':str(exc)},ensure_ascii=False));sys.exit(2)
