#!/usr/bin/env python3
"""IPTM 5.4.3: privileged transactional network runtime (root-console only).

Operations are typed and additive. Existing management addresses, default route,
iptables chains and network-manager profiles are never removed or replaced.
Pending changes are undone by an independent systemd timer and boot recovery.
A successful unit test is NOT a substitute for a live console recovery test.
"""
from __future__ import annotations

import contextlib
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

VERSION = '5.30.12'
ROOT = Path('/var/lib/iptm-network-runtime')
STATE = ROOT / 'transaction.json'
PLAN = ROOT / 'plan.json'
LOCK = ROOT / 'lock'
SCRIPT = f'/usr/local/lib/iptables-manager/web/releases/{VERSION}/extensions/network_runtime.py'
BOOT_UNIT = Path('/etc/systemd/system/iptm-network-runtime.service')
HEALTH_SERVICE = Path('/etc/systemd/system/iptm-network-wan-health.service')
HEALTH_TIMER = Path('/etc/systemd/system/iptm-network-wan-health.timer')
TIMER = 'iptm-network-runtime-expire'
TTL = 180
IFACE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$')
HEX64 = re.compile(r'^[a-f0-9]{64}$')
HEX24 = re.compile(r'^[a-f0-9]{24}$')
PHYSICAL_ROLES = {'wan', 'lan', 'iot', 'guest', 'vpn', 'management', 'spare'}
RESERVED = {'lo', 'docker0', 'virbr0'}
CHAIN_FWD = 'IPTM5_FWD'
CHAIN_NAT = 'IPTM5_NAT'
PICK_A = 'IPTM5_PICK_A'
PICK_B = 'IPTM5_PICK_B'
OWNED_LINK_TAG = 'iptm5-network-runtime-owned'
PRIVATES = [ipaddress.ip_network(x) for x in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')]

class NetworkError(RuntimeError):
    pass


def boot_id():
    try:return Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    except OSError:return 'unknown'


def require_root():
    if os.geteuid() != 0:
        raise NetworkError('Operazione consentita soltanto a root')


def require_console():
    # Root calls from PHP-FPM/CGI have no controlling terminal. Do not permit
    # high-impact network changes through a sudo-capable web endpoint.
    try: fd=os.open('/dev/tty',os.O_RDONLY|os.O_NOCTTY)
    except OSError as exc:
        raise NetworkError('Serve una console root interattiva, non una richiesta web') from exc
    else:os.close(fd)


def run(argv: list[str], *, check=True, timeout=20, runner=None):
    """No shell, fixed executable names and bounded output."""
    if not isinstance(argv,list) or not argv or not all(isinstance(x,str) and len(x)<512 for x in argv):
        raise NetworkError('Comando non valido')
    func = runner or subprocess.run
    try:
        p = func(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                 timeout=timeout, stdin=subprocess.DEVNULL, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise NetworkError('Comando non disponibile: '+argv[0]) from exc
    if check and p.returncode != 0:
        raise NetworkError(f'{argv[0]} terminato con exit {p.returncode}: {str(p.stderr)[:160]}')
    return p


def cmd_json(args, runner=None):
    p=run(args,runner=runner)
    try:return json.loads(p.stdout)
    except (TypeError,ValueError) as exc:raise NetworkError('Risposta iproute2 non valida') from exc


def get_live(runner=None):
    links=cmd_json(['ip','-j','-d','link','show'],runner)
    addresses=cmd_json(['ip','-j','-4','addr','show'],runner)
    defaults=cmd_json(['ip','-j','-4','route','show','default'],runner)
    return {'links':links,'addresses':addresses,'default':defaults}


def nic(name):
    if not isinstance(name,str) or not IFACE.fullmatch(name) or name in RESERVED:
        raise NetworkError('Nome interfaccia non valido')
    return name


def addr4(value):
    try:
        x=ipaddress.IPv4Interface(value)
        if x.ip.is_loopback or x.ip.is_multicast or x.ip.is_unspecified or x.ip.is_link_local:
            raise ValueError()
        return str(x)
    except (TypeError,ValueError) as exc:raise NetworkError('Indirizzo IPv4 CIDR non valido') from exc


def net4(value):
    try:
        x=ipaddress.IPv4Network(value,strict=True)
        if x.is_multicast or x.is_loopback or x.is_unspecified or x.is_link_local:
            raise ValueError()
        return str(x)
    except (TypeError,ValueError) as exc:raise NetworkError('Sottorete IPv4 non valida') from exc


def pure_ip(value):
    try:
        x=ipaddress.IPv4Address(value)
        if x.is_multicast or x.is_loopback or x.is_unspecified:
            raise ValueError()
        return str(x)
    except (TypeError,ValueError) as exc:raise NetworkError('IPv4 non valido') from exc


def bounded(n, lo, hi):
    if type(n) is not int or not lo <= n <= hi:
        raise NetworkError(f'Numero fuori intervallo {lo}-{hi}')
    return n


def typed(data, allowed, required=()):
    if not isinstance(data,dict) or set(data)-set(allowed) or not set(required)<=set(data):
        raise NetworkError('Schema configurazione sconosciuto o incompleto')


def physical(live):
    return {x.get('ifname'):x for x in live['links'] if isinstance(x,dict) and x.get('ifname')}


def is_physical(link):
    if link.get('physical') is True:  # test fixture only; live probes do not include this key
        return True
    name=link.get('ifname')
    return isinstance(name,str) and bool(IFACE.fullmatch(name)) and Path('/sys/class/net',name,'device').exists()


def protected(live):
    return {x.get('dev') for x in live['default'] if x.get('dev')} | {
        x.get('ifname') for x in live['links'] if x.get('ifname') == 'lo'}


def exists_ipv4(live):
    out=set();nets=[]
    for row in live['addresses']:
        for a in row.get('addr_info',[]):
            if a.get('family')=='inet':
                out.add(str(a.get('local')))
                try:nets.append((row.get('ifname'),ipaddress.IPv4Interface(f"{a['local']}/{a['prefixlen']}").network))
                except (ValueError,KeyError):raise NetworkError('IPv4 kernel non interpretabile')
    return out,nets


def validate_config(raw, live):
    """Reject missing hardware, subnet collisions and destructive physical operations."""
    typed(raw,{'schema','vlans','aliases','bridges','bonds','firewall','dhcp','wan'},('schema',))
    if raw['schema']!=1:raise NetworkError('Schema rete non supportato')
    names=physical(live); management=protected(live)
    already_ip,connected=exists_ipv4(live)
    used_networks=list(connected);created=set();steps=[];risks=[]
    if not management:
        raise NetworkError('Route di gestione WAN sconosciuta: applicazione vietata')
    for key in ('vlans','aliases','bridges','bonds'):
        if not isinstance(raw.get(key,[]),list) or len(raw.get(key,[]))>12:
            raise NetworkError(f'{key}: numero oggetti non valido')
    for v in raw.get('vlans',[]):
        typed(v,{'name','parent','vid','address'},('name','parent','vid'))
        name=nic(v['name']);parent=nic(v['parent']);vid=bounded(v['vid'],1,4094)
        if name in names or name in created or parent not in names or parent in created:
            raise NetworkError('VLAN: parent non esistente o nome duplicato')
        link=names[parent]
        if not is_physical(link) or link.get('master') or (link.get('linkinfo') or {}).get('info_kind') in ('bond','bridge','vlan'):
            raise NetworkError('Parent VLAN già asservito ad altra interfaccia')
        ip=addr4(v['address']) if v.get('address') else ''
        if ip:
            subnet=ipaddress.IPv4Interface(ip).network
            if any(subnet.overlaps(net) for _,net in used_networks):
                raise NetworkError('VLAN: rete sovrapposta ad indirizzi esistenti')
            used_networks.append((name,subnet))
        created.add(name)
        steps.append({'kind':'vlan','name':name,'parent':parent,'vid':vid,'address':ip})
    # Adds extra IPv4 addresses only. Never modifies or removes the primary address.
    for a in raw.get('aliases',[]):
        typed(a,{'interface','address'},('interface','address'))
        name=nic(a['interface']);ip=addr4(a['address']);value=ipaddress.IPv4Interface(ip)
        if name not in names and name not in created:raise NetworkError('Alias: interfaccia assente')
        if name in management and value.network.prefixlen != 32:
            raise NetworkError('Alias gestione deve essere /32 per evitare nuova route connessa')
        if str(value.ip) in already_ip or any(str(value.ip)==str(ipaddress.IPv4Interface(x['address']).ip)
             for x in steps if x.get('address')):
            raise NetworkError('Alias: IP duplicato')
        if any(value.ip in net for _,net in used_networks if value.network.prefixlen==32):
            raise NetworkError('Alias: IP già incluso in rete attiva')
        if value.network.prefixlen!=32 and any(value.network.overlaps(net) for _,net in used_networks):
            raise NetworkError('Alias: sottorete già configurata')
        used_networks.append((name,value.network));steps.append({'kind':'alias','interface':name,'address':ip})
    # New bridge and bond creation is limited to free spare physical ports: no
    # DHCP, IP, master, default route or dependent VLAN on a slave.
    assigned=set(); vlan_parents={x['parent'] for x in steps if x['kind']=='vlan'}
    for b in raw.get('bridges',[]):
        typed(b,{'name','ports','stp','address'},('name','ports'))
        name=nic(b['name']);ports=b['ports'];stp=b.get('stp',True)
        if type(stp) is not bool or not isinstance(ports,list) or not 1<=len(ports)<=4:
            raise NetworkError('Bridge: porte o STP invalidi')
        if name in names or name in created or len(set(ports))!=len(ports):raise NetworkError('Bridge: duplicazione')
        for p in ports:
            p=nic(p)
            if p not in names or p in management or p in vlan_parents or p in assigned:
                raise NetworkError('Bridge: porta non libera')
            l=names[p]
            if not is_physical(l) or l.get('master') or any(row.get('ifname')==p and row.get('addr_info') for row in live['addresses']):
                raise NetworkError('Bridge: porta con IP o già slave')
        address=addr4(b['address']) if b.get('address') else ''
        if address:
            net=ipaddress.IPv4Interface(address).network
            if any(net.overlaps(n) for _,n in used_networks):raise NetworkError('Bridge: subnet sovrapposta')
            used_networks.append((name,net))
        if any(x.get('kind')=='alias' and x.get('interface') in ports for x in steps):
            raise NetworkError('Bridge: porta con alias IPv4 proposto')
        assigned.update(ports);created.add(name)
        steps.append({'kind':'bridge','name':name,'ports':ports,'stp':stp,'address':address})
    for b in raw.get('bonds',[]):
        typed(b,{'name','ports','mode','address','lacp_confirmed'},('name','ports','mode'))
        name=nic(b['name']);ports=b['ports'];mode=b['mode']
        if name in names or name in created or mode not in ('active-backup','802.3ad') or not isinstance(ports,list) or not 2<=len(ports)<=4 or len(set(ports))!=len(ports):
            raise NetworkError('Bond: nome/porte/mode non validi')
        if mode=='802.3ad' and b.get('lacp_confirmed') is not True:
            raise NetworkError('LACP: conferma configurazione switch necessaria')
        for p in ports:
            p=nic(p)
            if p not in names or p in management or p in assigned or p in vlan_parents:
                raise NetworkError('Bond: porta non libera')
            l=names[p]
            if not is_physical(l) or l.get('master') or any(row.get('ifname')==p and row.get('addr_info') for row in live['addresses']):
                raise NetworkError('Bond: porta con indirizzo o già slave')
        address=addr4(b['address']) if b.get('address') else ''
        if address:
            net=ipaddress.IPv4Interface(address).network
            if any(net.overlaps(n) for _,n in used_networks):raise NetworkError('Bond: subnet sovrapposta')
            used_networks.append((name,net))
        if any(x.get('kind')=='alias' and x.get('interface') in ports for x in steps):
            raise NetworkError('Bond: porta con alias IPv4 proposto')
        assigned.update(ports);created.add(name)
        steps.append({'kind':'bond','name':name,'ports':ports,'mode':mode,'address':address})
    firewall=raw.get('firewall',{})
    if firewall:
        typed(firewall,{'zones','allow','masquerade'},('zones',))
        zones=firewall['zones']; allow=firewall.get('allow',[]);masq=firewall.get('masquerade',[])
        if not isinstance(zones,list) or not 1<=len(zones)<=12 or not isinstance(allow,list) or not isinstance(masq,list):
            raise NetworkError('Firewall: zone o regole malformate')
        znames={}; interfaces=set()
        for z in zones:
            typed(z,{'name','interface','network'},('name','interface','network'))
            zone=z['name'];iface=nic(z['interface']);subnet=net4(z['network'])
            if zone not in PHYSICAL_ROLES or zone in znames or iface not in set(names)|created or iface in interfaces:
                raise NetworkError('Firewall: zona duplicata o NIC sconosciuta')
            znames[zone]=z;interfaces.add(iface)
        for a in allow:
            typed(a,{'from','to'},('from','to'))
            if a['from'] not in znames or a['to'] not in znames or a['from']==a['to']:
                raise NetworkError('Firewall: allow zone non valide')
        for n in masq:
            typed(n,{'from','wan'},('from','wan'))
            if n['from'] not in znames or n['wan'] not in names or n['wan'] not in management:
                raise NetworkError('Masquerade: WAN o sorgente non valida')
        steps.append({'kind':'firewall','zones':zones,'allow':allow,'masquerade':masq})
    wan=raw.get('wan',{})
    if wan:
        typed(wan,{'uplinks','source','mode'},('uplinks','source','mode'))
        uplinks=wan['uplinks'];mode=wan['mode'];source=nic(wan['source'])
        if not isinstance(uplinks,list) or not 2<=len(uplinks)<=3 or mode not in ('balanced','failover'):
            raise NetworkError('WAN: servono due/tre uplink e una strategia nota')
        if source not in set(names)|created or source in management:
            raise NetworkError('WAN: sorgente di instradamento non valida')
        uplink_names=set();default_names={x.get('dev') for x in live['default']}
        for idx,w in enumerate(uplinks):
            typed(w,{'interface','gateway','weight','address'},('interface','gateway','weight'))
            dev=nic(w['interface']);gw=pure_ip(w['gateway']);bounded(w['weight'],1,100)
            if dev not in names or dev in uplink_names or dev==source:
                raise NetworkError('WAN: interfaccia duplicata o assente')
            if idx==0 and dev not in default_names:raise NetworkError('WAN principale deve coincidere con route attuale')
            wanted_ip=pure_ip(w.get('address'))
            current=[ipaddress.IPv4Interface(f"{x.get('local')}/{x.get('prefixlen')}")
                      for row in live['addresses'] if row.get('ifname')==dev
                      for x in row.get('addr_info',[]) if x.get('family')=='inet']
            staged=[ipaddress.IPv4Interface(x['address']) for x in steps
                    if x.get('kind')=='alias' and x['interface']==dev]
            available=current+staged
            if not any(str(x.ip)==wanted_ip for x in available):
                raise NetworkError('WAN: indirizzo effettivo o staged interfaccia non corrisponde')
            if not any(ipaddress.IPv4Address(gw) in x.network for x in available):
                raise NetworkError('WAN: gateway non raggiungibile su subnet diretta')
            uplink_names.add(dev)
        steps.append({'kind':'wan','source':source,'mode':mode,'uplinks':uplinks})
    dhcp=raw.get('dhcp',{})
    if dhcp:
        from network_audit import validate_dhcp
        typed(dhcp,{'primary','secondary','confirmed_l2_isolation','pihole_api_port'},('primary','secondary','confirmed_l2_isolation'))
        if dhcp['confirmed_l2_isolation'] is not True:
            raise NetworkError('DHCP: conferma separazione L2 necessaria')
        try:plan=validate_dhcp(dhcp['primary'],dhcp['secondary'])
        except (ValueError,TypeError,KeyError) as exc:raise NetworkError('DHCP: '+str(exc)) from exc
        first=plan['primary']['interface'];second=plan['secondary']['interface']
        if first not in names or second not in names or first==second:
            raise NetworkError('DHCP: interfacce distinte mancanti')
        # A bond/bridge can legitimately own Pi-hole's LAN address. Slaves
        # cannot own DHCP. The secondary must be a separate physical L2 port.
        primary_kind=(names[first].get('linkinfo') or {}).get('info_kind')
        if names[first].get('master') or not (is_physical(names[first]) or primary_kind in ('bond','bridge')):
            raise NetworkError('DHCP Pi-hole: usare master bond/bridge, non una porta slave')
        if not is_physical(names[second]) or names[second].get('master'):
            raise NetworkError('DHCP secondario: richiede NIC fisica libera, non slave')
        if not any(row.get('ifname')==first and any(x.get('local')==str(ipaddress.IPv4Interface(dhcp['primary']['address']).ip) for x in row.get('addr_info',[])) for row in live['addresses']):
            raise NetworkError('DHCP Pi-hole: interfaccia primaria non configurata col gateway indicato')
        secondary_ip=str(ipaddress.IPv4Interface(dhcp['secondary']['address']).ip)
        secondary_live=any(row.get('ifname')==second and any(x.get('local')==secondary_ip
                             for x in row.get('addr_info',[])) for row in live['addresses'])
        secondary_staged=any(step.get('kind')=='alias' and step.get('interface')==second and
                             str(ipaddress.IPv4Interface(step['address']).ip)==secondary_ip
                             for step in steps)
        if not (secondary_live or secondary_staged):
            raise NetworkError('DHCP secondario: configurare il gateway sulla NIC o aggiungerlo nello stesso piano')
        if 'pihole_api_port' not in dhcp:
            raise NetworkError('DHCP: porta API locale Pi-hole obbligatoria (es. 8089)')
        port=bounded(dhcp['pihole_api_port'],1,65535)
        steps.append({'kind':'dhcp','plan':plan,'api_port':port})
    # Hardware binding: NIC names alone are mutable. Bind staged transactions to
    # stable MAC addresses and to the current management default gateway.
    physical_ref=set()
    for step in steps:
        for key in ('parent','interface','source'):
            if step.get(key) in names:physical_ref.add(step[key])
        physical_ref.update(n for n in step.get('ports',[]) if n in names)
        for x in step.get('uplinks',[]):
            if x['interface'] in names:physical_ref.add(x['interface'])
        for x in step.get('zones',[]):
            if x['interface'] in names:physical_ref.add(x['interface'])
        for section in (step.get('plan',{}).get('primary',{}),step.get('plan',{}).get('secondary',{})):
            if section.get('interface') in names:physical_ref.add(section['interface'])
    identity=[(name,names[name].get('address','')) for name in sorted(physical_ref)]
    mgmt_routes=sorted((str(x.get('dev','')),str(x.get('gateway',''))) for x in live['default'])
    digest=hashlib.sha256(json.dumps({'steps':steps,'identity':identity,'default':mgmt_routes},
                                     sort_keys=True,separators=(',',':')).encode()).hexdigest()
    return {'version':VERSION,'hash':digest,'steps':steps,'management':sorted(x for x in management if x),'risks':risks,
            'rollback_seconds':TTL,'existing_primary_route_unchanged':True}


def ensure_private(path):
    if path.is_symlink():raise NetworkError('Directory simbolica non consentita')
    path.mkdir(mode=0o700,parents=True,exist_ok=True)
    s=path.stat()
    if s.st_uid!=0 or s.st_mode&0o077:raise NetworkError('Directory root-only richiesta')


def atom(path,content):
    ensure_private(path.parent)
    fd,tmp=tempfile.mkstemp(prefix='.iptm-',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as f:
            os.fchmod(f.fileno(),0o600);f.write(content);f.flush();os.fsync(f.fileno())
        os.replace(tmp,path)
        folder=os.open(path.parent,os.O_DIRECTORY|os.O_RDONLY|os.O_NOFOLLOW)
        try:os.fsync(folder)
        finally:os.close(folder)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)


def read_doc(path):
    if not path.exists() and not path.is_symlink():return None
    if path.is_symlink() or not path.is_file() or path.stat().st_uid!=0 or path.stat().st_mode & 0o077:
        raise NetworkError('Documento non root-only')
    try:return json.loads(path.read_text())
    except (ValueError,UnicodeError) as exc:raise NetworkError('Documento non valido') from exc


def write_doc(path,data):
    atom(path,json.dumps(data,sort_keys=True,separators=(',',':')).encode())


@contextlib.contextmanager
def mutex():
    require_root();ensure_private(ROOT)
    fd=os.open(LOCK,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'r+') as f:
        fcntl.flock(f,fcntl.LOCK_EX)
        yield




def new_flow_selection(source,uplinks,mode,available=None,*,chain='IPTM5_SELECT'):
    """Only marks NEW forwarded connections; established conntrack marks stay."""
    if mode not in ('balanced','failover'):raise NetworkError('Strategia WAN sconosciuta')
    if chain not in ('IPTM5_SELECT', PICK_A, PICK_B):raise NetworkError('Catena di selezione WAN non consentita')
    selected=[(i,w) for i,w in enumerate(uplinks) if available is None or w['interface'] in available]
    if not selected:raise NetworkError('Nessuna WAN verificata per nuove connessioni')
    if mode=='failover':selected=selected[:1]
    remaining=sum(w['weight'] for i,w in selected)
    out=[]
    for index,wan in selected:
        mark='0x%08x' % ((index+1)<<24)
        if len(selected)>1 and (index,wan)!=selected[-1]:
            flags=['-m','statistic','--mode','random','--probability',f'{wan["weight"]/remaining:.8f}']
        else:flags=[]
        remaining-=wan['weight']
        out.append(['iptables','-w','-t','mangle','-A',chain,
                    '-m','mark','--mark','0x00000000/0xff000000']+flags+
                   ['-j','MARK','--set-xmark',mark+'/0xff000000'])
    return out


def route_commands(step):
    """PBR for forwarded flows: stable marks, symmetric return and per-WAN tables."""
    uplinks=step['uplinks'];source=step['source'];name='IPTM5_MARK';picker='IPTM5_SELECT'
    # Double-buffered WAN selectors: build new rules in the inactive chain,
    # then replace one jump atomically. Never flush the chain carrying traffic.
    cmds=[(['iptables','-w','-t','mangle','-N',name],['iptables','-w','-t','mangle','-F',name]),
          (['iptables','-w','-t','mangle','-N',picker],['iptables','-w','-t','mangle','-F',picker]),
          (['iptables','-w','-t','mangle','-N',PICK_A],['iptables','-w','-t','mangle','-F',PICK_A]),
          (['iptables','-w','-t','mangle','-N',PICK_B],['iptables','-w','-t','mangle','-F',PICK_B]),
          (['iptables','-w','-t','mangle','-A',picker,'-j',PICK_A],
           ['iptables','-w','-t','mangle','-D',picker,'-j',PICK_A]),
          (['iptables','-w','-t','mangle','-I','PREROUTING','1','-j',name],
           ['iptables','-w','-t','mangle','-D','PREROUTING','-j',name])]
    for destination in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','169.254.0.0/16','127.0.0.0/8'):
        cmds.append((['iptables','-w','-t','mangle','-A',name,'-i',source,'-d',destination,'-j','RETURN'],None))
    cmds.append((['iptables','-w','-t','mangle','-A',name,'-i',source,'-m','conntrack','--ctstate','ESTABLISHED,RELATED',
                  '-j','CONNMARK','--restore-mark','--nfmask','0xff000000','--ctmask','0xff000000'],None))
    cmds.append((['iptables','-w','-t','mangle','-A',name,'-i',source,'-m','conntrack','--ctstate','NEW',
                  '-m','connmark','--mark','0x00000000/0xff000000','-j',picker],None))
    cmds.extend((x,None) for x in new_flow_selection(source,uplinks,step['mode'],chain=PICK_A))
    cmds.append((['iptables','-w','-t','mangle','-A',name,'-i',source,'-m','conntrack','--ctstate','NEW',
                  '-j','CONNMARK','--save-mark','--nfmask','0xff000000','--ctmask','0xff000000'],None))
    for i,w in enumerate(uplinks):
        dev=w['interface'];gateway=w['gateway'];mark='0x%08x' % ((i+1)<<24)
        cmds.append((['iptables','-w','-t','mangle','-A',name,'-i',dev,'-m','conntrack','--ctstate','NEW',
                      '-j','CONNMARK','--set-xmark',mark+'/0xff000000'],None))
        table=str(220+i);priority=str(12010+i)
        cmds.append((['ip','-4','route','add','default','via',gateway,'dev',dev,'table',table],
                     ['ip','-4','route','flush','table',table]))
        cmds.append((['ip','-4','rule','add','priority',priority,'fwmark',mark+'/0xff000000','lookup',table],
                     ['ip','-4','rule','del','priority',priority,'fwmark',mark+'/0xff000000','lookup',table]))
    return cmds


def health_check(*,runner=None):
    """Hysteresis: avoid flipping when a single gateway probe fails.

    Only new-flow selection rules are touched. Existing conntrack state and
    the kernel's default route are left intact. No full chain flush.
    """
    require_root()
    state=read_doc(STATE)
    if not state or state.get('status')!='confirmed':return {'ok':True,'status':'inactive'}
    raw=read_doc(PLAN) or {}
    wan=raw.get('wan')
    if not wan:return {'ok':True,'status':'no-multiwan'}
    uplinks=wan['uplinks'];hist_path=ROOT/'wan-health.json'
    old=read_doc(hist_path) or {'links':{},'active':[]}
    links=old.get('links',{});now=[]
    for item in uplinks:
        dev=item['interface'];gateway=item['gateway']
        row=links.get(dev,{'fails':0,'passes':0,'healthy':True})
        probe=run(['ping','-n','-c','1','-W','2','-I',dev,gateway],runner=runner,check=False,timeout=6)
        if probe.returncode==0:
            row['passes']=min(4,row.get('passes',0)+1);row['fails']=0
            if row['passes']>=2:row['healthy']=True
        else:
            row['fails']=min(4,row.get('fails',0)+1);row['passes']=0
            if row['fails']>=3:row['healthy']=False
        links[dev]=row
        if row['healthy']:now.append(dev)
    if not now:
        # Both gateways failed: do not disconnect every new flow by clearing all.
        now=old.get('active') or [uplinks[0]['interface']]
    # Read the kernel's actual single selector jump; the on-disk journal is
    # not authoritative after a process crash or a failed disk write.
    rules=run(['iptables','-w','-t','mangle','-S','IPTM5_SELECT'],runner=runner)
    entries=[line.split() for line in rules.stdout.splitlines()
             if line.startswith('-A IPTM5_SELECT ')]
    if len(entries)!=1 or entries[0][:3]!=['-A','IPTM5_SELECT','-j'] or \
       len(entries[0])!=4 or entries[0][3] not in (PICK_A,PICK_B):
        raise NetworkError('Selettore WAN non riconosciuto: cambio negato')
    active=entries[0][3]
    if now!=old.get('active') or active!=old.get('selector'):
        inactive=PICK_B if active==PICK_A else PICK_A
        # Only the *inactive* chain is ever flushed. A failed append does not
        # alter the active forwarding path, and no conntrack entries are cleared.
        run(['iptables','-w','-t','mangle','-F',inactive],runner=runner)
        try:
            for cmd in new_flow_selection(wan['source'],uplinks,wan['mode'],now,chain=inactive):
                run(cmd,runner=runner)
        except Exception:
            run(['iptables','-w','-t','mangle','-F',inactive],runner=runner,check=False)
            raise
        # iptables -R replaces a single jump in one kernel operation.
        run(['iptables','-w','-t','mangle','-R','IPTM5_SELECT','1','-j',inactive],runner=runner)
    write_doc(hist_path,{'links':links,'active':now,'selector':inactive if (now!=old.get('active') or active!=old.get('selector')) else active,
                         'updated_at':int(time.time()),'mode':wan['mode']})
    return {'ok':True,'status':'healthy' if len(now)==len(uplinks) else 'degraded','active':now}


def network_command_list(step):
    """Convert selected operations into commands and idempotent reverse operations.

    Existing IPs and interfaces are *never* deleted; rollback owns only created
    kernel links, aliases, iptables chains, ip rules and routes from this engine.
    """
    kind=step['kind']
    if kind=='vlan':
        n,p,vid=step['name'],step['parent'],str(step['vid'])
        out=[(['ip','link','add','link',p,'name',n,'type','vlan','id',vid],['ip','link','del','dev',n])]
        out.append((['ip','link','set','dev',n,'alias',OWNED_LINK_TAG],None))
        if step['address']:out.append((['ip','addr','add',step['address'],'dev',n],None))
        out.append((['ip','link','set',n,'up'],None));return out
    if kind=='alias':
        dev=step['interface'];ip=step['address']
        return [(['ip','addr','add',ip,'dev',dev],['ip','addr','del',ip,'dev',dev])]
    if kind=='bridge':
        n=step['name'];cmds=[(['ip','link','add','name',n,'type','bridge','stp_state','1' if step['stp'] else '0'],['ip','link','del','dev',n])]
        cmds.append((['ip','link','set','dev',n,'alias',OWNED_LINK_TAG],None))
        for p in step['ports']:
            cmds.append((['ip','link','set',p,'master',n],['ip','link','set',p,'nomaster']))
        if step['address']:cmds.append((['ip','addr','add',step['address'],'dev',n],None))
        cmds.append((['ip','link','set',n,'up'],None));return cmds
    if kind=='bond':
        n=step['name'];cmds=[(['ip','link','add','name',n,'type','bond','mode',step['mode']],['ip','link','del','dev',n])]
        cmds.append((['ip','link','set','dev',n,'alias',OWNED_LINK_TAG],None))
        for p in step['ports']:
            cmds.append((['ip','link','set',p,'master',n],['ip','link','set',p,'nomaster']))
        if step['address']:cmds.append((['ip','addr','add',step['address'],'dev',n],None))
        cmds.append((['ip','link','set',n,'up'],None));return cmds
    if kind=='firewall':
        cmds=[(['iptables','-w','-N',CHAIN_FWD],['iptables','-w','-F',CHAIN_FWD]),
              (['iptables','-w','-I','FORWARD','1','-j',CHAIN_FWD],['iptables','-w','-D','FORWARD','-j',CHAIN_FWD])]
        z={x['name']:x for x in step['zones']}
        allowed={(x['from'],x['to']) for x in step['allow']}
        for src in z.values():
            for dst in z.values():
                if src['name']==dst['name']:continue
                if (src['name'],dst['name']) in allowed:
                    continue  # Existing firewall decides; no unconditional ACCEPT bypass.
                cmds.append((['iptables','-w','-A',CHAIN_FWD,'-i',src['interface'],'-o',dst['interface'],'-j','DROP'],None))
        if step['masquerade']:
            cmds.append((['iptables','-w','-t','nat','-N',CHAIN_NAT],['iptables','-w','-t','nat','-F',CHAIN_NAT]))
            cmds.append((['iptables','-w','-t','nat','-I','POSTROUTING','1','-j',CHAIN_NAT],['iptables','-w','-t','nat','-D','POSTROUTING','-j',CHAIN_NAT]))
            for item in step['masquerade']:
                source=z[item['from']]['network']
                cmds.append((['iptables','-w','-t','nat','-A',CHAIN_NAT,'-s',source,'-o',item['wan'],'-j','MASQUERADE'],None))
        return cmds
    if kind=='wan':
        return route_commands(step)
    return []


def pihole_call(method,path,body=None,*,port=80,password=None,transport=None,sid=None):
    """Pi-hole API v6 on loopback. Never redirect an authenticated request."""
    import urllib.request
    if method not in ('GET','PATCH','POST') or path not in ('/api/auth','/api/config','/api/config/dhcp','/api/config/dns'):
        raise NetworkError('Endpoint Pi-hole non autorizzato')
    if password is not None:
        raise NetworkError('Credenziali API non devono essere passate come parametro secondario')
    headers={'Content-Type':'application/json'}
    if sid:
        if not isinstance(sid,str) or not 8<=len(sid)<=256:
            raise NetworkError('SID Pi-hole non valido')
        headers['X-FTL-SID']=sid
    data=json.dumps(body,separators=(',',':')).encode() if body is not None else None
    req=urllib.request.Request(f'http://127.0.0.1:{bounded(port,1,65535)}{path}',headers=headers,data=data,method=method)
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request, fp, code, msg, headers, newurl):
            raise NetworkError('Pi-hole API: redirect vietato per proteggere il SID')
    try:
        open_request=transport or urllib.request.build_opener(NoRedirect()).open
        response=open_request(req,timeout=7)
        with response:
            payload=response.read(65537)
            if len(payload)>65536:raise NetworkError('Risposta API eccessiva')
            if not payload and method=='PATCH' and getattr(response,'status',200)==204:
                return {'ok':True}
            obj=json.loads(payload)
            if not isinstance(obj,dict) or obj.get('error'):
                raise NetworkError('API Pi-hole: risposta non valida')
            return obj
    except (OSError,ValueError) as exc:
        raise NetworkError('API Pi-hole non disponibile o incompatibile') from exc


def api_session(port,transport=None):
    from pihole_credentials import get_password
    password=get_password()
    if not password:raise NetworkError('Credenziali API Pi-hole non configurate')
    obj=pihole_call('POST','/api/auth',{'password':password},port=port,transport=transport)
    sid=(obj.get('session') or {}).get('sid')
    if not isinstance(sid,str) or not 8<=len(sid)<=256:raise NetworkError('Sessione Pi-hole API non valida')
    return sid


def get_dhcp(port,sid,transport=None):
    obj=pihole_call('GET','/api/config/dhcp',port=port,sid=sid,transport=transport)
    record=obj.get('config',{}).get('dhcp') if isinstance(obj.get('config'),dict) else obj.get('dhcp')
    if not isinstance(record,dict) or any(k not in record for k in ('active','start','end','router','netmask')):
        raise NetworkError('Schema DHCP Pi-hole non compatibile')
    return {k:record[k] for k in ('active','start','end','router','netmask')}


def patch_dhcp(port,sid,dhcp,transport=None):
    payload={'config':{'dhcp':dhcp}}
    return pihole_call('PATCH','/api/config',payload,port=port,sid=sid,transport=transport)


# Pi-hole v6 dns.interface also controls DHCP. A guarded API change keeps
# the second LAN from becoming the primary DHCP interface on link-up.
BIND_STATE = Path('/var/lib/iptm-pihole-bind/state.json')
BIND_ROOT = BIND_STATE.parent
BIND_UNIT = Path('/etc/systemd/system/iptm-pihole-bind-boot.service')
BIND_TIMER = 'iptm-pihole-bind-revert'
BIND_TTL = 120


def pihole_dns_interface(port,sid,transport=None):
    obj=pihole_call('GET','/api/config/dns',port=port,sid=sid,transport=transport)
    data=obj.get('config',{}).get('dns') if isinstance(obj.get('config'),dict) else obj.get('dns')
    if not isinstance(data,dict) or not isinstance(data.get('interface'),str):
        raise NetworkError('Schema Pi-hole dns.interface non riconosciuto')
    return data['interface']


def pihole_dns_patch(port,sid,interface,transport=None):
    if interface and (not IFACE.fullmatch(interface) or interface in RESERVED):
        raise NetworkError('Interfaccia Pi-hole non valida')
    return pihole_call('PATCH','/api/config',{'config':{'dns':{'interface':interface}}},port=port,sid=sid,transport=transport)


def pihole_bind_save(doc):
    ensure_private(BIND_ROOT)
    write_doc(BIND_STATE,doc)


def pihole_bind_read():
    obj=read_doc(BIND_STATE)
    if obj and (obj.get('schema')!=1 or obj.get('status') not in ('pending','confirmed','rollback-incomplete')):
        raise NetworkError('Journal vincolo Pi-hole sconosciuto')
    return obj


def pihole_bind_install_guard(*, runner=None):
    require_console()
    if BIND_UNIT.is_symlink():raise NetworkError('Unità recovery simbolica non consentita')
    if BIND_UNIT.exists() and 'Description=IPTM Pi-hole interface boot recovery' not in BIND_UNIT.read_text():
        raise NetworkError('Unità di recupero Pi-hole non gestita da IPTM')
    content=('[Unit]\nDescription=IPTM Pi-hole interface boot recovery\nAfter=pihole-FTL.service\n'
             '[Service]\nType=oneshot\nExecStart=/usr/local/sbin/iptm-helper pihole-bind boot-recover\n'
             '[Install]\nWantedBy=multi-user.target\n')
    fd,t=tempfile.mkstemp(prefix='.iptm-pihole-',dir=BIND_UNIT.parent)
    try:
        with os.fdopen(fd,'w') as f:
            f.write(content);f.flush();os.fsync(f.fileno());os.fchmod(f.fileno(),0o644)
        os.replace(t,BIND_UNIT)
    finally:
        if os.path.exists(t):os.unlink(t)
    run(['systemctl','daemon-reload'],runner=runner)
    run(['systemctl','enable','iptm-pihole-bind-boot.service'],runner=runner)
    return {'ok':True,'guard':'installed'}


def pihole_bind_rollback(*, port=None, runner=None):
    state=pihole_bind_read()
    if not state or state.get('status')!='pending':return {'ok':True,'status':'idle'}
    original=state.get('original')
    if not isinstance(original,str) or len(original)>15:
        raise NetworkError('Backup interfaccia Pi-hole non valido')
    port=port or state.get('port')
    try:
        sid=api_session(port)
        pihole_dns_patch(port,sid,original)
        if pihole_dns_interface(port,sid)!=original:raise NetworkError('API Pi-hole non ha ripristinato il valore')
    except NetworkError:
        # Independent local FTL CLI is used if the API is unreachable.
        try:run(['pihole-FTL','--config','dns.interface',original],runner=runner)
        except NetworkError:
            state['status']='rollback-incomplete';pihole_bind_save(state)
            raise
    BIND_STATE.unlink()
    return {'ok':True,'status':'restored','interface':original}


def pihole_bind(args):
    require_root()
    if not args:raise NetworkError('Comando Pi-hole mancante')
    action=args[0]
    if action in ('install-guard','apply','confirm','rollback'):
        require_console()
    if action=='install-guard' and len(args)==1:return pihole_bind_install_guard()
    if action in ('expire','boot-recover','rollback') and len(args)==1:
        return pihole_bind_rollback()
    if action=='status' and len(args)==1:
        return {'ok':True,'state':(pihole_bind_read() or {}).get('status','idle')}
    if action in ('preview','apply') and len(args)==2:
        interface=nic(args[1]);live=get_live()
        links=physical(live)
        if interface not in links or links[interface].get('master'):
            raise NetworkError('Pi-hole richiede un master o una NIC indipendente')
        if interface not in {x.get('dev') for x in live['default']}:
            # An explicit non-WAN primary can be supported later, but never
            # silently disconnect the actual management DNS path.
            raise NetworkError('Pi-hole: verificare prima la rete primaria e l’accesso DNS')
        port=8089;sid=api_session(port);original=pihole_dns_interface(port,sid)
        if action=='preview':return {'ok':True,'current':original,'proposed':interface,'changes':False}
        state=pihole_bind_read()
        if state and state.get('status') in ('pending','rollback-incomplete'):
            raise NetworkError('Modifica Pi-hole già pendente')
        if not BIND_UNIT.is_file() or 'Description=IPTM Pi-hole interface boot recovery' not in BIND_UNIT.read_text():
            raise NetworkError('Prima installare il watchdog Pi-hole da console')
        if original==interface:return {'ok':True,'status':'already-configured','interface':interface}
        token=secrets.token_hex(12)
        doc={'schema':1,'status':'pending','token':token,'original':original,
             'requested':interface,'port':port,'started_at':int(time.time())}
        pihole_bind_save(doc)
        try:
            run(['systemd-run','--quiet','--unit='+BIND_TIMER,'--on-active='+str(BIND_TTL)+'s',
                 '/usr/local/sbin/iptm-helper','pihole-bind','expire'])
        except Exception:
            # No change to FTL has been attempted. Do not leave a phantom pending journal.
            if BIND_STATE.exists(): BIND_STATE.unlink()
            raise
        try:
            pihole_dns_patch(port,sid,interface)
            if pihole_dns_interface(port,sid)!=interface:
                raise NetworkError('Interfaccia Pi-hole non confermata')
        except Exception:
            # Keep watchdog armed when apply failed or acknowledgement failed.
            raise
        return {'ok':True,'status':'pending','interface':interface,'token':token,
                'expires_seconds':BIND_TTL}
    if action=='confirm' and len(args)==2 and HEX24.fullmatch(args[1]):
        state=pihole_bind_read()
        if not state or state.get('status')!='pending' or state.get('token')!=args[1]:
            raise NetworkError('Token conferma non valido')
        sid=api_session(state['port'])
        if pihole_dns_interface(state['port'],sid)!=state['requested']:
            raise NetworkError('Pi-hole non usa l’interfaccia richiesta')
        # Commit the state before stopping the timer: if interrupted, the timer
        # sees a confirmed record and cannot undo an already accepted choice.
        state['status']='confirmed';pihole_bind_save(state)
        run(['systemctl','stop',BIND_TIMER+'.timer'],check=False)
        return {'ok':True,'status':'confirmed','interface':state['requested']}
    raise NetworkError('Comando Pi-hole non autorizzato')


def ensure_secondary_link(name, *, runner=None, live=None):
    """Require a physical, independent, connected secondary DHCP port.

    Never assume a link without carrier is safe for DHCP. The kernel check is
    performed immediately before the daemon starts, not just at plan time.
    """
    data = live if live is not None else get_live(runner)
    link=next((x for x in data['links'] if x.get('ifname')==name),None)
    if not link or not is_physical(link) or link.get('master'):
        raise NetworkError('DHCP secondario: richiede NIC fisica libera')
    if str(link.get('operstate','')).upper() in ('DOWN','LOWERLAYERDOWN','NOTPRESENT','DORMANT') or link.get('carrier') is False:
        raise NetworkError('DHCP secondario: portante non disponibile')
    if runner is None:
        carrier=Path('/sys/class/net',name,'carrier')
        if not carrier.is_file() or carrier.read_text().strip()!='1':
            raise NetworkError('DHCP secondario: nessuna portante Ethernet')
    return True


def verify_secondary_listeners(sockets: str, interface: str, server_ip: str) -> None:
    """Make sure DHCP service actually bound to the secondary LAN, never globally."""
    from network_audit import parse_dhcp_sockets
    if not IFACE.fullmatch(interface):
        raise NetworkError('DHCP: interfaccia non valida')
    try: ipaddress.IPv4Address(server_ip)
    except ValueError as exc:raise NetworkError('DHCP: server non valido') from exc
    records=parse_dhcp_sockets(sockets)
    if not any('dnsmasq' in row['process'] and
               (row['interface_scope']==interface or row['local'].startswith(server_ip+':67'))
               for row in records):
        raise NetworkError('DHCP secondario senza listener UDP 67 sulla NIC scelta')
    if any('dnsmasq' in row['process'] and row['wildcard'] and not row['interface_scope']
           for row in records):
        raise NetworkError('DHCP secondario ascolta su tutte le schede: rollback')


def configure_secondary(step,*,runner=None,previous=None,sid=None):
    path=ROOT/'dhcp-secondary.conf'
    unit=Path('/etc/systemd/system/iptm-dhcp-secondary.service')
    if path.exists() or path.is_symlink() or unit.exists() or unit.is_symlink():
        raise NetworkError('DHCP secondario già configurato: niente sovrascritture automatiche')
    if not shutil.which('dnsmasq'):raise NetworkError('dnsmasq non installato')
    # A secondary DHCP server must not start on an unplugged or administratively
    # down interface. A missing carrier is NOT a sign that a link is safe to use.
    ensure_secondary_link(step['plan']['secondary']['interface'], runner=runner)
    # Socket ownership is a mandatory *live* preflight. A wildcard UDP 67
    # listener can prevent reliable binding of the second DHCP server.
    from network_audit import dhcp_preflight, SafetyError
    try:
        probe=dhcp_preflight(step['plan']['primary']['interface'],
                             step['plan']['secondary']['interface'])
    except SafetyError as exc:
        raise NetworkError('DHCP: socket/gestori non verificabili: '+str(exc)) from exc
    if not probe['can_start_secondary']:
        raise NetworkError('DHCP: '+', '.join(probe['blockers']))
    # A link coming UP must never cause FTL auto-detection to serve DHCP on
    # the secondary NIC. Pin FTL's shared DNS/DHCP interface before apply.
    from network_audit import pihole_dhcp_local
    ftl=pihole_dhcp_local()
    if ftl.get('fields',{}).get('interface')!=step['plan']['primary']['interface']:
        raise NetworkError('Pi-hole dns.interface non vincolata alla NIC primaria: DHCP secondario bloccato')
    # Revalidate expected FTL state by API, including its previous values.
    p=step['plan'];port=step['api_port']
    sid=sid or api_session(port)
    previous=previous or get_dhcp(port,sid)
    if previous['active'] is not True:
        raise NetworkError('Pi-hole non è DHCP primario attivo: rifiuto aggiornamento')
    if str(previous['router'])!=p['primary']['gateway']:
        raise NetworkError('Pi-hole gateway attuale diverso: riconfigurazione remota vietata')
    # Bound DHCP secondary to one NIC and no DNS port; isolated service instance.
    raw=p['secondary_config_preview'].replace('# IPTM 4.7.1 - BOZZA, non installare senza verifica UDP/67 e isolamento L2',
                                               '# IPTM network-runtime managed, one isolated DHCP domain')
    fd,tmp=tempfile.mkstemp(prefix='iptm-dhcp-test-',suffix='.conf')
    try:
        os.write(fd,raw.encode());os.close(fd)
        run(['dnsmasq','--test','--conf-file='+tmp],runner=runner)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)
    ensure_private(path.parent)
    atom(path,raw.encode())
    content=('[Unit]\nDescription=IPTM isolated secondary DHCP\nAfter=network-online.target iptm-network-runtime.service pihole-FTL.service\nWants=network-online.target\n'
             '[Service]\nType=simple\nExecStart=/usr/sbin/dnsmasq --keep-in-foreground --conf-file='+str(path)+'\n'
             'Restart=on-failure\nRestartSec=3s\n'
             '[Install]\nWantedBy=multi-user.target\n')
    # Use private staging then install a world-readable unit (no secrets in it).
    fd,t=tempfile.mkstemp(prefix='.iptm-dhcp-',dir=unit.parent)
    try:
        with os.fdopen(fd,'w') as f:f.write(content);f.flush();os.fsync(f.fileno());os.fchmod(f.fileno(),0o644)
        os.replace(t,unit)
    finally:
        if os.path.exists(t):os.unlink(t)
    run(['systemctl','daemon-reload'],runner=runner)
    run(['systemctl','start','iptm-dhcp-secondary.service'],runner=runner)
    # Verify a *real* running service and a bounded UDP/67 socket. A successful
    # systemctl start alone is not sufficient: dnsmasq may exit immediately.
    active=run(['systemctl','is-active','iptm-dhcp-secondary.service'],runner=runner,check=False)
    if active.returncode or active.stdout.strip()!='active':
        raise NetworkError('DHCP secondario non attivo dopo avvio: rollback necessario')
    sockets=run(['ss','-H','-u','-l','-n','-p'],runner=runner).stdout
    verify_secondary_listeners(sockets,p['secondary']['interface'],p['secondary']['server_ip'])
    patch_dhcp(port,sid,p['primary_api']['payload']['config']['dhcp'])
    return {'previous_dhcp':previous,'port':port,'unit':str(unit),'path':str(path)}


def rollback_secondary(info,*,runner=None):
    errors=[]
    try:
        sid=api_session(info['port'])
        patch_dhcp(info['port'],sid,info['previous_dhcp'])
    except Exception:
        # Root-local documented FTL configuration CLI is an independent
        # recovery path if the HTTP API has become unavailable.
        previous=info.get('previous_dhcp') or {}
        try:
            if set(previous)!={'active','start','end','router','netmask'}:
                raise NetworkError('Backup DHCP precedente incompleto')
            for key in ('start','end','router','netmask','active'):
                val=previous[key]
                if key=='active' and type(val) is not bool:raise NetworkError('DHCP active non booleano')
                if key!='active' and (not isinstance(val,str) or len(val)>32):raise NetworkError('DHCP campo non valido')
                run(['pihole-FTL','--config','dhcp.'+key,
                     'true' if val is True else 'false' if val is False else val],runner=runner)
        except Exception:errors.append('pihole-dhcp-restore-failed')
    # Never stop or delete a foreign service that occupied our service name.
    # This snapshot is recorded before creating either file.
    if not info.get('paths_were_absent'):
        errors.append('DHCP service ownership unknown; no files deleted')
        return errors
    unit=Path(info['unit']);path=Path(info['path'])
    if any(p.is_symlink() for p in (unit,path)):
        errors.append('DHCP: symbolic link unexpectedly installed')
        return errors
    marker_unit='Description=IPTM isolated secondary DHCP'
    marker_conf='# IPTM network-runtime managed, one isolated DHCP domain'
    if unit.is_file() and marker_unit not in unit.read_text():
        errors.append('DHCP: existing service not owned by IPTM')
        return errors
    if path.is_file() and marker_conf not in path.read_text():
        errors.append('DHCP: existing config not owned by IPTM')
        return errors
    if unit.is_file():
        run(['systemctl','stop','iptm-dhcp-secondary.service'],runner=runner,check=False)
        run(['systemctl','disable','iptm-dhcp-secondary.service'],runner=runner,check=False)
    for f in (unit,path):
        if f.is_file():f.unlink()
    run(['systemctl','daemon-reload'],runner=runner,check=False)
    return errors



def install_health_units(*,runner=None):
    require_root()
    configs=(
      (HEALTH_SERVICE,'[Unit]\nDescription=IPTM WAN health and route selection\nAfter=network-online.target iptm-network-runtime.service\n'
       '[Service]\nType=oneshot\nExecStart=/usr/bin/python3 -B '+SCRIPT+' health-check\n'),
      (HEALTH_TIMER,'[Unit]\nDescription=IPTM WAN health minute monitor\n'
       '[Timer]\nOnBootSec=70s\nOnUnitActiveSec=60s\nAccuracySec=5s\nUnit=iptm-network-wan-health.service\n'
       '[Install]\nWantedBy=timers.target\n'))
    for path,txt in configs:
        if path.is_symlink():raise NetworkError('Unità monitor symlink')
        if path.exists() and 'Description=IPTM WAN health' not in path.read_text():
            raise NetworkError('Unità WAN esistente sconosciuta')
        fd,tmp=tempfile.mkstemp(prefix='.iptm-wan-',dir=path.parent)
        try:
            with os.fdopen(fd,'w') as f:
                os.fchmod(f.fileno(),0o644);f.write(txt);f.flush();os.fsync(f.fileno())
            os.replace(tmp,path)
        finally:
            if os.path.exists(tmp):os.unlink(tmp)
    run(['systemctl','daemon-reload'],runner=runner)


def guard_install(*,runner=None):
    require_root()
    previous=read_doc(STATE)
    if previous and previous.get('status') in ('pending','confirmed','reconciling','rollback-incomplete') and previous.get('version')!=VERSION:
        # Replacing the boot recovery worker of an active older release would
        # strand its undo log on an incompatible runtime. Migrate only via a
        # dedicated reviewed state schema, never implicitly during install.
        raise NetworkError('Transazione di release precedente attiva: mantenere il watchdog originale')
    if BOOT_UNIT.is_symlink():raise NetworkError('Unità boot recovery non sicura')
    if BOOT_UNIT.exists() and 'Description=IPTM network transaction boot recovery' not in BOOT_UNIT.read_text():
        raise NetworkError('Unità di sistema preesistente sconosciuta')
    script=Path(SCRIPT)
    if runner is None and not script.is_file():raise NetworkError('Installazione moduli versione errata')
    contents=('[Unit]\nDescription=IPTM network transaction boot recovery\nAfter=local-fs.target network-online.target\n'
              'Wants=network-online.target\nAfter=pihole-FTL.service\n[Service]\nType=oneshot\nExecStart=/usr/bin/python3 -B '+SCRIPT+' boot-recover\n'
              '[Install]\nWantedBy=multi-user.target\n')
    fd,tmp=tempfile.mkstemp(prefix='.iptm-net-',dir=BOOT_UNIT.parent)
    try:
        with os.fdopen(fd,'w') as f:f.write(contents);f.flush();os.fsync(f.fileno());os.fchmod(f.fileno(),0o644)
        os.replace(tmp,BOOT_UNIT)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)
    run(['systemctl','daemon-reload'],runner=runner)
    run(['systemctl','enable',BOOT_UNIT.name],runner=runner)
    install_health_units(runner=runner)
    return {'installed':True,'unit':str(BOOT_UNIT)}


def guard_ready(*,runner=None):
    if BOOT_UNIT.is_symlink() or not BOOT_UNIT.is_file() or SCRIPT not in BOOT_UNIT.read_text():
        raise NetworkError('Il watchdog boot non è installato per questa release')
    p=run(['systemctl','is-enabled',BOOT_UNIT.name],runner=runner,check=False)
    if p.returncode or p.stdout.strip()!='enabled':raise NetworkError('Recupero boot disabilitato')


def mark(state,status):
    state['status']=status;write_doc(STATE,state)


def apply_plan(expected,*,runner=None,live=None):
    require_root()
    if not HEX64.fullmatch(expected):raise NetworkError('Digest piano non valido')
    guard_ready(runner=runner)
    pending=read_doc(STATE)
    if pending and pending.get('status') in ('pending','confirmed','rollback-incomplete'):
        raise NetworkError('Transazione precedente non chiusa')
    raw=read_doc(PLAN)
    if raw is None:raise NetworkError('Nessun piano root configurato')
    # Reserve our owned chains/tables. Existing firewall or PBR state must survive.
    for table,chain in [('filter',CHAIN_FWD),('nat',CHAIN_NAT),('mangle','IPTM5_MARK'),('mangle','IPTM5_SELECT'),('mangle',PICK_A),('mangle',PICK_B)]:
        p=run(['iptables','-w','-t',table,'-S',chain],runner=runner,check=False)
        if p.returncode==0:raise NetworkError('Catena IPTM già esistente: rifiuto sovrascrittura')
    if raw.get('wan'):
        for i in range(len(raw['wan']['uplinks'])):
            if cmd_json(['ip','-j','-4','route','show','table',str(220+i)],runner):
                raise NetworkError('Tabella policy routing già occupata')
        rules=cmd_json(['ip','-j','-4','rule','show'],runner)
        if any(12010<=int(r.get('priority',0))<=12012 for r in rules):
            raise NetworkError('Priorità policy routing già occupata')
    validated=validate_config(raw,live or get_live(runner))
    if validated['hash']!=expected:raise NetworkError('Piano o hardware modificato')
    now=int(time.time())
    state={'schema':1,'version':VERSION,'status':'pending','token':secrets.token_hex(12),
           'created':now,'deadline':now+TTL,'hash':expected,'undo':[], 'dhcp':None,
           'boot_id':boot_id(), 'ports':_snapshot_port_owners(validated['steps'],live or get_live(runner))}
    write_doc(STATE,state)
    try:
        run(['systemd-run',f'--unit={TIMER}',f'--on-active={TTL}s','--collect','/usr/bin/python3','-B',SCRIPT,'expire'],runner=runner)
        for step in validated['steps']:
            if step['kind']=='dhcp':
                # Save original live values and recovery paths BEFORE any change.
                sid=api_session(step['api_port'])
                previous=get_dhcp(step['api_port'],sid)
                unit=Path('/etc/systemd/system/iptm-dhcp-secondary.service')
                conf=ROOT/'dhcp-secondary.conf'
                if any(f.exists() or f.is_symlink() for f in (unit,conf)):
                    raise NetworkError('DHCP service/config present before applying: no overwrites')
                state['dhcp']={'port':step['api_port'],'unit':str(unit),
                               'path':str(conf),'previous_dhcp':previous,
                               'paths_were_absent':True}
                write_doc(STATE,state)
                info=configure_secondary(step,runner=runner,previous=previous,sid=sid)
                info['paths_were_absent']=True
                state['dhcp']=info;write_doc(STATE,state)
                continue
            for forward,undo in network_command_list(step):
                if undo is not None:
                    state['undo'].insert(0,undo)
                    write_doc(STATE,state)
                run(forward,runner=runner)
        # A failed health check always rolls back instead of leaving new rules.
        run(['ip','-j','-4','route','show','default'],runner=runner)
        state['status']='pending';write_doc(STATE,state)
        return {'ok':True,'status':'pending','token':state['token'],'seconds':TTL}
    except Exception:
        rollback_state(state,runner=runner)
        raise


def owned_link(name,*,runner=None):
    # An interface name is not an ownership token. NetworkManager, udev, or
    # another service may replace an interface between apply and recovery.
    result=run(['ip','-j','-d','link','show','dev',name],runner=runner,check=False)
    if result.returncode:return False
    try: links=json.loads(result.stdout)
    except (ValueError,TypeError):return False
    return (isinstance(links,list) and len(links)==1 and
            links[0].get('ifname')==name and links[0].get('ifalias')==OWNED_LINK_TAG)


def _port_fingerprint(link):
    # The ifindex plus MAC identifies a live NIC for the duration of a trial.
    return {'ifindex':link.get('ifindex'),'address':link.get('address')}


def _safe_slave_undo(command, state, *, runner=None):
    """Never detach a port from a different master or a recycled NIC name."""
    if not (command[:3] == ['ip','link','set'] and len(command)==5 and
            command[4]=='nomaster'):
        return True, ''
    port=command[3]
    entry=(state.get('ports') or {}).get(port)
    if not isinstance(entry,dict) or not entry.get('master'):
        return False, 'Rollback slave privo di identità: '+port
    response=run(['ip','-j','-d','link','show','dev',port],runner=runner,check=False)
    if response.returncode:
        return False, 'Porta non recuperabile: '+port
    try:
        links=json.loads(response.stdout)
    except (TypeError,ValueError):
        return False, 'Dati NIC non validi: '+port
    if not isinstance(links,list) or len(links)!=1:
        return False, 'Identità NIC ambigua: '+port
    link=links[0]
    if (link.get('ifname')!=port or _port_fingerprint(link)!=entry.get('fingerprint')):
        return False, 'Identità porta cambiata: '+port
    # If a different manager took this interface, leave it alone.
    if link.get('master') != entry['master']:
        return False, 'Master della porta cambiato: '+port
    if not owned_link(entry['master'],runner=runner):
        return False, 'Master non più di proprietà IPTM: '+port
    return True, ''


def _snapshot_port_owners(steps, live):
    names=physical(live);out={}
    for step in steps:
        if step.get('kind') not in ('bridge','bond'):
            continue
        for name in step['ports']:
            link=names[name]
            fp=_port_fingerprint(link)
            if type(fp['ifindex']) is not int or not isinstance(fp['address'],str) or not fp['address']:
                raise NetworkError('Identità slave non verificabile: '+name)
            out[name]={'master':step['name'],'fingerprint':fp}
    return out


def rollback_state(state,*,runner=None):
    require_root();errors=[]
    if state.get('version') not in (None,VERSION):
        raise NetworkError('Rollback di altra release: usare il worker originario')
    run(['systemctl','disable','--now',HEALTH_TIMER.name],runner=runner,check=False)
    if state.get('dhcp'):
        info=state['dhcp']
        if info.get('previous_dhcp') is None:
            # Pi-hole may already have changed between state writes: snapshot was
            # not yet captured, so do not silently assume it is recoverable.
            errors.append('DHCP changes without committed prior-state snapshot')
        else:errors.extend(rollback_secondary(info,runner=runner))
    for command in state.get('undo',[]):
        if command[:3]==['ip','link','set'] and command[-1:] == ['nomaster']:
            allowed,reason=_safe_slave_undo(command,state,runner=runner)
            if not allowed:
                errors.append(reason)
                continue
        if command[:3]==['ip','link','del'] and not owned_link(command[-1],runner=runner):
            # Missing or re-owned links are left intact, never deleted by name.
            # A foreign live interface with the same name must survive rollback.
            check=run(['ip','-j','-d','link','show','dev',command[-1]],runner=runner,check=False)
            if check.returncode==0:errors.append('Link non riconosciuto, intervento manuale: '+command[-1])
            continue
        p=run(command,runner=runner,check=False)
        if p.returncode and not (command[0]=='ip' and 'del' in command):
            errors.append('rollback command failed: '+command[0])
    # Chain deletion after removing jump hooks; otherwise retain chain on error.
    for table,chain in [('filter',CHAIN_FWD),('nat',CHAIN_NAT),('mangle','IPTM5_MARK'),('mangle','IPTM5_SELECT'),('mangle',PICK_A),('mangle',PICK_B)]:
        p=run(['iptables','-w','-t',table,'-X',chain],runner=runner,check=False)
        if p.returncode and any(x[0]=='iptables' and chain in x for x in state.get('undo',[])):
            errors.append('iptables chain cleanup: '+chain)
    run(['systemctl','stop',TIMER+'.timer'],runner=runner,check=False)
    state['status']='rollback-incomplete' if errors else 'rolled-back'
    state['errors']=errors
    write_doc(STATE,state)
    return {'ok':not errors,'status':state['status'],'errors':errors}


def confirm(token,*,runner=None):
    require_root()
    state=read_doc(STATE)
    if not state or state.get('status')!='pending' or not HEX24.fullmatch(token) or token!=state.get('token'):
        raise NetworkError('Token o transazione non validi')
    if int(time.time())>=state['deadline']:
        return rollback_state(state,runner=runner)
    # Arm persistent WAN health checks before final confirmation.
    raw=read_doc(PLAN) or {}
    if raw.get('wan'):
        install_health_units(runner=runner)
        run(['systemctl','enable','--now',HEALTH_TIMER.name],runner=runner)
    if state.get('dhcp'):
        run(['systemctl','enable','iptm-dhcp-secondary.service'],runner=runner)
    state['status']='confirmed';write_doc(STATE,state)
    run(['systemctl','stop',TIMER+'.timer'],runner=runner,check=False)
    return {'ok':True,'status':'confirmed'}


def boot_recover(*,runner=None,live=None):
    require_root()
    state=read_doc(STATE)
    if not state:return {'ok':True,'status':'empty'}
    if state.get('version') not in (None,VERSION):
        raise NetworkError('Recovery di altra release: rifiuto gestione del journal')
    if state.get('status') in ('pending','reconciling'):
        # The old kernel state may have vanished on reboot; rollback never
        # restores foreign IP addresses or a global iptables snapshot.
        return rollback_state(state,runner=runner)
    if state.get('status')!='confirmed' or state.get('boot_id')==boot_id():
        return {'ok':True,'status':state['status']}
    raw=read_doc(PLAN)
    if not raw:raise NetworkError('Configurazione persistente assente')
    compiled=validate_config(raw,live or get_live(runner))
    if compiled['hash']!=state['hash']:
        raise NetworkError('Modello/hardware cambiato al boot: nessuna modifica applicata')
    # Refuse to overwrite chains potentially restored by iptables-persistent.
    for table,chain in [('filter',CHAIN_FWD),('nat',CHAIN_NAT),('mangle','IPTM5_MARK'),('mangle','IPTM5_SELECT'),('mangle',PICK_A),('mangle',PICK_B)]:
        if run(['iptables','-w','-t',table,'-S',chain],runner=runner,check=False).returncode==0:
            raise NetworkError('Catena persistita da altro gestore: intervento manuale necessario')
    state['status']='reconciling';state['boot_id']=boot_id();state['undo']=[]
    state['ports']=_snapshot_port_owners(compiled['steps'],live or get_live(runner))
    write_doc(STATE,state)
    try:
        for step in compiled['steps']:
            if step['kind']=='dhcp':continue  # Dedicated enabled service handles restart.
            for forward,undo in network_command_list(step):
                if undo:
                    state['undo'].insert(0,undo);write_doc(STATE,state)
                run(forward,runner=runner)
        state['status']='confirmed';write_doc(STATE,state)
        return {'ok':True,'status':'confirmed','reapplied':True}
    except Exception:
        rollback_state(state,runner=runner)
        raise


def stage(raw,*,runner=None,live=None):
    require_root()
    validated=validate_config(raw,live or get_live(runner))
    old=read_doc(STATE)
    if old and old.get('status') in ('pending','confirmed','rollback-incomplete'):
        raise NetworkError('Transazione esistente: eseguire rollback prima')
    write_doc(PLAN,raw)
    return {'ok':True,'hash':validated['hash'],'operations':len(validated['steps']),'watchdog':TTL}


def dhcp_stage_from_live(args,*,live=None,ftl=None):
    """Convenience CLI: derive Pi-hole master/pool from the current FTL state.

    A staged DHCP-only plan changes nothing. The existing console transaction
    applies it with a systemd rollback; no HTTP endpoint can call it.
    """
    if len(args)!=6 or args[5]!='ISOLATED-L2':
        raise NetworkError('Uso: dhcp-stage NIC CIDR POOL_START POOL_END PORT ISOLATED-L2')
    iface=nic(args[0]);secondary_cidr=addr4(args[1]);start=pure_ip(args[2]);end=pure_ip(args[3])
    try:port=int(args[4])
    except ValueError as exc:raise NetworkError('Porta API Pi-hole non valida') from exc
    bounded(port,1,65535)
    from network_audit import pihole_dhcp_local
    state=ftl if ftl is not None else pihole_dhcp_local()
    fields=state.get('fields') if isinstance(state,dict) else None
    if not isinstance(fields,dict) or fields.get('active') is not True:
        raise NetworkError('Pi-hole DHCP primario non attivo o non verificabile')
    primary=fields.get('interface','')
    if not isinstance(primary,str) or not IFACE.fullmatch(primary):
        raise NetworkError('Pi-hole deve essere vincolato a un master esplicito')
    for key in ('start','end','router','netmask'):
        if not fields.get(key):raise NetworkError('Pi-hole: campo DHCP mancante '+key)
    kernel=live if live is not None else get_live()
    try:
        network=ipaddress.IPv4Network(fields['router']+'/'+fields['netmask'],strict=False)
    except ValueError as exc:raise NetworkError('Rete DHCP Pi-hole non valida') from exc
    matching=[]
    for row in kernel['addresses']:
        if row.get('ifname')!=primary:continue
        for addr in row.get('addr_info',[]):
            try: ip=ipaddress.IPv4Interface(str(addr['local'])+'/'+str(addr['prefixlen']))
            except (ValueError,KeyError,TypeError):continue
            if ip.ip in network:matching.append(str(ip))
    if len(matching)!=1:
        raise NetworkError('Pi-hole: indirizzo primario ambiguo sul master, scegliere manualmente tramite stage JSON')
    server=str(ipaddress.IPv4Interface(secondary_cidr).ip)
    raw={'schema':1,'dhcp':{'primary':{
        'interface':primary,'address':matching[0],'start':fields['start'],
        'end':fields['end'],'gateway':fields['router']},
        'secondary':{'interface':iface,'address':secondary_cidr,
                     'start':start,'end':end,'gateway':server,
                     'dns':str(ipaddress.IPv4Interface(matching[0]).ip)},
        'pihole_api_port':port,'confirmed_l2_isolation':True}}
    result=stage(raw,live=kernel)
    result['primary_interface']=primary;result['secondary_interface']=iface
    result['message']='Piano salvato; nessun server avviato. Applicare da console con apply HASH.'
    return result


def main(args):
    require_root()
    if not args:raise NetworkError('Comando mancante')
    action=args[0]
    if action=='pihole-bind':
        return pihole_bind(args[1:])
    if action in ('install-guard','stage','dhcp-stage','apply','confirm','rollback'):
        require_console()
    if action=='install-guard' and len(args)==1:return guard_install()
    if action=='status' and len(args)==1:
        obj=read_doc(STATE)
        return {'ok':True,'status':obj.get('status') if obj else 'empty','version':VERSION}
    if action=='dhcp-stage' and len(args)==7:
        with mutex():return dhcp_stage_from_live(args[1:])
    if action=='stage' and len(args)==1:
        content=sys.stdin.buffer.read(32769)
        if len(content)>32768:raise NetworkError('Configurazione troppo grande')
        with mutex():return stage(json.loads(content))
    with mutex():
        if action=='apply' and len(args)==2:return apply_plan(args[1])
        if action=='health-check' and len(args)==1:return health_check()
        if action=='confirm' and len(args)==2:return confirm(args[1])
        if action=='rollback' and len(args)==2:
            state=read_doc(STATE)
            if not state or state.get('token')!=args[1] or not HEX24.fullmatch(args[1]):
                raise NetworkError('Token rollback non valido')
            return rollback_state(state)
        if action in ('expire','boot-recover') and len(args)==1:
            return boot_recover() if action=='boot-recover' else (rollback_state(read_doc(STATE)) if read_doc(STATE) and read_doc(STATE).get('status')=='pending' else {'ok':True,'status':'idle'})
    raise NetworkError('Comando sconosciuto')


if __name__=='__main__':
    try:
        print(json.dumps(main(sys.argv[1:]),sort_keys=True))
    except (NetworkError,OSError,ValueError,KeyError,TypeError) as exc:
        print(json.dumps({'ok':False,'error':str(exc)}));sys.exit(1)
