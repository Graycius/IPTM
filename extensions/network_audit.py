#!/usr/bin/env python3
"""IPTM network inventory and safe NetworkManager helpers, 5.4.3.

Inventory and DHCP probes are read-only and never export secrets. Separate,
explicitly dispatched NM commands may create an inactive static profile or
activate/disconnect only independently verified, IPTM-owned spare ports.
No automatic gateway, DHCP, primary bond or managed-client route changes.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from typing import Any

VERSION = '5.30.5'
MAX_FILES = 384
MAX_FILE_BYTES = 256 * 1024
IFACE_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.:-]{0,14}$')
CONFIG_GROUPS: dict[str, tuple[str, ...]] = {
    'dietpi-ifupdown': ('etc/network/interfaces', 'etc/network/interfaces.d/*', 'boot/dietpi.txt',
                       'boot/dietpi/config.txt', 'boot/dietpi/network/*'),
    'networkmanager': ('etc/NetworkManager/NetworkManager.conf', 'etc/NetworkManager/conf.d/*.conf',
                       'etc/NetworkManager/system-connections/*'),
    'systemd-networkd': ('etc/systemd/network/*.network', 'etc/systemd/network/*.netdev',
                         'etc/systemd/network/*.link', 'etc/systemd/resolved.conf'),
    'dhcpcd': ('etc/dhcpcd.conf', 'etc/dhcpcd.conf.d/*'),
    'pihole': ('etc/pihole/pihole.toml', 'etc/pihole/01-pihole.conf'),
    'dhcp-dnsmasq': ('etc/dnsmasq.conf', 'etc/dnsmasq.d/*.conf', 'etc/default/dnsmasq'),
    'dhcp-isc-kea': ('etc/default/isc-dhcp-server', 'etc/dhcp/dhcpd.conf',
                     'etc/kea/kea-dhcp4.conf', 'etc/kea/kea-dhcp6.conf', 'etc/udhcpd.conf'),
    'vpn': ('etc/wireguard/*.conf', 'etc/openvpn/*.conf', 'etc/openvpn/server/*.conf',
            'etc/openvpn/client/*.conf', 'etc/ipsec.conf', 'etc/strongswan.conf'),
    'firewall-qos': ('etc/iptables/rules.v4', 'etc/iptables/rules.v6', 'etc/nftables.conf',
                     'etc/iptables-manager.conf', 'etc/iptables-manager.d/*',
                     'etc/shorewall/interfaces', 'etc/ufw/before.rules'),
    'security-dns': ('etc/suricata/suricata.yaml', 'etc/crowdsec/acquis.yaml',
                     'etc/unbound/unbound.conf', 'etc/unbound/unbound.conf.d/*.conf',
                     'etc/dnscrypt-proxy/dnscrypt-proxy.toml', 'etc/hostapd/hostapd.conf'),
    'services': ('etc/systemd/system/iptm-*.service', 'etc/systemd/system/iptm-*.timer',
                 'etc/systemd/system/dnsmasq*.service.d/*.conf'),
}
SERVICES = ('NetworkManager', 'systemd-networkd', 'networking', 'dhcpcd', 'pihole-FTL',
            'dnsmasq', 'isc-dhcp-server', 'kea-dhcp4-server', 'udhcpd', 'hostapd',
            'suricata', 'crowdsec', 'unbound', 'dnscrypt-proxy', 'iptm-wanfo.timer')
PACKAGES = ('network-manager', 'ifupdown', 'systemd-networkd', 'dhcpcd5', 'dnsmasq',
            'dnsmasq-base', 'isc-dhcp-server', 'kea-dhcp4-server', 'pihole-FTL',
            'iproute2', 'ifenslave', 'vlan', 'ethtool', 'bridge-utils', 'openvswitch-switch')

# Feature ideas traditionally available in consumer and enterprise routers.
# Local-only: no device discovery, credentials, remote commands or vendor APIs.
LOCAL_ROUTER_FEATURES = {
    'guest_isolation': {'linux': ['802.1Q VLAN', 'iptables zone rules'], 'mode':'local'},
    'parental_schedules': {'linux': ['iptables time matches', 'Pi-hole groups'], 'mode':'design-only'},
    'per_device_qos': {'linux': ['tc CAKE', 'iptables marks'], 'mode':'design-only'},
    'dhcp_reservations': {'linux': ['Pi-hole FTL v6 REST API'], 'mode':'design-only'},
    'vpn_access': {'linux': ['WireGuard'], 'mode':'local'},
    'traffic_statistics': {'linux': ['vnStat', 'tc', 'iptables counters'], 'mode':'local'},
    'dns_privacy': {'linux': ['Pi-hole', 'Unbound', 'DNSCrypt'], 'mode':'local'},
    'wan_health': {'linux': ['iproute2', 'conntrack marks'], 'mode':'local'},
}


def installed_packages() -> dict[str,bool]:
    status={}
    for name in PACKAGES:
        code,output=command(['dpkg-query','-W','-f=${Status}',name],timeout=2)
        status[name] = code==0 and output.strip()=='install ok installed'
    return status


def kernel_l2(sys_root: Path = Path('/')) -> dict:
    result={'bonding':{},'bridge_ports':{},'vlan_config_present':False}
    bonding=sys_root/'proc/net/bonding'
    if not bonding.is_symlink() and bonding.is_dir():
        for path in sorted(bonding.iterdir())[:16]:
            if path.is_symlink() or not path.is_file() or not IFACE_RE.fullmatch(path.name):
                continue
            try:
                content=path.read_text(encoding='utf-8',errors='replace')[:65536]
                result['bonding'][path.name]={'slaves':re.findall(r'(?m)^Slave Interface: ([A-Za-z0-9_.:-]{1,15})$',content),
                                              'active':True}
            except OSError:
                continue
    net=sys_root/'sys/class/net'
    if not net.is_symlink() and net.is_dir():
        for path in sorted(net.iterdir())[:64]:
            if not IFACE_RE.fullmatch(path.name):continue
            brif=path/'brif'
            if brif.is_dir():
                try:result['bridge_ports'][path.name]=[p.name for p in brif.iterdir() if IFACE_RE.fullmatch(p.name)][:64]
                except OSError:pass
    result['vlan_config_present']=(sys_root/'proc/net/vlan/config').is_file()
    return result


def command(argv: list[str], timeout: float = 3.0) -> tuple[int, str]:
    if not shutil.which(argv[0]):
        return 127, ''
    try:
        result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                text=True, timeout=timeout, check=False, stdin=subprocess.DEVNULL)
        return result.returncode, result.stdout[:32768]
    except (OSError, subprocess.TimeoutExpired):
        return 124, ''


def _json_command(argv: list[str]) -> Any:
    rc, output = command(argv)
    if rc:
        return []
    try:
        return json.loads(output)
    except ValueError:
        return []


def _intf_refs(data: str, names: set[str]) -> list[str]:
    # A full identifier must match: eth0 does not match eth00 or myeth0.
    return sorted(n for n in names if re.search(r'(?<![A-Za-z0-9_.:-])'+re.escape(n)+r'(?![A-Za-z0-9_.:-])', data))


def scan_files(root: Path = Path('/'), interface_names: set[str] | None = None) -> list[dict]:
    """Known networking configs only; no recursive /etc walk, no content in output.

    Race protection: skip symlinks, special files, oversized and non-root-owned
    files. Unlike a backup, this inventory never exposes passwords or keys.
    """
    names = {x for x in (interface_names or set()) if isinstance(x, str) and IFACE_RE.fullmatch(x)}
    found: list[dict] = []
    seen: set[str] = set()
    for group, patterns in CONFIG_GROUPS.items():
        for pattern in patterns:
            for path in sorted(root.glob(pattern)):
                if len(found) >= MAX_FILES:
                    return found
                rel = path.relative_to(root).as_posix()
                if rel in seen or path.is_symlink() or not path.is_file():
                    continue
                seen.add(rel)
                try:
                    st = path.stat()
                    if st.st_size > MAX_FILE_BYTES or st.st_size < 0 or st.st_mode & 0o002:
                        continue
                    # Do not ingest arbitrarily large or world-writable data from config trees.
                    content = path.read_bytes()
                    if len(content) > MAX_FILE_BYTES:
                        continue
                except (PermissionError, OSError, ValueError):
                    continue
                found.append({'path': '/'+rel, 'category': group, 'bytes': len(content),
                              'sha256': hashlib.sha256(content).hexdigest(),
                              'interfaces': _intf_refs(content.decode('utf-8', 'replace'), names),
                              'requires_review': bool(_intf_refs(content.decode('utf-8', 'replace'), names))})
    return found


def _pihole(root: Path) -> dict:
    p = root / 'etc/pihole/pihole.toml'
    status = {'installed_config': False, 'dhcp': {'verified': False}, 'api_v6': 'probe_from_console'}
    if p.is_symlink() or not p.is_file():
        return status
    status['installed_config'] = True
    try:
        if p.stat().st_size > MAX_FILE_BYTES:
            return status
        import tomllib  # Debian 12 and newer
        data = tomllib.loads(p.read_text(encoding='utf-8'))
        settings = data.get('dhcp') if isinstance(data, dict) else None
        if isinstance(settings, dict):
            # Deliberate allow-list, do not return the TOML or credentials.
            dhcp = {k: settings.get(k) for k in ('active','start','end','router','netmask','ipv6')
                    if isinstance(settings.get(k), (str, bool))}
            status['dhcp'] = {'verified': True, **dhcp}
    except (ImportError, OSError, UnicodeError, ValueError):
        pass
    return status


def _services() -> dict:
    status = {}
    for name in SERVICES:
        active_rc, active = command(['systemctl', 'is-active', name], timeout=2)
        enabled_rc, enabled = command(['systemctl', 'is-enabled', name], timeout=2)
        status[name] = {'active': active_rc == 0 and active.strip() == 'active',
                        'enabled': enabled_rc == 0 and enabled.strip() == 'enabled'}
    return status


def _l2_topology(links: list[dict]) -> list[dict]:
    result=[]
    for x in links[:96]:
        if not isinstance(x,dict) or not isinstance(x.get('ifname'),str): continue
        ifname = x['ifname']
        if not IFACE_RE.fullmatch(ifname): continue
        info = x.get('linkinfo') or {}
        result.append({'name': ifname, 'ifindex': x.get('ifindex'),
                       'master': x.get('master'), 'kind': info.get('info_kind') or x.get('link_type'),
                       'physical': x.get('physical') is True or (Path('/sys/class/net')/ifname/'device').exists(),
                       'link': x.get('link'), 'operstate': x.get('operstate')})
    return result



def topology_risks(links: list[dict], addresses: list[dict], kernel: dict) -> list[dict]:
    """Report link/bond/subnet risks without inferring a new LAN or WAN role.

    Advisory only: the result is never used to change the active interface,
    restart a network manager, or alter DHCP/routes. Input can be synthetic.
    """
    warnings: list[dict] = []
    seen: set[tuple[str, str]] = set()
    def add(code: str, name: str, message: str) -> None:
        if (code, name) in seen: return
        seen.add((code,name))
        warnings.append({'severity':'warning', 'code':code, 'interface':name,
                         'message':message})
    interfaces={x.get('ifname'):x for x in links[:96]
                if isinstance(x,dict) and isinstance(x.get('ifname'),str)}
    for ifname, link in interfaces.items():
        if not IFACE_RE.fullmatch(ifname):continue
        if link.get('physical') is not True and not (Path('/sys/class/net')/ifname/'device').exists():
            continue
        oper=str(link.get('operstate') or '').upper()
        # This is a warning; 'DOWN' is not proof that the NIC is unused.
        if oper in ('DOWN','LOWERLAYERDOWN','NOTPRESENT') or link.get('carrier') is False:
            add('physical-link-not-ready',ifname,
                'Portante fisica assente o interfaccia non operativa; non usarla per DHCP/WAN automaticamente')
    bonding=kernel.get('bonding',{}) if isinstance(kernel,dict) else {}
    for name, data in bonding.items():
        if name not in interfaces or not IFACE_RE.fullmatch(name) or not isinstance(data,dict):continue
        slaves=data.get('slaves',[])
        if isinstance(slaves,list) and len(slaves)<2:
            add('bond-redundancy-unavailable',name,
                'Bond con meno di due slave: non presumere failover o somma delle velocita')
    for addr in addresses[:96]:
        if not isinstance(addr,dict):continue
        name=addr.get('ifname')
        if not isinstance(name,str) or name not in bonding:continue
        nets=set()
        for item in addr.get('addr_info',[])[:24]:
            if not isinstance(item,dict) or item.get('family')!='inet':continue
            try: nets.add(str(ipaddress.ip_interface(item['local']+'/'+str(item['prefixlen'])).network))
            except (ValueError, KeyError, TypeError):continue
        if len(nets)>1:
            add('bond-multiple-ipv4-subnets',name,
                'Piu subnet IPv4 sullo stesso bond: non costituiscono segmentazione Layer 2')
    return warnings


def audit(*, root: Path = Path('/'), live: dict | None = None,
          services: dict | None = None, files: list[dict] | None = None) -> dict:
    if live is None:
        links = _json_command(['ip', '-j', 'link', 'show'])
        addr = _json_command(['ip', '-j', '-4', 'addr', 'show'])
        route = _json_command(['ip', '-j', '-4', 'route', 'show', 'table', 'all'])
        rules = _json_command(['ip', '-j', '-4', 'rule', 'show'])
        listeners_rc, listeners = command(['ss', '-H', '-u', '-l', '-n', '-p'], timeout=3)
        live = {'links': links, 'addresses': addr, 'routes': route, 'rules': rules,
                'dhcp_listeners': listeners if listeners_rc == 0 else None}
    names = {x.get('ifname') for x in live.get('links', []) if isinstance(x,dict)}
    names.discard(None)
    paths = scan_files(root, names) if files is None else files
    deps = {n: sorted({f['path'] for f in paths if n in f.get('interfaces', [])}) for n in names}
    services = _services() if services is None else services
    active = [k for k,v in services.items() if v.get('active')]
    pihole = _pihole(root)
    warning = []
    network_owners = [k for k in ('NetworkManager','systemd-networkd','networking','dhcpcd') if k in active]
    if len(network_owners)>1:
        warning.append({'severity': 'block', 'code': 'manager-ownership',
                        'message': 'Diversi gestori attivi: verificare il proprietario per NIC, non arrestarli globalmente'})
    dhcps = [k for k in ('pihole-FTL','dnsmasq','isc-dhcp-server','kea-dhcp4-server','udhcpd') if k in active]
    if pihole['dhcp'].get('active') is True and len(dhcps)>1:
        warning.append({'severity': 'block', 'code': 'dhcp-l2-unknown',
                        'message': 'Pi-hole e altri daemon DHCP attivi: isolamento L2 e binding UDP67 da verificare'})
    if live.get('dhcp_listeners') is None:
        warning.append({'severity': 'unknown', 'code': 'dhcp-sockets',
                        'message': 'Porta UDP 67 non verificata: non avviare un secondo server senza controllare i bind'})
    kernel = kernel_l2(root)
    warning.extend(topology_risks(live.get('links',[]),live.get('addresses',[]),kernel))
    return {'schema': 1, 'version': VERSION, 'mode': 'read-only', 'scan_complete': len(paths)<MAX_FILES,
            'interfaces': _l2_topology(live.get('links',[])),
            'addresses': live.get('addresses',[])[:96], 'routes': live.get('routes',[])[:96],
            'rules': live.get('rules',[])[:96], 'services': services, 'active_services': active,
            'packages': installed_packages() if live.get('read_packages', True) else {},
            'kernel_l2': kernel, 'local_router_features': LOCAL_ROUTER_FEATURES,
            'pihole': pihole, 'network_files': paths, 'references': deps,
            'dhcp_listeners': 'collected' if live.get('dhcp_listeners') is not None else 'unavailable',
            'warnings': warning, 'applied': False}


def _ip(value: str) -> ipaddress.IPv4Address:
    try:
        v = ipaddress.ip_address(value)
        if not isinstance(v, ipaddress.IPv4Address) or not v.is_private or v.is_loopback or v.is_multicast:
            raise ValueError()
        return v
    except (TypeError, ValueError) as e:
        raise ValueError('Indirizzo IPv4 privato richiesto') from e


def validate_dhcp(primary: dict, secondary: dict) -> dict:
    """DHCP Pi-hole LAN and second dnsmasq segment; fail-closed on L2 uncertainty."""
    if not isinstance(primary, dict) or not isinstance(secondary, dict):
        raise ValueError('DHCP: due configurazioni obbligatorie')
    if set(primary)-{'interface','address','start','end','gateway'} or set(secondary)-{'interface','address','start','end','gateway','dns'}:
        raise ValueError('DHCP: proprietà sconosciute')
    n1,n2=primary.get('interface'),secondary.get('interface')
    if not all(isinstance(n,str) and IFACE_RE.fullmatch(n) for n in (n1,n2)) or n1==n2:
        raise ValueError('DHCP: interfacce separate obbligatorie')
    try:
        pnet = ipaddress.ip_interface(primary['address']); snet = ipaddress.ip_interface(secondary['address'])
        if not all(isinstance(x,ipaddress.IPv4Interface) for x in (pnet,snet)):
            raise ValueError()
    except (TypeError,KeyError,ValueError) as ex:
        raise ValueError('DHCP: indirizzi gateway CIDR non validi') from ex
    if (not pnet.ip.is_private or not snet.ip.is_private or
            not 8 <= pnet.network.prefixlen <= 30 or not 8 <= snet.network.prefixlen <= 30):
        raise ValueError('DHCP: reti private con prefisso /8-/30 obbligatorie')
    if pnet.network.overlaps(snet.network):
        raise ValueError('DHCP: subnet sovrapposte, vietato doppio DHCP sulla stessa rete')
    def pool(config, nic):
        lo,hi,gw=(_ip(config[k]) for k in ('start','end','gateway'))
        if not all(x in nic.network for x in (lo,hi,gw)) or not (int(lo)<=int(hi)):
            raise ValueError('DHCP: pool/gateway fuori subnet o invertiti')
        if any(int(lo)<=int(x)<=int(hi) for x in (gw,nic.ip)):
            raise ValueError('DHCP: pool include gateway o server DHCP')
        if lo==nic.network.network_address or hi==nic.network.broadcast_address:
            raise ValueError('DHCP: pool include network/broadcast')
        return str(lo),str(hi),str(gw)
    plo,phi,pgw=pool(primary,pnet)
    slo,shi,sgw=pool(secondary,snet)
    dns = secondary.get('dns',str(snet.ip))
    dns_ip=_ip(dns)
    if dns_ip not in snet.network and dns_ip not in pnet.network:
        raise ValueError('DHCP secondario: DNS non raggiungibile tramite reti previste')
    config = ('# IPTM 5.4.3 - BOZZA, non installare senza verifica UDP/67 e isolamento L2\n'
              'port=0\n'
              'interface='+n2+'\n'
              'bind-dynamic\n'
              'dhcp-range='+slo+','+shi+',12h\n'
              'dhcp-option=option:router,'+sgw+'\n'
              'dhcp-option=option:dns-server,'+str(dns_ip)+'\n'
              'dhcp-leasefile=/var/lib/iptm-dhcp-secondary.leases\n')
    api_patch = pihole_dhcp_patch({'active':True,'start':plo,'end':phi,
                                   'router':pgw,'netmask':str(pnet.network.netmask)})
    return {'valid': True, 'primary_api':{'method':'PATCH','path':'/api/config',
                                            'payload':api_patch,'apply_enabled':False}, 'primary': {'provider':'pihole-FTL-v6', 'interface':n1,
            'network':str(pnet.network), 'pool':[plo,phi], 'gateway':pgw},
            'secondary': {'provider':'dnsmasq-dhcp-only','interface':n2,'network':str(snet.network),
             'pool':[slo,shi], 'gateway':sgw, 'server_ip':str(snet.ip), 'dns':str(dns_ip)},
            'secondary_config_preview':config,
            'requirements':['Pi-hole v6 active/healthy','disjoint physical L2 or proven VLAN isolation',
                            'UDP 67 binding verified on both services','no other DHCP servers on either segment',
                            'router DHCP disabled in both segments','DNS accessible from secondary VLAN',
                            'confirmed console and rollback before activation'],
            'execution_enabled': False}


def pihole_dhcp_patch(plan: dict) -> dict:
    """Only allow well-typed, bounded DHCP fields. Never patch hosts/dns interface."""
    if set(plan) != {'active','start','end','router','netmask'} or type(plan['active']) is not bool:
        raise ValueError('Schema PATCH Pi-hole ristretto al DHCP')
    net = ipaddress.ip_network('0.0.0.0/'+plan['netmask'])
    if not 8 <= net.prefixlen <= 30:
        raise ValueError('Pi-hole: netmask DHCP non valida')
    start,end,router=(_ip(plan[k]) for k in ('start','end','router'))
    if not (start<=end and not start<=router<=end and
            router in ipaddress.ip_network(f'{router}/{net.prefixlen}',strict=False) and
            start in ipaddress.ip_network(f'{router}/{net.prefixlen}',strict=False) and
            end in ipaddress.ip_network(f'{router}/{net.prefixlen}',strict=False)):
        raise ValueError('Pi-hole: intervallo e gateway non compatibili')
    return {'config':{'dhcp':{'active':plan['active'],'start':str(start),
                              'end':str(end),'router':str(router),'netmask':str(net.netmask)}}}


def change_impact(report: dict, rename: dict[str,str] | None = None) -> dict:
    """Explicit dependency graph and rollback requirements, zero shell substitutions."""
    names={x['name'] for x in report.get('interfaces',[]) if 'name' in x}
    rename=rename or {}
    if not isinstance(rename,dict) or any(a not in names or not isinstance(b,str) or not IFACE_RE.fullmatch(b) or a==b for a,b in rename.items()):
        raise ValueError('Mappatura rename non valida')
    if len(set(rename.values()))!=len(rename) or any(b in names and b not in rename for b in rename.values()):
        raise ValueError('Rename collide con una interfaccia esistente')
    affected={a:report.get('references',{}).get(a,[]) for a in rename}
    steps=[{'stage':'01-inventory','mode':'read-only','detail':'Acquisire link/route/rule, DNS e processi DHCP e tutti i file citanti le NIC'},
           {'stage':'02-preflight','mode':'read-only','detail':'Verificare manager owner, bonding, subnet, L2, UDP67, gateway, SSH e DNS'},
           {'stage':'03-backup','mode':'root-console','detail':'Backup cifrato o offline dei file, snapshot iptables/ip rule/ip route e configurazione gestori'},
           {'stage':'04-migration','mode':'NOT IMPLEMENTED','detail':'Rendere coerenti per-service i riferimenti: prima componenti inattivi, poi NIC e policy'},
           {'stage':'05-verify','mode':'NOT IMPLEMENTED','detail':'Verificare DHCP, DNS Pi-hole, routing simmetrico, accesso LAN/SSH, servizi e VPN'},
           {'stage':'06-confirm','mode':'NOT IMPLEMENTED','detail':'Conferma esplicita con scadenza e watchdog di rollback persistente'}]
    return {'steps':steps, 'referenced_files':affected, 'blockers':report.get('warnings',[]),
            'safe_to_apply': False, 'execution_enabled':False,
            'note':'Nessuna riconfigurazione automatica o promessa di continuità; richiede console e watchdog.'}


def pihole_dhcp_local(*, root: Path = Path('/'), config: dict | None = None) -> dict:
    """Read-only Pi-hole DHCP configuration. Whitelisted fields only.

    Prefer the on-host Pi-hole v6 CLI for effective values. TOML is a
    configuration fallback, not proof of a running DHCP service. Never export
    passwords or arbitrary TOML fields. No requests or writes to FTL.
    """
    keys=('active','start','end','router','netmask')
    dns_keys=('interface','listeningMode')
    values={}
    source='unavailable'
    dns_fields={}
    file=root/'etc/pihole/pihole.toml'
    if config is not None:
        raw=config.get('dhcp', {}) if isinstance(config, dict) else {}
        dns_fields=config.get('dns', {}) if isinstance(config.get('dns', {}),dict) else {}
        if isinstance(raw, dict):
            values={key:raw[key] for key in keys if key in raw}
            source='fixture'
    elif file.is_file() and not file.is_symlink():
        try:
            import tomllib
            with file.open('rb') as stream:
                cfg=tomllib.load(stream)
            dns_fields=cfg.get('dns', {}) if isinstance(cfg.get('dns',{}),dict) else {}
            raw=cfg.get('dhcp', {})
            if isinstance(raw,dict):
                values={key:raw[key] for key in keys if key in raw}
                source='pihole.toml'
        except (OSError,ValueError,ImportError):
            pass
    if config is None and root==Path('/') and shutil.which('pihole-FTL'):
        cli_values={}
        for key in keys:
            rc,out=command(['pihole-FTL','--config','dhcp.'+key],timeout=2)
            if rc:continue
            line=out.strip().splitlines()[-1].strip() if out.strip() else ''
            # Accept either a bare value or 'dhcp.start = "..."'. Never
            # trust a long or multiline response from an unexpected binary.
            if len(line)>100:continue
            if '=' in line: line=line.rsplit('=',1)[1].strip()
            line=line.strip().strip(chr(34)).strip(chr(39))
            if key=='active':
                if line.lower() in ('true','false'): cli_values[key]=line.lower()=='true'
            elif re.fullmatch(r'[0-9.]{7,16}',line):
                try: cli_values[key]=str(ipaddress.IPv4Address(line))
                except ValueError: pass
        if len(cli_values)==len(keys):
            values=cli_values
            source='pihole-ftl-cli'
        for key in dns_keys:
            rc,out=command(['pihole-FTL','--config','dns.'+key],timeout=2)
            if rc or len(out)>512:continue
            line=out.strip().splitlines()[-1].strip() if out.strip() else ''
            if '=' in line:line=line.rsplit('=',1)[1].strip()
            line=line.strip().strip(chr(34)).strip(chr(39))
            if key=='interface' and (line=='' or IFACE_RE.fullmatch(line)):
                dns_fields[key]=line
            elif key=='listeningMode' and re.fullmatch(r'[A-Za-z0-9_-]{1,32}',line):
                dns_fields[key]=line
    result={'ok':bool(values),'source':source,'verified_live':source=='pihole-ftl-cli',
            'fields':{},'writes_enabled':False}
    for key in keys:
        value=values.get(key)
        if key=='active' and type(value) is bool:
            result['fields'][key]=value
        elif key!='active' and isinstance(value,str) and len(value)<32:
            try:result['fields'][key]=str(ipaddress.IPv4Address(value))
            except ValueError:pass
    if isinstance(dns_fields.get('interface'),str):
        value=dns_fields['interface']
        if value=='' or IFACE_RE.fullmatch(value):result['fields']['interface']=value
    if isinstance(dns_fields.get('listeningMode'),str):
        result['fields']['listening_mode']=dns_fields['listeningMode'][:32]
    result['interface_explicit']=bool(result['fields'].get('interface'))
    result['dhcp_iface_source']='dns.interface (imposta anche l’interfaccia DNS)' if 'interface' in result['fields'] else 'non verificato'
    if source=='pihole.toml':
        result['note']='Configurazione locale letta; confermare eventuali override FTL/env prima di applicare'
    return result


def pihole_api_probe(*, port: int = 8089) -> dict:
    """Probe only the loopback API. No password transmission and never a PATCH."""
    from urllib.error import HTTPError, URLError
    from urllib.request import Request, HTTPHandler, HTTPRedirectHandler, build_opener
    if not isinstance(port, int) or port < 1 or port > 65535:
        raise ValueError('Porta API fuori intervallo')
    url = f'http://127.0.0.1:{port}/api/config/dhcp'
    class NoRedirect(HTTPRedirectHandler):
        def redirect_request(self, request, fp, code, msg, headers, newurl):
            return None  # Never follow HTTP redirects to remote hosts.
    opener=build_opener(HTTPHandler(),NoRedirect())
    try:
        with opener.open(Request(url, method='GET'), timeout=2.5) as response:
            body=response.read(4096)
            try: obj=json.loads(body)
            except ValueError: obj={}
            return {'reachable':True, 'http_status':response.status,
                    'api_v6_dhcp':isinstance(obj,dict) and ('config' in obj or 'dhcp' in obj),
                    'auth_required':False,'writes_enabled':False}
    except HTTPError as exc:
        return {'reachable':True,'http_status':exc.code,'auth_required':exc.code in (401,403),
                'writes_enabled':False}
    except (URLError,OSError,TimeoutError):
        return {'reachable':False,'http_status':None,'writes_enabled':False}


# DHCP socket and manager probes (fail closed; no network changes).
IFNAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$')
KNOWN_DHCP = ('pihole-FTL','dnsmasq','isc-dhcp-server','kea-dhcp4-server','udhcpd')
class SafetyError(RuntimeError):
    pass


def invoke(argv, *, timeout=4):
    if not shutil.which(argv[0]):
        raise SafetyError('Comando non installato: '+argv[0])
    try:
        p = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, text=True, check=False, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SafetyError('Probe fallita: '+argv[0]) from exc
    if p.returncode:
        raise SafetyError('Probe exit non zero: '+argv[0])
    return p.stdout[:65536]


def parse_dhcp_sockets(stdout: str) -> list[dict]:
    """Parse ss -H -u -l -n -p, retaining only UDP port 67 sockets.

    ss usually prints e.g. 'UNCONN 0 0 0.0.0.0:67 0.0.0.0:* users:...'.
    UDP 67 with wildcard address is unsafe for a second DHCP binding.
    """
    if not isinstance(stdout, str) or len(stdout) > 65536:
        raise SafetyError('Output socket non valido')
    rows = []
    for line in stdout.splitlines():
        fields = line.split(None, 6)
        if len(fields) < 5 or not fields[0].startswith(('UNCONN','ESTAB')):
            continue
        endpoint = fields[3]
        if not re.search(r':67$', endpoint):
            continue
        match=re.search(r'%([A-Za-z0-9_.:-]{1,15}):67$',endpoint)
        rows.append({'local':endpoint, 'interface_scope':match.group(1) if match else '',
                     'wildcard':endpoint.startswith(('0.0.0.0:', '*:', '[::]:', ':::')),
                     'process':(fields[5][:200] if len(fields) > 5 else '')})
    return rows


def dhcp_preflight(primary_iface: str, secondary_iface: str, *, sockets: str | None = None,
                   active_services: dict | None = None) -> dict:
    if (not isinstance(primary_iface, str) or not isinstance(secondary_iface, str)
        or not IFNAME.fullmatch(primary_iface) or not IFNAME.fullmatch(secondary_iface)
        or primary_iface == secondary_iface):
        raise SafetyError('Le interfacce DHCP devono essere differenti')
    data = sockets if sockets is not None else invoke(['ss','-H','-u','-l','-n','-p'])
    entries = parse_dhcp_sockets(data)
    if active_services is None:
        active_services = {}
        for name in KNOWN_DHCP:
            try:
                active_services[name] = invoke(['systemctl','is-active',name]).strip()=='active'
            except SafetyError:
                active_services[name] = False
    blockers = []
    if not active_services.get('pihole-FTL'):
        blockers.append('Pi-hole FTL non risulta attivo')
    for name in KNOWN_DHCP:
        if name!='pihole-FTL' and active_services.get(name):
            blockers.append('Altro DHCP attivo: '+name)
    if not entries:
        blockers.append('Nessun listener DHCP primario verificabile su UDP 67')
    if any(x['wildcard'] for x in entries):
        blockers.append('DHCP UDP 67 su indirizzo wildcard; binding secondario non isolabile con certezza')
    # Requiring a known listener is safer than assuming Pi-hole is bound correctly.
    if not any('pihole-FTL' in x['process'] for x in entries):
        blockers.append('Socket UDP 67 non attribuibile con certezza a Pi-hole FTL')
    for row in entries:
        if 'pihole-FTL' in row['process'] and row['interface_scope'] and row['interface_scope']!=primary_iface:
            blockers.append('Pi-hole DHCP non limitato al master '+primary_iface)
        if row['interface_scope']==secondary_iface:
            blockers.append('La NIC secondaria ha già un listener DHCP: '+secondary_iface)
    return {'version':VERSION, 'primary':primary_iface, 'secondary':secondary_iface,
            'sockets':entries, 'blockers':sorted(set(blockers)),
            'can_start_secondary':not blockers, 'applied':False}


def interface_owners(ifname: str, *, nmcli: str | None = None, networkd: str | None = None,
                     interfaces_file: str | None = None) -> dict:
    if not isinstance(ifname, str) or not IFNAME.fullmatch(ifname):
        raise SafetyError('Nome NIC non valido')
    if nmcli is None:
        try:nmcli = invoke(['nmcli','-t','-f','DEVICE,STATE,CONNECTION','device','status'])
        except SafetyError:nmcli = ''
    if networkd is None:
        try:networkd = invoke(['networkctl','status',ifname,'--no-pager'])
        except SafetyError:networkd = ''
    if interfaces_file is None:
        try: interfaces_file = Path('/etc/network/interfaces').read_text(errors='replace')[:65536]
        except OSError: interfaces_file = ''
    nm = []
    for line in nmcli.splitlines():
        # nmcli escaped ':' in connection names; device name is always first.
        if line.split(':',1)[0] == ifname:
            nm.append(line[:200])
    ifup = bool(re.search(r'(?m)^\s*iface\s+'+re.escape(ifname)+r'\s+inet(?:6)?\s+',interfaces_file))
    nd = bool(re.search(r'(?i)Network File\s*:',networkd))
    return {'interface':ifname,'networkmanager':nm,'ifupdown':ifup,
            'networkd_configuration':nd,
            'conflict':bool(nm and (ifup or nd)), 'mode':'read-only'}



# Native NetworkManager integration, limited to *spare physical NICs*.  No
# bond member, default gateway or management-client path may be disrupted.
# device down is never a substitute for a coordinated network transaction.
def nm_safety(name: str, *, client: str = '', links: list | None = None,
              routes: list | None = None, pihole_iface: str | None = None) -> dict:
    if not isinstance(name,str) or not IFACE_RE.fullmatch(name):
        raise SafetyError('Nome di interfaccia non valido')
    if links is None:
        links=_json_command(['ip','-j','link','show'])
    if routes is None:
        routes=_json_command(['ip','-j','route','show','table','main'])
    record=next((r for r in links if isinstance(r,dict) and r.get('ifname')==name),None)
    if not record:raise SafetyError('Interfaccia non rilevata dal kernel')
    kind=(record.get('linkinfo') or {}).get('info_kind','')
    sysdev=Path('/sys/class/net')/name
    physical=record.get('physical') is True or (sysdev/'device').exists()
    reasons=[]
    if not physical:reasons.append('non è una NIC fisica indipendente')
    if record.get('master'):reasons.append('porta slave di '+str(record['master']))
    if kind in ('bond','bridge','vlan','veth','wireguard','tun','dummy'):reasons.append('interfaccia virtuale protetta')
    if any(r.get('dst')=='default' and r.get('dev')==name for r in routes if isinstance(r,dict)):
        reasons.append('porta della route predefinita')
    if pihole_iface is None:
        pihole_iface=pihole_dhcp_local()['fields'].get('interface','')
    if pihole_iface==name:reasons.append('interfaccia primaria Pi-hole')
    # If FTL auto-detects, only permit operations on a truly spare physical NIC
    # distinct from any interface holding a configured local address.
    if not pihole_iface and _json_command(['ip','-j','-4','addr','show','dev',name]):
        addresses=_json_command(['ip','-j','-4','addr','show','dev',name])
        if any(row.get('addr_info') for row in addresses if isinstance(row,dict)):
            reasons.append('Pi-hole è in auto-rilevamento e questa NIC ha indirizzi')
    if client:
        try:
            address=ipaddress.ip_address(client)
            if address.version!=4:reasons.append('sessione IPv6 non verificabile')
            else:
                table=_json_command(['ip','-j','route','get',str(address)])
                if not table:reasons.append('route verso il client non verificabile')
                elif any(r.get('dev')==name for r in table if isinstance(r,dict)):
                    reasons.append('sessione amministrativa passa da questa NIC')
        except ValueError:reasons.append('indirizzo IP client non valido')
    else:reasons.append('client amministrativo non identificato')
    # Inventory only: the GUI must not offer an unusable Up button before an
    # IPTM-owned, offline NetworkManager profile exists.
    profile_rc, profile_iface = command(['nmcli','-g','connection.interface-name',
                                        'connection','show','iptm-secondary-'+name],timeout=2)
    profile_present = profile_rc==0 and profile_iface.strip()==name
    profile_info={}
    if profile_present:
        for key,label in [('ipv4.addresses','profile_ipv4'),('802-3-ethernet.mtu','profile_mtu'),
                          ('ipv4.route-metric','profile_metric')]:
            prc, value=command(['nmcli','-g',key,'connection','show','iptm-secondary-'+name],timeout=2)
            if prc==0:profile_info[label]=value.strip()
    return {'ok':True,'interface':name,'safe_to_disconnect':not reasons,
            'managed_profile':profile_present,'blockers':reasons,
            'bond_member':bool(record.get('master')),'bond_master':str(record.get('master') or ''),
            'carrier':record.get('operstate'),
            **profile_info,
            'note':'Il controllo protegge la sessione corrente, non garantisce accesso alternativo.'}


def nm_manage(action: str, name: str, client: str, *, checker=None, executor=None) -> dict:
    if action not in ('up','down'):raise SafetyError('Comando NetworkManager non autorizzato')
    check=(checker or nm_safety)(name,client=client)
    if not check.get('safe_to_disconnect'):
        raise SafetyError('Operazione bloccata: '+', '.join(check.get('blockers',[])))
    if action=='up':
        pihole=pihole_dhcp_local()
        if pihole.get('fields',{}).get('active') and not pihole.get('fields',{}).get('interface'):
            raise SafetyError('Pi-hole DHCP in auto-rilevamento: vincolare dns.interface al master prima di attivare una NIC')
        # A port can be configured while unplugged, but NM cannot turn a
        # missing physical carrier into a working link.
        if executor is None:
            carrier=Path('/sys/class/net')/name/'carrier'
            try:ready=carrier.read_text().strip()=='1'
            except OSError:ready=False
            if not ready:raise SafetyError('Cavo non collegato: profilo salvato ma interfaccia non attivabile')
    if not shutil.which('nmcli'):
        raise SafetyError('NetworkManager/nmcli non installato')
    if command(['systemctl','is-active','NetworkManager'],timeout=2)!=(0,'active\n'):
        raise SafetyError('NetworkManager non risulta attivo')
    # Only activate the unique profile created by this module. A pre-existing
    # Ethernet profile might contain a default route, DHCP client or autoconnect
    # rules: "nmcli device up" could silently select it and steal the gateway.
    profile='iptm-secondary-'+name
    p=subprocess.run(['nmcli','-g','connection.id','connection','show',profile],
                     stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=3)
    if p.returncode!=0:
        raise SafetyError('Profilo IPTM non presente: creare prima Configura offline')
    values={}
    for key in ('connection.interface-name','ipv4.never-default','ipv4.method','connection.autoconnect'):
        rc,out=command(['nmcli','-g',key,'connection','show',profile],timeout=3)
        if rc:raise SafetyError('Impossibile verificare il profilo NM: '+key)
        values[key]=out.strip().lower()
    if (values['connection.interface-name']!=name.lower() or
        values['ipv4.never-default'] not in ('yes','true') or
        values['ipv4.method']!='manual' or
        values['connection.autoconnect'] not in ('no','false')):
        raise SafetyError('Profilo IPTM alterato o con rischio route/autoconnect')
    call=executor or invoke
    if executor is None:
        rc,current=command(['nmcli','-g','GENERAL.CONNECTION','device','show',name],timeout=3)
        if rc:raise SafetyError('Connessione attiva non verificabile')
        current=current.strip()
        if action=='down' and current!=profile:
            raise SafetyError('Disconnessione rifiutata: NetworkManager non sta usando il profilo IPTM')
        if action=='up' and current not in ('','--',profile):
            raise SafetyError('Un altro profilo NetworkManager è attivo sulla scheda')
    if action=='up':
        call(['nmcli','--wait','8','connection','up','id',profile,'ifname',name],timeout=12)
    else:
        call(['nmcli','--wait','8','connection','down','id',profile],timeout=12)
    if executor is None:
        # After the subprocess completes, NM must report the expected state.
        code,reported=command(['nmcli','-g','GENERAL.CONNECTION','device','show',name],timeout=3)
        if code or (action=='up' and reported.strip()!=profile) or (action=='down' and reported.strip()==profile):
            raise SafetyError('NetworkManager non conferma il nuovo stato; controlla la scheda')
    return {'ok':True,'interface':name,'operation':action,'applied':True,
            'dhcp_started':False,'warning':'NetworkManager verificato; nessun server DHCP è stato modificato'}


def nm_prepare(name: str, client: str, cidr: str, *, checker=None, executor=None,
               addresses: list | None = None) -> dict:
    """Provision an OFFLINE, non-autoconnecting NM profile for a spare port.

    Does not bring a link up; fails if any live address or overlapping subnet
    already exists. Never accepts a gateway or DNS override from the web.
    """
    status=(checker or nm_safety)(name,client=client)
    if not status.get('safe_to_disconnect'):
        raise SafetyError('Interfaccia protetta: '+', '.join(status.get('blockers',[])))
    if not isinstance(cidr,str) or len(cidr)>32:
        raise SafetyError('CIDR non valido')
    try:
        selected=ipaddress.IPv4Interface(cidr)
        if (not selected.ip.is_private or not 8<=selected.network.prefixlen<=30 or
            selected.ip in (selected.network.network_address,selected.network.broadcast_address)):
            raise ValueError()
    except ValueError as exc:
        raise SafetyError('Indirizzo secondario privato /8–/30 richiesto') from exc
    addresses = addresses if addresses is not None else _json_command(['ip','-j','-4','addr','show'])
    for entry in addresses:
        if not isinstance(entry,dict):continue
        for item in entry.get('addr_info',[]):
            try:
                other=ipaddress.IPv4Interface(item['local']+'/'+str(item['prefixlen']))
            except (KeyError,TypeError,ValueError):continue
            if other.network.overlaps(selected.network):
                raise SafetyError('Subnet '+str(selected.network)+' in conflitto con '+str(other.network))
    if not shutil.which('nmcli'):
        raise SafetyError('NetworkManager non installato')
    if command(['systemctl','is-active','NetworkManager'],timeout=2)!=(0,'active\n'):
        raise SafetyError('NetworkManager non attivo')
    profile='iptm-secondary-'+name
    rc,_=command(['nmcli','-g','connection.id','connection','show',profile],timeout=3)
    if rc==0:raise SafetyError('Profilo già esistente: modificare da NetworkManager, non sovrascrivere')
    call=executor or invoke
    call(['nmcli','--wait','8','connection','add','type','ethernet','ifname',name,
          'con-name',profile,'connection.autoconnect','no','ipv4.method','manual',
          'ipv4.addresses',str(selected),'ipv4.never-default','yes',
          'ipv6.method','disabled'],timeout=12)
    return {'ok':True,'profile':profile,'interface':name,'ipv4':str(selected),
            'applied':True,'activated':False,'message':'Profilo creato senza attivare la scheda o il server DHCP'}



# Curated NetworkManager operations.  Only IPTM-owned, inactive profiles on
# spare physical ports may be edited.  No web request may modify the primary
# bond/bridge, its members, routes, DNS or a currently active profile.
def _nm_profile(name: str) -> str:
    if not isinstance(name,str) or not IFACE_RE.fullmatch(name):
        raise SafetyError('Interfaccia non valida')
    return 'iptm-secondary-'+name


def nm_ipv4_list(values: Any, *, addresses: list | None = None, iface: str = '') -> list[str]:
    if not isinstance(values,list) or not 1<=len(values)<=8:
        raise SafetyError('Inserire da 1 a 8 indirizzi IPv4 CIDR')
    result=[];subnets=[]
    for raw in values:
        if not isinstance(raw,str) or len(raw)>32:
            raise SafetyError('Indirizzo IPv4 non valido')
        try:
            address=ipaddress.IPv4Interface(raw.strip())
            if not (address.ip.is_private and 8<=address.network.prefixlen<=30) or address.ip in (address.network.network_address,address.network.broadcast_address):
                raise ValueError()
        except ValueError as exc:raise SafetyError('Richiesto un IPv4 privato valido con prefisso /8–/30') from exc
        if any(address.ip == ipaddress.IPv4Interface(previous).ip for previous in result):
            raise SafetyError('Indirizzo IPv4 duplicato sulla stessa interfaccia')
        # NetworkManager supports several IPs in one subnet on a single NIC.
        # Different overlapping prefixes remain unsafe/ambiguous for the manager.
        if any(address.network.overlaps(x) and address.network != x for x in subnets):
            raise SafetyError('Sottoreti sovrapposte con maschere diverse sulla stessa scheda')
        subnets.append(address.network);result.append(str(address))
    if addresses is None:addresses=_json_command(['ip','-j','-4','addr','show'])
    if not isinstance(addresses,list):raise SafetyError('Inventario indirizzi non disponibile')
    for row in addresses:
        if not isinstance(row,dict) or row.get('ifname')==iface:continue
        for rec in row.get('addr_info',[]):
            try:other=ipaddress.IPv4Interface(str(rec['local'])+'/'+str(rec['prefixlen']))
            except (KeyError,ValueError,TypeError):continue
            if any(other.network.overlaps(x) for x in subnets):
                raise SafetyError('Subnet già utilizzata da '+str(row.get('ifname','un altro dispositivo')))
    return result


def nm_profile_save(name: str, client: str, config: dict, *, checker=None,
                    executor=None, command_func=None, addresses: list | None=None) -> dict:
    safety=(checker or nm_safety)(name,client=client)
    if not safety.get('safe_to_disconnect'):
        raise SafetyError('Scheda protetta: '+', '.join(safety.get('blockers',[])))
    if not isinstance(config,dict) or set(config)!={'ipv4','mtu','metric'}:
        raise SafetyError('Schema del profilo non valido')
    ips=nm_ipv4_list(config['ipv4'],addresses=addresses,iface=name)
    mtu=config['mtu'];metric=config['metric']
    if type(mtu) is not int or not 576<=mtu<=9000 or type(metric) is not int or not 1<=metric<=9999:
        raise SafetyError('MTU o metrica fuori intervallo')
    if not shutil.which('nmcli'):
        raise SafetyError('NetworkManager non installato')
    cmd=command_func or command
    if cmd(['systemctl','is-active','NetworkManager'],timeout=3)!=(0,'active\n'):
        raise SafetyError('NetworkManager non attivo')
    profile=_nm_profile(name)
    rc,old_iface=cmd(['nmcli','-g','connection.interface-name','connection','show',profile],timeout=3)
    exists=rc==0
    if exists and old_iface.strip()!=name:
        raise SafetyError('Profilo con identificativo IPTM non appartenente alla scheda')
    if exists:
        rc,typ=cmd(['nmcli','-g','connection.type','connection','show',profile],timeout=3)
        if rc or typ.strip()!='802-3-ethernet':
            raise SafetyError('Il profilo IPTM non è di tipo Ethernet')
        rc,controller=cmd(['nmcli','-g','connection.controller','connection','show',profile],timeout=3)
        if rc or controller.strip() not in ('','--'):
            raise SafetyError('Il profilo è già assegnato a un master')
        rc,active=cmd(['nmcli','-g','GENERAL.CONNECTION','device','show',name],timeout=3)
        if rc or active.strip()==profile:
            raise SafetyError('Profilo attivo o stato incerto: disconnettere prima di modificare')
        for key,accepted in [('ipv4.never-default',('yes','true')),('connection.autoconnect',('no','false'))]:
            rc,old=cmd(['nmcli','-g',key,'connection','show',profile],timeout=3)
            if rc or old.strip().lower() not in accepted:
                raise SafetyError('Profilo IPTM alterato: '+key)
    options=['connection.autoconnect','no','ipv4.method','manual','ipv4.addresses',','.join(ips),
             'ipv4.never-default','yes','ipv4.gateway','','ipv4.dns','','ipv4.ignore-auto-dns','yes',
             'ipv4.route-metric',str(metric),'802-3-ethernet.mtu',str(mtu),'ipv6.method','disabled']
    execute=executor or invoke
    if exists:
        execute(['nmcli','--wait','8','connection','modify',profile]+options,timeout=12)
    else:
        execute(['nmcli','--wait','8','connection','add','type','ethernet','ifname',name,
                 'con-name',profile]+options,timeout=12)
    return {'ok':True,'interface':name,'profile':profile,'addresses':ips,'mtu':mtu,
            'metric':metric,'activated':False,'dhcp_started':False,
            'message':'Profilo NetworkManager salvato, non attivato'}


def nm_bond_port(action: str, port: str, client: str, config: dict, *, checker=None,
                 executor=None, command_func=None) -> dict:
    # Bond editing via the web is deliberately limited to creating/deleting
    # OFFLINE IPTM-owned port profiles. Never reparent an active port.
    if action not in ('bond-add','bond-remove') or not isinstance(config,dict) or set(config)!={'bond'}:
        raise SafetyError('Richiesta bond non valida')
    bond=config['bond']
    if not isinstance(bond,str) or not IFACE_RE.fullmatch(bond) or bond==port:
        raise SafetyError('Nome bond non valido')
    safe=(checker or nm_safety)(port,client=client)
    if not safe.get('safe_to_disconnect'):
        raise SafetyError('Porta protetta: '+', '.join(safe.get('blockers',[])))
    cmd=command_func or command
    if cmd(['systemctl','is-active','NetworkManager'],timeout=3)!=(0,'active\n'):
        raise SafetyError('NetworkManager non attivo')
    rc,kind=cmd(['nmcli','-g','connection.type','connection','show',bond],timeout=3)
    if rc or kind.strip()!='bond':raise SafetyError('Bond non trovato fra i profili NetworkManager')
    profile='iptm-bond-port-'+port
    rc,ifname=cmd(['nmcli','-g','connection.interface-name','connection','show',profile],timeout=3)
    if action=='bond-add':
        if rc==0:raise SafetyError('Profilo porta bond già presente')
        rc,_=cmd(['nmcli','-g','connection.id','connection','show',_nm_profile(port)],timeout=3)
        if rc==0:raise SafetyError('La scheda ha già un profilo IP secondario IPTM')
        (executor or invoke)(['nmcli','--wait','8','connection','add','type','ethernet',
            'ifname',port,'con-name',profile,'connection.controller',bond,
            'connection.port-type','bond','connection.autoconnect','no',
            'ipv4.method','disabled','ipv6.method','disabled'],timeout=12)
    else:
        if rc or ifname.strip()!=port:raise SafetyError('Porta non configurata da IPTM')
        for key,want in [('connection.controller',bond),('connection.port-type','bond'),('connection.autoconnect','no')]:
            code,out=cmd(['nmcli','-g',key,'connection','show',profile],timeout=3)
            if code or out.strip()!=want:raise SafetyError('Profilo bond alterato: '+key)
        code,active=cmd(['nmcli','-g','GENERAL.CONNECTION','device','show',port],timeout=3)
        if code or active.strip()==profile:raise SafetyError('Porta ancora attiva: rifiuto scollegamento dal bond')
        (executor or invoke)(['nmcli','--wait','8','connection','delete',profile],timeout=12)
    return {'ok':True,'profile':profile,'interface':port,'bond':bond,
            'operation':action,'activated':False,'message':'Solo profilo offline modificato; bond live invariato'}


def nm_bond_live(action: str, port: str, bond: str, *, command_func=None,
                 executor=None, link_reader=None, carrier_reader=None,
                 require_console=True) -> dict:
    """Activate/deactivate an IPTM-owned standby bond port with NM's confirmation checkpoint.

    Never changes a bond master, active slave or profile configuration. NM asks
    for confirmation on the controlling terminal and reverts if the session dies.
    This cannot be called through a web CGI or headless scheduler.
    """
    if action not in ('attach','detach') or not all(isinstance(n,str) and IFNAME.fullmatch(n)
           for n in (port,bond)) or port==bond:
        raise SafetyError('Operazione o interfaccia bond non valida')
    if require_console:
        try: fd=os.open('/dev/tty',os.O_RDONLY|os.O_NOCTTY)
        except OSError as exc: raise SafetyError('Usare una console root interattiva per il bond') from exc
        else: os.close(fd)
    cmd=command_func or command
    if not shutil.which('nmcli') or cmd(['systemctl','is-active','NetworkManager'],timeout=3)!=(0,'active\n'):
        raise SafetyError('NetworkManager non attivo')
    if not (Path('/sys/class/net')/port/'device').exists() and link_reader is None:
        raise SafetyError('La porta non e una NIC fisica')
    rc,typ=cmd(['nmcli','-g','connection.type','connection','show',bond],timeout=3)
    if rc or typ.strip()!='bond': raise SafetyError('Il master non e un bond NetworkManager')
    rc,controller=cmd(['nmcli','-g','GENERAL.CONNECTION','device','show',bond],timeout=3)
    if rc or controller.strip() not in (bond,):
        raise SafetyError('Bond master non attivo nel profilo atteso')
    profile='iptm-bond-port-'+port
    expected={'connection.interface-name':port,'connection.controller':bond,
              'connection.port-type':'bond','connection.autoconnect':'no',
              'ipv4.method':'disabled','ipv6.method':'disabled'}
    for key,want in expected.items():
        rc,value=cmd(['nmcli','-g',key,'connection','show',profile],timeout=3)
        if rc or value.strip()!=want:raise SafetyError('Profilo porta non verificato: '+key)
    rc,mode=cmd(['cat','/proc/net/bonding/'+bond],timeout=3)
    if rc or 'Bonding Mode: fault-tolerance (active-backup)' not in mode:
        raise SafetyError('Attivazione live consentita soltanto a bond active-backup')
    reader=link_reader or (lambda n:_json_command(['ip','-j','-d','link','show','dev',n]))
    ports=reader(port)
    if len(ports)!=1 or ports[0].get('ifname')!=port:
        raise SafetyError('Identita della porta non verificabile')
    master=ports[0].get('master')
    rc,src=cmd(['ip','-4','-o','address','show','dev',port],timeout=3)
    if rc or src.strip():raise SafetyError('Porta con indirizzi IPv4: operazione vietata')
    rc,defaults=cmd(['ip','-4','route','show','default','dev',port],timeout=3)
    if rc or defaults.strip():raise SafetyError('La porta possiede una route predefinita')
    if action=='attach':
        if master:raise SafetyError('Porta gia assegnata a un master')
        reader_carrier=carrier_reader or (lambda n:(Path('/sys/class/net')/n/'carrier').read_text().strip())
        try: plugged=reader_carrier(port)=='1'
        except OSError:plugged=False
        if not plugged:raise SafetyError('Portante assente: prepara soltanto il profilo offline')
        rc,current=cmd(['nmcli','-g','GENERAL.CONNECTION','device','show',port],timeout=3)
        if rc or current.strip() not in ('','--'):
            raise SafetyError('Un altro profilo attivo controlla la porta')
        command_line=['nmcli','--wait','12','connection','up','id',profile,'ifname',port]
    else:
        if master!=bond:raise SafetyError('La porta non appartiene al bond previsto')
        if re.search(r'(?m)^Currently Active Slave:\s*'+re.escape(port)+r'\s*$',mode):
            raise SafetyError('Porta attiva del bond: distacco vietato')
        rc,current=cmd(['nmcli','-g','GENERAL.CONNECTION','device','show',port],timeout=3)
        if rc or current.strip()!=profile:
            raise SafetyError('Porta non attivata con profilo IPTM')
        command_line=['nmcli','--wait','12','connection','down','id',profile]
    # The outer nmcli command owns a DBus checkpoint and demands interactive
    # confirmation. A lost SSH session causes NM to revert within 120s.
    argv=['nmcli','device','checkpoint','--timeout','120',bond,port,'--']+command_line
    if executor is not None:
        executor(argv)
    else:
        cp=subprocess.run(argv,timeout=170,stdin=None,stdout=None,stderr=None,check=False)
        if cp.returncode:raise SafetyError('Operazione non confermata da NetworkManager; checkpoint annullato')
        after=reader(port)
        if len(after)!=1 or after[0].get('master')!= (bond if action=='attach' else None):
            raise SafetyError('Master della porta inatteso dopo il checkpoint')
    return {'ok':True,'operation':action,'interface':port,'master':bond,
            'applied':True,'checkpoint':'confirmed' if executor is None else 'simulated',
            'dhcp_started':False}


def main(argv: list[str]) -> int:
    if len(argv)==4 and argv[0]=='bond-live':
        if os.geteuid()!=0:
            print(json.dumps({'ok':False,'error':'Solo root'}));return 1
        try:
            result=nm_bond_live(argv[1],argv[2],argv[3])
            print(json.dumps(result,ensure_ascii=False));return 0
        except (SafetyError,ValueError,OSError,subprocess.TimeoutExpired) as exc:
            print(json.dumps({'ok':False,'error':str(exc)},ensure_ascii=False));return 2
    if len(argv)==3 and argv[0] in ('profile-save','bond-add','bond-remove'):
        if os.geteuid()!=0:
            print(json.dumps({'ok':False,'error':'Solo root'}));return 1
        try:
            raw=sys.stdin.buffer.read(4097)
            if len(raw)>4096:raise SafetyError('Richiesta troppo grande')
            obj=json.loads(raw)
            if argv[0]=='profile-save':res=nm_profile_save(argv[1],argv[2],obj)
            else:res=nm_bond_port(argv[0],argv[1],argv[2],obj)
            print(json.dumps(res,ensure_ascii=False));return 0
        except (SafetyError,ValueError,TypeError,KeyError) as exc:
            print(json.dumps({'ok':False,'error':str(exc)},ensure_ascii=False));return 2
    if len(argv) in (2,3,4) and argv[0] in ('owner','dhcp','nm-check','nm-up','nm-down','nm-prepare'):
        if os.geteuid()!=0:
            print(json.dumps({'ok':False,'error':'Solo root'}));return 1
        try:
            if argv[0]=='owner' and len(argv)==2:
                result=interface_owners(argv[1])
            elif argv[0]=='dhcp' and len(argv)==3:
                result=dhcp_preflight(argv[1],argv[2])
            elif argv[0]=='nm-check' and len(argv)==3:
                result=nm_safety(argv[1],client=argv[2])
            elif argv[0] in ('nm-up','nm-down') and len(argv)==3:
                result=nm_manage(argv[0][3:],argv[1],argv[2])
            elif argv[0]=='nm-prepare' and len(argv)==4:
                result=nm_prepare(argv[1],argv[2],argv[3])
            else:raise SafetyError('Parametri errati')
            print(json.dumps(result,ensure_ascii=False));return 0
        except SafetyError as exc:
            print(json.dumps({'ok':False,'error':str(exc)},ensure_ascii=False));return 2
    if len(argv)!=1 or argv[0] not in ('inventory','impact','pihole-schema','pihole-probe','pihole-dhcp','dhcp-preview'):
        print('uso: iptm-helper net-audit inventory|impact|pihole-schema|pihole-probe|dhcp-preview',file=sys.stderr)
        return 2
    if os.geteuid()!=0:
        print('Audit da console root o helper autorizzato',file=sys.stderr)
        return 1
    if argv[0]=='dhcp-preview':
        raw=sys.stdin.buffer.read(8193)
        if len(raw)>8192:
            print(json.dumps({'ok':False,'error':'DHCP: input oltre 8 KiB'}))
            return 2
        try:
            data=json.loads(raw)
            if not isinstance(data,dict) or set(data) != {'primary','secondary'}:
                raise ValueError('DHCP: formato non valido')
            result=validate_dhcp(data['primary'],data['secondary'])
            print(json.dumps({'ok':True,'plan':result},ensure_ascii=False))
            return 0
        except (ValueError,TypeError,KeyError) as exc:
            print(json.dumps({'ok':False,'error':str(exc)},ensure_ascii=False))
            return 2
    if argv[0]=='pihole-dhcp':
        print(json.dumps(pihole_dhcp_local(),ensure_ascii=False));return 0
    if argv[0]=='pihole-schema':
        print(json.dumps({'endpoint':'PATCH /api/config','auth':'POST /api/auth, X-FTL-SID',
                          'enabled':False,'secrets':'never included in CLI/UI'}))
        return 0
    if argv[0]=='pihole-probe':
        print(json.dumps(pihole_api_probe()))
        return 0
    result=audit()
    if argv[0]=='impact': result={'inventory':result,'plan':change_impact(result)}
    print(json.dumps(result,ensure_ascii=False,sort_keys=True))
    return 0


if __name__=='__main__':
    sys.exit(main(sys.argv[1:]))
