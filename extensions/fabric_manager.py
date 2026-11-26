#!/usr/bin/env python3
"""Topology and zone model for IPTM network fabric.

Pure validation, kernel command *preview* and packet-path simulation. Nothing
in this module modifies the host. External switches are inventory/port plans,
never remote configuration or assumed discovery credentials.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
from typing import Any

IFACE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$')
ZONE = re.compile(r'^[a-z][a-z0-9_-]{0,23}$')
NAME = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9 _.-]{0,39}$')
POLICIES = {'allow', 'deny'}
SWITCH_MODES = {'access', 'trunk', 'hybrid'}
BOND_MODES = {'active-backup', '802.3ad', 'balance-xor'}
MAX = {'bridges': 12, 'vlans': 64, 'bonds': 8, 'zones': 24, 'switches': 12, 'policies': 256}

class FabricError(ValueError):
    pass


def _iface(value: Any, label: str) -> str:
    if not isinstance(value, str) or not IFACE.fullmatch(value) or value == 'lo':
        raise FabricError(f'{label}: nome interfaccia non valido')
    return value


def _zone(value: Any) -> str:
    if not isinstance(value, str) or not ZONE.fullmatch(value):
        raise FabricError('Zona: identificatore non valido')
    return value


def _uint(value: Any, label: str, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, (str, int)) or not re.fullmatch(r'[0-9]{1,12}',str(value)):
        raise FabricError(f'{label}: intero richiesto')
    n = int(value)
    if not low <= n <= high:
        raise FabricError(f'{label}: intervallo {low}-{high}')
    return n


def _cidr(value: Any, label: str) -> str:
    if value in (None, ''):
        return ''
    try:
        if not isinstance(value,str):raise ValueError()
        i = ipaddress.ip_interface(value)
        if i.version != 4 or i.ip.is_loopback or i.ip.is_unspecified or i.ip.is_multicast:
            raise ValueError()
        return str(i)
    except (ValueError, TypeError) as exc:
        raise FabricError(f'{label}: indirizzo IPv4 CIDR non valido') from exc


def _array(model: dict, key: str) -> list:
    rows = model.get(key, [])
    if not isinstance(rows, list) or len(rows) > MAX[key]:
        raise FabricError(f'{key}: numero elementi eccessivo o formato non valido')
    return rows


def validate_fabric(value: Any, physical_names: set[str], *, reserved_networks=()) -> dict:
    """Reject cross-L2 mixing, overlapping networks and unsupported switch assumptions.

    Pure planner: never treats a software bridge as a substitute for a managed
    switch nor assumes VLANs work over all adapters.
    """
    if value is None:
        value = {}
    if not isinstance(value, dict) or set(value) - set(MAX):
        raise FabricError('Topologia: campi non riconosciuti')
    model = {k: _array(value, k) for k in MAX}
    names = set(physical_names)
    bridged_ports: set[str] = set()
    bond_slaves: set[str] = set()
    bridge_names: set[str] = set()
    zones = {}
    for obj in model['zones']:
        if not isinstance(obj, dict) or set(obj) - {'name', 'default'}:
            raise FabricError('Zona: formato non valido')
        z = _zone(obj.get('name'))
        if z in zones:
            raise FabricError('Zona duplicata: ' + z)
        default = obj.get('default', 'deny')
        if default not in POLICIES:
            raise FabricError('Zona: policy di default non valida')
        zones[z] = {'name': z, 'default': default}
    # Canonical zones are always represented in preview and may be referenced.
    for z in ('wan', 'lan', 'iot', 'guest', 'management', 'vpn'):
        zones.setdefault(z, {'name': z, 'default': 'deny'})

    bonds = []
    for obj in model['bonds']:
        if not isinstance(obj, dict) or set(obj) - {'name', 'ports', 'mode', 'lacp_confirmed'}:
            raise FabricError('Bond: formato non valido')
        n = _iface(obj.get('name'), 'Bond')
        ports = obj.get('ports')
        mode = obj.get('mode', 'active-backup')
        if n in names or not isinstance(ports, list) or len(ports) < 2 or mode not in BOND_MODES:
            raise FabricError('Bond: interfaccia, porte o modalità non valide')
        if len(set(ports)) != len(ports) or any(p not in physical_names or p in bond_slaves for p in ports):
            raise FabricError('Bond: porta fisica sconosciuta, duplicata o già assegnata')
        if mode == '802.3ad' and obj.get('lacp_confirmed') is not True:
            raise FabricError('LACP richiede conferma switch 802.3ad compatibile')
        names.add(n)
        bond_slaves.update(ports)
        bonds.append({'name': n, 'ports': sorted(ports), 'mode': mode,
                      'lacp_confirmed': obj.get('lacp_confirmed') is True})

    networks = [(str(net), ipaddress.ip_network(net, strict=False)) for net in reserved_networks if net]
    bridges = []
    for obj in model['bridges']:
        if not isinstance(obj, dict) or set(obj) - {'name', 'ports', 'stp', 'vlan_filtering', 'address', 'zone'}:
            raise FabricError('Bridge: formato non valido')
        n = _iface(obj.get('name'), 'Bridge')
        ports = obj.get('ports')
        if n in names or not isinstance(ports, list) or not ports:
            raise FabricError('Bridge: nome duplicato oppure nessuna porta')
        if len(ports) != len(set(ports)) or any(p not in names or p in bridged_ports or p in bond_slaves for p in ports):
            raise FabricError('Bridge: porta sconosciuta, duplicata o già associata a bond/bridge')
        # Bridges of WAN and LAN at the same time are rejected by the caller's
        # physical role check (fabric alone has no role information).
        if type(obj.get('stp', True)) is not bool or type(obj.get('vlan_filtering', False)) is not bool:
            raise FabricError('Bridge: STP/filtraggio VLAN booleani obbligatori')
        address = _cidr(obj.get('address', ''), 'Bridge')
        z = _zone(obj.get('zone', 'lan'))
        if z not in zones:
            raise FabricError('Bridge: zona non dichiarata')
        if address:
            net = ipaddress.ip_interface(address).network
            if any(net.overlaps(other) for _,other in networks):
                raise FabricError(f'Bridge {n}: subnet sovrapposta')
            networks.append((n,net))
        names.add(n); bridge_names.add(n); bridged_ports.update(ports)
        bridges.append({'name': n, 'ports': list(ports), 'stp': obj.get('stp', True),
                        'vlan_filtering': obj.get('vlan_filtering', False),
                        'address': address, 'zone': z})

    vlan_names: set[str] = set()
    vlan_keys: set[tuple[str, int]] = set()
    vlans = []
    for obj in model['vlans']:
        if not isinstance(obj, dict) or set(obj) - {'name', 'parent', 'vid', 'zone', 'address', 'dhcp_server'}:
            raise FabricError('VLAN: formato non valido')
        n = _iface(obj.get('name'), 'VLAN')
        parent = _iface(obj.get('parent'), 'VLAN parent')
        vid = _uint(obj.get('vid'), 'VLAN ID', 1, 4094)
        z = _zone(obj.get('zone'))
        addr = _cidr(obj.get('address', ''), 'VLAN')
        if parent not in names or parent in bond_slaves or parent in bridged_ports or parent in vlan_names:
            raise FabricError('VLAN: parent non valido, scegliere NIC, bond o bridge')
        if parent in bridge_names and not next(b['vlan_filtering'] for b in bridges if b['name'] == parent):
            raise FabricError('VLAN: bridge parent richiede vlan_filtering')
        if z not in zones or n in names or (parent, vid) in vlan_keys:
            raise FabricError('VLAN: zona/identificatore duplicato o non valido')
        if z == 'wan' and obj.get('dhcp_server'):
            raise FabricError('VLAN WAN: server DHCP vietato')
        if type(obj.get('dhcp_server', False)) is not bool:
            raise FabricError('VLAN: flag server DHCP non valido')
        if addr:
            net = ipaddress.ip_interface(addr).network
            for old_name, other in networks:
                if net.overlaps(other):
                    raise FabricError(f'VLAN {n}: rete sovrapposta a {old_name}')
            networks.append((n, net))
        names.add(n); vlan_names.add(n); vlan_keys.add((parent, vid))
        vlans.append({'name': n, 'parent': parent, 'vid': vid, 'zone': z,
                      'address': addr, 'dhcp_server': obj.get('dhcp_server', False)})

    policies = []
    policy_keys = set()
    for obj in model['policies']:
        if not isinstance(obj, dict) or set(obj) - {'source', 'destination', 'action'}:
            raise FabricError('Policy: formato non valido')
        a = _zone(obj.get('source')); b = _zone(obj.get('destination')); act = obj.get('action')
        if a not in zones or b not in zones or act not in POLICIES or (a, b) in policy_keys:
            raise FabricError('Policy: zone/azione non valide o coppia duplicata')
        policy_keys.add((a, b)); policies.append({'source': a, 'destination': b, 'action': act})
    switches = []
    for obj in model['switches']:
        if not isinstance(obj, dict) or set(obj) - {'name', 'management_ip', 'ports', 'vendor'}:
            raise FabricError('Switch: formato non valido')
        n = obj.get('name')
        if not isinstance(n, str) or not NAME.fullmatch(n) or any(x['name'] == n for x in switches):
            raise FabricError('Switch: nome invalido o duplicato')
        mgmt = obj.get('management_ip', '')
        if mgmt:
            try: ipaddress.ip_address(mgmt)
            except ValueError as exc: raise FabricError('Switch: IP di gestione non valido') from exc
        ports = obj.get('ports', [])
        if not isinstance(ports, list) or len(ports) > 64:
            raise FabricError('Switch: porte non valide')
        safe_ports = []
        seen_ports = set()
        for p in ports:
            if not isinstance(p, dict) or set(p) - {'name', 'mode', 'pvid', 'tagged'}:
                raise FabricError('Switch: definizione porta non valida')
            pn = p.get('name'); mode = p.get('mode', 'access')
            if not isinstance(pn, str) or not NAME.fullmatch(pn) or pn in seen_ports or mode not in SWITCH_MODES:
                raise FabricError('Switch: porta duplicata o modo non valido')
            tagged = p.get('tagged', [])
            if not isinstance(tagged, list) or len(tagged) > 64:
                raise FabricError('Switch: VLAN tagged non valide')
            tags = [_uint(v, 'VID switch tagged', 1, 4094) for v in tagged]
            if len(tags) != len(set(tags)) or (mode == 'access' and tags):
                raise FabricError('Switch: porta access non può avere VLAN tagged')
            pvid = _uint(p.get('pvid', 1), 'PVID', 1, 4094)
            if pvid in tags:
                raise FabricError('Switch: VLAN native/PVID anche tagged')
            seen_ports.add(pn)
            safe_ports.append({'name': pn, 'mode': mode, 'pvid': pvid, 'tagged': tags})
        vendor = obj.get('vendor', '')
        if not isinstance(vendor, str) or len(vendor) > 64:
            raise FabricError('Switch: marca non valida')
        switches.append({'name': n, 'vendor': vendor, 'management_ip': str(mgmt), 'ports': safe_ports,
                         'configured_remotely': False})

    return {'bridges': bridges, 'bonds': bonds, 'vlans': vlans,
            'zones': list(zones.values()), 'policies': policies, 'switches': switches}


def plan_fabric(fabric: dict, *, nic_roles: dict[str, str] | None = None) -> dict:
    """Render suggestions, explicitly not commands allowed for an executor."""
    roles = nic_roles or {}
    warnings = ['La bozza non modifica i gestori di rete, il kernel, iptables né gli switch esterni.']
    steps = []
    for bond in fabric['bonds']:
        steps.append({'category': 'bond', 'detail': f"Creare {bond['name']} ({bond['mode']}) con porte {', '.join(bond['ports'])}; verificare lo switch e il recupero console"})
    for bridge in fabric['bridges']:
        steps.append({'category': 'bridge', 'detail': f"Creare {bridge['name']} con {', '.join(bridge['ports'])}; STP={'on' if bridge['stp'] else 'off'}, VLAN filtering={'on' if bridge['vlan_filtering'] else 'off'}"})
        if not bridge['stp'] and len(bridge['ports']) > 1:
            warnings.append(f"{bridge['name']}: STP disattivato con più porte, verificare assenza di loop L2")
        if any(roles.get(p) == 'wan' for p in bridge['ports']):
            raise FabricError('Bridge: una WAN fisica non può essere inserita in bridge LAN/IoT senza progetto isolato')
    for vlan in fabric['vlans']:
        steps.append({'category': 'vlan', 'detail': f"VLAN {vlan['vid']} su {vlan['parent']} → {vlan['name']} / zona {vlan['zone']} / IPv4 {vlan['address'] or 'non assegnato'}"})
        if roles.get(vlan['parent']) == 'wan' and vlan['zone'] != 'wan':
            warnings.append(f"{vlan['name']}: VLAN {vlan['zone']} su uplink WAN fisico, verificare trunk L2 e separazione provider")
        if vlan['dhcp_server']:
            warnings.append(f"{vlan['name']}: DHCP server richiesto ma non ancora configurato; impedire sovrapposizione con Pi-hole/DHCP esistente")
    for switch in fabric['switches']:
        steps.append({'category': 'switch', 'detail': f"Switch {switch['name']}: {len(switch['ports'])} porte dichiarate, gestione manuale/vendor specifica"})
    for policy in fabric['policies']:
        steps.append({'category': 'zone', 'detail': f"{policy['source']} → {policy['destination']}: {policy['action']}"})
    return {'steps': steps, 'warnings': warnings, 'execution_enabled': False,
            'zone_default': 'deny', 'switch_auto_configuration': False,
            'layer2_isolation_enforced': False, 'routing_enforced': False}


def simulate_packet(fabric: dict, source: str, destination: str, *, flow: str = '') -> dict:
    """Policy check and explain-only forwarding outcome. No claim of real packet handling."""
    zones = {z['name']: z for z in fabric['zones']}
    if source not in zones or destination not in zones:
        raise FabricError('Simulazione: zona sconosciuta')
    matched = next((p for p in fabric['policies'] if p['source'] == source and p['destination'] == destination), None)
    action = matched['action'] if matched else ('allow' if source == destination else zones[source]['default'])
    fingerprint = hashlib.sha256(flow.encode()).hexdigest()[:12] if flow else ''
    return {'source': source, 'destination': destination, 'action': action,
            'reason': 'policy esplicita' if matched else 'default zona',
            'flow_fingerprint': fingerprint, 'simulation_only': True}
