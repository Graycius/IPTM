#!/usr/bin/env python3
"""Preview-only multi-uplink routing and QoS model.

Matches the route/NAT/conntrack dependencies without mutating iproute, qdisc,
iptables or DNS. No live flow aggregation claims are made.
"""
from __future__ import annotations
import hashlib
import ipaddress


def propose(wans: list[dict], strategy: str, weights: dict[str, int]) -> dict:
    paths = []
    for index, wan in enumerate(wans):
        address = wan.get('address', '')
        gateway = wan.get('gateway', '') or ('DHCP lease: dynamic' if wan.get('dhcp') else '')
        if gateway and gateway != 'DHCP lease: dynamic':
            gateway = str(ipaddress.ip_address(gateway))
        paths.append({'interface': wan['name'], 'priority': wan['priority'],
                      'route_table': 210 + index, 'gateway': gateway,
                      'weight': weights.get(wan['name'], 1),
                      'capacity_mbps': wan['capacity_mbps'],
                      'qos_existing_limits_preserved': True,
                      'uplink_capacity_not_measured': True,
                      'snat': 'masquerade interface' if wan.get('dhcp') else 'SNAT or masquerade per uplink',
                      'return_path': 'restore per-flow connmark/fwmark on reply; conntrack zone review'})
    return {'mode': strategy, 'paths': paths,
            'policy': 'per-connessione, mai bilanciamento casuale per pacchetto',
            'conntrack_global_flush': False,
            'router_originated_traffic': 'separate OUTPUT policy requires explicit rule',
            'incoming': 'DNAT per-WAN with symmetric return route: separate validation required',
            'ipv6': 'isolated preview; no IPv6 route or sysctl changes',
            'activation': 'none - plans are not iptables/iproute scripts',
            'failure_monitoring': 'per-WAN gateway and external probes, quorum and hysteresis required',
            'sqm': 'CAKE per uplink; keep last verified limits; speedtest failures never lower configured limits'}


def select_flow(uplinks: list[dict], flow_id: str) -> dict:
    """Deterministic example for *new* connections, not runtime route selection."""
    if not uplinks or not isinstance(flow_id, str) or len(flow_id) > 256:
        raise ValueError('flow non valido')
    if any(not isinstance(w,dict) or type(w.get('weight')) is not int or not isinstance(w.get('interface'),str) or not w['interface'] for w in uplinks):
        raise ValueError('uplink non valido')
    if len({w['interface'] for w in uplinks}) != len(uplinks):
        raise ValueError('uplink duplicato')
    total = sum(w['weight'] for w in uplinks)
    if total <= 0 or total > 128 or any(w['weight'] < 1 for w in uplinks):
        raise ValueError('pesi WAN non validi')
    ticket = int.from_bytes(hashlib.blake2s(flow_id.encode(), digest_size=8).digest(), 'big') % total
    for uplink in uplinks:
        ticket -= int(uplink['weight'])
        if ticket < 0:
            return {'interface': uplink['interface'], 'simulation_only': True,
                    'inbound_symmetric_return_not_verified': True}
    raise RuntimeError('Errore aritmetico dei pesi')
