#!/usr/bin/env python3
"""Read-only per-LAN-neighbour connection overview, inspired by RethinkDNS.

Unlike Android VPNService, a router cannot attribute flows to Android apps.
No firewall modification, packet payload capture or persistent activity log.
"""
import collections
import ipaddress
import json
from command_transport import capture, OutputLimitError
import re
import subprocess

MAX_DATA = 1_000_000
MAX_ROWS = 3500


def bounded_output(argv, limit, timeout):
    """Partial stdout is explicitly labelled; all other consumers reject it."""
    try:
        result = capture(argv, timeout=timeout, stdout_limit=limit,
                         stderr_limit=65536, retain_prefix=True, encoding='utf-8',
                         env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
        return ('ok', result.stdout) if result.returncode == 0 else ('unavailable', '')
    except OutputLimitError as exc:
        return ('truncated', exc.prefix.decode('utf-8','replace')) if exc.stream == 0 else ('unavailable','')
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return 'unavailable', ''


def parse_neighbours(raw):
    try:
        entries=json.loads(raw)
    except (ValueError,TypeError):
        return {}
    if not isinstance(entries,list):
        return {}
    found={}
    for row in entries[:2048]:
        if not isinstance(row,dict):
            continue
        ip,mac=row.get('dst'),row.get('lladdr')
        if not isinstance(ip,str) or not isinstance(mac,str):
            continue
        if not re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}',mac.lower()) or 'FAILED' in str(row.get('state','')) or 'INCOMPLETE' in str(row.get('state','')):
            continue
        try:
            obj=ipaddress.IPv4Address(ip)
        except ValueError:
            continue
        if obj.is_private and not (obj.is_loopback or obj.is_unspecified or obj.is_multicast):
            found[str(obj)]=mac.lower()
    return found


def neighbours():
    state, raw=bounded_output(['ip','-j','-4','neigh','show'],200000,3)
    return parse_neighbours(raw) if state=='ok' else {}


def kernel_data():
    for source in ('/proc/net/nf_conntrack','/proc/net/ip_conntrack'):
        try:
            with open(source,'rb') as f:
                data=f.read(MAX_DATA+1)
            state='truncated' if len(data)>MAX_DATA else 'kernel'
            return state,data[:MAX_DATA].decode('ascii','replace')
        except OSError:
            continue
    state,raw=bounded_output(['conntrack','-L','-f','ipv4'],MAX_DATA,3)
    return ('netlink' if state=='ok' else state),raw


def analyze(raw, mapping):
    totals = collections.defaultdict(lambda: {'connections': 0, 'tcp': 0, 'udp': 0, 'other_protocol': 0,
                                               'dns': 0, 'dot': 0, 'https': 0, 'other': 0})
    seen = 0
    for line in raw.splitlines()[:MAX_ROWS]:
        # Original-direction tuple only. Reply tuple often repeats src/dst and
        # must not count as an independent connection.
        m = re.search(r'\bsrc=(\d{1,3}(?:\.\d{1,3}){3})\s+dst=(\d{1,3}(?:\.\d{1,3}){3})\b', line)
        if not m:
            continue
        client = m.group(1) if m.group(1) in mapping else m.group(2) if m.group(2) in mapping else None
        if not client:
            continue
        try:
            proto = 'tcp' if re.search(r'\btcp\b', line.split('src=', 1)[0]) else (
                    'udp' if re.search(r'\budp\b', line.split('src=', 1)[0]) else 'other')
            port = re.search(r'\bdport=(\d{1,5})\b', line)
            port = int(port.group(1)) if port else 0
        except (ValueError, IndexError):
            continue
        item = totals[client]
        item['connections'] += 1
        item[proto if proto != 'other' else 'other_protocol'] += 1
        item['dns' if port == 53 else 'dot' if port == 853 else 'https' if port == 443 else 'other'] += 1
        seen += 1
    return [{'ip': ip, 'mac': mapping[ip], **stat} for ip, stat in sorted(
        totals.items(), key=lambda item: (-item[1]['connections'], ipaddress.ip_address(item[0])))[:40]], seen


def main():
    mapping = neighbours()
    status, raw = kernel_data()
    devices, connections = analyze(raw, mapping)
    print(json.dumps({'ok': status in ('kernel', 'netlink', 'truncated'), 'source': status,
                      'neighbours': len(mapping), 'connections': connections,
                      'devices': devices, 'partial': status == 'truncated' or len(raw.splitlines()) > MAX_ROWS,
                      'note': 'Solo connessioni tracciate e IP presenti in ip neigh. Nessuna attribuzione alle app Android. HTTPS non viene decifrato.'}))


if __name__ == '__main__':
    main()
