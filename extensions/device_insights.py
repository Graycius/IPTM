#!/usr/bin/env python3
"""Read-only per-LAN-neighbour connection overview, inspired by RethinkDNS.

Unlike Android VPNService, a router cannot attribute flows to Android apps.
No firewall modification, packet payload capture or persistent activity log.
"""
import collections
import ipaddress
import json
import selectors
import time
import re
import subprocess

MAX_DATA = 1_000_000
MAX_ROWS = 3500


def neighbours():
    try:
        p = subprocess.run(['ip', '-j', '-4', 'neigh', 'show'], capture_output=True, text=True, timeout=3)
        if p.returncode:
            return {}
        entries = json.loads(p.stdout[:200_000])
        found = {}
        for row in entries[:2048]:
            ip = row.get('dst', '')
            mac = row.get('lladdr', '').lower()
            state = row.get('state', '')
            if re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', mac) and 'FAILED' not in str(state):
                obj = ipaddress.ip_address(ip)
                if obj.version == 4 and obj.is_private and not obj.is_loopback:
                    found[str(obj)] = mac
        return found
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return {}


def kernel_data():
    for source in ('/proc/net/nf_conntrack', '/proc/net/ip_conntrack'):
        try:
            with open(source, 'rb') as f:
                data = f.read(MAX_DATA + 1)
            if len(data) > MAX_DATA:
                return 'truncated', data[:MAX_DATA].decode('ascii', 'replace')
            return 'kernel', data.decode('ascii', 'replace')
        except (OSError, PermissionError):
            continue
    # Some kernels expose conntrack through netlink only. Bound both time and
    # output to avoid hanging a web worker on a damaged/overloaded kernel.
    try:
        proc = subprocess.Popen(['conntrack', '-L', '-f', 'ipv4'], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        selector = selectors.DefaultSelector()
        selector.register(proc.stdout, selectors.EVENT_READ)
        chunks = []
        total = 0
        deadline = time.monotonic() + 3.0
        try:
            while time.monotonic() < deadline and total <= MAX_DATA:
                events = selector.select(timeout=min(0.2, max(0.0, deadline - time.monotonic())))
                if not events and proc.poll() is not None:
                    break
                for key, _ in events:
                    block = key.fileobj.read1(min(16384, MAX_DATA + 1 - total))
                    if not block:
                        selector.unregister(key.fileobj)
                        break
                    chunks.append(block)
                    total += len(block)
                if total > MAX_DATA:
                    break
            data = b''.join(chunks)
            if total > MAX_DATA:
                return 'truncated', data[:MAX_DATA].decode('ascii', 'replace')
            if proc.poll() is None:
                # Differentiate an empty completed command from a timed out one.
                return 'unavailable', ''
            return ('netlink' if proc.returncode in (0, 1) else 'unavailable'), data.decode('ascii', 'replace')
        finally:
            selector.close()
            if proc.poll() is None:
                proc.kill()
            proc.wait(timeout=3)
    except (OSError, subprocess.TimeoutExpired):
        return 'unavailable', ''


def analyze(raw, mapping):
    totals = collections.defaultdict(lambda: {'connections': 0, 'tcp': 0, 'udp': 0,
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
        item[proto] += 1
        item['dns' if port == 53 else 'dot' if port == 853 else 'https' if port == 443 else 'other'] += 1
        seen += 1
    return [{'ip': ip, 'mac': mapping[ip], **stat} for ip, stat in sorted(
        totals.items(), key=lambda item: -item[1]['connections'])[:40]], seen


def main():
    mapping = neighbours()
    status, raw = kernel_data()
    devices, connections = analyze(raw, mapping)
    print(json.dumps({'ok': status in ('kernel', 'netlink', 'truncated'), 'source': status,
                      'neighbours': len(mapping), 'connections': connections,
                      'devices': devices, 'partial': status == 'truncated',
                      'note': 'Solo connessioni tracciate e IP presenti in ip neigh. Nessuna attribuzione alle app Android. HTTPS non viene decifrato.'}))


if __name__ == '__main__':
    main()
