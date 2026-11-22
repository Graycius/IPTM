#!/usr/bin/env python3
"""Offline regression fixtures. Do not contain user configuration or MAC IDs."""
from pathlib import Path
import importlib.util
import json
import subprocess
import sys

source = Path(__file__).resolve().parents[1] / 'extensions' / 'rules_optimizer.py'
spec = importlib.util.spec_from_file_location('iptm_rules_optimizer_test', source)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

rules = '''*raw
:PREROUTING ACCEPT [0:0]
# >>> IPTM:raw-drop
-A PREROUTING -p udp --dport 1900 -j DROP
# <<< IPTM:raw-drop
COMMIT
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
# >>> IPTM:lockout
-A INPUT -s 192.168.50.0/24 -p tcp --dport 22 -j ACCEPT
# <<< IPTM:lockout
# >>> IPTM:svc-in-a
-A INPUT -p tcp --dport 22 -j ACCEPT
# <<< IPTM:svc-in-a
# >>> IPTM:lan-tcp
-A INPUT -s 192.168.50.0/24 -p tcp -j ACCEPT
# <<< IPTM:lan-tcp
# >>> IPTM:apps
-A INPUT -s 192.168.50.0/24 -p udp --dport 1900 -j ACCEPT -m comment --comment "IPTM-app:minidlna"
-A INPUT -s 192.168.50.0/24 -p tcp --dport 2375 -j ACCEPT -m comment --comment "IPTM-app:docker"
# <<< IPTM:apps
COMMIT
'''
r = module.analyze(rules)
assert r['ok'] and r['changes']
assert '-A INPUT -p tcp --dport 22 -j ACCEPT\n' not in r['draft']
assert '-A INPUT -s 192.168.50.0/24 -p tcp -j ACCEPT\n' not in r['draft']
assert 'IPTM-app:docker' not in r['draft']
assert '-A PREROUTING -p udp --dport 1900 -j DROP' not in r['draft']
assert module.analyze(r['draft'])['changes'] == []

# Port conflicts on a dedicated WAN are not evidence of a LAN problem.
dedicated = rules.replace('-A PREROUTING -p udp --dport 1900 -j DROP',
                          '-A PREROUTING -i eth0 -p udp --dport 1900 -j DROP')
x = module.analyze(dedicated)
assert '-A PREROUTING -i eth0 -p udp --dport 1900 -j DROP' in x['draft']
assert x['findings']

scope = '''*raw
:PREROUTING ACCEPT [0:0]
-A PREROUTING -p tcp --dport 8080 -j DROP
COMMIT
*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -o eth0 -j MASQUERADE
COMMIT
*filter
:FORWARD DROP [0:0]
-A FORWARD -s 192.168.50.0/24 -j ACCEPT
:INPUT DROP [0:0]
-A INPUT -i eth0 -p tcp --dport 22 -j ACCEPT
COMMIT
'''
x = module.analyze(scope)
ids = {f['id'] for f in x['findings']}
assert {'RAW_ALL_INTERFACES', 'GLOBAL_SNAT', 'FORWARD_UNBOUNDED', 'SSH_INTERFACE_ONLY'} <= ids, ids
assert x['draft'] == scope # manual policy is not rewritten

for mode in ('audit', 'conservative'):
    p = subprocess.run([sys.executable, '-B', str(source), mode], input=rules.encode(),
                       capture_output=True, check=True)
    j = json.loads(p.stdout)
    assert j['draft'] == rules and not j['changes']

p = subprocess.run([sys.executable, '-B', str(source), 'harden'],
                   input=b'*filter\x00', capture_output=True)
assert p.returncode != 0 and json.loads(p.stdout)['ok'] is False
print('PASS optimizer: security regressions, scoped WAN, read-only mode, idempotence and invalid input')
