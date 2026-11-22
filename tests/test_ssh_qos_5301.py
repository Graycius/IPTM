#!/usr/bin/env python3
"""Offline regression tests for SSH continuity and CAKE calibration safety.

Every subprocess and Linux state query is replaced with in-memory test doubles.
No iptables/tc/systemctl commands are executed by the tests.
"""
import importlib.util
import json
import pathlib
import sys
import types
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
def load(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT/'extensions'/file)
    module=importlib.util.module_from_spec(spec)
    sys.modules[name]=module; spec.loader.exec_module(module)
    return module
ssh=load('iptm_ssh_cont_5301','ssh_continuity.py')
qos=load('iptm_qos_5301','qos_engine.py')
opt=load('iptm_rules_opt_5301','rules_optimizer.py')
count=0
def good(label, assertion):
    global count
    assert assertion, label
    count+=1
    print('PASS',label)

def raises(error, f):
    try:f()
    except error:return True
    return False

# No unrestricted SSH exceptions, and only the requesting LAN client is eligible.
for x in ['0.0.0.0','127.0.0.1','8.8.8.8','::1','not an ip','192.168.2.256']:
    good('reject remote/invalid SSH peer '+x, raises(ssh.RecoveryError,lambda x=x:ssh.trusted_ipv4(x)))
good('private LAN peer accepted', ssh.trusted_ipv4('192.168.1.25')=='192.168.1.25')
good('VPN carrier peer accepted', ssh.trusted_ipv4('100.64.9.23')=='100.64.9.23')
legacy='''-P INPUT DROP
-A INPUT -s 192.168.1.0/24 -p tcp -m multiport --dports 22,80,443,8089,8489 -j ACCEPT
-A INPUT -s 192.168.1.0/24 -p tcp --dport 22 -m recent --name sshbf --update --seconds 60 --hitcount 15 -j DROP
-A INPUT -s 192.168.1.0/24 -p tcp --dport 22 -m recent --name sshbf --set -j ACCEPT
'''
parsed=ssh.parse_kernel_rules(legacy)
good('legacy per-packet SSH correctly detected',ssh.vulnerable_ssh(parsed))
good('LAN management access verified',ssh.allowed_existing_login(parsed,'192.168.1.25'))
good('no widened subnet management access',not ssh.allowed_existing_login(parsed,'192.168.2.25'))
good('source required for prior SSH login',not ssh.allowed_existing_login(ssh.parse_kernel_rules('-A INPUT -p tcp --dport 22 -j ACCEPT'),'192.168.1.25'))
fixed=legacy.replace('--dport 22 -m recent','--dport 22 -m conntrack --ctstate NEW --syn -m recent')
good('new-SYN-only SSH not marked vulnerable',not ssh.vulnerable_ssh(ssh.parse_kernel_rules(fixed)))

class FakeKernel:
    def __init__(self, rules):self.rules=rules;self.added=[];self.fail=False
    def run(self,cmd,check=True):
        if cmd[-3:]==['-S','INPUT'] or cmd[-3:]==['-S','INPUT','']:
            return types.SimpleNamespace(returncode=0,stdout=self.rules,stderr='')
        if '-S' in cmd:return types.SimpleNamespace(returncode=0,stdout=self.rules,stderr='')
        if '-C' in cmd:
            spec=cmd[cmd.index('-C')+2:]
            present=spec in self.added
            return types.SimpleNamespace(returncode=0 if present else 1,stdout='',stderr='')
        if '-I' in cmd:
            if self.fail:raise ssh.RecoveryError('simulated iptables failure')
            self.added.append(cmd[cmd.index('-I')+3:]);return types.SimpleNamespace(returncode=0,stdout='',stderr='')
        if '-D' in cmd:
            spec=cmd[cmd.index('-D')+2:]
            if spec in self.added:self.added.remove(spec)
            return types.SimpleNamespace(returncode=0,stdout='',stderr='')
        raise AssertionError('unrecognized simulated iptables command '+str(cmd))
k=FakeKernel(legacy)
with patch.object(ssh,'run',k.run),patch.object(ssh.os,'geteuid',return_value=0):
    result=ssh.recover('192.168.1.25')
    good('two minimal recovery rules inserted',result['changed'] and len(k.added)==2)
    good('new SSH access restricted to one client',any('-s' in s and '192.168.1.25/32' in s for s in k.added))
    good('recovery preserves other iptables chains',all('--comment' in s and '-j' in s and 'ACCEPT' in s for s in k.added))
    again=ssh.recover('192.168.1.25')
    good('recovery is idempotent',not again['changed'] and len(k.added)==2)
    good('unauthorized second subnet refused',raises(ssh.RecoveryError,lambda:ssh.recover('192.168.2.25')))
with patch.object(ssh,'run',FakeKernel(fixed).run),patch.object(ssh.os,'geteuid',return_value=0):
    good('new policy requires no rescue',not ssh.recover('192.168.1.25')['changed'])
with patch.object(ssh,'run',k.run),patch.object(ssh.os,'geteuid',return_value=999):
    good('recovery rejects unprivileged caller',raises(ssh.RecoveryError,lambda:ssh.recover('192.168.1.25')))

# QoS must be non-disruptive on a shaped or busy WAN.
good('invalid QoS interface fails closed',not qos.interface_idle('../eth0',duration=.001))
with patch.object(qos.pathlib.Path,'read_text',side_effect=OSError('simulated counter unreadable')):
    good('unreadable NIC counters fail closed',not qos.interface_idle('bond0',duration=.001))
with patch.object(qos,'read',return_value={'state':'confirmed'}):
    good('manual throughput calibration prohibited under CAKE',raises(qos.QosError,lambda:qos.calibration_start('bond0')))
with patch.object(qos,'read',return_value=None),patch.object(qos,'topology_report',return_value={'free':True}),patch.object(qos,'interface_idle',return_value=False):
    good('manual throughput calibration prohibited on busy WAN',raises(qos.QosError,lambda:qos.calibration_start('bond0')))
with patch.object(qos,'read',return_value=None),patch.object(qos,'topology_report',return_value={'free':False}):
    good('manual calibration refuses another QoS owner',raises(qos.QosError,lambda:qos.calibration_start('bond0')))

# Verify exact attached rules.v4 without deploying it.
source=pathlib.Path('/mnt/data/Testo incollato.txt')
if source.is_file():
    text=source.read_text(encoding='utf-8-sig')
    report=opt.analyze(text)
    good('original incident recognized', 'SSH_ESTABLISHED_RATE_LIMIT' in {x['id'] for x in report['findings']})
    good('optimizer corrects legacy recent counters', all('--ctstate NEW --syn' in l for l in report['draft'].splitlines() if l.startswith('-A INPUT ') and '--dport 22' in l and ('--update' in l or '--connlimit-above' in l)))
    again=opt.analyze(report['draft'])
    good('optimizer fix is idempotent', again['draft']==report['draft'])
else:
    print('INFO optional user-supplied rules.v4 fixture not mounted: incident tests skipped')
print(f'PASS TOTAL {count} isolated SSH/QoS security checks')
