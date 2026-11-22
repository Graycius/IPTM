#!/usr/bin/env python3
"""Offline regression: no real firewall, qdisc or proxy mutations."""
import importlib.util, json, unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
def get(n):
    p=ROOT/'extensions'/n
    spec=importlib.util.spec_from_file_location('iptm_test_'+p.stem,p)
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    return mod
rp=get('rules_performance.py')
fw=get('firewall_recovery.py'); qos=get('qos_engine.py');traffic=get('traffic_observer.py')
RULES='''*filter
:INPUT DROP [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -m set --match-set crowdsec-blacklists-3 src -j DROP
-A INPUT -p tcp --dport 22 -j ACCEPT
-A FORWARD -p udp --dport 443 -j DROP
-A FORWARD -m hashlimit --hashlimit-above 2000kb/s --hashlimit-name bwup -j DROP
COMMIT
'''

class AuditTests(unittest.TestCase):
    def test_quic_and_drop_rate(self):
        v=rp.analyze(RULES)
        self.assertTrue(v['read_only'])
        self.assertIn('quic',[x['id'] for x in v['findings']])
        self.assertIn('rate-drops',[x['id'] for x in v['findings']])
    def test_real_rules_logging(self):
        raw='*filter\n:INPUT DROP [0:0]\n' + ''.join('-A INPUT -m limit --limit 2/min -j LOG\n' for _ in range(25)) + ''.join('-A INPUT -m set --match-set bl_test src -j DROP\n' for _ in range(25)) + 'COMMIT\n'
        v=rp.analyze(raw)
        self.assertGreater(v['counts']['logging'],20)
        self.assertGreater(v['counts']['ipset_lookups'],20)
    def test_malformed_inputs(self):
        for raw in ('','\x00','X'*(rp.MAX_BYTES+1),'-A INPUT -j DROP\n'*30001):
            with self.subTest(length=len(raw)):
                with self.assertRaises(rp.AuditError):rp.analyze(raw)

class FirewallTests(unittest.TestCase):
    def test_missing_set_drop_only(self):
        result,removed=fw.normalized(RULES.encode(),set(),'4')
        self.assertEqual(removed,['crowdsec-blacklists-3'])
        self.assertIn(b'--dport 22 -j ACCEPT',result)
        self.assertNotIn(b'--match-set',result)
    def test_present_set_same_bytes(self):
        result,removed=fw.normalized(RULES.encode(),{'crowdsec-blacklists-3'},'4')
        self.assertEqual(result,RULES.encode())
        self.assertEqual(removed,[])
    def test_non_crowdsec_fail_closed(self):
        for name,target in [('my_private','DROP'),('crowdsec-blacklists-3','ACCEPT')]:
            data=RULES.replace('crowdsec-blacklists-3',name).replace('src -j DROP',f'src -j {target}')
            with self.assertRaises(fw.RecoveryError):fw.normalized(data.encode(),set(),'4')
    def test_bad_input_and_wrong_family(self):
        for data in [b'',b'\x00x',b'X'*(fw.MAX_BYTES+1)]:
            with self.assertRaises(fw.RecoveryError):fw.normalized(data,set(),'4')
        with self.assertRaises(fw.RecoveryError):fw.normalized(RULES.encode(),set(),'6')

class QosTests(unittest.TestCase):
    def test_unlimited_both_directions(self):
        state={'interface':'bond0','ifb':'ifb0','up_mbit':50,'down_mbit':250,
               'diffserv':'diffserv4','nat':False,'wash':False,'ack_filter':False,'overhead':0}
        commands=[]
        def run(args,**kw):commands.append(args);return SimpleNamespace(stdout='',returncode=0)
        with patch.object(qos,'owned'),patch.object(qos,'verified_ingress_for_state',return_value=True),\
             patch.object(qos,'check_cake_bandwidth'),patch.object(qos,'run',side_effect=run):
            qos.set_unlimited(state)
        self.assertEqual(len(commands),2)
        self.assertTrue(all('unlimited' in cmd for cmd in commands))
        self.assertIn('bond0',commands[0]);self.assertIn('ifb0',commands[1])
    def test_no_watchdog_no_calibration(self):
        with patch.object(qos,'guard_ready',side_effect=qos.QosError('no guard')),\
             patch.object(qos,'run',side_effect=AssertionError('must not mutate')):
            with self.assertRaises(qos.QosError):qos.start_unshaped_calibration('bond0',{}, {})
    def test_original_rate_recovery(self):
        state={'state':'confirmed','version':qos.VERSION,'interface':'bond0','ifb':'ifb0',
               'up_mbit':50,'down_mbit':250,'diffserv':'diffserv4','nat':False,'wash':False,
               'ack_filter':False,'overhead':0,'ifindex':7,'ifb_ifindex':8,
               'mac':'00:11:22:33:44:55','ingress_added':True,'ingress_policy_count':0}
        journal={'state':'pending','version':qos.VERSION,'interface':'bond0','ifb':'ifb0'}
        seen=[]
        def run(args,**kw):seen.append(args);return SimpleNamespace(stdout='',returncode=0)
        with patch.object(qos,'read',return_value=state),patch.object(qos,'owned'),\
             patch.object(qos,'root_cake_text'),patch.object(qos,'check_cake_bandwidth'),\
             patch.object(qos,'run',side_effect=run),patch.object(qos,'atom'):
            qos.restore_cake_after_calibration(journal)
        self.assertIn('50mbit',seen[0]);self.assertIn('250mbit',seen[1])
        self.assertEqual(journal['state'],'restored')
    def test_downgrade_only_manual(self):
        samples=[{'download_mbit':90,'upload_mbit':24},{'download_mbit':91,'upload_mbit':24.5}]
        proposal=qos.calibration_proposal(samples,{'proposal':{'down_mbit':100,'up_mbit':25}})
        self.assertEqual(proposal['direction_decisions']['down'],'review-decrease')
        self.assertFalse(proposal['auto_approved'])
    def test_unstable_never_lower(self):
        samples=[{'download_mbit':20,'upload_mbit':3},{'download_mbit':110,'upload_mbit':35}]
        old={'proposal':{'down_mbit':100,'up_mbit':30}}
        self.assertEqual(qos.calibration_proposal(samples,old)['proposal'],old['proposal'])
    def test_unshaped_reject_foreign_owner(self):
        with patch.object(qos,'read',return_value=None),\
             patch.object(qos,'run',return_value=SimpleNamespace(stdout='inactive')),\
             patch.object(qos,'topology_report',return_value={'free':False}):
            with self.assertRaises(qos.QosError):qos.calibration_start('bond0')

class ClassificationTests(unittest.TestCase):
    def test_l7(self):
        r=traffic.parse_eve('{"event_type":"flow","app_proto":"dns"}\nnot-json')
        self.assertEqual(r[0]['class'],'interactive')
    def test_process(self):
        r=traffic.parse_ss('users:(("sshd",pid=123,fd=3))')
        self.assertEqual(r[0]['process'],'sshd')

if __name__=='__main__':unittest.main(verbosity=2)
