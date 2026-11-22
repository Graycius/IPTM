#!/usr/bin/env python3
"""Offline tests for performance analyzer, LAN cache ACL and unshaped calibration."""
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
rp=get('rules_performance.py'); proxy=get('cache_proxy.py')
fw=get('firewall_recovery.py'); qos=get('qos_engine.py')
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
PROFILE={'interface':'bond0','listen_ip':'192.168.1.1','port':3128,
         'allowed_nets':['192.168.1.0/24'],'disk_mib':128,'memory_mib':16}
class AuditTests(unittest.TestCase):
    def test_costs(self):
        v=rp.analyze(RULES)
        self.assertTrue(v['read_only'])
        self.assertTrue({'quic','rate-drops'}.issubset({x['id'] for x in v['findings']}))
    def test_high_logging_and_sets(self):
        raw='*filter\n:INPUT DROP [0:0]\n'+''.join('-A INPUT -j LOG\n' for _ in range(25))+''.join('-A INPUT -m set --match-set bl1 src -j DROP\n' for _ in range(25))+'COMMIT\n'
        v=rp.analyze(raw)
        self.assertGreater(v['counts']['logging'],20)
        self.assertGreater(v['counts']['ipset_lookups'],20)
    def test_invalid_input(self):
        for raw in ('','\x00','A'*(rp.MAX_BYTES+1),'-A INPUT -j DROP\n'*30001):
            with self.assertRaises(rp.AuditError):rp.analyze(raw)
class ProxyTests(unittest.TestCase):
    def test_safe_acl(self):
        c=proxy.config_text(proxy.parse_config(PROFILE))
        self.assertIn('http_port 192.168.1.1:3128',c)
        self.assertIn('http_access deny CONNECT !SSL_ports',c)
        self.assertLess(c.index('http_access deny blocked_dst'),c.index('http_access allow iptm_clients'))
        self.assertIn('http_access deny all',c)
        self.assertNotIn('ssl_bump',c)
    def test_bad_configs(self):
        for bad in (dict(PROFILE,listen_ip='0.0.0.0'),
                    dict(PROFILE,listen_ip='8.8.8.8'),dict(PROFILE,port=True),
                    dict(PROFILE,port=80),dict(PROFILE,interface='../etc'),
                    dict(PROFILE,allowed_nets=['0.0.0.0/0']),
                    dict(PROFILE,allowed_nets=['192.168.2.0/24']),
                    dict(PROFILE,allowed_nets=['192.168.1.0/24\nallow all']),
                    dict(PROFILE,disk_mib=10**50),dict(PROFILE,evil=1)):
            with self.subTest(bad=bad):
                with self.assertRaises(proxy.ProxyError):proxy.parse_config(bad)
    def test_requires_squid(self):
        with patch.object(proxy,'SQUID',Path('/nonexistent/squid')):
            with self.assertRaises(proxy.ProxyError):proxy.verify_ownership()
    def test_bind_to_assigned_ip(self):
        link={'ifname':'bond0','addr_info':[{'family':'inet','local':'192.168.2.2'}]}
        with patch.object(proxy,'command',return_value=SimpleNamespace(stdout=json.dumps([link]))):
            with self.assertRaises(proxy.ProxyError):proxy.verify_interface(PROFILE)
class FirewallTests(unittest.TestCase):
    def test_stale_crowdsec_drop_only(self):
        out,removed=fw.normalized(RULES.encode(),set(),'4')
        self.assertEqual(removed,['crowdsec-blacklists-3'])
        self.assertIn(b'--dport 22 -j ACCEPT',out)
        self.assertNotIn(b'--match-set',out)
    def test_existing_set_byte_exact(self):
        out,_=fw.normalized(RULES.encode(),{'crowdsec-blacklists-3'},'4')
        self.assertEqual(out,RULES.encode())
    def test_unrelated_sets_fail_closed(self):
        for setname,target in [('local_block','DROP'),('crowdsec-blacklists-3','ACCEPT')]:
            candidate=RULES.replace('crowdsec-blacklists-3',setname).replace('src -j DROP','src -j '+target)
            with self.assertRaises(fw.RecoveryError):fw.normalized(candidate.encode(),set(),'4')
    def test_malformed_or_wrong_family(self):
        for buf in (b'',b'\0',b'X'*(fw.MAX_BYTES+1)):
            with self.assertRaises(fw.RecoveryError):fw.normalized(buf,set(),'4')
        with self.assertRaises(fw.RecoveryError):fw.normalized(RULES.encode(),set(),'6')
class CalibrationTests(unittest.TestCase):
    def test_unlimited_both(self):
        state={'interface':'bond0','ifb':'ifb0','up_mbit':50,'down_mbit':250,'diffserv':'diffserv4',
               'nat':False,'wash':False,'ack_filter':False,'overhead':0}
        cmds=[]
        def run(a,**kw):cmds.append(a);return SimpleNamespace(stdout='',returncode=0)
        with patch.object(qos,'owned'),patch.object(qos,'verified_ingress_for_state',return_value=True),\
             patch.object(qos,'check_cake_bandwidth'),patch.object(qos,'run',side_effect=run):
            qos.set_unlimited(state)
        self.assertEqual(len(cmds),2)
        self.assertTrue(all('unlimited' in c for c in cmds))
    def test_watchdog_required(self):
        with patch.object(qos,'guard_ready',side_effect=qos.QosError('no guard')),\
             patch.object(qos,'run',side_effect=AssertionError('mutated')):
            with self.assertRaises(qos.QosError):qos.start_unshaped_calibration('bond0',{}, {})
    def test_rates_restored(self):
        st={'state':'confirmed','version':qos.VERSION,'interface':'bond0','ifb':'ifb0','up_mbit':50,
            'down_mbit':250,'diffserv':'diffserv4','nat':False,'wash':False,'ack_filter':False,'overhead':0}
        journal={'state':'pending','version':qos.VERSION,'interface':'bond0','ifb':'ifb0'}
        cmds=[]
        with patch.object(qos,'read',return_value=st),patch.object(qos,'owned'),\
             patch.object(qos,'root_cake_text'),patch.object(qos,'check_cake_bandwidth'),\
             patch.object(qos,'run',side_effect=lambda a,**k:(cmds.append(a) or SimpleNamespace(stdout='',returncode=0))),patch.object(qos,'atom'):
            qos.restore_cake_after_calibration(journal)
        self.assertIn('50mbit',cmds[0]);self.assertIn('250mbit',cmds[1])
        self.assertEqual(journal['state'],'restored')
    def test_manual_review_decrease(self):
        p=qos.calibration_proposal([{'download_mbit':90,'upload_mbit':24},{'download_mbit':91,'upload_mbit':24.5}],
                                   {'proposal':{'down_mbit':100,'up_mbit':25}})
        self.assertEqual(p['direction_decisions']['down'],'review-decrease')
        self.assertFalse(p['auto_approved'])
    def test_no_degrade_on_noisy_samples(self):
        old={'proposal':{'down_mbit':100,'up_mbit':30}}
        p=qos.calibration_proposal([{'download_mbit':20,'upload_mbit':3},
                                    {'download_mbit':110,'upload_mbit':35}],old)
        self.assertEqual(p['proposal'],old['proposal'])
if __name__=='__main__':unittest.main(verbosity=2)
