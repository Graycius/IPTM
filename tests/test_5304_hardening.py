#!/usr/bin/env python3
"""Strict, non-privileged offline safety cases for IPTM native release.

The runtime is NEVER invoked; every kernel/systemd interaction is mocked.
"""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]

def module(filename):
    p=ROOT/'extensions'/filename
    spec=importlib.util.spec_from_file_location('test_'+p.stem,p)
    obj=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj

qos=module('qos_engine.py')
fw=module('firewall_recovery.py')
proxy=module('cache_proxy.py')
ret=module('retention_manager.py')
audit=module('rules_performance.py')

STATE={'state':'confirmed','version':qos.VERSION,'interface':'bond0',
       'ifb':'ifb-iptm0','up_mbit':80,'down_mbit':250,'ifindex':21,
       'ifb_ifindex':33,'mac':'00:11:22:33:44:55',
       'ingress_added':True,'ingress_policy_count':0,
       'diffserv':'diffserv4','nat':False,'wash':False,
       'ack_filter':False,'overhead':0}

class Tests(unittest.TestCase):
    def test_01_minimal_confirmed_state_rejected(self):
        with self.assertRaises(qos.QosError):qos.validate_confirmed_state({'state':'confirmed','version':qos.VERSION})

    def test_02_valid_confirmed_profile(self):
        self.assertEqual(qos.validate_confirmed_state(dict(STATE),'bond0')['ifindex'],21)

    def test_03_wrong_interface_cannot_calibrate(self):
        with self.assertRaises(qos.QosError):qos.validate_confirmed_state(dict(STATE),'eth0')

    def test_04_malicious_interface_is_rejected(self):
        with self.assertRaises(qos.QosError):qos.validate_confirmed_state(dict(STATE,interface='../bond0'))

    def test_05_bool_index_is_rejected(self):
        with self.assertRaises(qos.QosError):qos.validate_confirmed_state(dict(STATE,ifindex=True))

    def test_06_negative_rate_is_rejected(self):
        with self.assertRaises(qos.QosError):qos.validate_confirmed_state(dict(STATE,up_mbit=-100))

    def test_07_null_mac_is_rejected(self):
        with self.assertRaises(qos.QosError):qos.validate_confirmed_state(dict(STATE,mac=None))

    def test_08_unbounded_ingress_policy_rejected(self):
        with self.assertRaises(qos.QosError):qos.validate_confirmed_state(dict(STATE,ingress_policy_count=10**10))

    def test_09_version_mismatch_rejected(self):
        with self.assertRaises(qos.QosError):qos.validate_confirmed_state(dict(STATE,version='0.0.0'))

    def test_10_malformed_tc_json_object_rejected(self):
        with patch.object(qos,'run',return_value=SimpleNamespace(stdout='[null,{"handle":"1:"}]')):
            with self.assertRaises(qos.QosError):qos.jcmd(['tc','-j','qdisc'])

    def test_11_malformed_tc_string_rejected(self):
        with patch.object(qos,'run',return_value=SimpleNamespace(stdout='["invalid"]')):
            with self.assertRaises(qos.QosError):qos.jcmd(['tc','-j','qdisc'])

    def test_12_calibration_invalid_state_fails_before_tc(self):
        values={'state':'confirmed','version':qos.VERSION,'interface':'bond0'}
        def load(path):return values if path==qos.STATE else None
        with patch.object(qos,'read',side_effect=load), \
             patch.object(qos,'run',return_value=SimpleNamespace(stdout='inactive')), \
             patch.object(qos,'start_unshaped_calibration',side_effect=AssertionError('tc must not change')):
            with self.assertRaises(qos.QosError):qos.calibration_start('bond0')

    def test_13_adaptive_mutations_blocked_during_measurement(self):
        with patch.object(qos,'read',return_value={'state':'pending'}), \
             patch.object(qos,'run',side_effect=AssertionError('tc must not change')):
            with self.assertRaises(qos.QosError):qos.adapt_change_one(STATE,'up',70)

    def test_14_adaptive_disable_blocked_during_measurement(self):
        with patch.object(qos,'read',return_value={'state':'pending'}), \
             patch.object(qos,'run',side_effect=AssertionError('systemctl must not run')):
            with self.assertRaises(qos.QosError):qos.adapt_disable()

    def test_15_restore_rejects_changed_ifb_identity(self):
        journal={'state':'pending','version':qos.VERSION,'interface':STATE['interface'],
                 'ifb':STATE['ifb'],'ifb_ifindex':999,
                 'original_up':STATE['up_mbit'],'original_down':STATE['down_mbit']}
        with patch.object(qos,'read',return_value=dict(STATE)), \
             patch.object(qos,'run',side_effect=AssertionError('tc must not change')):
            with self.assertRaises(qos.QosError):qos.restore_cake_after_calibration(journal)

    def test_16_restore_rejects_changed_rate(self):
        journal={'state':'pending','version':qos.VERSION,'interface':STATE['interface'],
                 'ifb':STATE['ifb'],'original_up':55,'original_down':250}
        with patch.object(qos,'read',return_value=dict(STATE)), \
             patch.object(qos,'run',side_effect=AssertionError('tc must not change')):
            with self.assertRaises(qos.QosError):qos.restore_cake_after_calibration(journal)

    def test_17_firewall_valid_drop_missing_set(self):
        data=b'*filter\n:INPUT DROP [0:0]\n-A INPUT -m set --match-set crowdsec-blacklists-3 src -j DROP\nCOMMIT\n'
        after,deleted=fw.normalized(data,set(),'4')
        self.assertEqual(deleted,['crowdsec-blacklists-3'])
        self.assertIn(b':INPUT DROP',after)

    def test_18_firewall_unclosed_filter_rejected(self):
        data=b'*filter\n:INPUT DROP [0:0]\n*nat\n:PREROUTING ACCEPT [0:0]\nCOMMIT\n'
        with self.assertRaises(fw.RecoveryError):fw.normalized(data,set(),'4')

    def test_19_firewall_spurious_commit_rejected(self):
        data=b'*filter\n:INPUT DROP [0:0]\nCOMMIT\nCOMMIT\n'
        with self.assertRaises(fw.RecoveryError):fw.normalized(data,set(),'4')

    def test_20_proxy_untrusted_config_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            bad=Path(d)/'squid.conf';bad.symlink_to('/etc/hosts')
            with patch.object(proxy,'SQUID',Path('/bin/sh')),patch.object(proxy,'CONF',bad), \
                 patch.object(proxy,'UNIT',Path(d)/'nosuch_unit'), \
                 patch.object(proxy.pwd,'getpwnam',return_value=SimpleNamespace(pw_gid=1)):
                with self.assertRaises(proxy.ProxyError):proxy.verify_ownership()

    def test_21_proxy_non_lan_listen(self):
        cfg={'interface':'bond0','listen_ip':'8.8.8.8','port':3128,
             'allowed_nets':['192.168.1.0/24'],'disk_mib':128,'memory_mib':16}
        with self.assertRaises(proxy.ProxyError):proxy.parse_config(cfg)

    def test_22_proxy_no_open_connect_port(self):
        cfg={'interface':'bond0','listen_ip':'192.168.1.1','port':3128,
             'allowed_nets':['192.168.1.0/24'],'disk_mib':128,'memory_mib':16}
        data=proxy.config_text(proxy.parse_config(cfg))
        self.assertIn('http_access deny CONNECT !SSL_ports',data)
        self.assertLess(data.index('http_access deny blocked_dst'),data.index('http_access allow iptm_clients'))

    def test_23_retention_blocks_pending_network_backup(self):
        with tempfile.TemporaryDirectory() as td:
            d=Path(td);(d/'pending.json').write_text('{}')
            self.assertTrue(ret.active_recovery(d,d/'no-recovery'))

    def test_24_retention_rejects_bad_policy(self):
        p=dict(ret.DEFAULTS,backup_keep=-1)
        with self.assertRaises(ValueError):ret.validate_policy(p)

    def test_25_rules_audit_is_readonly(self):
        report=audit.analyze('*filter\n:INPUT DROP [0:0]\nCOMMIT\n')
        self.assertTrue(report['read_only'])
        self.assertEqual(report['counts'].get('rules',0),0)

if __name__=='__main__':unittest.main(verbosity=2)
