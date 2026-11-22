#!/usr/bin/env python3
"""Non-mutating regression tests for Debian Squid detection and saved settings."""
import json
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'extensions'))
import cache_proxy as cp
import cache_redirect as cr

PROFILE={'interface':'bond0','listen_ip':'192.168.1.165','port':3129,
         'allowed_nets':['192.168.1.0/24'],'disk_mib':128,'memory_mib':16,
         'intercept_http':True}

class Squid5306Tests(unittest.TestCase):
    def test_01_squid_gnutls_reported_installed(self):
        def command(args,**kw):
            status='install ok installed' if args[-1]=='squid-gnutls' else ''
            return SimpleNamespace(returncode=0 if status else 1,stdout=status)
        with patch.object(cp,'command',side_effect=command):
            self.assertTrue(cp.package_installed())

    def test_02_absent_packages_do_not_claim_install(self):
        with patch.object(cp,'command',return_value=SimpleNamespace(returncode=1,stdout='')):
            self.assertFalse(cp.package_installed())

    def test_03_trusted_debian_symlink_resolves(self):
        """A legitimate Debian root-owned symlink must not trigger the 5.30.4 error."""
        entry=Path('/usr/sbin/squid')
        target=Path('/usr/sbin/squid-gnutls')
        def cmd(args,**kw):
            return SimpleNamespace(returncode=0,stdout='/usr/sbin/squid\n')
        with patch.object(cp,'command',side_effect=cmd),\
             patch.object(cp,'SQUID',entry),\
             patch.object(Path,'is_file',lambda x:x==entry or x==target),\
             patch.object(Path,'resolve',lambda x,strict=True:target if x==entry else x),\
             patch.object(Path,'stat',lambda x:SimpleNamespace(st_uid=0,st_mode=0o755)),\
             patch.object(cp.os,'access',return_value=True):
            self.assertEqual(cp.trusted_binary(),target)

    def test_04_debian_lib_executable_requires_package_manifest(self):
        entry=Path('/usr/lib/squid/squid')
        def cmd(args,**kw):
            return SimpleNamespace(returncode=0,stdout=(str(entry)+'\n') if args[-1]=='squid' else '')
        with patch.object(cp,'command',side_effect=cmd),\
             patch.object(cp,'SQUID',Path('/usr/sbin/no-squid')) ,\
             patch.object(Path,'is_file',lambda x:x==entry),\
             patch.object(Path,'resolve',lambda x,strict=True:x),\
             patch.object(Path,'stat',lambda x:SimpleNamespace(st_uid=0,st_mode=0o755)),\
             patch.object(cp.os,'access',return_value=True):
            self.assertEqual(cp.trusted_binary(),entry)

    def test_05_untrusted_writeable_ancestor_rejected(self):
        entry=Path('/usr/sbin/squid')
        target=Path('/usr/lib/squid/squid')
        def cmd(args,**kw):return SimpleNamespace(returncode=0,stdout='')
        with patch.object(cp,'command',side_effect=cmd),\
             patch.object(Path,'is_file',lambda x:x in (entry,target)),\
             patch.object(Path,'resolve',lambda x,strict=True:target),\
             patch.object(Path,'stat',lambda x:SimpleNamespace(st_uid=0,st_mode=0o777 if str(x)=='/usr/lib' else 0o755)),\
             patch.object(cp.os,'access',return_value=True):
            self.assertIsNone(cp.trusted_binary())

    def test_06_save_only_without_squid_or_gateway(self):
        saved=[]
        with patch.object(cp,'atom_json',side_effect=lambda p,v:saved.append((p,v))),\
             patch.object(cp,'verify_interface',side_effect=AssertionError('no live check')),\
             patch.object(cp,'trusted_binary',side_effect=AssertionError('no bin lookup')),\
             patch.object(cp,'redirect_on',side_effect=AssertionError('no NAT')):
            result=cp.save_preferences(PROFILE)
        self.assertTrue(result['saved'])
        self.assertFalse(result['enabled'])
        self.assertEqual(saved[0][0],cp.PREFS)
        self.assertEqual(saved[0][1]['profile']['port'],3129)

    def test_07_saved_preferences_survive_stage_topology_failure(self):
        saved=[]
        with patch.object(cp,'atom_json',side_effect=lambda p,v:saved.append((p,v))),\
             patch.object(cp,'verify_interface',side_effect=cp.ProxyError('NIC down')):
            with self.assertRaisesRegex(cp.ProxyError,'NIC down'):
                cp.stage(PROFILE)
        self.assertEqual(len(saved),1)
        self.assertEqual(saved[0][0],cp.PREFS)

    def test_08_malicious_input_never_persisted(self):
        cases=[dict(PROFILE,interface='eth0;rm -rf /'),
               dict(PROFILE,allowed_nets=['0.0.0.0/0']),
               dict(PROFILE,intercept_http='true'),
               dict(PROFILE,port=-1),
               dict(PROFILE,listen_ip='127.0.0.1')]
        with patch.object(cp,'atom_json',side_effect=AssertionError('no write')):
            for bad in cases:
                with self.subTest(bad=bad),self.assertRaises(cp.ProxyError):
                    cp.save_preferences(bad)

    def test_09_status_explains_installed_but_missing_binary(self):
        with patch.object(cp,'read_json',return_value={}),\
             patch.object(cp,'trusted_binary',return_value=None),\
             patch.object(cp,'package_installed',return_value=True):
            report=cp.status()
        self.assertTrue(report['package_installed'])
        self.assertFalse(report['installed'])
        self.assertIn('dpkg -L',report['binary_warning'])

    def test_10_transparent_only_port80(self):
        rules=cr.chain_rules(PROFILE)
        self.assertTrue(any('--dport' in r and '80' in r for r in rules))
        self.assertFalse(any('--dport' in r and '443' in r for r in rules))
        self.assertTrue(any('intercept' in t for t in cp.config_text(PROFILE).splitlines()))
        self.assertNotIn('ssl_bump',cp.config_text(PROFILE))

    def test_11_block_default_drop_forward_for_security(self):
        source='-P FORWARD DROP\n-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n'
        self.assertIn('restrittiva',cr.unsafe_forward_policy(source))

    def test_12_disable_independent_of_squid_installation(self):
        calls=[]
        with patch.object(cp,'verify_owned_files'),\
             patch.object(cp,'read_json',return_value=None),\
             patch.object(cp,'redirect_off',side_effect=lambda:calls.append('NAT removed')),\
             patch.object(cp,'atom_json',side_effect=lambda *args:None),\
             patch.object(cp,'trusted_binary',side_effect=AssertionError('no lookup')),\
             patch.object(cp,'UNIT',Path('/nonexistent/squid/IPTM-unit')) ,\
             patch.object(cp,'RECONCILE_TIMER',Path('/nonexistent/squid/IPTM-timer')):
            self.assertEqual(cp.disable()['enabled'],False)
        self.assertEqual(calls,['NAT removed'])

    def test_13_helper_accepts_save_only(self):
        text=(Path(__file__).resolve().parents[1]/'runtime'/'iptm-helper').read_text()
        self.assertIn('cache-proxy)\n    shift; case "${1:-}" in status|stage|save-preferences',text)

    def test_14_explicit_proxy_no_periodic_redirect_timer(self):
        text=Path(cp.__file__).read_text()
        self.assertIn("if profile['intercept_http']:\n            command(['systemctl','enable','--now',RECONCILE_TIMER.name]",text)

    def test_15_ui_offline_and_disable_actions_available(self):
        root=Path(__file__).resolve().parents[1]
        page=(root/'modules'/'41_performance_pages.php').read_text()
        actions=(root/'actions'/'performance.php').read_text()
        for needle in ('cache_proxy_save','cache_proxy_stage','cache_proxy_disable'):
            self.assertIn(needle,page)
            self.assertIn(needle,actions)
        self.assertIn('Resolver DNS',page)

if __name__=='__main__':unittest.main()
