#!/usr/bin/env python3
"""Pure offline tests: simulated iptables; never touch the host firewall."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'extensions'))
import cache_proxy as proxy
import cache_redirect as redir

PROFILE={'interface':'bond0','listen_ip':'192.168.1.165','port':3129,
         'allowed_nets':['192.168.1.0/24'],'disk_mib':128,'memory_mib':16,
         'intercept_http':True}

class FakeIptables:
    def __init__(self):
        self.rules={('nat','PREROUTING'):[],('filter','INPUT'):[]}
        self.trace=[]
        self.fail_on=None
    def call(self,binary,table,*args,check=True):
        self.trace.append([binary,table,*args]);code=0;out='';err=''
        op=args[0];chain=args[1]
        key=(table,chain);data=self.rules.get(key)
        rule=list(args[2:])
        if self.fail_on and self.fail_on in (table,op,chain):
            self.fail_on=None
            raise redir.RedirectError('Injected failure')
        if op=='-N':
            if data is not None:raise redir.RedirectError('Chain exists')
            self.rules[key]=[]
        elif op=='-S':
            if data is None:code=1
            else:out='-N '+chain+'\n'+'\n'.join('-A '+chain+' '+' '.join(r) for r in data)
        elif data is None:raise redir.RedirectError('Chain missing')
        elif op=='-A':data.append(rule)
        elif op=='-I':data.insert(0,list(args[3:]))
        elif op=='-C':code=0 if rule in data else 1
        elif op=='-D':
            if rule in data:data.remove(rule)
            else:raise redir.RedirectError('Rule not found')
        elif op=='-F':data.clear()
        elif op=='-X':
            if data:raise redir.RedirectError('Not empty')
            del self.rules[key]
        else:raise AssertionError(op)
        return SimpleNamespace(returncode=code,stdout=out,stderr=err)

class Cache5305(unittest.TestCase):
    def test_01_configuration_accepts_intercept_bool(self):
        self.assertTrue(proxy.parse_config(PROFILE)['intercept_http'])
    def test_02_rejects_nonbool_and_null_mode(self):
        for val in ('true',1,None,[],{}):
            with self.assertRaises(proxy.ProxyError):proxy.parse_config(dict(PROFILE,intercept_http=val))
    def test_03_rejects_external_subnet_and_injection(self):
        for nets in (['8.8.8.0/24'],['192.168.1.0/24; DROP ALL'],['0.0.0.0/0']):
            with self.assertRaises(proxy.ProxyError):proxy.parse_config(dict(PROFILE,allowed_nets=nets))
    def test_04_never_intercept_https(self):
        text=proxy.config_text(PROFILE)
        self.assertIn('http_port 192.168.1.165:3129 intercept',text)
        self.assertNotIn('ssl_bump',text)
        self.assertNotIn('https_port',text)
        self.assertIn('http_access deny blocked_dst',text)
    def test_05_disabled_mode_is_explicit_connect(self):
        txt=proxy.config_text(dict(PROFILE,intercept_http=False))
        self.assertIn('http_port 192.168.1.165:3129\n',txt)
        self.assertNotIn('3129 intercept',txt)
        self.assertIn('http_access deny CONNECT !SSL_ports',txt)
    def test_06_stage_saves_preference_without_squid_binary(self):
        writes={}
        def write(k,v):writes[str(k)]=v
        with patch.object(proxy,'verify_interface'),patch.object(proxy,'verify_owned_files'),\
             patch.object(proxy,'trusted_binary',side_effect=AssertionError('no squid lookup during stage')),\
             patch.object(proxy,'atom_json',side_effect=write):
            out=proxy.stage(PROFILE)
        self.assertTrue(out['ok']);self.assertFalse(out['applied'])
        self.assertEqual(writes[str(proxy.PREFS)]['profile']['listen_ip'],'192.168.1.165')
    def test_07_nat_never_redirects_ssh_dns_https_or_output(self):
        for args in redir.hooks(PROFILE):
            self.assertEqual(args[args.index('--dport')+1],'80')
            self.assertNotIn('443',args)
        for rules in (redir.hooks(PROFILE),redir.accept_rules(PROFILE)):
            self.assertTrue(all(r[r.index('-i')+1]=='bond0' for r in rules))
        self.assertIn(['-d','192.168.0.0/16','-j','RETURN'],redir.chain_rules(PROFILE))
        self.assertNotIn('OUTPUT',repr(redir.hooks(PROFILE)))
    def test_08_install_then_remove_returns_direct_traffic(self):
        fw=FakeIptables()
        with patch.object(redir,'call',side_effect=fw.call):
            redir.install(redir.BACKENDS['legacy'],PROFILE)
            self.assertTrue(redir.healthy(redir.BACKENDS['legacy'],PROFILE))
            redir.remove(redir.BACKENDS['legacy'],PROFILE)
        self.assertEqual(fw.rules[('nat','PREROUTING')],[])
        self.assertEqual(fw.rules[('filter','INPUT')],[])
        self.assertNotIn(('nat',redir.CHAIN),fw.rules)
    def test_09_repeated_install_is_idempotent(self):
        fw=FakeIptables();b=redir.BACKENDS['legacy']
        with patch.object(redir,'call',side_effect=fw.call):
            redir.install(b,PROFILE)
            redir.install(b,PROFILE)
        self.assertEqual(len(fw.rules[('nat','PREROUTING')]),1)
        self.assertEqual(len(fw.rules[('filter','INPUT')]),1)
    def test_10_foreign_chain_rejected_without_flush(self):
        fw=FakeIptables();b=redir.BACKENDS['legacy']
        fw.rules[('nat',redir.CHAIN)]=[['-j','DROP']]
        with patch.object(redir,'call',side_effect=fw.call):
            with self.assertRaises(redir.RedirectError):redir.install(b,PROFILE)
        self.assertEqual(fw.rules[('nat',redir.CHAIN)],[['-j','DROP']])
        self.assertEqual(fw.rules[('nat','PREROUTING')],[])
    def test_11_failure_during_jump_rolls_back_owned_rules(self):
        fw=FakeIptables();b=redir.BACKENDS['legacy'];fw.fail_on='PREROUTING'
        with patch.object(redir,'call',side_effect=fw.call):
            with self.assertRaises(redir.RedirectError):redir.install(b,PROFILE)
        self.assertEqual(fw.rules[('nat','PREROUTING')],[])
        self.assertEqual(fw.rules[('filter','INPUT')],[])
        self.assertNotIn(('nat',redir.CHAIN),fw.rules)
    def test_12_disable_without_binary_still_removes_redirect(self):
        called=[]
        with patch.object(proxy,'verify_owned_files'),patch.object(proxy,'read_json',return_value=None),\
             patch.object(proxy,'redirect_off',side_effect=lambda:called.append('nat')),\
             patch.object(proxy,'atom_json',side_effect=lambda *a:None),\
             patch.object(proxy,'trusted_binary',side_effect=AssertionError('should not inspect squid')),\
             patch.object(proxy,'UNIT',Path('/file/missing/unit')),\
             patch.object(proxy,'RECONCILE_TIMER',Path('/file/missing/timer')):
            self.assertFalse(proxy.disable()['enabled'])
        self.assertEqual(called,['nat'])
    def test_13_reconcile_stops_redirect_when_service_down(self):
        state={'enabled':True,'profile':PROFILE}
        removed=[]
        with patch.object(proxy,'read_json',return_value=state),\
             patch.object(proxy,'require_forwarding'), patch.object(proxy,'verify_interface'),patch.object(proxy,'proxy_ready',return_value=False),\
             patch.object(proxy,'redirect_off',side_effect=lambda:removed.append('redirect')):\
            self.assertFalse(proxy.reconcile()['redirect'])
        self.assertEqual(removed,['redirect'])
    def test_14_stop_post_always_failopen_without_lock(self):
        self.assertIn('ExecStopPost=+/usr/local/sbin/iptm-helper cache-proxy failopen',proxy.unit_text('/usr/sbin/squid'))
        self.assertIn('OnUnitInactiveSec=30s',proxy.reconcile_timer_text())
    def test_15_binary_in_untrusted_tmp_not_accepted(self):
        with tempfile.TemporaryDirectory() as td:
            tmp=Path(td);exe=tmp/'squid';exe.write_text('#!/bin/sh\nexit 0\n');exe.chmod(0o755)
            link=tmp/'alias';link.symlink_to(exe)
            with patch.object(proxy,'SQUID',link):
                self.assertFalse(proxy.trusted_binary()==exe)
    def test_15b_debian13_squid_gnutls_binary_is_accepted(self):
        candidate=Path('/usr/sbin/squid-gnutls')
        fake=lambda *a,**kw:SimpleNamespace(returncode=0,stdout='/usr/sbin/squid-gnutls\n')
        with patch.object(proxy,'SQUID',Path('/usr/sbin/no-squid-bin')),\
             patch.object(proxy,'command',side_effect=fake),\
             patch.object(Path,'is_file',lambda obj:obj==candidate),\
             patch.object(Path,'resolve',lambda obj,strict=True:obj),\
             patch.object(Path,'stat',lambda obj:SimpleNamespace(st_uid=0,st_mode=0o755)),\
             patch.object(proxy.os,'access',return_value=True):
            self.assertEqual(proxy.trusted_binary(),candidate)

    def test_15c_squid_openssl_debian_package_is_recognized(self):
        def cmd(args,**kw):
            if args[-1]=='squid':return SimpleNamespace(returncode=1,stdout='')
            return SimpleNamespace(returncode=0,stdout='install ok installed')
        with patch.object(proxy,'command',side_effect=cmd):
            self.assertTrue(proxy.package_installed())

    def test_16_listen_ip_must_be_primary_in_intercept_mode(self):
        state={'ifname':'bond0','addr_info':[{'family':'inet','local':'192.168.1.1'},
                                               {'family':'inet','local':'192.168.1.165'}]}
        with patch.object(proxy,'command',return_value=SimpleNamespace(stdout=json.dumps([state]))):
            with self.assertRaises(proxy.ProxyError):proxy.verify_interface(PROFILE)
    def test_17_php_prefill_and_snapshot_docs(self):
        code='''<?php function net_of($c){[$i,$p]=explode('/',$c);$a=ip2long($i);$m=$p?(-1<<(32-(int)$p)):0;return long2ip($a&$m).'/'.$p;} require $argv[1]; $_SERVER['SERVER_ADDR']='192.168.1.165';echo json_encode(iptm_proxy_form_defaults(['wg0'=>['10.19.165.1/24'],'bond0'=>['192.168.1.165/24']],[]));'''
        with tempfile.TemporaryDirectory() as td:
            php=Path(td)/'check.php';php.write_text(code)
            r=subprocess.run(['php',str(php),str(ROOT/'modules/41_performance_pages.php')],capture_output=True,text=True,timeout=5)
        self.assertEqual(r.returncode,0,r.stderr)
        out=json.loads(r.stdout)
        self.assertEqual(out['listen_ip'],'192.168.1.165')
        self.assertEqual(out['allowed_nets'],['192.168.1.0/24'])
        self.assertEqual(out['interface'],'bond0')
        self.assertTrue(out['intercept_http'])
    def test_18_transparent_denied_for_restrictive_forward(self):
        self.assertEqual(redir.unsafe_forward_policy('-P FORWARD DROP\n-A FORWARD -j IPTM-IOT'),
                         'Policy FORWARD predefinita restrittiva')
        self.assertIsNotNone(redir.unsafe_forward_policy('-P FORWARD ACCEPT\n-A FORWARD -j IPTM-MAC-FWD'))
        self.assertIsNone(redir.unsafe_forward_policy('-P FORWARD ACCEPT\n-A FORWARD -m conntrack --ctstate ESTABLISHED -j ACCEPT'))
    def test_18b_unknown_forward_custom_chain_is_blocked(self):
        self.assertIsNotNone(redir.unsafe_forward_policy('-P FORWARD ACCEPT\n-A FORWARD -j PRIVATE-ACL'))
        self.assertIsNotNone(redir.unsafe_forward_policy('-P FORWARD ACCEPT\n-A FORWARD -g CUSTOM-ACL'))
        self.assertIsNotNone(redir.unsafe_forward_policy('-P FORWARD ACCEPT\n-A FORWARD -s 192.168.1.0/24 -j ACCEPT'))
        self.assertIsNotNone(redir.unsafe_forward_policy('-P FORWARD ACCEPT\n-A FORWARD -j REJECT'))

    def test_19_security_preflight_blocks_before_change(self):
        with patch.object(redir,'call',return_value=SimpleNamespace(stdout='-P FORWARD DROP\n')):
            with self.assertRaises(redir.RedirectError):redir.security_preflight(redir.BACKENDS['legacy'])
    def test_20_malicious_or_missing_backend_rejected(self):
        with self.assertRaises(redir.RedirectError):redir.backend_path('/usr/bin/echo')
        with self.assertRaises(redir.RedirectError):redir.call('/bin/sh','nat','-L','PREROUTING')

if __name__=='__main__':unittest.main(verbosity=2)
