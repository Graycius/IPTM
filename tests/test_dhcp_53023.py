import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import importlib.util

spec=importlib.util.spec_from_file_location('na',str(Path(__file__).resolve().parents[1]/'extensions'/'network_audit.py'))
na=importlib.util.module_from_spec(spec)
spec.loader.exec_module(na)
MAC1='aa:bb:cc:dd:ee:11'
MAC2='aa:bb:cc:dd:ee:22'
MAC3='aa:bb:cc:dd:ee:33'

class TestDhcp(unittest.TestCase):
    def setUp(self):
        self.t=tempfile.TemporaryDirectory()
        self.addCleanup(self.t.cleanup)
        self.base=Path(self.t.name)
        self.path=self.base/'pihole.toml'
        self.records=[f'{MAC1},192.168.1.55,old-host,24h']
        self.write(self.records)
        self.calls=[]
        self.fail=''
        self.original_root=na.IPTM_DHCP_STATE
        self.original_cfg=na.PIHOLE_DHCP_CONFIG
        na.IPTM_DHCP_STATE=self.base
        na.PIHOLE_DHCP_CONFIG=self.path
        self.addCleanup(lambda: setattr(na,'IPTM_DHCP_STATE',self.original_root))
        self.addCleanup(lambda: setattr(na,'PIHOLE_DHCP_CONFIG',self.original_cfg))
        self.geteuid=patch.object(na.os,'geteuid',return_value=0)
        self.which=patch.object(na.shutil,'which',return_value='/usr/bin/pihole-FTL')
        self.command=patch.object(na,'command',side_effect=self.fake_command)
        self.geteuid.start();self.which.start();self.command.start()
        self.addCleanup(self.geteuid.stop);self.addCleanup(self.which.stop);self.addCleanup(self.command.stop)

    def write(self,entries):
        self.path.write_text('[dhcp]\nhosts = '+json.dumps(entries)+'\n',encoding='utf8')

    def fake_command(self,args,timeout=5):
        self.calls.append(args)
        if len(args)==4:
            if self.fail=='unmodified':return 1,'write rejected'
            arr=json.loads(args[3])
            self.write(arr)
            if self.fail=='write_after_change':
                self.fail=''
                return 1,'failed after write'
            return 0,'ok'
        return 0,'[ '+', '.join(self.records)+' ]'

    def apply(self,entries,mode='apply'):
        return na.apply_dhcp_reservations(entries,address='192.168.1.165/24',start='192.168.1.100',end='192.168.1.200',gateway='192.168.1.1',mode=mode)

    def test_merge_keeps_advanced_original(self):
        r=self.apply([{'mac':MAC2,'ip':'192.168.1.77','hostname':'test'}])
        self.assertTrue(r['applied'])
        self.assertEqual(r['hosts_preserved'],1)
        self.assertEqual(r['hosts_added'],1)
        self.assertEqual(na._dhcp_existing_hosts(),[self.records[0],f'{MAC2},192.168.1.77,test'])
        backup=json.loads(Path(r['backup']).read_text())
        self.assertEqual(backup,self.records)
        self.assertEqual(Path(r['backup']).stat().st_mode & 0o777,0o600)

    def test_same_identity_no_write_and_original_hostname_kept(self):
        r=self.apply([{'mac':MAC1.upper(),'ip':'192.168.1.55','hostname':'different'}])
        self.assertTrue(r['unchanged']);self.assertEqual(r['hosts_added'],0)
        self.assertEqual(na._dhcp_existing_hosts(),self.records)
        self.assertEqual(self.calls,[])

    def test_mac_conflict_fails_without_write(self):
        with self.assertRaisesRegex(ValueError,'MAC'):
            self.apply([{'mac':MAC1,'ip':'192.168.1.77'}])
        self.assertEqual(self.calls,[])

    def test_ip_conflict_fails_without_write(self):
        with self.assertRaisesRegex(ValueError,'IP'):
            self.apply([{'mac':MAC2,'ip':'192.168.1.55'}])
        self.assertEqual(self.calls,[])

    def test_existing_unrecognized_fails_closed(self):
        self.write(['*,192.168.1.45'])
        with self.assertRaisesRegex(ValueError,'non riconosciuto'):
            self.apply([{'mac':MAC2,'ip':'192.168.1.77'}])
        self.assertEqual(self.calls,[])

    def test_write_failure_preserves_original(self):
        self.fail='unmodified'
        with self.assertRaisesRegex(ValueError,'fallita'):
            self.apply([{'mac':MAC2,'ip':'192.168.1.77'}])
        self.assertEqual(na._dhcp_existing_hosts(),self.records)

    def test_cli_reports_error_after_write_rollback(self):
        self.fail='write_after_change'
        with self.assertRaisesRegex(ValueError,'fallita'):
            self.apply([{'mac':MAC2,'ip':'192.168.1.77'}])
        self.assertEqual(na._dhcp_existing_hosts(),self.records)
        self.assertGreaterEqual(len([x for x in self.calls if len(x)==4]),2)

    def test_check_never_reads_pihole_or_applies(self):
        r=self.apply([{'mac':MAC2,'ip':'192.168.1.77'}],mode='check')
        self.assertTrue(r['ok']);self.assertFalse(r['applied']);self.assertFalse(self.calls)

    def test_existing_multiple_ip_ambiguous(self):
        self.write([f'{MAC1},192.168.1.55,192.168.1.56'])
        with self.assertRaisesRegex(ValueError,'più IP'):
            self.apply([{'mac':MAC2,'ip':'192.168.1.77'}])

if __name__=='__main__':unittest.main()
