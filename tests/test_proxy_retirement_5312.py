#!/usr/bin/env python3
"""Offline-only tests for decommissioning of legacy IPTM-managed proxy."""
import importlib.util, json, pathlib, tempfile, unittest
from unittest.mock import patch
from types import SimpleNamespace
R=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('iptm_retire',R/'extensions/retire_legacy_proxy.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class Tests(unittest.TestCase):
    def test_01_empty_install_fails_if_nat_hooks_remain(self):
        with tempfile.TemporaryDirectory() as td:
            p=pathlib.Path(td)
            with patch.object(m,'LEGACY_LOG',p/'no-tool-log'),patch.object(m,'DIRECTORIES',(p/'etc',p/'var')),patch.object(m,'UNITS',{}),\
                 patch.object(m,'ROOT',p),patch.object(m,'nat_residue',return_value=['legacy:PREROUTING']),\
                 patch.object(m.os,'geteuid',return_value=0):
                with self.assertRaises(m.RetireError):m.retire('5.30.11')
    def test_02_no_artifacts_and_nat_clean_is_noop(self):
        with tempfile.TemporaryDirectory() as td:
            p=pathlib.Path(td)
            with patch.object(m,'LEGACY_LOG',p/'no-tool-log'),patch.object(m,'DIRECTORIES',(p/'etc',p/'var')),patch.object(m,'UNITS',{}),\
                 patch.object(m,'ROOT',p),patch.object(m,'nat_residue',return_value=[]),\
                 patch.object(m,'execute',return_value=SimpleNamespace(stdout='inactive\n',returncode=3)),\
                 patch.object(m.os,'geteuid',return_value=0):
                self.assertFalse(m.retire('5.30.11')['retired'])
    def test_03_foreign_unit_rejected_before_helper(self):
        with tempfile.TemporaryDirectory() as td:
            p=pathlib.Path(td);unit=p/'iptm-cache-proxy.service';unit.write_text('[Unit]\nDescription=UNRELATED\n')
            with patch.object(m,'LEGACY_LOG',p/'no-tool-log'),patch.object(m,'DIRECTORIES',(p/'state',)),patch.object(m,'UNITS',{unit:'IPTM owned marker'}),\
                 patch.object(m,'execute',return_value=SimpleNamespace(stdout='inactive\n',returncode=3)),\
                 patch.object(m.os,'geteuid',return_value=0):
                with self.assertRaises(m.RetireError):m.retire('5.30.11')
    def test_04_symlink_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            p=pathlib.Path(td);(p/'danger').symlink_to('/etc')
            with patch.object(m,'LEGACY_LOG',p/'no-tool-log'),patch.object(m,'DIRECTORIES',(p/'danger',)),patch.object(m,'UNITS',{}),\
                 patch.object(m.os,'geteuid',return_value=0):
                with self.assertRaises(m.RetireError):m.retire('5.30.11')
    def test_05_invalid_version_is_rejected(self):
        with patch.object(m.os,'geteuid',return_value=0):
            with self.assertRaises(m.RetireError):m.retire('../5.30.11')
    def test_06_stale_nat_after_disable_aborts_without_deleting_files(self):
        with tempfile.TemporaryDirectory() as td:
            p=pathlib.Path(td);root=p/'releases';worker=root/'5.30.11/extensions/cache_proxy.py';worker.parent.mkdir(parents=True)
            worker.write_text('legacy')
            unit=p/'iptm-cache-proxy.service';unit.write_text('Description=OWNER\n')
            data=p/'state';data.mkdir();(data/'preferences.json').write_text('{}')
            def command(*args,**kwargs):
                if args[:3]==('/usr/bin/python3','-B',str(worker)):
                    return SimpleNamespace(stdout=json.dumps({'ok':True,'redirect':False}),returncode=0)
                return SimpleNamespace(stdout='inactive\n',returncode=3)
            with patch.object(m,'LEGACY_LOG',p/'no-tool-log'),patch.object(m,'DIRECTORIES',(data,)),patch.object(m,'UNITS',{unit:'Description=OWNER'}),\
                 patch.object(m,'CONFIG',p/'not-present'),patch.object(m,'REDIRECT',data/'redirect.json'),\
                 patch.object(m,'ROOT',root),patch.object(m,'execute',side_effect=command),\
                 patch.object(m,'nat_residue',return_value=['nft:PREROUTING']),\
                 patch.object(m.os,'geteuid',return_value=0):
                with self.assertRaises(m.RetireError):m.retire('5.30.11')
                self.assertTrue(unit.exists())
                self.assertTrue(data.exists())
    def test_07_safe_retirement_deletes_owned_artifacts_only(self):
        with tempfile.TemporaryDirectory() as td:
            p=pathlib.Path(td);root=p/'releases';worker=root/'5.30.11/extensions/cache_proxy.py';worker.parent.mkdir(parents=True)
            worker.write_text('legacy')
            unit=p/'iptm-cache-proxy.service';unit.write_text('Description=OWNER\n')
            data=p/'state';data.mkdir();(data/'preferences.json').write_text('{}')
            foreign=p/'unrelated.txt';foreign.write_text('preserve')
            def command(*args,**kwargs):
                if args[:3]==('/usr/bin/python3','-B',str(worker)):
                    return SimpleNamespace(stdout=json.dumps({'ok':True,'redirect':False}),returncode=0)
                return SimpleNamespace(stdout='inactive\n',returncode=3)
            with patch.object(m,'LEGACY_LOG',p/'no-tool-log'),patch.object(m,'DIRECTORIES',(data,)),patch.object(m,'UNITS',{unit:'Description=OWNER'}),\
                 patch.object(m,'CONFIG',p/'not-present'),patch.object(m,'REDIRECT',data/'redirect.json'),\
                 patch.object(m,'ROOT',root),patch.object(m,'execute',side_effect=command),\
                 patch.object(m,'nat_residue',return_value=[]),patch.object(m.os,'geteuid',return_value=0):
                out=m.retire('5.30.11')
                self.assertTrue(out['retired'])
                self.assertFalse(unit.exists());self.assertFalse(data.exists())
                self.assertTrue(foreign.exists())
    def test_08_active_unit_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            p=pathlib.Path(td);root=p/'releases';worker=root/'5.30.11/extensions/cache_proxy.py';worker.parent.mkdir(parents=True)
            worker.write_text('legacy');unit=p/'iptm-cache-proxy.service';unit.write_text('Description=OWNER\n')
            def command(*args,**kwargs):
                if args[0]=='/usr/bin/python3':return SimpleNamespace(stdout=json.dumps({'ok':True,'redirect':False}),returncode=0)
                return SimpleNamespace(stdout='active\n',returncode=0)
            with patch.object(m,'LEGACY_LOG',p/'no-tool-log'),patch.object(m,'DIRECTORIES',(p/'none',)),patch.object(m,'UNITS',{unit:'Description=OWNER'}),\
                 patch.object(m,'CONFIG',p/'not-present'),patch.object(m,'REDIRECT',p/'redirect.json'),\
                 patch.object(m,'ROOT',root),patch.object(m,'execute',side_effect=command),\
                 patch.object(m.os,'geteuid',return_value=0):
                with self.assertRaises(m.RetireError):m.retire('5.30.11')
                self.assertTrue(unit.exists())
    def test_09_active_feature_removed_from_runtime(self):
        self.assertFalse((R/'extensions/cache_proxy.py').exists())
        self.assertFalse((R/'extensions/cache_redirect.py').exists())
        self.assertFalse((R/'actions/performance.php').exists())
        self.assertNotIn('cache-proxy)',(R/'runtime/iptm-helper').read_text())
        self.assertNotIn("'cache_proxy_save' =>",(R/'modules/22_actions_controller.php').read_text())
        self.assertNotIn("'squid' =>",(R/'modules/28_system_monitoring.php').read_text())
    def test_10_previous_installer_still_active_blocks_retirement(self):
        with tempfile.TemporaryDirectory() as td:
            p=pathlib.Path(td)
            with patch.object(m,'LEGACY_LOG',p/'no-tool-log'),patch.object(m,'DIRECTORIES',(p/'none',)),patch.object(m,'UNITS',{}),                 patch.object(m,'execute',return_value=SimpleNamespace(stdout='active\n',returncode=0)),                 patch.object(m.os,'geteuid',return_value=0):
                with self.assertRaises(m.RetireError):m.retire('5.30.11')
    def test_11_native_migration_calls_retirement_before_swapping_runtime(self):
        s=(R/'extensions/native_update.py').read_text()
        self.assertLess(s.index("retire_worker=stage/"),s.index('        new_root=RELEASE_BASE/version'))

if __name__=='__main__':unittest.main(verbosity=2)
