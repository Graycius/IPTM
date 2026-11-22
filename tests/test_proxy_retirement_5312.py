#!/usr/bin/env python3
"""Offline regression checks for the *residual-only* IPTM proxy retirement.

The 5.30.12+ retirement no longer has a ROOT or runs the legacy cache_proxy
worker. These tests simulate the real path and never touch systemd or iptables.
"""
import importlib.util
import pathlib
import tempfile
import unittest
from contextlib import ExitStack, contextmanager
from types import SimpleNamespace
from unittest.mock import patch

R = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    'iptm_retire', R / 'extensions/retire_legacy_proxy.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


@contextmanager
def isolated(base, *, units=None, directories=None, nat=None, active=None,
             patch_owner=False, check_dirs=False):
    """Point every mutable path at an isolated temporary tree."""
    units = {} if units is None else units
    directories = () if directories is None else directories
    active = {} if active is None else active
    commands = []

    def fake_execute(*args, **kwargs):
        commands.append(args)
        return SimpleNamespace(stdout='inactive\n', stderr='', returncode=3)

    def fake_service(unit):
        return active.get(unit, 'inactive')

    with ExitStack() as s:
        for name, value in (
            ('BASE', base / 'proxy'),
            ('REDIRECT', base / 'proxy' / 'redirect.json'),
            ('CONFIG', base / 'missing-conf' / 'squid.conf'),
            ('LEGACY_LOG', base / 'missing-tool-log'),
            ('DIRECTORIES', directories),
            ('UNITS', units),
        ):
            s.enter_context(patch.object(m, name, value))
        s.enter_context(patch.object(m.os, 'geteuid', return_value=0))
        s.enter_context(patch.object(m, 'execute', side_effect=fake_execute))
        s.enter_context(patch.object(m, 'service_state', side_effect=fake_service))
        if nat is not None:
            s.enter_context(patch.object(m, 'nat_residue', side_effect=nat))
        if patch_owner:
            s.enter_context(patch.object(m, 'owned_file', return_value=True))
        if not check_dirs:
            s.enter_context(patch.object(m, 'safe_dir'))
        yield commands


class Tests(unittest.TestCase):
    def test_01_no_artifacts_rejects_orphan_nat(self):
        with tempfile.TemporaryDirectory() as td:
            with isolated(pathlib.Path(td), nat=lambda: ['iptables']) as _:
                with self.assertRaisesRegex(m.RetireError, 'Redirect residuo'):
                    m.retire('5.30.11')

    def test_02_no_artifacts_and_clean_nat_is_noop(self):
        with tempfile.TemporaryDirectory() as td:
            with isolated(pathlib.Path(td), nat=lambda: []) as _:
                result = m.retire('5.30.11')
                self.assertFalse(result['retired'])

    def test_03_foreign_unit_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            unit = root / 'iptm-cache-proxy.service'
            unit.write_text('[Unit]\nDescription=UNRELATED\n')
            original_stat = m._safe_stat
            # Test the ownership marker independently of the test runner UID.
            def fake_stat(path):
                st = original_stat(path)
                return SimpleNamespace(st_uid=0, st_mode=st.st_mode, st_size=st.st_size)
            with isolated(root, units={unit: 'IPTM isolated LAN HTTP caching proxy'}, nat=lambda: []):
                with patch.object(m, '_safe_stat', side_effect=fake_stat):
                    with self.assertRaisesRegex(m.RetireError, 'Marcatore'):
                        m.retire('5.30.11')
            self.assertTrue(unit.exists())

    def test_04_symlink_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            link = root / 'danger'
            link.symlink_to('/etc')
            with isolated(root, directories=(link,), check_dirs=True, nat=lambda: []):
                with self.assertRaisesRegex(m.RetireError, 'simbolica'):
                    m.retire('5.30.11')

    def test_05_invalid_version_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            with isolated(pathlib.Path(td), nat=lambda: []):
                with self.assertRaisesRegex(m.RetireError, 'Versione'):
                    m.retire('../5.30.11')

    def test_06_stale_nat_blocks_cleanup_without_deleting_files(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            unit = root / 'iptm-cache-proxy.service'
            unit.write_text('Description=IPTM isolated LAN HTTP caching proxy\n')
            state = root / 'state'
            state.mkdir()
            (state / 'preferences.json').write_text('{}')
            with isolated(root, units={unit: 'Description=IPTM isolated LAN HTTP caching proxy'},
                          directories=(state,), nat=lambda: ['iptables'], patch_owner=True):
                with self.assertRaisesRegex(m.RetireError, 'NAT incompleta'):
                    m.retire('5.30.11')
            self.assertTrue(unit.exists())
            self.assertTrue((state / 'preferences.json').exists())

    def test_07_cleanup_removes_only_owned_artifacts(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            unit = root / 'iptm-cache-proxy.service'
            unit.write_text('Description=IPTM isolated LAN HTTP caching proxy\n')
            state = root / 'state'
            state.mkdir()
            (state / 'preferences.json').write_text('{}')
            foreign = root / 'unrelated.txt'
            foreign.write_text('preserve')
            with isolated(root, units={unit: 'Description=IPTM isolated LAN HTTP caching proxy'},
                          directories=(state,), nat=lambda: [], patch_owner=True) as commands:
                result = m.retire('5.30.11')
            self.assertTrue(result['retired'])
            self.assertFalse(unit.exists())
            self.assertFalse(state.exists())
            self.assertEqual(foreign.read_text(), 'preserve')
            self.assertTrue(any(a[:2] == ('systemctl', 'stop') for a in commands))

    def test_08_still_active_unit_blocks_cleanup(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            unit = root / 'iptm-cache-proxy.service'
            unit.write_text('Description=IPTM isolated LAN HTTP caching proxy\n')
            with isolated(root, units={unit: 'Description=IPTM isolated LAN HTTP caching proxy'},
                          nat=lambda: [], patch_owner=True,
                          active={'iptm-cache-proxy.service': 'active'}):
                with self.assertRaisesRegex(m.RetireError, 'ancora attiva'):
                    m.retire('5.30.11')
            self.assertTrue(unit.exists())

    def test_09_runtime_has_no_active_proxy_command(self):
        self.assertFalse((R / 'extensions/cache_proxy.py').exists())
        self.assertFalse((R / 'extensions/cache_redirect.py').exists())
        self.assertFalse((R / 'actions/performance.php').exists())
        self.assertNotIn('cache-proxy)', (R / 'runtime/iptm-helper').read_text())
        self.assertNotIn("'cache_proxy_save' =>", (R / 'modules/22_actions_controller.php').read_text())

    def test_10_legacy_installer_active_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            with isolated(pathlib.Path(td), nat=lambda: [],
                          active={'iptm-tool-squid.service': 'active'}):
                with self.assertRaisesRegex(m.RetireError, 'precedente ancora attiva'):
                    m.retire('5.30.11')

    def test_11_native_update_retires_before_swapping_runtime(self):
        text = (R / 'extensions/native_update.py').read_text()
        self.assertLess(text.index('retire_worker=stage/'),
                        text.index('        new_root=RELEASE_BASE/version'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
