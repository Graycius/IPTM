#!/usr/bin/env python3
"""Offline tests of the real privileged Squid APT wrapper; no APT/systemd invoked."""
from pathlib import Path
import re,os,subprocess,tempfile,unittest
ROOT=Path(__file__).resolve().parents[1]
HELPER=(ROOT/'runtime/iptm-helper').read_text()
UI=(ROOT/'modules/28_system_monitoring.php').read_text()
PERF=(ROOT/'modules/41_performance_pages.php').read_text()
# Extract exactly the real function from helper; mocked shell commands only.
START=HELPER.index('squid_install_safely() {')
END=HELPER.index('\ntool_pkg_installed() {',START)
TARGET=HELPER[START:END]

MOCKS='''
tool_pkg_installed(){ [ "${PKG_INSTALLED:-0}" = 1 ]; }
command(){
 if [ "${1:-}" = '-v' ] && [ "${2:-}" = squid ]; then
   [ "${SQUID_FOREIGN_BIN:-0}" = 1 ]; return $?
 fi
 builtin command "$@"
}
systemctl(){
 printf 'systemctl %s\\n' "$*" >> "$LOG"
 case "$*" in
  'is-active --quiet squid.service') [ "${SQUID_FOREIGN_ACTIVE:-0}" = 1 ];;
  'cat squid.service') [ "${SQUID_FOREIGN_UNIT:-0}" = 1 ];;
  'mask --runtime squid.service') [ "${MASK_FAIL:-0}" != 1 ];;
  'unmask --runtime squid.service') [ "${UNMASK_FAIL:-0}" != 1 ];;
  'disable --now squid.service') [ "${DISABLE_FAIL:-0}" != 1 ];;
  *) printf 'unexpected systemctl %s\\n' "$*" >&2;return 97;;
 esac
}
apt-get(){ printf 'apt-get %s\\n' "$*" >> "$LOG"; [ "${APT_FAIL:-0}" != 1 ] || return 55; }
'''

class TestSquidTools(unittest.TestCase):
 def run_install(self, **changes):
  with tempfile.TemporaryDirectory() as tmp:
   logfile=Path(tmp)/'calls.log'
   env=dict(os.environ,LOG=str(logfile),PKG_INSTALLED='0',SQUID_FOREIGN_BIN='0',SQUID_FOREIGN_ACTIVE='0',SQUID_FOREIGN_UNIT='0',MASK_FAIL='0',UNMASK_FAIL='0',DISABLE_FAIL='0',APT_FAIL='0')
   env.update({k:str(v) for k,v in changes.items()})
   p=subprocess.run(['bash','-c',MOCKS+TARGET+'\nsquid_install_safely'],env=env,text=True,capture_output=True,timeout=4)
   events=logfile.read_text().splitlines() if logfile.exists() else []
   return p,events

 def test_catalog_and_proxy_page(self):
  self.assertIn("'squid' => ['Squid · cache e proxy LAN'",UI)
  self.assertIn('?p=performance',UI)
  self.assertIn('?p=progs#tool-squid',PERF)
  self.assertIn('if ($k === \'squid\' && !empty($t[\'inst\']))',UI)

 def test_status_and_typed_apt_install(self):
  self.assertIn('dnscrypt squid ipset',HELPER)
  self.assertIn('dnscrypt-proxy squid squid-openssl squid-gnutls clamav',HELPER)
  self.assertIn('squid) echo "squid";;',HELPER)
  self.assertIn('squid) { [ -n "${inst[squid]:-}" ] || [ -n "${inst[squid-openssl]:-}" ]',HELPER)
  self.assertIn('if [ "$n" = squid ]; then\n                squid_install_safely',HELPER)
  self.assertNotIn('squid) echo "squid.service"',HELPER) # no unsafe UI service control

 def test_safe_new_install(self):
  p,events=self.run_install()
  self.assertEqual(p.returncode,0,(p.stdout,p.stderr))
  self.assertEqual([e.split(' ')[1] for e in events if e.startswith('systemctl ') and e.split(' ')[1] not in ('is-active','cat')], ['mask','unmask','disable'])
  self.assertEqual(len([e for e in events if e.startswith('apt-get install ')]),1)
  self.assertIn('squid',events[-3] if len(events)>2 else ''.join(events))

 def test_already_installed_no_changes(self):
  p,events=self.run_install(PKG_INSTALLED=1)
  self.assertEqual(p.returncode,0);self.assertEqual(events,[])

 def test_custom_running_service_protected(self):
  for overrides in (dict(SQUID_FOREIGN_ACTIVE=1),dict(SQUID_FOREIGN_UNIT=1),dict(SQUID_FOREIGN_BIN=1)):
   with self.subTest(overrides=overrides):
    p,events=self.run_install(**overrides)
    self.assertNotEqual(p.returncode,0)
    self.assertFalse(any('apt-get' in e or 'mask --runtime' in e for e in events))

 def test_failed_mask_aborts_before_apt(self):
  p,events=self.run_install(MASK_FAIL=1)
  self.assertNotEqual(p.returncode,0)
  self.assertFalse(any(e.startswith('apt-get') for e in events))

 def test_apt_failure_cleans_mask(self):
  p,events=self.run_install(APT_FAIL=1)
  self.assertEqual(p.returncode,55)
  self.assertIn('systemctl unmask --runtime squid.service',events)
  self.assertFalse(any('systemctl disable' in e for e in events))

 def test_failed_unmask_fails_closed(self):
  p,events=self.run_install(UNMASK_FAIL=1)
  self.assertNotEqual(p.returncode,0)
  self.assertIn('systemctl mask --runtime squid.service',events)

 def test_failed_disable_reports_error(self):
  p,events=self.run_install(DISABLE_FAIL=1)
  self.assertNotEqual(p.returncode,0)
  self.assertIn('systemctl disable --now squid.service',events)

if __name__=='__main__':unittest.main(verbosity=2)
