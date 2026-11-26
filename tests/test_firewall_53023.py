"""Static guards for the current single-button firewall trial workflow."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
tx = (ROOT / 'modules/11_firewall_transaction.php').read_text()
apply = tx.split('function do_apply(', 1)[1].split('function iptm_runtime_fingerprint(', 1)[0]
confirm = tx.split('function confirm_pending(', 1)[1].split('function revert_pending(', 1)[0]
assert 'confirm_pending()' not in apply, 'Auto-confirm inside do_apply is unsafe'
assert 'pending.json' in apply
assert apply.index('iptm_recovery_prepare($live,$fam)') < apply.index("priv('rollback-arm'")
assert apply.index('atomic_data_write($pf, $pendingData') < apply.index("priv('rollback-arm'") < apply.index("priv('restore' . $sx, $txt)")
assert "$record['health_ok'] = true" in apply and "priv('selftest')" in apply
assert "if (($p['health_ok'] ?? false) !== true)" in confirm
assert "hash_equals($p['runtime_hash'],iptm_runtime_fingerprint($runtimeRules))" in confirm
assert confirm.index("priv('selftest')") < confirm.index('write_live($txt, $fam)')
assert confirm.index('write_live($txt, $fam)') < confirm.index("priv('rollback-cancel'") < confirm.index("unlink(DATA_DIR . '/pending.json')")
firewall = (ROOT / 'actions/firewall.php').read_text()
assert "do_apply($secs, '4', false, true)" in firewall
assert "do_apply($secs, '6')" in firewall
assert "do_apply($secs, '4', true, true)" not in firewall
assert "do_apply($secs, '6', true, true)" not in firewall
assert 'iptm_dns_guard_losses(rules_live(),$draftTxt)' in firewall
system = (ROOT / 'actions/system.php').read_text()
assert "do_apply(ROLLBACK_SECS, '4', true, true)" not in system
ui = (ROOT / 'modules/23_firewall_pages.php').read_text()
assert 'La bozza non include alcune protezioni DNS/DoT' in ui
assert 'Senza conferma si attiva il ripristino automatico' in ui
banner = (ROOT / 'modules/29_render_frontend.php').read_text()
assert 'action value=confirm' in banner and "($pd['health_ok'] ?? false) === true" in banner
print('PASS: independent watchdog, explicit healthy confirmation, scoped apply and DNS guard warning')
