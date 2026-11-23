"""Static guard regressions: unsafe automatic apply must never return."""
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
tx=(ROOT/'modules/11_firewall_transaction.php').read_text()
apply=tx.split('function do_apply(',1)[1].split('function confirm_pending(',1)[0]
assert 'confirm_pending()' not in apply, 'Auto-confirm inside do_apply is unsafe'
assert "priv('rollback-arm'" in apply
assert 'priv(\'restore\'' in apply or 'priv(\'restore' in apply
assert 'pending.json' in apply and 'Regole in PROVA' in apply
firewall=(ROOT/'actions/firewall.php').read_text()
assert "do_apply((int)($_POST['secs'] ?? ROLLBACK_SECS), '4', false, !empty($_POST['confirm_dns_guard_removal']))" in firewall
assert "do_apply(ROLLBACK_SECS, '6')" in firewall
assert 'Salvataggio bloccato: rimozione DoT/DNS' in firewall
system=(ROOT/'actions/system.php').read_text()
assert "do_apply(ROLLBACK_SECS, '4', true, true)" not in system
ui=(ROOT/'modules/23_firewall_pages.php').read_text()
assert 'name=confirm_dns_guard_removal' in ui and 'Applica in prova con rollback' in ui
banner=(ROOT/'modules/29_render_frontend.php').read_text()
assert 'action value=confirm' in banner and 'Ho verificato SSH' in banner
print('PASS: no auto-confirm, watchdog present, DNS guard confirmation explicit')
