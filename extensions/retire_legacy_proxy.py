#!/usr/bin/env python3
"""Residual cleanup of IPTM-owned HTTP cache proxy artifacts.

Called by native update before switching the privileged helper.
Does not require cache_proxy.py (removed since 5.30.12).
Never flushes unrelated firewall tables or touches distribution packages.
"""
from __future__ import annotations
import json
import importlib.util
import os
import pathlib
import pwd
import re
import shutil
import subprocess
import sys

from command_transport import capture

BASE = pathlib.Path('/var/lib/iptm-cache-proxy')
REDIRECT = BASE / 'redirect.json'
UNITS = {
    pathlib.Path('/etc/systemd/system/iptm-cache-proxy.service'):
        'Description=IPTM isolated LAN HTTP caching proxy',
    pathlib.Path('/etc/systemd/system/iptm-cache-redirect.service'):
        'Description=IPTM HTTP cache redirect reconciliation',
    pathlib.Path('/etc/systemd/system/iptm-cache-redirect.timer'):
        '# IPTM HTTP redirect timer',
}
CONFIG = pathlib.Path('/etc/iptm-cache-proxy/squid.conf')
LEGACY_LOG = pathlib.Path('/var/lib/iptm/tool-squid.log')
DIRECTORIES = (
    pathlib.Path('/etc/iptm-cache-proxy'),
    BASE,
    pathlib.Path('/var/cache/iptm-cache-proxy'),
    pathlib.Path('/var/log/iptm-cache-proxy'),
)
VERSION_RE = re.compile(r'^\d+\.\d+\.\d+$')
TAG = 'IPTM_HTTP_CACHE_V1'
CHAIN = 'IPTM_HTTP_CACHE'
MAX_FILE = 16384
MAX_DIR_ENTRIES = 64


class RetireError(ValueError):
    pass


def execute(*argv, timeout=20, check=True):
    try:
        r = capture(list(argv), timeout=timeout, stdout_limit=1048576, stderr_limit=262144)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RetireError('Comando non eseguibile: ' + str(exc)[:160]) from exc
    if check and r.returncode:
        raise RetireError('Operazione negata: ' + (r.stderr or r.stdout)[-350:])
    return r


def _safe_stat(path: pathlib.Path):
    if path.is_symlink():
        raise RetireError('Percorso simbolico non gestibile: ' + str(path))
    try:
        return path.stat()
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise RetireError(f'Stat fallito su {path}: {exc}') from exc


def owned_file(path: pathlib.Path, marker: str) -> bool:
    if not path.exists() and not path.is_symlink():
        return False
    st = _safe_stat(path)
    if (not path.is_file() or st.st_uid != 0 or st.st_nlink != 1 or (st.st_mode & 0o022) or
            st.st_size > MAX_FILE):
        raise RetireError('File non attribuibile a IPTM: ' + str(path))
    try:
        content = path.read_text(encoding='utf-8', errors='strict')
    except (OSError, UnicodeError) as exc:
        raise RetireError(f'Lettura file fallita: {path}: {exc}') from exc
    if marker not in content:
        raise RetireError('Marcatore proprietario assente: ' + str(path))
    return True


def safe_dir(path: pathlib.Path) -> None:
    if path.is_symlink():
        raise RetireError('Directory simbolica: ' + str(path))
    if not path.exists():
        return
    st = _safe_stat(path)
    uid_ok = {0}
    if path in DIRECTORIES[2:]:
        try:
            uid_ok.add(pwd.getpwnam('proxy').pw_uid)
        except KeyError:
            pass
    if not path.is_dir() or st.st_uid not in uid_ok or (st.st_mode & 0o022):
        raise RetireError('Directory non sicura: ' + str(path))
    try:
        entries = list(path.iterdir())
    except OSError as exc:
        raise RetireError(f'Lettura directory fallita: {path}: {exc}') from exc
    if len(entries) > MAX_DIR_ENTRIES:
        raise RetireError('Directory troppo popolata: ' + str(path))


def service_state(unit: str) -> str:
    r = execute('systemctl', 'is-active', unit, timeout=10, check=False)
    return (r.stdout or '').strip() or 'unknown'


def nat_residue() -> list[str]:
    found = []
    for binary in ('iptables', 'ip6tables'):
        r = execute(binary, '-t', 'nat', '-S', timeout=15, check=False)
        if r.returncode:
            continue
        text = r.stdout or ''
        if TAG in text or f'-j {CHAIN}' in text or f':{CHAIN}' in text:
            found.append(binary)
    return found


def retire(old_version: str) -> dict:
    if os.geteuid() != 0:
        raise RetireError('root richiesto')
    if not VERSION_RE.fullmatch(old_version):
        raise RetireError('Versione precedente non valida')

    if service_state('iptm-tool-squid.service') in (
            'active', 'activating', 'reloading'):
        raise RetireError(
            'Installazione precedente ancora attiva: iptm-tool-squid.service'
        )

    for d in DIRECTORIES:
        safe_dir(d)

    if LEGACY_LOG.is_symlink():
        raise RetireError('Log installazione simbolico')
    if LEGACY_LOG.exists():
        st = _safe_stat(LEGACY_LOG)
        if (not LEGACY_LOG.is_file() or st.st_uid != 0 or
                (st.st_mode & 0o022) or st.st_size > MAX_FILE):
            raise RetireError(
                'Log installazione non riconosciuto: ' + str(LEGACY_LOG)
            )

    present_units = [p for p, m in UNITS.items() if owned_file(p, m)]
    if CONFIG.parent.exists() and CONFIG.exists():
        owned_file(CONFIG, '# IPTM cache proxy')

    if REDIRECT.exists() and REDIRECT.is_symlink():
        raise RetireError('Journal NAT simbolico')

    artifacts = bool(
        present_units or any(d.exists() for d in DIRECTORIES) or LEGACY_LOG.exists()
    )
    if not artifacts:
        remain = nat_residue()
        if remain:
            raise RetireError(
                'Redirect residuo senza journal: ' + ','.join(remain)
            )
        return {
            'ok': True,
            'retired': False,
            'reason': 'nessuna installazione IPTM precedente',
        }

    # Residual-only path: stop units, require inactive + clean NAT, then unlink.
    for unit in (
            'iptm-cache-redirect.service',
            'iptm-cache-proxy.service',
            'iptm-cache-redirect.timer'):
        execute('systemctl', 'stop', unit, timeout=20, check=False)
        execute('systemctl', 'disable', unit, timeout=20, check=False)

    for unit in (
            'iptm-cache-proxy.service',
            'iptm-cache-redirect.timer',
            'iptm-cache-redirect.service'):
        if service_state(unit) in ('active', 'activating', 'reloading'):
            raise RetireError('Unità ancora attiva: ' + unit)

    remain = nat_residue()
    if remain:
        raise RetireError(
            'Rimozione NAT incompleta; nessuna cancellazione di file: ' +
            ','.join(remain)
        )

    if REDIRECT.exists():
        st = _safe_stat(REDIRECT)
        if (not REDIRECT.is_file() or st.st_uid != 0 or (st.st_mode & 0o022) or
                st.st_size > MAX_FILE):
            raise RetireError('Journal redirect non attribuibile a IPTM')
        REDIRECT.unlink()

    for path in present_units:
        path.unlink()
    if present_units:
        execute('systemctl', 'daemon-reload', timeout=20)

    for d in DIRECTORIES:
        if d.exists():
            safe_dir(d)
            shutil.rmtree(d)

    if LEGACY_LOG.exists():
        LEGACY_LOG.unlink()

    final_remain = nat_residue()
    if final_remain:
        raise RetireError(
            'Residui NAT ancora presenti dopo cleanup: ' + ','.join(final_remain)
        )

    return {
        'ok': True,
        'retired': True,
        'removed_units': [p.name for p in present_units],
        'packages_removed': False,
        'firewall_other_rules_changed': False,
        'mode': 'residual-only',
    }


def staged_preflight(old_version: str) -> dict:
    """Compatibility hook invoked by the 5.30.29 updater before its journal.

    In this context no service, qdisc, NAT or configuration may be changed.
    Use the new preflight to catch pending transactions missed by the old code.
    Explicit console invocation outside staging retains the legacy cleanup.
    """
    if not VERSION_RE.fullmatch(old_version):
        raise RetireError('Versione precedente non valida')
    stage = pathlib.Path(__file__).resolve().parent.parent
    worker = stage / 'extensions/native_update.py'
    loader = stage / 'loader/iptables-manager.php'
    if any(p.is_symlink() or not p.is_file() or p.stat().st_uid != 0 or p.stat().st_mode & 0o022 for p in (worker,loader)):
        raise RetireError('Staging non protetto')
    match = re.search(r"APP_VERSION\s*=\s*'([0-9.]+)'", loader.read_text())
    if not match:
        raise RetireError('Versione target non disponibile')
    spec = importlib.util.spec_from_file_location('iptm_staged_native',worker)
    native = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(native)
    try:
        native.preflight_network_transactions(match.group(1))
    except (native.UpdateError,OSError,ValueError) as exc:
        raise RetireError(str(exc)) from exc
    return {'ok':True,'retired':False,'reason':'preflight compatibile; nessuna modifica di rete prima del commit'}


def main(args: list[str]) -> dict:
    if len(args) != 2 or args[0] != 'apply':
        raise RetireError('Uso: apply <versione-precedente>')
    if pathlib.Path(__file__).resolve().parent.parent.name.startswith('.native-stage-'):
        return staged_preflight(args[1])
    return retire(args[1])


if __name__ == '__main__':
    try:
        print(json.dumps(main(sys.argv[1:]), sort_keys=True))
    except RetireError as exc:
        print(json.dumps({'ok': False, 'error': str(exc)}), file=sys.stderr)
        sys.exit(2)
