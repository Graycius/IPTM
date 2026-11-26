#!/usr/bin/env python3
"""Conservative, reversible retirement of *recognised* legacy IoT Warden resources.

This tool never edits live iptables and never executes configuration as shell code.
Explicit service names and exact filesystem paths only. Unsupported deployments are
reported as blockers rather than guessed or deleted. Python 3.9+ stdlib.
"""
import argparse
import contextlib
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid

# Shared transport loaded only for commands; journal recovery stays standalone.
def iptm_capture(argv, **options):
    import importlib.util
    from pathlib import Path
    source=Path(__file__).resolve()
    if source.parent.name == 'runtime':
        module=source.parent.parent/'extensions'/'command_transport.py'
    else:
        module=Path('/usr/local/lib/iptables-manager/web/releases/6.0.8/extensions/command_transport.py')
    if not module.is_file() or module.is_symlink():
        raise OSError('Trasporto IPTM assente o non sicuro')
    cached=getattr(iptm_capture,'_module',None)
    if cached is None:
        spec=importlib.util.spec_from_file_location('_iptm_runtime_transport',module)
        cached=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cached)
        iptm_capture._module=cached
    return cached.capture(argv, **options)


UNITS = ('iot-warden.service', 'iot-warden.timer', 'iotwarden.service', 'iotwarden.timer')
KNOWN = (
    '/etc/cron.d/iot-warden', '/etc/cron.d/iotwarden',
    '/root/iot_warden.sh',
    '/etc/iot-warden', '/etc/iotwarden',
    '/opt/iot-warden', '/opt/iotwarden',
    '/usr/local/bin/iot-warden', '/usr/local/bin/iotwarden',
    '/usr/local/sbin/iot-warden', '/usr/local/sbin/iotwarden',
    '/usr/local/bin/iot-warden.sh', '/usr/local/sbin/iot-warden.sh',
    '/etc/systemd/system/iot-warden.service', '/etc/systemd/system/iot-warden.timer',
    '/etc/systemd/system/iotwarden.service', '/etc/systemd/system/iotwarden.timer',
)
CHAIN_NAMES = ('IOT_FW', 'IOT_DNS')
WARDEN_RE = re.compile(r'iot[-_]?warden', re.I)
CONFIG_RE = re.compile(r'^\s*(POST_SCRIPT|POST_SERVICES)\s*=\s*(.*)$')
MAX_ITEMS = 1500
MAX_BYTES = 48 * 1024 * 1024


def safe_json(obj):
    print(json.dumps(obj, ensure_ascii=False, sort_keys=True))


class Warden:
    def __init__(self, root='/', runner=None):
        # root is injected in tests only; main() always uses '/' and ignores env overrides.
        self.root = Path(root)
        self.runner = runner or self._run
        self.backups = self.path('/var/lib/iptables-manager/backups/iot-warden')
        self.lockpath = self.path('/run/lock/iptm-iot-warden.lock')

    def path(self, value):
        return self.root / value.lstrip('/')

    @staticmethod
    def _run(cmd):
        try:
            return iptm_capture(cmd, timeout=12, stdout_limit=1048576, stderr_limit=262144)
        except (OSError, subprocess.TimeoutExpired) as e:
            return subprocess.CompletedProcess(cmd, 127, '', type(e).__name__)

    def exec(self, cmd, *, required=False):
        r = self.runner(cmd)
        if required and r.returncode:
            # Never expose arbitrary service output in the UI (may include secrets).
            raise RuntimeError(f'comando fallito: {cmd[0]} {cmd[1]} (exit {r.returncode})')
        return r

    def unit_state(self, name):
        r = self.exec(['systemctl', 'show', name, '-p', 'LoadState', '-p', 'ActiveState', '-p', 'UnitFileState', '--no-pager'])
        fields = dict(re.findall(r'^(LoadState|ActiveState|UnitFileState)=([^\n]*)', r.stdout or '', re.M))
        trustworthy = r.returncode == 0 and 'LoadState' in fields and 'ActiveState' in fields and 'UnitFileState' in fields
        return {'name': name, 'verified': trustworthy,
                'loaded': fields.get('LoadState', '') not in ('not-found', '', 'masked'),
                'active': fields.get('ActiveState') == 'active',
                'enabled': fields.get('UnitFileState') in ('enabled', 'enabled-runtime', 'linked', 'linked-runtime'),
                'masked': fields.get('LoadState') == 'masked'}

    def _path_safe(self, p):
        """Return count/bytes/metadata digest; reject links, devices and unsafe owners."""
        if not p.exists() and not p.is_symlink():
            return 0, 0, ""
        parent = p.parent
        while parent != self.root and parent != parent.parent:
            if parent.is_symlink():
                raise ValueError(f'percorso con link simbolico: {p}')
            parent = parent.parent
        count = total = 0
        fingerprint = hashlib.sha256()
        stack = [p]
        while stack:
            f = stack.pop()
            st = f.lstat()
            if not (stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode)):
                raise ValueError(f'file non regolare / symlink: {f}')
            if self.root == Path('/') and (st.st_uid != 0 or st.st_mode&0o022):
                raise ValueError(f'risorsa non protetta di root: {f}')
            if stat.S_ISREG(st.st_mode) and st.st_nlink!=1:raise ValueError(f'hardlink non gestibile: {f}')
            if f.is_mount():
                raise ValueError(f'filesystem montato non gestibile automaticamente: {f}')
            count += 1
            fingerprint.update((str(f.relative_to(self.root)) + ':' + str(st.st_mode) + ':' +
                                str(st.st_size) + ':' + str(st.st_mtime_ns) + '\n').encode())
            if stat.S_ISDIR(st.st_mode):
                stack.extend(sorted(f.iterdir(), reverse=True))
            else:
                total += st.st_size
            if count > MAX_ITEMS or total > MAX_BYTES:
                raise ValueError(f'risorsa troppo grande, rimozione manuale: {p}')
            if stat.S_ISREG(st.st_mode):
                fd=os.open(f,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
                with os.fdopen(fd,'rb') as stream:
                    current=os.fstat(stream.fileno())
                    if (current.st_dev,current.st_ino,current.st_size,current.st_mtime_ns)!=(st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns):raise ValueError(f'risorsa modificata: {f}')
                    content=stream.read(st.st_size+1)
                    if len(content)!=st.st_size or os.fstat(stream.fileno()).st_ctime_ns!=st.st_ctime_ns:raise ValueError(f'risorsa modificata: {f}')
                    fingerprint.update(hashlib.sha256(content).digest())
        return count, total, fingerprint.hexdigest()

    def _conf(self):
        conf = self.path('/etc/iptables-manager.conf')
        if not conf.exists():
            return '', {}, []
        if conf.is_symlink() or not conf.is_file():
            return '', {}, ['config IPTM non regolare: ispezionare manualmente']
        try:
            raw = conf.read_text(encoding='utf-8')
        except (OSError, UnicodeError):
            return '', {}, ['config IPTM non leggibile']
        entries = {}
        blockers = []
        for line in raw.splitlines():
            m = CONFIG_RE.match(line)
            if not m: continue
            key, val = m.groups()
            if key in entries:
                blockers.append(f'{key} duplicato: revisione manuale')
                continue
            val = val.strip()
            # Only simple unquoted, single-quoted and double-quoted values.
            if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                val = val[1:-1]
            if re.search(r'[\n\r`$\\;]', val):
                blockers.append(f'{key} non semplice: revisione manuale')
            entries[key] = val
        return raw, entries, blockers

    @staticmethod
    def _simple_warden_script_value(value):
        """Recognise only plain direct invocations of /root/iot_warden.sh."""
        raw = (value or "").strip().strip("\"'")
        if not raw or re.search(r'[\n\r`$|;&<>]', raw):
            return False
        return raw in (
            '/root/iot_warden.sh',
            '/bin/bash /root/iot_warden.sh',
            '/usr/bin/bash /root/iot_warden.sh',
            '/bin/sh /root/iot_warden.sh',
            '/usr/bin/sh /root/iot_warden.sh',
            '/usr/bin/env bash /root/iot_warden.sh',
            '/usr/bin/env sh /root/iot_warden.sh',
        )

    @staticmethod
    def _simple_warden_cron(line):
        """Only plain invocations, without shell syntax, redirects, pipes or other commands."""
        raw=line.strip()
        if not raw or raw.startswith('#'):
            return False
        fields=raw.split(None,5)
        if raw.startswith('@reboot '):
            cmd=raw.split(None,1)[1]
        elif len(fields)==6 and all(re.fullmatch(r'[0-9*,/\-]+',f) for f in fields[:5]):
            cmd=fields[5]
        else:
            return False
        return cmd in ('/root/iot_warden.sh', '/bin/bash /root/iot_warden.sh',
                       '/usr/bin/bash /root/iot_warden.sh')

    def _scheduled_unknown(self):
        blockers, cron_actions = [], []
        watched = [self.path('/etc/crontab'), self.path('/var/spool/cron/crontabs/root')]
        cron_dir = self.path('/etc/cron.d')
        if cron_dir.is_dir():
            watched += sorted(cron_dir.iterdir())[:500]
        known = {self.path(k) for k in KNOWN}
        for f in watched:
            if f in known or not f.is_file() or f.is_symlink(): continue
            try:
                if f.stat().st_size > 262144: continue
                text = f.read_text(encoding='utf-8', errors='replace')
                numbers = [n for n,l in enumerate(text.splitlines()) if WARDEN_RE.search(l) and not l.lstrip().startswith('#')]
                if not numbers: continue
                # Never alter general system crontab or custom cron.d recipes. Only
                # a *root user's* exact known script with a plain invocation.
                if f == self.path('/var/spool/cron/crontabs/root') and all(
                    self._simple_warden_cron(text.splitlines()[n]) for n in numbers
                ) and (self.root != Path('/') or f.stat().st_uid == 0):
                    cron_actions.append({'path':'/var/spool/cron/crontabs/root',
                                         'line_indexes':numbers,
                                         'sha256':hashlib.sha256(text.encode()).hexdigest()})
                else:
                    blockers.append(f'Attivazione cron non riconosciuta: {str(f).replace(str(self.root),"/",1)}')
            except OSError:
                blockers.append(f'Impossibile leggere il crontab: {f.name}')
        system = self.path('/etc/systemd/system')
        if system.is_dir():
            for f in sorted(system.glob('*.service'))[:500] + sorted(system.glob('*.timer'))[:500]:
                if f.name in UNITS: continue
                if WARDEN_RE.search(f.name):
                    blockers.append(f'Unità systemd non riconosciuta: {f.name}')
        return blockers, cron_actions

    def rotate_retirement_backups(self, newest=None, keep=10):
        """Only completed retirement snapshots, never pending or unknown directories."""
        if self.backups.is_symlink() or not self.backups.is_dir(): return 0
        completed=[]
        for entry in self.backups.iterdir():
            if entry.is_symlink() or not entry.is_dir(): continue
            if not re.fullmatch(r'\d{8}T\d{6}Z-[0-9a-f]{8}',entry.name): continue
            manifest=entry/'manifest.json'
            if manifest.is_symlink() or not manifest.is_file():continue
            try:
                record=json.loads(manifest.read_text('utf-8'))
                if record.get('format')!='iptm.iot-warden.retired.v1':continue
                st=entry.lstat()
                completed.append((int(entry==newest),st.st_mtime_ns,entry.name,st.st_ino,entry))
            except (OSError,ValueError,UnicodeError,AttributeError):continue
        completed.sort(reverse=True)
        deleted=0
        for _,_,_,ino,path in completed[keep:]:
            try:
                if not path.is_symlink() and path.lstat().st_ino==ino:
                    shutil.rmtree(path);deleted+=1
            except OSError:pass
        return deleted

    def retirement_record(self):
        if not self.backups.is_dir() or self.backups.is_symlink():
            return ''
        for f in sorted(self.backups.glob('*/manifest.json'), reverse=True)[:32]:
            if not f.is_file() or f.is_symlink(): continue
            try:
                data = json.loads(f.read_text(encoding='utf-8')[:65536])
                if data.get('format') == 'iptm.iot-warden.retired.v1':
                    return str(f.parent)
            except (OSError, ValueError, AttributeError):
                continue
        return ''

    def inventory(self):
        paths, blockers = [], []
        for name in KNOWN:
            p = self.path(name)
            if not p.exists() and not p.is_symlink(): continue
            try:
                n, size, meta = self._path_safe(p)
                # Detect package-owned files: removing them breaks dpkg tracking.
                owned = self.exec(['dpkg-query', '-S', name]).returncode == 0 if self.root == Path('/') else False
                if owned: blockers.append(f'Risorsa gestita da dpkg: {name}')
                paths.append({'path': name, 'files': n, 'bytes': size, 'metadata_sha256': meta, 'package_owned': owned})
            except (OSError, ValueError) as ex:
                blockers.append(str(ex)[:200])
        units = [self.unit_state(x) for x in UNITS]
        if any(not x['verified'] for x in units):
            blockers.append('Impossibile verificare tutte le unità systemd: migrazione automatica sospesa')
        raw, conf, cb = self._conf()
        blockers.extend(cb)
        post = conf.get('POST_SCRIPT', '')
        scheduled = conf.get('POST_SERVICES', '').split()
        # The reversible switch only owns the root script, while the legacy
        # migration must still accept every explicitly allowlisted Warden path.
        if post and WARDEN_RE.search(post) and post not in KNOWN and not self._simple_warden_script_value(post):
            blockers.append('POST_SCRIPT IoT Warden non riconosciuto: controllare manualmente')
        unknown = [x for x in scheduled if WARDEN_RE.search(x) and x not in UNITS]
        if unknown: blockers.append('POST_SERVICES contiene unità Warden non riconosciute')
        cron_blockers, cron_actions = self._scheduled_unknown()
        blockers.extend(cron_blockers)
        # Presence of live chains does not establish program ownership.
        live = []
        for c in CHAIN_NAMES:
            status = self.exec(['iptables', '-w', '-S', c])
            if status.returncode == 0: live.append(c)
        evidence = bool(paths or any(x['loaded'] or x['active'] for x in units) or
                        WARDEN_RE.search(post or '') or any(WARDEN_RE.search(x) for x in scheduled))
        active = bool(any(x['active'] or x['enabled'] for x in units) or
                      WARDEN_RE.search(post or '') or any(WARDEN_RE.search(x) for x in scheduled))
        # Fingerprint excludes live packet counters/timestamps and PII.
        fingerprint_data = {'paths': paths, 'units': units, 'post': post, 'services': scheduled,
                            'blockers': sorted(set(blockers)), 'live': sorted(live), 'cron_actions': cron_actions}
        digest = hashlib.sha256(json.dumps(fingerprint_data, sort_keys=True).encode()).hexdigest()
        return {'ok': True, 'detected': evidence, 'active': active,
                'paths': paths, 'units': units, 'post_script': post if WARDEN_RE.search(post or '') else '',
                'post_services': [x for x in scheduled if WARDEN_RE.search(x)],
                'cron_actions': cron_actions,
                'retirement_backup': self.retirement_record(),
                'retired': bool(self.retirement_record()),
                'live_chains': live, 'blockers': sorted(set(blockers)), 'fingerprint': digest,
                'script_switch': self.script_switch_status(),
                'note': 'Solo risorse riconosciute esplicitamente. Catene live non eliminate: rimuoverle dalla bozza e applicare con watchdog.'}

    def script_switch_status(self):
        """Report only IPTM-managed toggles; executable permission is not a scheduler switch."""
        script = self.path('/root/iot_warden.sh')
        record = self.path('/var/lib/iptables-manager/iot-warden-script-switch.json')
        if script.is_symlink() or (script.exists() and not script.is_file()):
            return {'present': False, 'status': 'unsafe'}
        if not script.exists():
            return {'present': False, 'status': 'absent'}
        if record.is_file() and not record.is_symlink():
            return {'present': True, 'status': 'disabled-by-iptm'}
        return {'present': True, 'status': 'not-managed',
                'note': 'La presenza dello script non prova che sia pianificato.'}

    def switch_script(self, target, fingerprint):
        """Reversible scheduler switch; no script execution, deletion or firewall changes.

        Only the exact known root cron invocation and an exact IPTM POST_SCRIPT
        are managed. Any unrelated activator blocks the operation.
        """
        if target not in ('enable', 'disable'):
            raise ValueError('modalità non valida')
        if not re.fullmatch(r'[a-f0-9]{64}', fingerprint or ''):
            raise ValueError('fingerprint mancante: aggiorna inventario')
        if self.root == Path('/') and os.geteuid() != 0:
            raise ValueError('richiesti privilegi root')
        with self.locked():
            state = self.inventory()
            if state['fingerprint'] != fingerprint:
                raise ValueError('inventario modificato: ricaricare la pagina')
            if state['blockers']:
                raise ValueError('attivatori non riconosciuti: controllare cron e POST_SCRIPT')
            if any(u.get('active') or u.get('enabled') for u in state['units']):
                raise ValueError('unità Warden systemd attiva: gestirla separatamente')
            script = self.path('/root/iot_warden.sh')
            if not script.is_file() or script.is_symlink():
                raise ValueError('/root/iot_warden.sh assente o non regolare')
            self._path_safe(script)
            confpath = self.path('/etc/iptables-manager.conf')
            cronpath = self.path('/var/spool/cron/crontabs/root')
            record = self.path('/var/lib/iptables-manager/iot-warden-script-switch.json')
            originals = {}
            for f in (confpath, cronpath):
                if f.exists():
                    if f.is_symlink() or not f.is_file():
                        raise ValueError('configurazione o crontab non regolare')
                    originals[str(f)] = (f.read_bytes(), stat.S_IMODE(f.stat().st_mode))
            if target == 'disable':
                if record.exists():
                    raise ValueError('script già disattivato da IPTM; non sovrascrivo il backup')
                if not originals:
                    raise ValueError('nessun attivatore cron o POST_SCRIPT rilevato')
                updates = {}
                if confpath.exists():
                    old = originals[str(confpath)][0].decode('utf-8')
                    newlines, found = [], False
                    for line in old.splitlines(keepends=True):
                        match = CONFIG_RE.match(line)
                        if match and match[1] == 'POST_SCRIPT':
                            val = match[2].strip().strip('\"\'')
                            if self._simple_warden_script_value(val):
                                line = 'POST_SCRIPT=""\n'; found = True
                            elif WARDEN_RE.search(val):
                                raise ValueError('POST_SCRIPT personalizzato: revisione manuale')
                        newlines.append(line)
                    if found: updates[confpath] = ''.join(newlines).encode()
                if cronpath.exists():
                    old = originals[str(cronpath)][0].decode('utf-8')
                    changed = False; lines=[]
                    for line in old.splitlines(keepends=True):
                        if WARDEN_RE.search(line) and not line.lstrip().startswith('#'):
                            if not self._simple_warden_cron(line):
                                raise ValueError('cron IoT Warden personalizzato')
                            line = '# IPTM_WARDEN_DISABLED ' + line
                            changed = True
                        lines.append(line)
                    if changed: updates[cronpath] = ''.join(lines).encode()
                if not updates:
                    raise ValueError('nessun attivatore riconosciuto attivo; nulla da disattivare')
                payload = {'format': 'iptm.iot-script-switch.v1', 'target': 'disabled',
                           'files': {str(f.relative_to(self.root)): {
                               'before': originals[str(f)][0].hex(),
                               'mode': originals[str(f)][1],
                               'after_sha256': hashlib.sha256(data).hexdigest()}
                               for f, data in updates.items()}}
                record.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                if record.is_symlink(): raise ValueError('record di controllo non sicuro')
                # Persist rollback data first, then change the known activators.
                self._atomic_text(record, json.dumps(payload), 0o600)
                try:
                    for f, data in updates.items():
                        self._atomic_text(f, data.decode('utf-8'), originals[str(f)][1])
                except Exception:
                    for f in updates:
                        self._atomic_text(f, originals[str(f)][0].decode('utf-8'), originals[str(f)][1])
                    record.unlink(missing_ok=True)
                    raise
                return {'ok': True, 'status': 'disabled', 'changed': len(updates),
                        'note': 'Non esegue lo script e non modifica le catene iptables live.'}
            if not record.is_file() or record.is_symlink():
                raise ValueError('nessun backup IPTM reversibile: non abilito attivatori sconosciuti')
            payload = json.loads(record.read_text(encoding='utf-8'))
            if payload.get('format') != 'iptm.iot-script-switch.v1' or not isinstance(payload.get('files'), dict):
                raise ValueError('record di controllo non valido')
            restored=[]
            for relative, data in payload['files'].items():
                if relative not in ('etc/iptables-manager.conf', 'var/spool/cron/crontabs/root'):
                    raise ValueError('percorso di ripristino non previsto')
                f=self.path('/'+relative)
                if f.is_symlink() or not f.is_file() or hashlib.sha256(f.read_bytes()).hexdigest() != data['after_sha256']:
                    raise ValueError('cron o POST_SCRIPT modificato dopo disattivazione: non sovrascrivo')
                orig=bytes.fromhex(data['before'])
                restored.append((f, orig.decode('utf-8'), int(data['mode'])))
            # Verify entire set before any restore; rollback on I/O failures.
            try:
                for f, raw, mode in restored:
                    self._atomic_text(f, raw, mode)
            except Exception:
                for relative, data in payload['files'].items():
                    f=self.path('/'+relative)
                    if f.exists():
                        current=originals.get(str(f))
                        # Restore the disabled snapshot only when available.
                        if current: self._atomic_text(f, current[0].decode('utf-8'), current[1])
                raise
            record.unlink()
            return {'ok': True, 'status': 'enabled', 'changed': len(restored),
                    'note': 'Ripristinata esclusivamente la pianificazione precedente; nessuna esecuzione immediata.'}

    @contextlib.contextmanager
    def locked(self):
        self.lockpath.parent.mkdir(parents=True, exist_ok=True)
        with self.lockpath.open('a+b') as fp:
            fcntl.flock(fp, fcntl.LOCK_EX | fcntl.LOCK_NB)
            try:
                yield
            finally:
                fcntl.flock(fp, fcntl.LOCK_UN)

    @staticmethod
    def _atomic_text(path, text, mode):
        fd, tmp = tempfile.mkstemp(prefix='.iptm-warden-', dir=str(path.parent))
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as w:
                w.write(text); w.flush(); os.fsync(w.fileno())
            os.chmod(tmp, mode)
            os.replace(tmp, path)
        finally:
            if os.path.exists(tmp): os.unlink(tmp)

    def retire(self, fingerprint):
        if os.geteuid() != 0 and self.root == Path('/'):
            raise ValueError('richiesti privilegi root')
        if not re.fullmatch('[a-f0-9]{64}', fingerprint):
            raise ValueError('fingerprint non valido')
        with self.locked():
            state = self.inventory()
            if not state['detected']:
                raise ValueError('IoT Warden non individuato: nulla da rimuovere')
            if state['fingerprint'] != fingerprint:
                raise ValueError('Inventario IoT Warden cambiato: ripetere anteprima')
            if state['blockers']:
                raise ValueError('Risorse non riconosciute: disattivazione automatica rifiutata')
            if self.backups.is_symlink():
                raise ValueError('Directory archivi IoT Warden con link simbolico: disattivazione annullata')
            self.backups.mkdir(parents=True, exist_ok=True, mode=0o700)
            if self.backups.is_symlink() or not self.backups.is_dir():
                raise ValueError('Directory archivi IoT Warden non sicura')
            os.chmod(self.backups, 0o700)
            ident = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex[:8]
            backup = self.backups / ident
            backup.mkdir(mode=0o700)
            moved, changed_conf, stopped, changed_crons = [], None, [], []
            try:
                # Save snapshot for forensic/manual recovery; do not restore live rules here.
                saved = self.exec(['iptables-save'])
                if saved.returncode == 0:
                    self._atomic_text(backup/'iptables-live.v4', saved.stdout, 0o600)
                # Remove only exact root-crontab commands identified in preview.
                # Keep all unrelated jobs and preserve a copy for rollback.
                for cr in state.get('cron_actions', []):
                    dest=self.path(cr['path'])
                    if dest.is_symlink() or not dest.is_file():
                        raise ValueError('Cron root cambiato o non regolare')
                    raw_cron=dest.read_text(encoding='utf-8')
                    if hashlib.sha256(raw_cron.encode()).hexdigest() != cr['sha256']:
                        raise ValueError('Cron root modificato dopo l’anteprima')
                    lines=raw_cron.splitlines(keepends=True)
                    if not all(i<len(lines) and self._simple_warden_cron(lines[i]) for i in cr['line_indexes']):
                        raise ValueError('Cron Warden modificato dopo l’anteprima')
                    backup_file=backup/'cron-root.orig'
                    shutil.copy2(dest,backup_file)
                    changed_crons.append((dest,backup_file))
                    for i in cr['line_indexes']:
                        lines[i]='# IPTM disabled IoT Warden: '+lines[i]
                    self._atomic_text(dest,''.join(lines),stat.S_IMODE(dest.stat().st_mode))
                for u in state['units']:
                    if u['active'] or u['enabled']:
                        stopped.append(u)  # track even if systemctl partially changes state and returns nonzero
                        self.exec(['systemctl', 'disable', '--now', u['name']], required=True)
                raw, conf, _ = self._conf()
                keys = set()
                if WARDEN_RE.search(conf.get('POST_SCRIPT','')):
                    keys.add('POST_SCRIPT')
                if any(x in UNITS for x in conf.get('POST_SERVICES','').split()):
                    keys.add('POST_SERVICES')
                if keys:
                    dest = self.path('/etc/iptables-manager.conf')
                    shutil.copy2(dest, backup/'iptables-manager.conf')
                    changed_conf = dest
                    rebuilt = []
                    for line in raw.splitlines(keepends=True):
                        m = CONFIG_RE.match(line)
                        if not m or m[1] not in keys:
                            rebuilt.append(line); continue
                        if m[1] == 'POST_SCRIPT': rebuilt.append('POST_SCRIPT=""\n')
                        else:
                            remaining = [x for x in conf['POST_SERVICES'].split() if x not in UNITS]
                            rebuilt.append('POST_SERVICES="'+' '.join(remaining)+'"\n')
                    self._atomic_text(dest, ''.join(rebuilt), stat.S_IMODE(dest.stat().st_mode))
                for entry in state['paths']:
                    src = self.path(entry['path'])
                    # Files may change after preview; recheck type, owner and byte limits.
                    self._path_safe(src)
                    target = backup / 'removed' / entry['path'].lstrip('/')
                    target.parent.mkdir(parents=True, exist_ok=True)
                    if src.is_dir():
                        shutil.copytree(src, target, symlinks=False)
                        moved.append((src, target))  # track before any destructive step
                        shutil.rmtree(src)
                    else:
                        shutil.copy2(src, target)
                        moved.append((src, target))  # track before unlink can fail
                        src.unlink()
                self.exec(['systemctl', 'daemon-reload'], required=bool(moved and any('/systemd/system/' in p['path'] for p in state['paths'])))
                manifest = {'format':'iptm.iot-warden.retired.v1', 'id':ident,
                            'files':[str(p).replace(str(self.root), '/', 1) for p,_ in moved],
                            'units_stopped':stopped, 'modified_iptm_config':bool(changed_conf),
                            'active_chain_names':state['live_chains'], 'cron_disabled':sum(len(c['line_indexes']) for c in state.get('cron_actions', []))}
                self._atomic_text(backup/'manifest.json', json.dumps(manifest, indent=2), 0o600)
                try:
                    self.rotate_retirement_backups(newest=backup)
                except OSError:
                    # Completed retirement must not be rolled back merely because
                    # post-commit housekeeping could not remove old backups.
                    pass
                return {'ok': True, 'backup': str(backup), 'disabled_units':[x['name'] for x in stopped],
                        'quarantined':len(moved), 'post_script_disabled':'POST_SCRIPT' in keys,
                        'cron_disabled':sum(len(c['line_indexes']) for c in state.get('cron_actions', [])),
                        'live_chains_preserved':state['live_chains'],
                        'next_step':'Preparare la pulizia IOT_FW/IOT_DNS nella bozza e applicarla con il watchdog IPTM.'}
            except Exception as ex:
                errors = []
                for source, target in reversed(moved):
                    try:
                        source.parent.mkdir(parents=True, exist_ok=True)
                        if target.is_dir(): shutil.copytree(target, source, dirs_exist_ok=True)
                        else: shutil.copy2(target, source)
                    except Exception as restore_error: errors.append(str(restore_error)[:100])
                for dest, original in reversed(changed_crons):
                    try: shutil.copy2(original, dest)
                    except Exception as restore_error: errors.append(str(restore_error)[:100])
                if changed_conf:
                    try: shutil.copy2(backup/'iptables-manager.conf', changed_conf)
                    except Exception as restore_error: errors.append(str(restore_error)[:100])
                self.exec(['systemctl', 'daemon-reload'])
                for u in stopped:
                    try:
                        if u['enabled']: self.exec(['systemctl','enable',u['name']], required=True)
                        if u['active']: self.exec(['systemctl','start',u['name']], required=True)
                    except Exception as restore_error: errors.append(str(restore_error)[:100])
                raise RuntimeError(f'Disattivazione interrotta: {str(ex)[:180]}; '
                                   + ('ripristino parziale: '+', '.join(errors) if errors else 'risorse ripristinate')) from ex


def main():
    parser = argparse.ArgumentParser(description='IPTM: migration from legacy IoT Warden, no live firewall writes')
    parser.add_argument('action', choices=('inventory','retire','switch'))
    parser.add_argument('fingerprint', nargs='?')
    parser.add_argument('target', nargs='?', choices=('enable','disable'))
    args = parser.parse_args()
    app = Warden()
    if args.action == 'inventory': result = app.inventory()
    elif args.action == 'retire': result = app.retire(args.fingerprint or '')
    elif args.action == 'switch': result = app.switch_script(args.target, args.fingerprint or '')
    else: raise ValueError('azione non valida')
    safe_json(result)
    return 0 if result.get('ok') else 1


if __name__ == '__main__':
    try: sys.exit(main())
    except (OSError, RuntimeError, ValueError) as e:
        safe_json({'ok':False,'error':str(e)[:300]}); sys.exit(2)
