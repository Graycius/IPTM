#!/usr/bin/env python3
"""IPTM 5.30.1 — installazione iniziale conservativa per DietPi/Debian.

Non configura/ripristina iptables, DHCP, NAT, routing o resolver; non avvia
servizi di rete. Una Web UI PHP già operativa è un prerequisito.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import grp
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import tokenize

VERSION = "5.30.1"
BASE = Path(__file__).resolve().parent
SOURCE = BASE / "source"
ROOT_LIB = Path("/usr/local/lib/iptables-manager")
RELEASE = ROOT_LIB / "web/releases" / VERSION
HELPER = Path("/usr/local/sbin/iptm-helper")
CONFIG = Path("/etc/iptables-manager.conf")
DATA = Path("/var/lib/iptables-manager")
RECOVERY_DATA = Path("/var/lib/iptm-update-recovery")
RECOVERY = ROOT_LIB / "iptm-update-rescue.py"
UNIT = Path("/etc/systemd/system/iptm-update-recover.service")
RUNTIME_DEST = {
    "runtime/iptm-helper": HELPER,
    "runtime/iptm-maintenance.py": ROOT_LIB / "iptm-maintenance.py",
    "runtime/iptm-traffic-av.py": ROOT_LIB / "iptm-traffic-av.py",
    "runtime/iptm-security.py": ROOT_LIB / "iptm-security.py",
    "runtime/iptm-iot-warden.py": ROOT_LIB / "iptm-iot-warden.py",
    "runtime/iptm-dns-bundle.py": ROOT_LIB / "iptm-dns-bundle.py",
    "runtime/iptm-crowdsec-audit.py": ROOT_LIB / "iptm-crowdsec-audit.py",
}
ALLOWED_REL = re.compile(
    r"(?:modules/[0-9]{2}_[a-z0-9_]+\.php|actions/[a-z_]+\.php|"
    r"assets/[a-z]+\.(?:css|js)|extensions/[a-z0-9_]+\.py|"
    r"runtime/iptm-[a-z-]+(?:\.py)?|loader/iptables-manager\.php|CHANGELOG\.md)\Z"
)

class InstallError(Exception):
    pass


def need(ok, msg):
    if not ok:
        raise InstallError(msg)


def run(argv, timeout=30):
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as ex:
        raise InstallError(f"Comando non eseguibile: {argv[0]} ({type(ex).__name__})") from ex
    if r.returncode:
        raise InstallError(f"{argv[0]} non ha superato la verifica: {(r.stderr or r.stdout)[-400:].strip()}")
    return r.stdout.strip()


def check_source():
    need(SOURCE.is_dir() and not SOURCE.is_symlink(), "Sorgenti mancanti")
    manifest_file = SOURCE / "native-manifest.json"
    need(manifest_file.is_file() and not manifest_file.is_symlink(), "Manifest assente")
    meta = json.loads(manifest_file.read_bytes())
    need(meta.get("format") == "iptm-native" and meta.get("schema") == 1
         and meta.get("version") == VERSION and isinstance(meta.get("sha256"), dict),
         "Manifest Native Update incompatibile")
    checks = meta["sha256"]
    need(len(checks) >= 100, "Pacchetto nativo incompleto")
    allowed = set(checks) | {"native-manifest.json"}
    entries = {x.relative_to(SOURCE).as_posix() for x in SOURCE.rglob("*") if x.is_file() or x.is_symlink()}
    need(entries == allowed, f"File non previsti o mancanti: {sorted(entries ^ allowed)[:5]}")
    for rel, sha in checks.items():
        need(isinstance(rel, str) and ALLOWED_REL.fullmatch(rel) is not None,
             f"Percorso non valido: {rel}")
        need(isinstance(sha, str) and re.fullmatch(r"[a-f0-9]{64}", sha), "Hash malformato")
        path = SOURCE / rel
        need(path.is_file() and not path.is_symlink() and path.stat().st_size <= 900_000,
             f"File non sicuro: {rel}")
        need(hashlib.sha256(path.read_bytes()).hexdigest() == sha,
             f"File alterato: {rel}")
    loader = (SOURCE / "loader/iptables-manager.php").read_text()
    helper = (SOURCE / "runtime/iptm-helper").read_text()
    need(f"/web/releases/{VERSION}" in loader and f"APP_VERSION = '{VERSION}'" in loader,
         "Loader di versione non corrispondente")
    need(f"# iptm-helper v{VERSION} " in helper, "Helper di versione non corrispondente")
    need(set(RUNTIME_DEST).issubset(checks), "Helper e runtime incompleti")
    return checks


def check_syntax():
    need(shutil.which("php") is not None and shutil.which("bash") is not None,
         "Mancano PHP CLI e/o Bash")
    php_ok = run(["php", "-r", 'exit(PHP_VERSION_ID >= 80000 ? 0 : 1);'])
    for php in list((SOURCE / "modules").glob("*.php")) + list((SOURCE / "actions").glob("*.php")) + list((SOURCE / "loader").glob("*.php")):
        run(["php", "-l", str(php)])
    for py in list((SOURCE / "extensions").glob("*.py")) + list((SOURCE / "runtime").glob("*.py")):
        try:
            with tokenize.open(py) as src:
                compile(src.read(), str(py), "exec", dont_inherit=True)
        except (SyntaxError, OSError, UnicodeError) as ex:
            raise InstallError(f"Sintassi Python non valida: {py.name}") from ex
    run(["bash", "-n", str(SOURCE / "runtime/iptm-helper")])


def unit_text():
    return """[Unit]
Description=IPTM - ripristino aggiornamento interrotto
DefaultDependencies=no
After=local-fs.target
Before=network-pre.target
ConditionPathExists=/var/lib/iptm-update-recovery/pending.json

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 -B /usr/local/lib/iptables-manager/iptm-update-rescue.py update-recovery recover --state /var/lib/iptm-update-recovery

[Install]
WantedBy=multi-user.target
"""


class Installer:
    def __init__(self, webroot, webuser, root, dry_run):
        self.simulate = root != Path("/")
        self.root = root
        self.webroot = webroot
        self.webuser = webuser
        self.dry_run = dry_run
        self.files = []
        self.dirs = []
        self.service_enabled = False
        self.reload_needed = False
        self.uid, self.gid = (-1, -1)
        self.web = webroot / "iptables-manager.php"
        self.sudoers = Path("/etc/sudoers.d/90-iptm")

    def p(self, virtual):
        return self.root / str(virtual).lstrip("/")

    def safe_path(self, virtual, need_existing=False):
        # Reject dangerous symlink parents for any privileged write.
        path = self.p(virtual)
        cursor = self.root
        for part in Path(str(virtual).lstrip("/")).parts:
            cursor = cursor / part
            if cursor.is_symlink():
                raise InstallError(f"Link simbolico vietato: {cursor}")
        if need_existing:
            need(path.is_dir(), f"Directory richiesta assente: {virtual}")
        return path

    def directory(self, virtual, mode=0o755, uid=None, gid=None):
        path = self.safe_path(virtual)
        to_create = []
        cursor = path
        while not cursor.exists():
            to_create.append(cursor)
            cursor = cursor.parent
        for item in reversed(to_create):
            if not self.dry_run:
                item.mkdir(mode=mode if item == path else 0o755)
                self.dirs.append(item)
        if not self.dry_run and to_create and uid is not None:
            os.chown(path, uid, gid)
        if not self.dry_run and to_create:
            path.chmod(mode)
        return path

    def write(self, virtual, content, mode=0o644, uid=None, gid=None):
        path = self.safe_path(virtual)
        need(not path.exists() and not path.is_symlink(), f"File già presente, non sovrascritto: {virtual}")
        if self.dry_run:
            return
        need(path.parent.is_dir(), f"Directory destinazione non disponibile: {virtual}")
        fd, tmpname = tempfile.mkstemp(prefix=".iptm-install-", dir=path.parent)
        try:
            with os.fdopen(fd, "wb") as f:
                os.fchmod(f.fileno(), mode)
                f.write(content)
                f.flush()
                os.fsync(f.fileno())
            if uid is not None:
                os.chown(tmpname, uid, gid)
            os.replace(tmpname, path)
            self.files.append(path)
        finally:
            if os.path.lexists(tmpname):
                os.unlink(tmpname)

    def preflight(self, hashes):
        need(self.simulate or os.geteuid() == 0, "Eseguire con sudo/root")
        need(self.webroot.is_absolute() and not any(x in (".", "..") for x in self.webroot.parts),
             "Web root deve essere un percorso assoluto sicuro")
        need(re.fullmatch(r"/[A-Za-z0-9._/-]{1,200}", str(self.webroot)) is not None,
             "Web root contiene caratteri non consentiti")
        need(re.fullmatch(r"[a-z_][a-z0-9_-]{0,30}\Z", self.webuser) is not None,
             "Utente web non valido")
        if self.simulate:
            self.uid, self.gid = os.getuid(), os.getgid()
            self.directory(self.webroot)
            self.directory(Path("/etc/sudoers.d"))
            self.directory(Path("/etc/systemd/system"))
            self.directory(Path("/usr/local/sbin"))
        else:
            u = pwd.getpwnam(self.webuser)
            self.uid, self.gid = u.pw_uid, u.pw_gid
            for name in ("sudo", "visudo", "iptables-save", "iptables-restore", "ip", "systemctl"):
                need(shutil.which(name) is not None, f"Dipendenza mancante: {name}")
            need(Path("/run/systemd/system").is_dir(), "Systemd non attivo")
            need(self.safe_path(self.webroot, True).stat().st_uid == 0,
                 "Document root non di root: usare una directory protetta")
            need(not self.safe_path(self.webroot).stat().st_mode & 0o022,
                 "Document root scrivibile da gruppo/altri")
            need(self.safe_path(Path("/etc/sudoers.d"), True).stat().st_uid == 0,
                 "sudoers.d non protetta")
            need(Path("/etc/sudoers.d").stat().st_mode & 0o022 == 0,
                 "sudoers.d scrivibile da terzi")
            # No install into privileged trees with insecure pre-existing permissions.
            for privileged in (ROOT_LIB, ROOT_LIB / "web", ROOT_LIB / "web/releases",
                               HELPER.parent, UNIT.parent, CONFIG.parent):
                checked = self.safe_path(privileged)
                if checked.exists():
                    st = checked.stat()
                    need(checked.is_dir() and st.st_uid == 0 and st.st_mode & 0o022 == 0,
                         f"Directory privilegiata non protetta: {privileged}")
        all_file_paths = [self.web, self.sudoers, UNIT, CONFIG, RECOVERY] + list(RUNTIME_DEST.values())
        need(not any(self.p(x).exists() or self.p(x).is_symlink() for x in all_file_paths),
             "IPTM o una sua configurazione sono già presenti: usare Native Update per aggiornare")
        need(not self.safe_path(RELEASE).exists(), "Release già presente: usare Native Update")
        data = self.safe_path(DATA)
        need(not data.exists(), "Directory dati già presente: installazione esistente da preservare")
        rec = self.safe_path(RECOVERY_DATA)
        need(not rec.exists(), "Journal di recovery già presente")
        sudo_line = f"# IPTM - helper privilegiato; solo l'utente web\n{self.webuser} ALL=(root) NOPASSWD: /usr/local/sbin/iptm-helper *\n"
        if not self.simulate:
            with tempfile.NamedTemporaryFile("w", dir="/tmp", prefix="iptm-sudoers-", delete=False) as f:
                trial = f.name
                f.write(sudo_line)
            try:
                os.chmod(trial, 0o440)
                run(["visudo", "-cf", trial])
            finally:
                os.unlink(trial)
        return sudo_line

    def install(self, checks):
        sudo_line = self.preflight(checks)
        if self.dry_run:
            print(f"OK verifiche; installazione prevista: {self.web}, {RELEASE}, helper, sudoers, recovery")
            return
        try:
            self.directory(ROOT_LIB)
            self.directory(ROOT_LIB / "web/releases")
            self.directory(RELEASE)
            for sub in ("modules", "actions", "assets", "extensions"):
                self.directory(RELEASE / sub)
            content_checks = {}
            for rel, expected in checks.items():
                if rel.startswith(("modules/", "actions/", "assets/", "extensions/")):
                    self.write(RELEASE / rel, (SOURCE / rel).read_bytes())
                    content_checks[rel] = expected
            release_manifest = json.dumps({"version": VERSION, "sha256": content_checks}, sort_keys=True, separators=(",", ":")).encode() + b"\n"
            self.write(RELEASE / "native-manifest.json", release_manifest)
            for rel, target in RUNTIME_DEST.items():
                self.write(target, (SOURCE / rel).read_bytes(), mode=0o755 if rel.endswith("iptm-helper") else 0o644)
            # Stabile: l'updater aggiorna maintenance.py, ma non questo rescue indipendente.
            self.write(RECOVERY, (SOURCE / "runtime/iptm-maintenance.py").read_bytes())
            self.directory(RECOVERY_DATA, mode=0o700)
            self.directory(DATA, mode=0o700, uid=self.uid, gid=self.gid)
            self.write(CONFIG, b"# IPTM: configurazione privilegiata. Nessuna opzione di rete attivata.\n", mode=0o600)
            self.write(DATA / "setup-token.txt", (secrets.token_hex(16) + "\n").encode(), mode=0o600, uid=self.uid, gid=self.gid)
            self.write(self.web, (SOURCE / "loader/iptables-manager.php").read_bytes())
            self.write(self.sudoers, sudo_line.encode(), mode=0o440)
            self.write(UNIT, unit_text().encode())
            if not self.simulate:
                run(["visudo", "-cf", str(self.p(self.sudoers))])
                run([str(self.p(HELPER)), "version"])
                run([str(self.p(HELPER)), "ping"], timeout=90)
                run(["sudo", "-u", self.webuser, "sudo", "-n", str(HELPER), "version"], timeout=15)
                run(["systemctl", "daemon-reload"])
                self.reload_needed = True
                run(["systemctl", "enable", "iptm-update-recover.service"])
                self.service_enabled = True
            print("INSTALLAZIONE COMPLETATA — IPTM " + VERSION)
            print(f"Pagina: {self.web} (aprire /iptables-manager.php sulla porta del web server esistente)")
            print("Primo accesso: admin; leggere il codice con: sudo cat " + str(DATA / "setup-token.txt"))
            print("Nessuna regola firewall, impostazione DNS o servizio di rete modificato.")
        except BaseException:
            # Installazione fresh only: tutti i file installati sono nuovi e tracciati.
            self.rollback()
            raise

    def rollback(self):
        if self.service_enabled and not self.simulate:
            subprocess.run(["systemctl", "disable", "iptm-update-recover.service"], timeout=20, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        for item in reversed(self.files):
            try:
                if item.is_file() and not item.is_symlink():
                    item.unlink()
            except OSError:
                print(f"ATTENZIONE: file da verificare dopo errore: {item}", file=sys.stderr)
        for item in reversed(self.dirs):
            try:
                item.rmdir()
            except OSError:
                pass
        if self.reload_needed and not self.simulate:
            subprocess.run(["systemctl", "daemon-reload"], timeout=20, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


def main():
    ap = argparse.ArgumentParser(description="Prima installazione IPTM 5.30.1")
    ap.add_argument("--web-root", default="/var/www/html", help="Document root già servita da PHP")
    ap.add_argument("--web-user", default="www-data", help="Utente PHP della console")
    ap.add_argument("--dry-run", action="store_true", help="Verifica senza modificare il sistema")
    ap.add_argument("--test-root", help=argparse.SUPPRESS)
    a = ap.parse_args()
    try:
        need(not SOURCE.is_symlink(), "Sorgenti non sicuri")
        hashes = check_source()
        check_syntax()
        root = Path(a.test_root).resolve() if a.test_root else Path("/")
        need(root != Path("/") or not a.test_root, "test-root non può essere /")
        Installer(Path(a.web_root), a.web_user, root, a.dry_run).install(hashes)
    except (InstallError, OSError, ValueError, KeyError, RuntimeError) as ex:
        print("IPTM install: " + str(ex), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
