#!/usr/bin/env python3
"""Prepare an IPTM rollback snapshot without touching the kernel.

Only removes an obsolete *direct DROP* rule referring to a provably absent
CrowdSec IPSet. Never creates empty sets, rewrites foreign rules or accepts a
missing non-CrowdSec dependency. The caller MUST run iptables-restore --test
against the exact returned bytes before attempting the restore.
"""
from __future__ import annotations

import os
import re
import shlex
import subprocess
import sys

MAX_RULES = 2 * 1024 * 1024
CROWDSEC4 = re.compile(r"crowdsec-blacklists(?:-[0-9]{1,3})?\Z")
CROWDSEC6 = re.compile(r"crowdsec6-blacklists(?:-[0-9]{1,3})?\Z")


class RecoveryError(ValueError):
    """A rollback dependency cannot be reconciled automatically."""


def reconcile(snapshot: bytes, installed: set[str], family: str) -> tuple[bytes, list[str]]:
    if family not in ("4", "6"):
        raise RecoveryError("famiglia IPv4/IPv6 non valida")
    if not snapshot or len(snapshot) > MAX_RULES or b"\0" in snapshot:
        raise RecoveryError("snapshot assente, troppo grande o binario")
    try:
        lines = snapshot.decode("utf-8").splitlines(keepends=True)
    except UnicodeError as exc:
        raise RecoveryError("snapshot non UTF-8") from exc

    missing_re = CROWDSEC6 if family == "6" else CROWDSEC4
    table = None
    kept: list[str] = []
    skipped: list[str] = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("*"):
            table = stripped
        elif stripped == "COMMIT":
            table = None
        if not stripped.startswith("-A "):
            kept.append(line)
            continue
        if "--match-set" not in stripped:
            kept.append(line)
            continue
        try:
            words = shlex.split(stripped, comments=False, posix=True)
        except ValueError as exc:
            raise RecoveryError("sintassi snapshot IPSet malformata") from exc
        missing: list[str] = []
        for i, word in enumerate(words):
            if word != "--match-set":
                continue
            if i + 2 >= len(words):
                raise RecoveryError("IPSet incompleto nello snapshot")
            name = words[i + 1]
            if name not in installed:
                missing.append(name)
        if not missing:
            kept.append(line)
            continue
        # Only a dead CrowdSec drop can be removed. These absent IPsets have no
        # live members; all other chains, jumps and policy defaults are retained.
        target = [words[i + 1] for i, w in enumerate(words[:-1]) if w == "-j"]
        if (table != "*filter" or len(target) != 1 or target[0] != "DROP"
                or not all(missing_re.fullmatch(name) for name in missing)):
            raise RecoveryError("set IPSet mancante non riconciliabile: " + ", ".join(missing[:5]))
        skipped.extend(missing)
    # Rebuild in a second pass to keep the original bytes of every retained line.
    # Duplicate line bodies are not used as keys: identical rules may be intentional.
    table = None
    out: list[str] = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("*"):
            table = stripped
        elif stripped == "COMMIT":
            table = None
        if table == "*filter" and stripped.startswith("-A ") and "--match-set" in stripped:
            words = shlex.split(stripped, comments=False, posix=True)
            absent = [words[i + 1] for i, w in enumerate(words[:-2])
                      if w == "--match-set" and words[i + 1] not in installed]
            if absent:
                # The first pass already verified every missing dependency.
                continue
        out.append(line)
    result = "".join(out).encode("utf-8")
    if not result.strip() or b"*filter" not in result or b"COMMIT" not in result:
        raise RecoveryError("snapshot incompleto dopo riconciliazione")
    return result, sorted(set(skipped))


def kernel_ipsets() -> set[str]:
    try:
        proc = subprocess.run(["ipset", "list", "-name"], capture_output=True,
                              check=False, timeout=8, text=True, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RecoveryError("inventario IPSet indisponibile; rollback non modificato") from exc
    if proc.returncode:
        raise RecoveryError("inventario IPSet fallito; rollback non modificato")
    names = proc.stdout.splitlines()
    if len(names) > 20000 or any(not re.fullmatch(r"[A-Za-z0-9_.:-]{1,31}", n) for n in names):
        raise RecoveryError("inventario IPSet non attendibile")
    return set(names)


def main() -> int:
    if os.geteuid() != 0 or len(sys.argv) != 2:
        raise RecoveryError("uso root: firewall_recovery.py 4|6")
    snapshot = sys.stdin.buffer.read(MAX_RULES + 1)
    if not snapshot or len(snapshot) > MAX_RULES:
        raise RecoveryError("snapshot non valido")
    present = kernel_ipsets() if b"--match-set" in snapshot else set()
    prepared, removed = reconcile(snapshot, present, sys.argv[1])
    if removed:
        sys.stderr.write("IPTM rollback: riferimenti DROP CrowdSec obsoleti esclusi: "
                         + ", ".join(removed) + "\n")
    sys.stdout.buffer.write(prepared)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except RecoveryError as exc:
        print("IPTM rollback preflight: " + str(exc), file=sys.stderr)
        sys.exit(1)
