#!/usr/bin/env python3
"""Prepare snapshots containing obsolete dynamic CrowdSec DROP match-sets.

Never mutates live iptables or IPSet. Caller must run iptables-restore --test
on the exact returned bytes. Unknown dependencies remain fatal.
"""
from __future__ import annotations
import json,os,re,shlex,subprocess,sys

MAX_BYTES=2097152
PATTERNS={
    '4':re.compile(r'crowdsec-blacklists(?:-[0-9]{1,3})?\Z'),
    '6':re.compile(r'crowdsec6-blacklists(?:-[0-9]{1,3})?\Z'),
}
class RecoveryError(ValueError):pass


def normalized(snapshot: bytes, installed:set[str], fam:str):
    if fam not in PATTERNS:raise RecoveryError('Famiglia IPv4/IPv6 non valida')
    if not snapshot or len(snapshot)>MAX_BYTES or b'\x00' in snapshot:
        raise RecoveryError('Snapshot di rollback non valido')
    try:text=snapshot.decode('utf-8')
    except UnicodeError as exc:raise RecoveryError('Snapshot non UTF-8') from exc
    result=[];removed=set();table=None;filter_seen=False;commit_seen=False
    for line in text.splitlines(keepends=True):
        stripped=line.strip()
        if stripped.startswith('*'):
            if stripped=='*filter':filter_seen=True
            table=stripped
        elif stripped=='COMMIT':
            commit_seen=True;table=None
        if not stripped.startswith('-A ') or '--match-set' not in stripped:
            result.append(line);continue
        try:parts=shlex.split(stripped,comments=False,posix=True)
        except ValueError as exc:raise RecoveryError('Regola IPSet non interpretabile') from exc
        targets=[];missing=[]
        for i,w in enumerate(parts):
            if w=='--match-set':
                if i+2>=len(parts):raise RecoveryError('Opzioni IPSet incomplete')
                name=parts[i+1]
                if name not in installed:missing.append(name)
            if w=='-j' and i+1<len(parts):targets.append(parts[i+1])
        if not missing:
            result.append(line);continue
        # Do not weaken allow/jump/mangle/NAT rules. Only skip direct DROP to a
        # set which presently has no entries because the whole set disappeared.
        if (table!='*filter' or targets!=['DROP'] or
            not all(PATTERNS[fam].fullmatch(m) for m in missing)):
            raise RecoveryError('IPSet mancante non riconciliabile: '+', '.join(missing[:4]))
        removed.update(missing)
    data=''.join(result).encode('utf-8')
    if not filter_seen or not commit_seen or b':INPUT ' not in data or len(data)<30:
        raise RecoveryError('Snapshot incompleto')
    return data,sorted(removed)


def inventory():
    try:r=subprocess.run(['ipset','list','-name'],capture_output=True,text=True,
                         timeout=8,stdin=subprocess.DEVNULL)
    except (OSError,subprocess.TimeoutExpired) as exc:raise RecoveryError('Inventario IPSet indisponibile') from exc
    if r.returncode:raise RecoveryError('Inventario IPSet non verificabile')
    names=r.stdout.splitlines()
    if len(names)>20000 or any(not re.fullmatch(r'[A-Za-z0-9_.:-]{1,31}',n) for n in names):
        raise RecoveryError('Inventario IPSet non attendibile')
    return set(names)


def main():
    if os.geteuid()!=0 or len(sys.argv)!=2 or sys.argv[1] not in PATTERNS:
        raise RecoveryError('Uso: root firewall_recovery.py 4|6')
    raw=sys.stdin.buffer.read(MAX_BYTES+1)
    if len(raw)>MAX_BYTES:raise RecoveryError('Snapshot troppo grande')
    prepared,pruned=normalized(raw,inventory() if b'--match-set' in raw else set(),sys.argv[1])
    if pruned:sys.stderr.write('IPTM recovery: esclusi DROP CrowdSec per set non presenti: '+', '.join(pruned)+'\n')
    sys.stdout.buffer.write(prepared)

if __name__=='__main__':
    try:main()
    except RecoveryError as exc:
        print('IPTM rollback: '+str(exc),file=sys.stderr);sys.exit(1)
