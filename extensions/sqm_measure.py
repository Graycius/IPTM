#!/usr/bin/env python3
"""IPTM: bounded, read-only, two-way throughput measurement.

Never produces a numeric sample unless BOTH directions came from a completed
measurement by the same engine. Detailed raw speedtest output (including IPs)
never reaches the journal or web interface.
"""
from __future__ import annotations

import json
import re
import pathlib
import math
import socket
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Callable

OOKLA_TIMEOUT = 92
MAX_JSON_BYTES = 1048576


class SampleError(ValueError):
    pass


@dataclass(frozen=True)
class Sample:
    method: str
    down_mbit: int
    up_mbit: int
    latency_idle_ms: float = -1
    latency_down_ms: float = -1
    latency_up_ms: float = -1


def _metric(value):
    try:
        if isinstance(value, dict):
            value = value.get('iqm', -1)
        x = float(value)
        return round(x, 1) if math.isfinite(x) and 0 <= x <= 5000 else -1
    except (ValueError, TypeError):
        return -1


def _num(value, field):
    try:
        number = float(value)
    except (ValueError, TypeError):
        raise SampleError(field + '-missing')
    if not math.isfinite(number) or number <= 0:
        raise SampleError(field + '-zero')
    return number


def parse_response(payload: str, method: str) -> Sample:
    if len(payload.encode('utf-8', errors='replace')) > MAX_JSON_BYTES:
        raise SampleError('json-too-large')
    try:
        data = json.loads(payload)
    except (json.JSONDecodeError, UnicodeError):
        raise SampleError('invalid-json')
    if not isinstance(data, dict):
        raise SampleError('invalid-json')
    if method == 'ookla':
        if data.get('type') == 'error' or data.get('error'):
            raise SampleError('engine-error')
        download, upload = data.get('download', {}), data.get('upload', {})
        down = _num(download.get('bandwidth') if isinstance(download, dict) else None, 'download') * 8 / 1e6
        up = _num(upload.get('bandwidth') if isinstance(upload, dict) else None, 'upload') * 8 / 1e6
        ping = data.get('ping', {})
        return _sample('ookla', down, up,
                       _metric(ping.get('latency', -1)) if isinstance(ping, dict) else -1,
                       _metric(download.get('latency', -1)) if isinstance(download, dict) else -1,
                       _metric(upload.get('latency', -1)) if isinstance(upload, dict) else -1)
    raise SampleError('unsupported-engine')


def _sample(method, down, up, idle, lat_down, lat_up):
    # Do not round sub-megabit upload to zero and present it as a valid result.
    # Such results are not useful for calibrating Mbit/s CAKE profiles.
    if down < 1: raise SampleError('download-below-1mbit')
    if up < 1: raise SampleError('upload-below-1mbit')
    if down > 100000 or up > 100000: raise SampleError('out-of-range')
    return Sample(method, round(down), round(up), idle, lat_down, lat_up)


def _run(argv, timeout_seconds, runner: Callable = subprocess.run):
    try:
        result = runner(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        text=True, timeout=timeout_seconds, check=False)
    except subprocess.TimeoutExpired:
        return None, 'timeout'
    except (OSError, ValueError):
        return None, 'execution-error'
    if result.returncode != 0:
        return None, 'exit-' + str(min(abs(result.returncode), 255))
    if not result.stdout.strip():
        return None, 'empty-output'
    return result.stdout, ''


def is_ookla_binary(path: str) -> bool:
    """Accept only a native Linux executable, not a command-name-compatible script.

    Debian/Python wrappers may also be installed as ``speedtest`` and implement
    incompatible JSON formats. A non-native wrapper is not an eligible engine.
    The measured result must still pass the strict Ookla JSON parser.
    """
    try:
        resolved = pathlib.Path(path).resolve(strict=True)
        if not resolved.is_file():
            return False
        with resolved.open('rb') as binary:
            return binary.read(4) == b'\x7fELF'
    except (OSError, ValueError, RuntimeError):
        return False


def measure(which: Callable = shutil.which, runner: Callable = subprocess.run):
    """Run only the existing official Ookla CLI. Never downgrade to another engine."""
    path = which('speedtest')
    if not path:
        return None, ['ookla:not-installed']
    if not is_ookla_binary(path):
        return None, ['ookla:not-official-binary']
    payload, failure = _run([path, '--accept-license', '--accept-gdpr', '--format=json'],
                            OOKLA_TIMEOUT, runner)
    if failure:
        return None, ['ookla:' + failure]
    try:
        return parse_response(payload, 'ookla'), []
    except SampleError as exc:
        return None, ['ookla:' + str(exc)]


def cpu_core_counters():
    try:
        counters = {}
        for line in pathlib.Path('/proc/stat').read_text().splitlines():
            fields = line.split()
            if not fields or not fields[0].startswith('cpu') or not fields[0][3:].isdigit():
                continue
            values = [int(x) for x in fields[1:]]
            counters[fields[0]] = (sum(values), values[3] + values[4])
        return counters
    except (OSError, ValueError, IndexError):
        return {}


def cpu_peak_load(before, after):
    loads = []
    for name, (total, idle) in before.items():
        if name not in after:
            continue
        dt, di = after[name][0] - total, after[name][1] - idle
        if dt > 0 and 0 <= di <= dt:
            loads.append(round((dt - di) * 100 / dt))
    return max(loads) if loads else -1


def engine_check(which: Callable = shutil.which, runner: Callable = subprocess.run):
    """Read-only check of the official Ookla binary and HTTPS connectivity.

    Does not execute a bandwidth test or disclose IP/server/stderr details.
    """
    path = which('speedtest')
    if not path:
        print('ookla=missing')
    elif not is_ookla_binary(path):
        print('ookla=not-official-binary')
    else:
        try:
            result = runner([path, '--version'], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, timeout=5, check=False)
            ok = result.returncode == 0 and 'ookla' in result.stdout.lower()
            print('ookla=ready' if ok else 'ookla=version-check-failed')
        except (OSError, ValueError, subprocess.TimeoutExpired):
            print('ookla=execution-failed')
    try:
        with socket.create_connection(('www.speedtest.net', 443), timeout=4):
            print('network443=reachable')
    except (OSError, ValueError):
        print('network443=unreachable')
    print('note=connectivity-check-is-not-a-bandwidth-test')
    return 0


def main():
    before = cpu_core_counters()
    sample, failures = measure()
    cpu_load = cpu_peak_load(before, cpu_core_counters())
    if sample is None:
        # Only allowlisted reason codes; no raw upstream output is stored.
        print('failure=' + ','.join(failures), file=sys.stdout)
        print('err speedtest: nessuna misurazione bidirezionale completa', file=sys.stderr)
        return 69
    for key, value in (
        ('method', sample.method), ('down_mbit', sample.down_mbit),
        ('up_mbit', sample.up_mbit), ('ts', int(time.time())),
        ('latency_idle_ms', sample.latency_idle_ms),
        ('latency_down_ms', sample.latency_down_ms),
        ('latency_up_ms', sample.latency_up_ms),
        ('cpu_busy_pct', cpu_load),
    ):
        print(f'{key} {value}')
    return 0


# V2 deliberately observes the kernel without changing qdisc, ingress, IFB or filters.
# All mutating operations remain disabled until a separate guarded migration.
def _tc_json(argv, runner=subprocess.run):
    try:
        p = runner(['tc', '-j'] + argv, stdout=subprocess.PIPE,
                   stderr=subprocess.DEVNULL, text=True, timeout=4, check=False)
        if p.returncode or len(p.stdout)>262144: return None
        value=json.loads(p.stdout)
        return value if isinstance(value,list) else None
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None


def _interface_ok(name):
    return isinstance(name,str) and bool(re.fullmatch(r'[a-zA-Z0-9_.-]{1,15}',name)) and name not in ('.','..')


def _cake_root(rows):
    if rows is None: return 'read-error', None
    cakes=[r for r in rows if isinstance(r,dict) and r.get('kind')=='cake'
           and (r.get('parent')=='root' or r.get('root') is True)]
    if len(cakes)!=1:return ('missing' if not cakes else 'ambiguous'),None
    opts=cakes[0].get('options') or {}
    if not isinstance(opts,dict):opts={}
    return 'ok',opts


def _ingress_present(rows):
    if rows is None:return 'read-error'
    return 'ok' if any(isinstance(r,dict) and r.get('kind') in ('ingress','clsact') for r in rows) else 'missing'


def _redirect_present(rows, ifb):
    """Fail-closed inspection of tc JSON mirred redirect actions.

    Never accept a destination based on an incidental substring in JSON (e.g.
    'ifb-sqm-backup' or an unrelated diagnostic field).
    """
    if rows is None:
        return 'read-error'
    matches = 0
    conflicting = False
    for row in rows:
        if not isinstance(row, dict):
            continue
        opts = row.get('options')
        if not isinstance(opts, dict):
            continue
        actions = opts.get('actions', [])
        if isinstance(actions, dict):
            actions = [actions]
        if not isinstance(actions, list):
            continue
        for action in actions:
            if not isinstance(action, dict):
                continue
            detail = action.get('options') if isinstance(action.get('options'), dict) else action
            if action.get('kind', detail.get('kind')) != 'mirred':
                continue
            direction = detail.get('eaction', detail.get('mode', detail.get('action', '')))
            if direction not in ('redirect', 'egress redirect', 'egress_redirect'):
                continue
            destination = detail.get('to_dev', detail.get('dev', detail.get('ifname')))
            if destination == ifb:
                matches += 1
            elif destination is not None:
                conflicting = True
    if conflicting or matches > 1:
        return 'ambiguous'
    return 'ok' if matches == 1 else 'missing'


def _rate_mbit(options):
    value=options.get('bandwidth') or options.get('bandwidth_rate')
    if isinstance(value,(float,int)) and 0<value<1e12:
        # The tc JSON representation may use bit/s, not Mbit/s.
        return round(value/1e6,3)
    if isinstance(value,str):
        match=re.fullmatch(r'([0-9]+(?:\.[0-9]+)?)([kmg]?)(?:bit|bps)?',value.strip(),re.I)
        if match:
            return round(float(match.group(1))*{'':1e-6,'k':1e-3,'m':1,'g':1000}[match.group(2).lower()],3)
    return None


def sqm_v2_observe(iface, ifb='ifb-sqm', query=_tc_json):
    if not _interface_ok(iface) or not _interface_ok(ifb):raise SampleError('invalid-interface')
    wan,wan_opts=_cake_root(query(['qdisc','show','dev',iface]))
    ingress=_ingress_present(query(['qdisc','show','dev',iface]))
    ifb_status,ifb_opts=_cake_root(query(['qdisc','show','dev',ifb]))
    filters=query(['filter','show','dev',iface,'ingress'])
    if filters is None:
        # Compatible with old ingress ffff: (JSON implementations may omit ingress alias).
        filters=query(['filter','show','dev',iface,'parent','ffff:'])
    redirect=_redirect_present(filters,ifb)
    status={ 'interface':iface,'ifb':ifb,'wan_cake':wan,'ingress':ingress,
             'ifb_cake':ifb_status,'redirect':redirect,
             'upload_mbit':_rate_mbit(wan_opts or {}),'download_mbit':_rate_mbit(ifb_opts or {}) }
    status['verified']=all(status[k]=='ok' for k in ('wan_cake','ingress','ifb_cake','redirect'))
    status['mode']='read-only'
    status['reason']=('verified' if status['verified'] else 'topology-incomplete-or-ambiguous')
    return status


def sqm_v2_propose(saved_down,saved_up,measured_down,measured_up,quality,margin=0.92):
    # An observation taken under shaping is not a baseline; NEVER feed it back.
    previous=(int(saved_down),int(saved_up))
    if any(x<1 for x in previous) or quality!='unshaped-two-way-verified':
        return {'action':'keep','down_mbit':max(0,previous[0]),'up_mbit':max(0,previous[1]),'reason':'unverified-baseline'}
    if not all(isinstance(x,(float,int)) and math.isfinite(x) and x>=1 for x in (measured_down,measured_up)):
        return {'action':'keep','down_mbit':previous[0],'up_mbit':previous[1],'reason':'incomplete-measurement'}
    candidate=(int(measured_down*margin),int(measured_up*margin))
    if any(a<b for a,b in zip(candidate,previous)):
        return {'action':'keep','down_mbit':previous[0],'up_mbit':previous[1],'reason':'performance-regression'}
    if candidate==previous:
        return {'action':'keep','down_mbit':previous[0],'up_mbit':previous[1],'reason':'same-profile'}
    return {'action':'proposal-only','down_mbit':candidate[0],'up_mbit':candidate[1],
            'reason':'requires-explicit-trial-and-confirmation'}


def sqm_v2_cli(argv):
    if len(argv)==2 and argv[0]=='status':
        try:print(json.dumps(sqm_v2_observe(argv[1]),sort_keys=True))
        except SampleError as exc:
            print(json.dumps({'error':str(exc)}));return 2
        return 0
    print('usage: sqm_measure.py --v2 status INTERFACE',file=sys.stderr)
    return 2



def sqm_v3_observe(iface, query=_tc_json):
    """Unified, fail-closed, kernel-only QoS audit. Does not modify qdiscs.

    Avoid assuming an IFB name based on an unrelated interface, or silently
    adopting qdiscs owned by NetworkManager, systemd or a second SQM worker.
    """
    if not _interface_ok(iface):raise SampleError('invalid-interface')
    root_rows=query(['qdisc','show','dev',iface])
    if root_rows is None:return {'verified':False,'reason':'tc-json-unavailable','interface':iface,'mode':'read-only'}
    # The GUI reports foreign qdisc ownership as unknown, never IPTM-owned.
    roots=[r for r in root_rows if isinstance(r,dict) and (r.get('root') is True or r.get('parent')=='root')]
    if len(roots)!=1:
        return {'verified':False,'reason':'root-qdisc-ambiguous','interface':iface,'roots':len(roots),'mode':'read-only'}
    ingress=[r for r in root_rows if isinstance(r,dict) and r.get('kind') in ('ingress','clsact')]
    filters=query(['filter','show','dev',iface,'ingress'])
    if filters is None:filters=query(['filter','show','dev',iface,'parent','ffff:'])
    if filters is None:return {'verified':False,'reason':'filter-json-unavailable','interface':iface,'root_kind':roots[0].get('kind'),'mode':'read-only'}
    targets=set()
    for row in filters:
        if not isinstance(row,dict):continue
        opts=row.get('options') or {}
        if not isinstance(opts,dict):continue
        acts=opts.get('actions') or []
        if isinstance(acts,dict):acts=[acts]
        for action in acts:
            if not isinstance(action,dict):continue
            d=action.get('options') if isinstance(action.get('options'),dict) else action
            if action.get('kind',d.get('kind'))!='mirred':continue
            if d.get('eaction',d.get('mode',d.get('action'))) not in ('redirect','egress redirect','egress_redirect'):continue
            target=d.get('to_dev',d.get('dev',d.get('ifname')))
            if isinstance(target,str):targets.add(target)
    candidate=list(targets)
    if len(candidate)!=1 or not _interface_ok(candidate[0]) or candidate[0]==iface:
        return {'verified':False,'reason':'ifb-target-not-unique','interface':iface,
                'redirect_count':len(targets),'root_kind':roots[0].get('kind'),'mode':'read-only'}
    base=sqm_v2_observe(iface,candidate[0],query=query)
    base['root_kind']=roots[0].get('kind')
    base['mode']='read-only'
    base['ownership']='unknown-requires-runtime-transaction-check'
    base['reason']='kernel-topology-verified' if base['verified'] else 'kernel-topology-incomplete'
    return base


def sqm_v3_cli(argv):
    if len(argv)==2 and argv[0]=='status':
        try:print(json.dumps(sqm_v3_observe(argv[1]),sort_keys=True))
        except SampleError as exc:
            print(json.dumps({'error':str(exc)}));return 2
        return 0
    print('usage: sqm_measure.py --v3 status INTERFACE',file=sys.stderr)
    return 2

if __name__ == '__main__':
    sys.exit(sqm_v3_cli(sys.argv[2:]) if sys.argv[1:2] == ['--v3'] else
             sqm_v2_cli(sys.argv[2:]) if sys.argv[1:2] == ['--v2'] else
             engine_check() if '--check' in sys.argv[1:] else main())
