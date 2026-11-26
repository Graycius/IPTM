#!/usr/bin/env python3
"""IPTM local operator summaries. No writes, no UI framework, no extra daemon.

Inspired by CrowdSec Manager (decisions/scenarios), EveBox (event triage),
Scirius (source/rules visibility) and Cockpit (NetworkManager profile inventory).
Never emits IP addresses or secrets. Explicitly bounded work for Atom N450.
"""
from __future__ import annotations
import collections
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys

EVE_PATHS=(Path('/var/log/suricata/eve.json'), Path('/var/log/suricata/fast.json'))
MAX_EVE=1024*1024
SAFE_NAME=re.compile(r'^[A-Za-z0-9_.:@/+ -]{1,110}$')


def execute(args, timeout=6):
    # Same bounded process adapter as the connection inventory; no shell or stderr capture.
    from device_insights import bounded_output
    status, output = bounded_output(args, 524288, timeout)
    return output if status == 'ok' else None


def bounded_json(raw):
    if raw is None or len(raw)>524288:
        return None
    try:
        return json.loads(raw)
    except (ValueError,TypeError):
        return None


def crowdsec_summary():
    """Aggregate without exporting subjects, IPs, decisions or PII."""
    decisions=bounded_json(execute(['cscli','decisions','list','-o','json']))
    alerts=bounded_json(execute(['cscli','alerts','list','-o','json']))
    def rows(value):
        if isinstance(value,list):return [v for v in value if isinstance(v,dict)]
        if isinstance(value,dict):
            for name in ('decisions','alerts','items'):
                if isinstance(value.get(name),list):return rows(value[name])
        return []
    dl=rows(decisions); al=rows(alerts)
    origins=collections.Counter(); scenarios=collections.Counter()
    for d in dl[:1000]:
        value=str(d.get('origin','unknown'))[:72]
        if SAFE_NAME.fullmatch(value):origins[value]+=1
    for a in al[:1000]:
        value=str(a.get('scenario','unknown'))[:110]
        if SAFE_NAME.fullmatch(value):scenarios[value]+=1
    return {'available':decisions is not None or alerts is not None,
            'decisions_count':len(dl) if decisions is not None else None,
            'alerts_count':len(al) if alerts is not None else None,
            'origins':origins.most_common(8),'scenarios':scenarios.most_common(8),
            'privacy':'aggregate-only'}


def safe_tail(path,max_bytes=MAX_EVE):
    """Refuse symlinks, non-regular and group/world-writable log files."""
    fd=os.open(path,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        st=os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_mode&0o022:
            raise ValueError('proprietà/permessi EVE non sicuri')
        os.lseek(fd,max(0,st.st_size-max_bytes),os.SEEK_SET)
        data=os.read(fd,max_bytes)
        return data.split(b'\n')[1:] if st.st_size>max_bytes else data.split(b'\n')
    finally:os.close(fd)


def analyze_eve(lines):
    signatures=collections.Counter(); categories=collections.Counter()
    severity=collections.Counter(); hours=collections.Counter(); events=0; invalid=0
    for line in lines:
        if not line or len(line)>131072:continue
        try: row=json.loads(line)
        except (ValueError,UnicodeError):invalid+=1;continue
        if not isinstance(row,dict) or row.get('event_type')!='alert':continue
        alert=row.get('alert')
        if not isinstance(alert,dict):continue
        events+=1
        try:sid=int(alert.get('signature_id',0))
        except (TypeError,ValueError):sid=0
        if 0<sid<2**32:signatures[sid]+=1
        category=str(alert.get('category','unknown'))[:72]
        if SAFE_NAME.fullmatch(category):categories[category]+=1
        try:sev=int(alert.get('severity',0))
        except (ValueError,TypeError):sev=0
        if 1<=sev<=4:severity[sev]+=1
        timestamp=str(row.get('timestamp',''))
        if re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d.*',timestamp):hours[timestamp[:13]]+=1
    return {'events':events,'invalid_lines':invalid,'severities':sorted(severity.items()),
            'top_sids':signatures.most_common(12),'categories':categories.most_common(8),
            'hour_buckets':sorted(hours.items())[-12:],'privacy':'no IP addresses or payloads'}


def suricata_summary():
    for path in EVE_PATHS:
        try:
            rows=safe_tail(path)
            return {'available':True,'log_path':str(path),**analyze_eve(rows)}
        except (FileNotFoundError,PermissionError,ValueError,OSError):continue
    return {'available':False,'reason':'EVE JSON non disponibile o non verificabile'}


def network_summary():
    # Never use GENERAL.CONNECTION secret-bearing fields or nmcli show-secrets.
    raw=execute(['nmcli','-t','-f','DEVICE,TYPE,STATE','device','status'])
    devices=[]
    if raw is not None:
        for line in raw.splitlines()[:128]:
            parts=line.split(':',2)
            if len(parts)==3 and all(re.fullmatch('[A-Za-z0-9_. -]{1,80}',p) for p in parts):
                devices.append({'device':parts[0],'type':parts[1],'state':parts[2]})
    return {'available':raw is not None,'devices':devices,
            'checkpoint':'NetworkManager D-Bus checkpoint required for activation',
            'credentials':'never exported'}


def qos_summary():
    policy_path=Path('/var/lib/iptm-qos-policy/active.json')
    engine_path=Path('/var/lib/iptm-qos-engine/state.json')
    result={'available':shutil.which('tc') is not None,
            'features':{'bidirectional_cake':'requires verified qdiscs',
                        'ipv4_flow_dscp':'implemented',
                        'ingress_ipv4_pre_ifb':'implemented when topology verified',
                        'latency_adaptation':'optional; RTT only',
                        'process_level_classification':'not implemented',
                        'layer7_detection':'not implemented'},
            'cfosspeed_certified':False,'reason':'comparative real-device benchmarks absent'}
    for key,path in [('policy',policy_path),('engine',engine_path)]:
        try:
            from command_transport import read_private_json
            val=read_private_json(path,limit=65536)
            if isinstance(val,dict):result[key+'_state']=str(val.get('state','present'))[:36]
        except (OSError,ValueError,TypeError):pass
    return result


FUNCTIONS={'crowdsec':crowdsec_summary,'suricata':suricata_summary,
           'network':network_summary,'qos':qos_summary}

def main(args):
    if os.geteuid()!=0:raise PermissionError('root required')
    if len(args)!=1 or args[0] not in FUNCTIONS:raise ValueError('unknown mode')
    return {'ok':True,'module':args[0],**FUNCTIONS[args[0]]()}

if __name__=='__main__':
    try: print(json.dumps(main(sys.argv[1:]),ensure_ascii=False,sort_keys=True))
    except (ValueError,PermissionError) as exc:
        print(json.dumps({'ok':False,'error':str(exc)}));sys.exit(1)
