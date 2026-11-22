#!/usr/bin/env python3
"""Low-overhead, read-only Layer-7 and local-process traffic classification.

Suricata EVE app_proto records are the only L7 evidence. Kernel ss -p maps
local sockets to process names; remote client processes cannot be inferred.
No firewall, qdisc, sysctl or DSCP changes occur in this observer.
"""
from __future__ import annotations
from collections import Counter
import json
import os
from pathlib import Path
import re
import subprocess
import time

EVE = Path('/var/log/suricata/eve.json')
MAX_TAIL = 262144
MAX_EVENTS = 600
PROTO = re.compile(r'^[A-Za-z0-9_.+-]{1,32}$')
PROCESS = re.compile(r'^[A-Za-z0-9_.:+-]{1,64}$')
SS_PROCESS = re.compile(r'"([^"\\]{1,64})",pid=(\d{1,10})\b')
CLASSES = {
    'dns':'interactive', 'ntp':'interactive', 'ssh':'interactive',
    'sip':'realtime', 'rtp':'realtime', 'stun':'interactive',
    'bittorrent-dht':'background', 'bittorrent':'background',
    'ftp':'background', 'http':'normal', 'tls':'normal', 'quic':'normal'
}
LOCAL_BACKGROUND = {'rsync','rclone','syncthing','transmission-daemon','qbittorrent',
                    'aria2c','apt-get','apt','wget'}
LOCAL_INTERACTIVE = {'sshd','ssh','mosh-server','unbound','dnsmasq','pihole-ftl'}
LOCAL_REALTIME = {'asterisk','freeswitch'}


def classify_protocol(value: str) -> str:
    return CLASSES.get(value.lower(), 'normal')


def classify_process(value: str) -> str:
    name = value.lower()
    if name in LOCAL_BACKGROUND:return 'background'
    if name in LOCAL_INTERACTIVE:return 'interactive'
    if name in LOCAL_REALTIME:return 'realtime'
    return 'normal'


def parse_eve(text: str) -> list[dict]:
    counts: Counter[str] = Counter()
    for line in text.splitlines()[-MAX_EVENTS:]:
        if not line or len(line)>16384:continue
        try:record=json.loads(line)
        except (ValueError,TypeError):continue
        if not isinstance(record,dict):continue
        kind=record.get('event_type')
        if kind not in ('flow','alert','http','dns','tls','anomaly','fileinfo'):continue
        proto=record.get('app_proto')
        if not isinstance(proto,str) or not PROTO.fullmatch(proto):continue
        if proto.lower() in ('unknown','failed','undetected','none'):continue
        counts[proto.lower()]+=1
    return [{'protocol':key,'observations':val,'class':classify_protocol(key)}
            for key,val in counts.most_common(12)]


def read_eve(path: Path = EVE) -> dict:
    if path.is_symlink() or not path.is_file():
        return {'available':False,'reason':'EVE Suricata assente o non regolare','protocols':[]}
    try:
        st=path.stat()
        if st.st_size>100*1024*1024*1024:
            return {'available':False,'reason':'EVE oltre limite di dimensione','protocols':[]}
        with path.open('rb') as fd:
            if st.st_size>MAX_TAIL:
                fd.seek(-MAX_TAIL,os.SEEK_END)
                fd.readline()  # discard a partial first record
            buf=fd.read(MAX_TAIL)
        observations=parse_eve(buf.decode('utf-8',errors='replace'))
        return {'available':True,'source':'Suricata EVE app_proto',
                'protocols':observations,'window':'ultimi eventi disponibili, non necessariamente live'}
    except (OSError,ValueError):
        return {'available':False,'reason':'lettura EVE non riuscita','protocols':[]}


def parse_ss(text: str) -> list[dict]:
    counts: Counter[tuple[str,str]] = Counter()
    for line in text.splitlines()[:1500]:
        matches=SS_PROCESS.findall(line)
        for name,pid in matches[:4]:
            if not PROCESS.fullmatch(name):continue
            try:n=int(pid)
            except ValueError:continue
            if not 1<=n<=4294967295:continue
            counts[(name,classify_process(name))]+=1
    return [{'process':name,'class':klass,'sockets':n}
            for (name,klass),n in counts.most_common(12)]


def local_processes() -> dict:
    try:
        r=subprocess.run(['ss','-H','-tunap'],capture_output=True,text=True,
                         timeout=4,stdin=subprocess.DEVNULL)
    except (OSError,subprocess.TimeoutExpired):
        return {'available':False,'reason':'ss non disponibile','processes':[]}
    if r.returncode:
        return {'available':False,'reason':'ss non verificabile','processes':[]}
    return {'available':True,'scope':'solo socket dei processi locali (non client inoltrati)',
            'processes':parse_ss(r.stdout[:300000])}


def status() -> dict:
    if os.geteuid()!=0:
        return {'ok':False,'error':'richiesti permessi di lettura root'}
    return {'ok':True,'layer7':read_eve(),'process':local_processes(),
            'enforcement':'sola diagnosi; non modifica le priorità DSCP o CAKE',
            'measured_at':int(time.time())}


if __name__=='__main__':
    print(json.dumps(status(),ensure_ascii=False))
