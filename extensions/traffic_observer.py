#!/usr/bin/env python3
"""Read-only application/protocol observer for Suricata EVE and local Linux sockets.

Suricata app_proto is historical observation, not DPI enforcement. The ss
process association includes only the gateway's processes, not remote clients.
"""
from __future__ import annotations

from command_transport import capture, OutputLimitError
from collections import Counter
import json,os,pathlib,re,stat,subprocess,time

EVE=pathlib.Path('/var/log/suricata/eve.json')
MAX_TAIL=262144
MAX_EVENTS=600
PROTO=re.compile(r'[A-Za-z0-9_.+-]{1,32}\Z')
PROCESS=re.compile(r'[A-Za-z0-9_.:+-]{1,64}\Z')
SS_PROCESS=re.compile(r'"([^"\\]{1,64})",pid=(\d{1,10})\b')
CLASSES={'dns':'interactive','ssh':'interactive','ntp':'interactive','sip':'realtime',
         'rtp':'realtime','stun':'interactive','bittorrent':'background',
         'bittorrent-dht':'background','http':'normal','tls':'normal','quic':'normal'}
PROCESSES={'sshd':'interactive','ssh':'interactive','unbound':'interactive',
           'dnsmasq':'interactive','pihole-ftl':'interactive','asterisk':'realtime',
           'freeswitch':'realtime','rsync':'background','rclone':'background',
           'syncthing':'background','qbittorrent':'background',
           'transmission-daemon':'background','apt-get':'background'}


def parse_eve(text):
    result=Counter()
    for line in text.splitlines()[-MAX_EVENTS:]:
        if len(line)>16384:continue
        try:obj=json.loads(line)
        except (ValueError,TypeError):continue
        if not isinstance(obj,dict) or obj.get('event_type') not in ('flow','alert','http','dns','tls','fileinfo'):continue
        proto=obj.get('app_proto')
        if not isinstance(proto,str) or not PROTO.fullmatch(proto) or proto.lower() in ('unknown','failed','undetected','none'):
            continue
        result[proto.lower()]+=1
    return [{'protocol':p,'observations':n,'class':CLASSES.get(p,'normal')}
            for p,n in result.most_common(12)]


def read_eve(path=EVE):
    if path.is_symlink() or not path.is_file():
        return {'available':False,'reason':'Suricata EVE non disponibile','protocols':[]}
    try:
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as f:
            meta=os.fstat(f.fileno());size=meta.st_size
            if not stat.S_ISREG(meta.st_mode) or size>100*1024**3:raise ValueError('EVE non regolare o eccessivo')
            if size>MAX_TAIL:
                f.seek(size-MAX_TAIL);data=f.read(MAX_TAIL).partition(b'\n')[2]
            else:data=f.read(MAX_TAIL)
        return {'available':True,'source':'Suricata EVE app_proto',
                'protocols':parse_eve(data.decode('utf-8',errors='replace')),
                'window':'ultimi eventi disponibili, non classificazione inline'}
    except (OSError,ValueError):return {'available':False,'reason':'EVE non leggibile','protocols':[]}


def parse_ss(text):
    result=Counter()
    for line in text.splitlines()[:1500]:
        for name,pid in SS_PROCESS.findall(line)[:4]:
            if not PROCESS.fullmatch(name):continue
            n=int(pid)
            if not 1<=n<=4294967295:continue
            result[name]+=1
    return [{'process':p,'sockets':n,'class':PROCESSES.get(p.lower(),'normal')}
            for p,n in result.most_common(12)]


def local_processes():
    try:r=capture(['ss','-H','-tunap'],timeout=4,stdout_limit=300000)
    except (OSError,subprocess.TimeoutExpired):return {'available':False,'reason':'ss non disponibile','processes':[]}
    if r.returncode:return {'available':False,'reason':'ss non verificabile','processes':[]}
    return {'available':True,'scope':'soli processi locali del gateway',
            'processes':parse_ss(r.stdout[:300000])}


def status():
    if os.geteuid()!=0:return {'ok':False,'error':'root richiesto'}
    return {'ok':True,'layer7':read_eve(),'process':local_processes(),
            'enforcement':False,'measured_at':int(time.time())}

if __name__=='__main__':print(json.dumps(status(),ensure_ascii=False))
