#!/usr/bin/env python3
"""One-click, additive SSH session recovery for an already authenticated LAN admin.

Never flushes chains, changes default policies, or opens SSH from WAN. The two
rules are transient and disappear on the next managed ruleset replacement.
The actual generator fix is the permanent solution.
"""
from __future__ import annotations
import ipaddress
import json
import os
import shlex
import subprocess
import sys

TAG_EST='IPTM_SSH_RECOVERY_EST'
TAG_NEW='IPTM_SSH_RECOVERY_NEW'
PRIVATE=[ipaddress.ip_network(x) for x in (
    '10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','100.64.0.0/10')]

class RecoveryError(Exception):pass

def trusted_ipv4(value):
    try:addr=ipaddress.ip_address(value)
    except ValueError:raise RecoveryError('Indirizzo client non valido')
    if addr.version!=4 or not any(addr in net for net in PRIVATE):
        raise RecoveryError('Recupero SSH disponibile solo da client LAN o VPN locale')
    return str(addr)

def run(args,check=True):
    try:
        r=subprocess.run(args,stdin=subprocess.DEVNULL,capture_output=True,
                         text=True,timeout=9)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise RecoveryError('iptables non disponibile: '+type(exc).__name__) from exc
    if check and r.returncode:
        raise RecoveryError('Operazione iptables fallita: '+(r.stderr or r.stdout)[-200:])
    return r

def parse_kernel_rules(output):
    parsed=[]
    for line in output.splitlines():
        try:tokens=shlex.split(line)
        except ValueError:continue
        if tokens[:2]==['-A','INPUT']:parsed.append(tokens)
    return parsed

def has_value(tokens,key,value):
    return any(tokens[i]==key and tokens[i+1]==value for i in range(len(tokens)-1))

def allowed_existing_login(rules,addr):
    address=ipaddress.ip_address(addr)
    for tokens in rules:
        if not has_value(tokens,'-j','ACCEPT') or not has_value(tokens,'-p','tcp'):
            continue
        try:source=tokens[tokens.index('-s')+1]
        except (ValueError,IndexError):continue
        try:subnet=ipaddress.ip_network(source,strict=False)
        except ValueError:continue
        if subnet.version!=4 or subnet.prefixlen<16 or address not in subnet:
            continue
        ports=[]
        for flag in ('--dport','--dports'):
            if flag in tokens:
                idx=tokens.index(flag)
                if idx+1<len(tokens):ports+=tokens[idx+1].split(',')
        if '22' in ports:return True
    return False

def vulnerable_ssh(rules):
    return any(has_value(t,'--dport','22') and
               (('--update' in t and '-m' in t and 'recent' in t) or
                ('--connlimit-above' in t)) and
               not has_value(t,'--ctstate','NEW') for t in rules)

def safe_existing_ssh(rules):
    return any(has_value(t,'--dport','22') and
               has_value(t,'--ctstate','ESTABLISHED,RELATED') and
               has_value(t,'-j','ACCEPT') for t in rules)

def safe_rule_spec(ip,kind):
    spec=['-p','tcp','--dport','22','-m','conntrack']
    if kind=='est':
        spec+=['--ctstate','ESTABLISHED,RELATED']
        tag=TAG_EST
    else:
        spec+=['--ctstate','NEW','--syn','-s',ip+'/32']
        tag=TAG_NEW
    spec+=['-m','comment','--comment',tag,'-j','ACCEPT']
    return spec

def recover(ip):
    if os.geteuid()!=0:raise RecoveryError('Root richiesto')
    ip=trusted_ipv4(ip)
    cmd=['iptables','-w','5']
    rules=parse_kernel_rules(run(cmd+['-t','filter','-S','INPUT']).stdout)
    affected=vulnerable_ssh(rules)
    if not allowed_existing_login(rules,ip):
        raise RecoveryError('Client non presente nelle reti SSH autorizzate: nessuna eccezione creata')
    if not affected:
        return {'ok':True,'changed':False,'reason':'Nessun limite SSH legacy per-pacchetto rilevato'}
    inserted=[]
    for kind in ('new','est'):
        spec=safe_rule_spec(ip,kind)
        checked=run(cmd+['-t','filter','-C','INPUT']+spec,check=False)
        if checked.returncode==0:continue
        try:run(cmd+['-t','filter','-I','INPUT','1']+spec)
        except RecoveryError:
            # Do not undo an already-existing rule or alter third-party chains.
            for prev in reversed(inserted):run(cmd+['-t','filter','-D','INPUT']+prev,check=False)
            raise
        inserted.append(spec)
    return {'ok':True,'changed':bool(inserted),'preexisting_session_guard':safe_existing_ssh(rules),
            'reason':'Sessioni e nuovi accessi SSH da questo client autorizzato protetti; rigenera la bozza per una correzione permanente'}

def main(argv):
    if len(argv)==2 and argv[0]=='repair':return recover(argv[1])
    raise RecoveryError('Uso: repair IPV4_CLIENT_LAN')

if __name__=='__main__':
    try:print(json.dumps(main(sys.argv[1:]),ensure_ascii=False))
    except (RecoveryError,ValueError,KeyError,TypeError) as exc:
        print(json.dumps({'ok':False,'error':str(exc)},ensure_ascii=False));sys.exit(1)
