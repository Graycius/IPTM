#!/usr/bin/env python3
"""IPTM-owned IPv4 HTTP interception, fail open and scoped to a LAN interface.

Never redirects HTTPS or OUTPUT. No general firewall flush/iptables-restore.
All rule removal is by exact comparison and ownership, never by rule numbers.
"""
from __future__ import annotations
import ipaddress
import os
import pathlib
import re
import subprocess

CHAIN='IPTM_HTTP_CACHE'
TAG='IPTM_HTTP_CACHE_V1'
# Destination ranges we must never proxy, including private web UI / local DNS.
NO_INTERCEPT=(
 '0.0.0.0/8','10.0.0.0/8','100.64.0.0/10','127.0.0.0/8',
 '169.254.0.0/16','172.16.0.0/12','192.168.0.0/16','198.18.0.0/15',
 '224.0.0.0/4','240.0.0.0/4',
)
BACKENDS={'legacy':'/usr/sbin/iptables-legacy','nf_tables':'/usr/sbin/iptables-nft'}
class RedirectError(ValueError):pass


def command(args,check=True,timeout=9):
    try:
        result=subprocess.run(args,stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=timeout)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise RedirectError('Comando netfilter non eseguibile: '+str(exc)[:120]) from exc
    if check and result.returncode:
        raise RedirectError('Netfilter: '+(result.stderr or result.stdout)[-200:])
    return result


def backend_path(preferred=None):
    """Pin backend variant; update of system alternatives must not orphan rules."""
    if preferred is not None:
        if preferred not in BACKENDS.values():raise RedirectError('Backend salvato non autorizzato')
        candidate=preferred
    else:
        candidate='/usr/sbin/iptables'
    v=command([candidate,'-V']).stdout
    kind='nf_tables' if 'nf_tables' in v else 'legacy' if 'legacy' in v else None
    if kind is None:raise RedirectError('Backend iptables non riconosciuto')
    if preferred is not None and BACKENDS[kind]!=preferred:
        raise RedirectError('Backend iptables modificato')
    path=BACKENDS[kind]
    if not os.path.isfile(path) or not os.access(path,os.X_OK):
        raise RedirectError('Backend iptables esplicito assente: '+path)
    return path


def call(binary,table,*args,check=True):
    if binary not in BACKENDS.values():raise RedirectError('Backend non consentito')
    return command([binary,'-w','5','-t',table,*args],check=check)


def hook(profile):
    return ['-i',profile['interface'],'-p','tcp','-s',None, '--dport','80',
            '-m','comment','--comment',TAG,'-j',CHAIN]


def hooks(profile):
    h=hook(profile)
    return [[x if x is not None else net for x in h] for net in profile['allowed_nets']]


def accept_rules(profile):
    return [['-i',profile['interface'],'-p','tcp','-s',net,
             '-d',profile['listen_ip']+'/32','--dport',str(profile['port']),
             '-m','conntrack','--ctstate','NEW', '-m','comment','--comment',TAG,'-j','ACCEPT']
            for net in profile['allowed_nets']]


def chain_rules(profile):
    return [['-d',dest,'-j','RETURN'] for dest in NO_INTERCEPT]+[
        ['-p','tcp','--dport','80','-m','comment','--comment',TAG,
         '-j','REDIRECT','--to-ports',str(profile['port'])]]


def exists(binary,table,chain,rule):
    r=call(binary,table,'-C',chain,*rule,check=False)
    if r.returncode not in (0,1):raise RedirectError('Non è possibile verificare una regola iptables')
    return r.returncode==0


def chain_snapshot(binary):
    r=call(binary,'nat','-S',CHAIN,check=False)
    if r.returncode==1:return None
    if r.returncode:raise RedirectError('Impossibile controllare catena IPTM HTTP')
    return [line.strip() for line in r.stdout.splitlines() if line.strip()]


def chain_trusted(binary,profile):
    """Only a chain with precisely our expected rules may be flushed/deleted."""
    snap=chain_snapshot(binary)
    if snap is None:return False
    if not snap or snap[0]!='-N '+CHAIN or len(snap)!=len(chain_rules(profile))+1:
        raise RedirectError('Catena NAT alterata o con regole estranee')
    if not all(exists(binary,'nat',CHAIN,rule) for rule in chain_rules(profile)):
        raise RedirectError('Catena NAT con regole non IPTM')
    return True


def remove(binary,profile):
    """Fail-open first: remove PREROUTING hooks, then scoped INPUT grants."""
    errors=[]
    for table,base,rules in (('nat','PREROUTING',hooks(profile)),('filter','INPUT',accept_rules(profile))):
        for rule in rules:
            try:
                for _ in range(4):
                    if not exists(binary,table,base,rule):break
                    call(binary,table,'-D',base,*rule)
                if exists(binary,table,base,rule):
                    errors.append('Regole duplicate ancora presenti in '+base)
            except RedirectError as exc:errors.append(str(exc))
    if errors:raise RedirectError('; '.join(errors)[:300])
    # The user chain is never an interception hook by itself.
    if chain_trusted(binary,profile):
        call(binary,'nat','-F',CHAIN)
        call(binary,'nat','-X',CHAIN)


def install(binary,profile):
    """Build NAT chain before adding any PREROUTING hooks; ingress allowed first."""
    if chain_snapshot(binary) is not None:
        # Repair only if the existing chain is ours, not a foreign chain.
        chain_trusted(binary,profile)
    else:
        call(binary,'nat','-N',CHAIN)
        try:
            for rule in chain_rules(profile):call(binary,'nat','-A',CHAIN,*rule)
        except Exception:
            # Roll back incomplete isolated chain; no hooks installed yet.
            call(binary,'nat','-F',CHAIN,check=False)
            call(binary,'nat','-X',CHAIN,check=False)
            raise
    try:
        for rule in accept_rules(profile):
            if not exists(binary,'filter','INPUT',rule):
                call(binary,'filter','-I','INPUT','1',*rule)
        for rule in hooks(profile):
            if not exists(binary,'nat','PREROUTING',rule):
                call(binary,'nat','-I','PREROUTING','1',*rule)
    except Exception:
        remove(binary,profile)
        raise


def healthy(binary,profile):
    return (chain_trusted(binary,profile)
            and all(exists(binary,'filter','INPUT',r) for r in accept_rules(profile))
            and all(exists(binary,'nat','PREROUTING',r) for r in hooks(profile)))


def unsafe_forward_policy(filter_rules):
    """Conservative check: interception changes FORWARD to INPUT/OUTPUT.

    Reject when any FORWARD rule could enforce per-client restrictions; a
    transparent proxy would otherwise bypass MAC/IoT/zone/IPSet controls.
    """
    if not isinstance(filter_rules,str) or len(filter_rules)>2_000_000:
        raise RedirectError('Policy FORWARD non leggibile')
    lines=[x.strip() for x in filter_rules.splitlines()]
    if not any(x.startswith('-P FORWARD ') for x in lines):
        raise RedirectError('Policy FORWARD non individuata')
    if '-P FORWARD DROP' in lines or '-P FORWARD REJECT' in lines:
        return 'Policy FORWARD predefinita restrittiva'
    for line in lines:
        if not line.startswith('-A '):continue
        # Permit only a minimal stateful forwarding baseline. Complex ACLs
        # cannot be mirrored in the Squid proxy, so require explicit mode.
        if line.startswith('-A FORWARD '):
            # Forwarding into any user-defined chain can enforce isolation or
            # source-specific policy. We cannot prove it safe by the chain name.
            import shlex
            try: tokens=shlex.split(line)
            except ValueError: return 'FORWARD non interpretabile'
            target=None
            for option in ('-j','--jump','-g','--goto'):
                if option in tokens:
                    idx=tokens.index(option)
                    target=tokens[idx+1] if idx+1<len(tokens) else None
                    break
            if (target not in ('ACCEPT','RETURN') or
                any(x in tokens for x in ('--match-set','--mac-source','--uid-owner','--gid-owner')) or
                (target=='ACCEPT' and any(x in tokens for x in ('-s','-d','--sport','--dport')))):
                return 'FORWARD contiene restrizioni o catene di sicurezza'
        if line.startswith(('-A IPTM-MAC','-A IPTM-IOT','-A IPTM-ZONE')):
            return 'IPTM applica policy di isolamento IoT/MAC/zona'
    return None


def security_preflight(binary):
    text=call(binary,'filter','-S').stdout
    danger=unsafe_forward_policy(text)
    if danger:
        raise RedirectError('Intercettazione negata: '+danger+'. Il proxy bypasserebbe i filtri FORWARD; usare modalità esplicita oppure una LAN senza policy restrittive')
