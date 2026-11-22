#!/usr/bin/env python3
"""IPTM 5.20.25: non-invasive diagnostics adapted from IPTM 6.11.3.

Concepts adopted from IPTM6 acceptance, external_checks, suricata_inspect
and legacy_audit. This is NOT the IPTM6 root worker and deliberately has no
mutation APIs. The report is local evidence, not proof of LAN/WAN reachability.
"""
import json
import os
import pathlib
import shutil
import socket
import struct
import subprocess
import sys

SERVICES=(('pihole-FTL','Pi-hole FTL'),('unbound','Unbound'),('crowdsec','CrowdSec'),('suricata','Suricata'))
TX_PATHS=(('/var/lib/iptm-network-runtime/transaction.json','Rete'),
          ('/var/lib/iptm-qos-engine/active.json','QoS'),
          ('/var/lib/iptm-update-recovery/state.json','Aggiornamento'))
PENDING={'pending','applying','persisting','partial','rollback-failed','recovery-failed','unknown'}

def cmd(argv,seconds=1.5):
    """Fixed binary and argument arrays only; no shell. No raw logs released."""
    try:
        p=subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL, text=True,timeout=seconds)
        return p.returncode,p.stdout[:24000]
    except (OSError, subprocess.TimeoutExpired):return None,''

def service(unit):
    rc,_=cmd(['/usr/bin/systemctl','is-active','--quiet',unit+'.service'],1.3)
    return None if rc is None else rc==0

def services_status(units):
    """One systemctl invocation instead of a sequential probe per service.

    Exit code 3 merely means one or more units are inactive: parse *all* lines.
    If an older systemctl returns unexpected output, use the original checks.
    """
    rc,out=cmd(['/usr/bin/systemctl','is-active',*(u+'.service' for u in units)],2.0)
    lines=out.strip().splitlines()
    known={'active','inactive','failed','activating','deactivating','reloading','unknown'}
    if rc is not None and len(lines)==len(units) and all(x.strip() in known for x in lines):
        return dict(zip(units,(x.strip()=='active' for x in lines)))
    return {u:service(u) for u in units}

def ipv6_disabled():
    root=pathlib.Path('/proc/sys/net/ipv6/conf')
    if not root.is_dir():return None
    try:
        flags=[]
        for f in root.glob('*/disable_ipv6'):
            if f.parent.name in ('all','default'):continue
            if f.is_symlink():continue
            flags.append(f.read_text().strip()=='1')
        if not flags:return None
        return all(flags)
    except (OSError,ValueError):return None

def transactions():
    found=[]
    for name,label in TX_PATHS:
        path=pathlib.Path(name)
        try:
            if path.is_symlink() or not path.is_file() or path.stat().st_size>65536:continue
            doc=json.loads(path.read_text(encoding='utf8'))
            if not isinstance(doc,dict):continue
            state=doc.get('state','')
            if isinstance(state,str) and state in PENDING:found.append(label+': '+state)
        except (ValueError,OSError,UnicodeError):continue
    return found

def udp_dns(port):
    """Controlled DNS A query to localhost; only check reply ID/QR. No user data."""
    packet=struct.pack('!HHHHHH',0x4C62,0x0100,1,0,0,0)+b'\x07example\x03org\x00'+struct.pack('!HH',1,1)
    sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    try:
        sock.settimeout(.35);sock.sendto(packet,('127.0.0.1',port));raw,_=sock.recvfrom(1024)
        return len(raw)>=12 and raw[:2]==packet[:2] and bool(raw[2]&0x80)
    except OSError:return False
    finally:sock.close()

def report():
    checks=[]
    def add(group,title,state,detail):
        checks.append({'group':group,'title':title,'status':state,'detail':detail})
    status=services_status([key for key,_ in SERVICES]+['iptm-guard'])
    for unit,title in SERVICES:
        on=status[unit]
        # Stopped is not necessarily an error: all components are optional.
        add('Servizi',title,'ok' if on else 'info' if on is False else 'warn',
            'Servizio attivo' if on else 'Non attivo (può essere intenzionale)' if on is False else 'Stato non leggibile')
    ipt=shutil.which('iptables-save')
    hooks=None
    filter_rules=[]
    if ipt:
        rc,data=cmd([ipt,'-t','filter'],2.0)
        if rc==0:
            filter_rules=[line for line in data.splitlines() if line.startswith('-A ')]
            refs=[line for line in filter_rules if 'crowdsec' in line.lower()]
            hooks=len(refs)
            add('Protezione','Regole iptables leggibili','ok','Tabella filter acquisita; nessuna modifica eseguita')
        else:add('Protezione','Regole iptables leggibili','warn','iptables-save non ha restituito dati verificabili')
    else:add('Protezione','Regole iptables leggibili','warn','iptables-save non trovato')
    cscli=shutil.which('cscli'); bouncers=None
    if cscli:
        rc,out=cmd([cscli,'bouncers','list','-o','json'],2.0)
        if rc==0:
            try:
                parsed=json.loads(out)
                if isinstance(parsed,list):bouncers=len(parsed)
                elif isinstance(parsed,dict) and isinstance(parsed.get('items'),list):bouncers=len(parsed['items'])
            except (ValueError,TypeError):pass
    if status['crowdsec'] is True:
        if hooks and bouncers is not None and bouncers>0:
            add('Protezione','CrowdSec: integrazione firewall','ok',f'Bouncer registrati: {bouncers}; riferimenti iptables: {hooks}. Blocco effettivo non provato')
        elif hooks:
            add('Protezione','CrowdSec: integrazione firewall','info','Riferimenti iptables presenti; registrazione bouncer non verificata')
        else:
            add('Protezione','CrowdSec: integrazione firewall','warn','Servizio attivo, ma collegamento a iptables non dimostrato. Controlla il bouncer')
    elif cscli:
        add('Protezione','CrowdSec: integrazione firewall','info','CLI disponibile; CrowdSec non risulta attivo')
    su=shutil.which('suricata-update'); sc=shutil.which('suricata')
    if sc:
        if hooks is None:add('Protezione','Suricata IPS','info','Non è possibile verificare le regole NFQUEUE')
        else:
            inline=any('NFQUEUE' in line for line in filter_rules)
            add('Protezione','Suricata IPS','info','NFQUEUE visibile in filter: '+('sì' if inline else 'no')+'. Non certifica l’enforcement inline')
        if su:
            rc,out=cmd([su,'list-enabled-sources'],2.0)
            add('Protezione','Suricata: fonti firme','ok' if rc==0 else 'info',
                'Elenco fonti consultabile' if rc==0 else 'Comando non disponibile in questa installazione')
        else:add('Protezione','Suricata: fonti firme','info','suricata-update non installato')
    v6=ipv6_disabled()
    add('Rete','IPv6 sulle interfacce','info',
        'Disabilitato sulle interfacce rilevate' if v6 is True else
        'Almeno una interfaccia mantiene IPv6' if v6 is False else 'Stato IPv6 non determinabile')
    for unit,port in (('pihole-FTL',53),('unbound',5335)):
        if status[unit] is True:
            response=udp_dns(port)
            add('DNS',('Pi-hole' if unit=='pihole-FTL' else 'Unbound')+' · DNS locale',
                'ok' if response else 'info','Risposta DNS su 127.0.0.1:'+str(port) if response else
                'Nessuna risposta dal loopback:'+str(port)+'; il servizio può ascoltare su un altro IP/porta')
    pending=transactions()
    add('Ripristino','Transazioni locali','warn' if pending else 'ok',
        '; '.join(pending) if pending else 'Nessuna transazione sospesa rilevata nei registri noti')
    add('Ripristino','Protezione di rete','info',
        'IPTM guard attivo' if status['iptm-guard'] else 'Controllare lo stato del watchdog quando si applicano modifiche al firewall')
    counts={kind:sum(r['status']==kind for r in checks) for kind in ('ok','warn','info')}
    return {'ok':True,'mode':'READ_ONLY','origin':'IPTM 6.11.3: acceptance, external_checks, suricata_inspect',
            'checks':checks,'counts':counts,
            'limits':'Controlli locali: non dimostrano raggiungibilità LAN/WAN, blocco reale IPS, correttezza dei DNS dei client o possibilità di rollback dopo riavvio. Nessuna modifica applicata.'}

def main(argv):
    if argv!=['report']:raise ValueError('Comando non supportato')
    if os.geteuid()!=0:raise PermissionError('Root richiesto')
    print(json.dumps(report(),ensure_ascii=False,separators=(',',':')))

if __name__=='__main__':
    try:main(sys.argv[1:])
    except (ValueError,PermissionError,OSError) as error:
        print(json.dumps({'ok':False,'error':str(error)[:140]}));sys.exit(1)
