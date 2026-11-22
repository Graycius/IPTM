#!/usr/bin/env python3
"""Bounded, read-only cost and compatibility audit of generated iptables-save rules.

This is not a benchmark and never silently weakens a filter. It suggests an
operator-verified configuration change, not a kernel or rules-file edit.
"""
from __future__ import annotations
from collections import Counter
import json
import re
import sys

MAX_BYTES = 2097152
MAX_LINES = 30000

class AuditError(ValueError):
    pass


def analyze(raw: str) -> dict:
    if not isinstance(raw, str) or not raw or len(raw.encode('utf-8')) > MAX_BYTES or '\x00' in raw:
        raise AuditError('Rules assenti, troppo grandi o non testuali')
    lines=raw.splitlines()
    if len(lines)>MAX_LINES:raise AuditError('Troppe regole')
    stats=Counter()
    chain_hits=Counter()
    filter_table=False
    checks=[]
    seen=set()
    duplicates=[]
    rules=[]
    for lineno,line in enumerate(lines,1):
        t=line.strip()
        if t.startswith('*'):filter_table=t=='*filter'
        if t=='COMMIT':filter_table=False
        if not t.startswith('-A '):continue
        parts=t.split()
        if len(parts)<4:continue
        chain=parts[1]
        stats['rules']+=1
        if len(rules)<15000:rules.append((lineno,chain,t))
        chain_hits[chain]+=1
        if t in seen and len(duplicates)<20:duplicates.append(lineno)
        seen.add(t)
        if '-j LOG' in t or '-j NFLOG' in t or '-j ULOG' in t:stats['logging']+=1
        if '--match-set' in t:stats['ipset_lookups']+=1
        if '-m hashlimit' in t:stats['hashlimit']+=1
        if '-m recent' in t:stats['recent']+=1
        if 'NFQUEUE' in t or '-j QUEUE' in t:stats['userspace_queue']+=1
        if '-j TCPMSS' in t:stats['tcp_mss']+=1
        if ' -p udp ' in f' {t} ' and '--dport 443' in t and '-j DROP' in t:stats['quic_block']+=1
        if '-m string' in t or '-m layer7' in t:stats['payload_inspection']+=1
        if '-j TARPIT' in t:stats['tarpit']+=1
        if ' --hashlimit-above ' in t and ('kb/s' in t or 'mb/s' in t):stats['rate_drops']+=1
        if t.startswith(('-A INPUT ','-A FORWARD ','-A OUTPUT ')) and '-j LOG' in t:stats['hot_path_logs']+=1
        if filter_table and '--tcp-flags' in t and '-j LOG-DROP' in t:stats['tcp_flag_drop']+=1
    def add(code,level,title,detail,action,benefit):
        checks.append({'id':code,'priority':level,'title':title,'detail':detail,'recommendation':action,'security_tradeoff':benefit})
    if stats['rate_drops']:
        add('rate-drops','alto','Limiti di banda basati su DROP',
            'Il dropping di traffico oltre un limite può causare retransmission TCP, latenza e bassa velocità.',
            'Se CAKE gestisce la banda, disattivare bw_on dopo aver verificato i limiti realmente voluti.',
            'I limiti possono essere una policy deliberata per singolo host; conservarli dove necessari.')
    if stats['quic_block']:
        add('quic','alto','Blocco UDP 443 (QUIC/HTTP3)',
            'Può ritardare l’apertura di siti e video quando il fallback a TCP non è immediato.',
            'Valutare quic_block=0, salvo espressa esigenza anti-bypass.',
            'Se QUIC viene usato per aggirare controlli TLS/DNS, il blocco ha una funzione di sicurezza.')
    if stats['userspace_queue']:
        add('nfqueue','alto','Queue in userspace',
            'NFQUEUE può creare un collo di bottiglia quando il demone IDS/IPS non smaltisce i pacchetti.',
            'Verificare le statistiche IPS e profili fail-open/fail-closed prima di modificare.',
            'L’ispezione IPS potrebbe essere necessaria: non rimuovere automaticamente.')
    if stats['logging']>=15:
        add('logging','medio','Numerose regole di logging',
            'LOG/NFLOG può sovraccaricare CPU e disco sotto scansione o picchi.',
            'Ridurre bl_log, logdrop_on e log_drop o alzare i limiti dei messaggi; mantenere solo eventi importanti.',
            'Meno log riduce tracciabilità e auditing; non disabilita i DROP stessi.')
    if stats['ipset_lookups']>=24:
        add('ipsets','medio','Molte verifiche IPSet per pacchetto',
            'Ogni lookup è normalmente efficiente, ma decine di controlli e log in catene sempre percorse possono pesare.',
            'Consolidare liste equivalenti e privilegiare set source/dest appropriati. Non disabilitare liste di sicurezza senza misure.',
            'L’accorpamento richiede controllo di collisioni, aggiornamento e copertura delle blacklist.')
    if stats['tcp_flag_drop']>=5:
        add('tcpflags','medio','Regole TCP flag aggiuntive',
            'Controlli legacy duplicati rispetto a conntrack INVALID possono aumentare i confronti senza migliorare il filtraggio reale.',
            'Usare il solo INVALID con LOG limitato quando i test confermano la stessa protezione.',
            'Non rimuovere controlli anti-scan necessari su servizi pubblici.')
    if stats['tarpit']:
        add('tarpit','medio','TARPIT',
            'Richiede gestione di connessioni sospette e può caricare conntrack o kernel.',
            'Preferire un DROP se TARPIT non è giustificato da un’esigenza provata.',
            'Il TARPIT può avere un effetto deterrente limitato.')
    if duplicates:
        add('duplicates','basso','Regole testualmente duplicate',
            f'{len(duplicates)} possibili duplicati alle righe: '+', '.join(map(str,duplicates[:8])),
            'Valutare una singola occorrenza dopo verifica dell’ordine delle catene.',
            'Duplicati in catene diverse non devono essere unificati alla cieca.')
    if not checks:
        add('normal','basso','Nessun anti-pattern evidente',
            'La sola analisi statica non misura RTT, throughput, kernel CPU o interferenze.',
            'Confrontare contatori iptables, CPU, p95 RTT e traffico prima/dopo, senza cambiare le policy.',
            'Nessuna modifica automatica di sicurezza.')
    return {'ok':True,'read_only':True,'counts':dict(stats),'top_chains':chain_hits.most_common(10),
            'findings':checks,'notes':['Un numero alto di regole non prova da solo un rallentamento.',
            'CAKE influisce su qdisc, non è una regola iptables.','Nessun profilo viene modificato dall’audit.']}


def main():
    payload=sys.stdin.buffer.read(MAX_BYTES+1)
    if len(payload)>MAX_BYTES:raise AuditError('Rules troppo grandi')
    return analyze(payload.decode('utf-8'))

if __name__=='__main__':
    try:print(json.dumps(main(),ensure_ascii=False))
    except (AuditError,UnicodeError) as exc:
        print(json.dumps({'ok':False,'error':str(exc)},ensure_ascii=False));sys.exit(1)
