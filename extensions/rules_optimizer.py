#!/usr/bin/env python3
"""IPTM rules.v4 static policy audit and in-memory draft hardening.

No root commands, files, iptables calls, network access, or writes.
Only recognises ipsave text; opaque and unknown lines remain byte-identical.
Run: python3 rules_optimizer.py audit|harden|conservative < rules.v4
"""
from __future__ import annotations
import hashlib
import ipaddress
import json
import re
import shlex
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass

MAX_INPUT = 2 * 1024 * 1024
RISKY_STATE = ('-m recent', '-m hashlimit', '-m limit', '-m statistic', '-m connlimit',
               '-m quota', '-m connbytes', '-m nth', '-j LOG', '-j NFLOG', '-j SET', '-j MARK')
MANAGED_BEGIN = re.compile(r'^# >>> IPTM:([a-zA-Z0-9_.-]+)\b')
MANAGED_END = re.compile(r'^# <<< IPTM:([a-zA-Z0-9_.-]+)\b')
MAC_RX = re.compile(r'(?i)^([0-9a-f]{2}:){5}[0-9a-f]{2}$')

@dataclass
class R:
    index: int
    table: str
    chain: str
    section: str
    text: str
    tokens: list[str]
    target: str

    def option(self, *names):
        for x in names:
            try:
                i = self.tokens.index(x)
                if i + 1 < len(self.tokens):
                    return self.tokens[i + 1]
            except ValueError:
                continue
        return ''

    def ports(self):
        raw = self.option('--dport', '--dports', '--destination-port', '--destination-ports')
        result: set[int] = set()
        for item in raw.split(','):
            if item.isdigit():
                n = int(item)
                if 0 <= n <= 65535:
                    result.add(n)
            elif ':' in item:
                lo, _, hi = item.partition(':')
                if lo.isdigit() and hi.isdigit() and 0 <= int(lo) <= int(hi) <= 65535:
                    if int(hi) - int(lo) <= 65535:
                        result.update(range(int(lo), int(hi) + 1))
        return result

    def source(self):
        return self.option('-s', '--source')

    def proto(self):
        return self.option('-p', '--protocol')

    def mac(self):
        return self.option('--mac-source').lower()

    def unrestricted(self):
        # Destination narrowing is NOT a source restriction: SSH on the WAN
        # address remains reachable from the Internet. 0/0 is no restriction.
        if self.option('-i', '--in-interface', '--mac-source', '--src-range'):
            return False
        source = self.source()
        return source in ('', '0.0.0.0/0', '0/0', '0.0.0.0', 'anywhere')


def parse(text):
    lines = text.splitlines(keepends=True)
    rules: list[R] = []
    table = ''
    section = ''
    chains = defaultdict(set)
    warnings = []
    tables = set()
    for i, raw in enumerate(lines):
        s = raw.strip()
        if s.startswith('*'):
            table = s[1:]
            tables.add(table)
            section = ''
        elif s == 'COMMIT':
            table = ''
            section = ''
        elif table and s.startswith(':'):
            chains[table].add(s[1:].split(None, 1)[0])
        else:
            m = MANAGED_BEGIN.match(s)
            if m:
                section = m.group(1)
            elif MANAGED_END.match(s):
                section = ''
            if table and s.startswith('-A '):
                try:
                    tok = shlex.split(s, posix=True)
                except ValueError:
                    warnings.append({'id':'SYNTAX_UNPARSEABLE','severity':'high','line':i+1,'message':'Regola non analizzabile, mantenuta senza modifiche'})
                    continue
                if len(tok) < 3:
                    warnings.append({'id':'SYNTAX_SHORT','severity':'high','line':i+1,'message':'Regola incompleta'})
                    continue
                target = ''
                for j in range(len(tok)-1):
                    if tok[j] in ('-j','--jump','-g','--goto'):
                        target = tok[j+1]
                        break
                rules.append(R(i, table, tok[1], section, s, tok, target))
    return lines, rules, chains, tables, warnings


def cidr_nets(rules):
    nets = []
    for r in rules:
        if r.section not in ('lockout', 'ssh-acc', 'lan-tcp', 'dns-redir', 'nat-masq'):
            continue
        for val in r.source().split(','):
            if not val:
                continue
            try:
                net = ipaddress.ip_network(val, strict=False)
                if isinstance(net, ipaddress.IPv4Network) and net.is_private and net.prefixlen >= 8 and net not in nets:
                    nets.append(net)
            except ValueError:
                pass
    return nets


def parse_ports(raw):
    return {int(x) for x in re.findall(r'(?<!\d)\d{1,5}(?!\d)', raw) if int(x) <= 65535}


def analyze(original):
    lines, rules, chains, tables, warnings = parse(original)
    findings = list(warnings)
    changes = []
    removed = set()
    replaced = {}
    section_rules = defaultdict(list)
    by_chain = defaultdict(list)
    for r in rules:
        section_rules[(r.table, r.section)].append(r)
        by_chain[(r.table, r.chain)].append(r)
    lan = cidr_nets(rules)

    def report(id, sev, message, rs=(), fix='manual', extra=None):
        linesp = sorted({r.index+1 for r in rs})
        rec = {'id':id, 'severity':sev,'message':message,'lines':linesp,'resolution':fix}
        if extra:
            rec['details'] = extra
        findings.append(rec)

    def discard(r, reason):
        if r.index in removed:
            return
        removed.add(r.index)
        changes.append({'action':'remove','line':r.index+1,'reason':reason})

    # Legacy ssh-acc applied the recent/connlimit match to *every packet*.
    # Established sessions hit the threshold and were dropped before the SPI
    # rule. Narrow IPTM-owned matching to NEW SYN attempts only.
    old_ssh = [r for r in section_rules[('filter','ssh-acc')]
               if r.chain == 'INPUT' and r.proto() == 'tcp' and
               ('-m recent' in r.text or '-m connlimit' in r.text) and
               '--ctstate' not in r.tokens]
    if old_ssh:
        report('SSH_ESTABLISHED_RATE_LIMIT','critical',
               'Il limite SSH conta anche pacchetti di sessioni aperte: provoca disconnessioni dopo alcuni pacchetti.',
               old_ssh,'automatic')
        for rule in old_ssh:
            fixed=re.sub(r'(--dport\s+\d+)\b',r'\1 -m conntrack --ctstate NEW --syn',rule.text,count=1)
            if fixed!=rule.text:
                replaced[rule.index]=fixed
                changes.append({'action':'rewrite','line':rule.index+1,
                                'reason':'Limita recent/connlimit soltanto ai nuovi SYN SSH'})

    # Generated SSH rules without source/interface restrictions can expose remote administration.
    open_ssh = [r for r in by_chain[('filter','INPUT')] if r.target == 'ACCEPT'
                and r.proto() == 'tcp' and 22 in r.ports() and r.unrestricted()]
    physical_ssh = [r for r in by_chain[('filter','INPUT')]
                    if r.target == 'ACCEPT' and r.proto() == 'tcp' and 22 in r.ports()
                    and not r.source() and r.option('-i','--in-interface')
                    and not r.option('-i','--in-interface').startswith(('lo','wg','tun','tailscale','zt'))]
    if physical_ssh:
        report('SSH_INTERFACE_ONLY','high',
            'SSH autorizzato in base alla sola interfaccia fisica: su WAN o Single-NIC può essere raggiungibile da reti non fidate.',
            physical_ssh,'manual')
    if open_ssh:
        own = [r for r in open_ssh if r.section in ('svc-in-a', 'svc-in-b', 'apps')]
        report('SSH_GLOBAL','critical','SSH TCP/22 permesso senza limiti di origine o interfaccia.',open_ssh,
               'automatic' if len(own)==len(open_ssh) and lan else 'manual')
        if lan:
            for r in own:
                discard(r,'Rimuove SSH globale: le eccezioni di gestione LAN già presenti restano invariate')

    broad_lan = [r for r in by_chain[('filter','INPUT')] if r.section=='lan-tcp' and r.target=='ACCEPT'
                 and r.proto()=='tcp' and not r.ports()]
    if broad_lan:
        report('LAN_ANY_TCP','critical','Una regola permette ogni porta TCP dalla LAN, scavalcando i permessi delle applicazioni.',broad_lan,'automatic')
        for r in broad_lan:
            discard(r,'Rimuove l’accesso TCP generico; conserva aperture dei singoli servizi')

    docker_ports = [r for r in by_chain[('filter','INPUT')] if r.section=='apps'
                    and 'IPTM-app:docker' in r.text and r.target=='ACCEPT' and ({2375,2376}&r.ports())]
    if docker_ports:
        report('DOCKER_API','critical','Apertura dell’API Docker TCP/2375 o 2376: accesso amministrativo al demone.',docker_ports,'automatic')
        for r in docker_ports:
            discard(r,'Rimuove l’apertura dell’API Docker dal profilo apps')
    docker_host = [r for r in by_chain[('filter','INPUT')] if r.section in ('docker-net','svc-in-b','svc-in-a')
                   and r.target=='ACCEPT' and r.proto()=='' and r.source() and r.source().startswith('172.16.')]
    if docker_host:
        report('DOCKER_BROAD_HOST','high','Una subnet Docker può accedere a tutte le porte dell’host.',docker_host,'manual')
        # Preserve to avoid interrupting legitimate host-container communication.

    # raw drop precedes filter accept regardless of chain order.
    raw1900 = [r for r in by_chain[('raw','PREROUTING')] if r.section=='raw-drop' and r.proto()=='udp'
               and r.target=='DROP' and 1900 in r.ports()]
    ssdp_accept = [r for r in by_chain[('filter','INPUT')] if r.target=='ACCEPT'
                   and r.proto()=='udp' and 1900 in r.ports()]
    if raw1900 and ssdp_accept:
        unsafe_raw = [r for r in raw1900 if not r.option('-i','--in-interface')]
        report('SSDP_RAW_CONFLICT','high',
               'SSDP UDP/1900 è scartato in raw: se raw è sulla WAN dedicata, la regola LAN può essere intenzionale.',
               raw1900+ssdp_accept,'automatic' if unsafe_raw else 'manual')
        for r in unsafe_raw:
            raw = r.option('--dports','--dport')
            parts = raw.split(',')
            if '1900' not in parts:
                continue
            remaining = [p for p in parts if p!='1900']
            if remaining:
                new = r.text.replace(raw, ','.join(remaining), 1)
                replaced[r.index] = new
                changes.append({'action':'rewrite','line':r.index+1,'reason':'Rimuove SSDP dal drop raw; il filtro INPUT mantiene le aperture LAN'})
            else:
                discard(r,'Rimuove il drop raw completo su SSDP; INPUT resta default-DROP')

    # Correlate raw DROP with any later filter INPUT allow, not just SSDP.
    # Only rewrite IPTM-owned raw-drop and only ports explicitly permitted by INPUT.
    for rr in by_chain[('raw','PREROUTING')]:
        if rr.section != 'raw-drop' or rr.target != 'DROP' or rr.proto() not in ('tcp','udp'):
            continue
        if rr.option('-i','--in-interface'):
            # WAN-only raw DROP and LAN-only INPUT ACCEPT are not a conflict.
            # The network inventory, not this text file, defines their boundary.
            continue
        if rr.proto() == 'udp' and rr in raw1900 and ssdp_accept:
            continue  # SSDP already handled above.
        allowed_ports = set()
        involved = []
        for ar in by_chain[('filter','INPUT')]:
            if ar.target == 'ACCEPT' and ar.proto() == rr.proto() and ar.ports():
                overlap = rr.ports() & ar.ports()
                if overlap and (ar.source() or ar.option('-i')):
                    allowed_ports.update(overlap)
                    involved.append(ar)
        if not allowed_ports:
            continue
        report('RAW_FILTER_CONFLICT','high',
            'Il blocco raw impedisce porte che il filtro INPUT consente ('
            + rr.proto() + ': ' + ','.join(map(str,sorted(allowed_ports))) + ').',
            [rr]+involved[:3], 'automatic')
        raw = rr.option('--dports','--dport')
        if not all(p.isdigit() for p in raw.split(',')):
            findings[-1]['resolution'] = 'manual'
            continue  # mixed port ranges/names require a policy-specific rewrite
        left = [p for p in raw.split(',') if int(p) not in allowed_ports]
        if len(left) == len(raw.split(',')):
            continue
        if left:
            new = rr.text.replace(raw, ','.join(left), 1)
            replaced[rr.index] = new
            changes.append({'action':'rewrite','line':rr.index+1,
                            'reason':'Conserva i blocchi raw sulle porte non abilitate dalla LAN'})
        else:
            discard(rr,'Rimuove la regola raw in conflitto con il filtro INPUT')

    # Detect a wide ACCEPT hiding restrictive rules later in the same chain.
    for (table,chain), rr in by_chain.items():
        if table!='filter' or chain not in ('INPUT','FORWARD','OUTPUT'):
            continue
        for i,r in enumerate(rr):
            if r.target!='ACCEPT':
                continue
            if r.proto()=='' and r.source()=='' and r.option('-i')=='':
                continue
            later = [q for q in rr[i+1:] if q.target in ('DROP','REJECT','LOG-DROP')]
            if chain=='FORWARD' and r.option('-o') and not r.ports() and later:
                targeted=[q for q in later if q.proto() and q.ports()]
                if targeted:
                    report('FORWARD_SHADOW','high','ACCEPT di transito anticipato può scavalcare blocchi su porte/protocolli successivi.',[r]+targeted[:3],'manual')
                    break

    # Move generated dot block before unconditional LAN/WG outbound ACCEPT in FORWARD.
    dot_section = [r for r in section_rules[('filter','dot')] if r.chain=='FORWARD' and r.target in ('DROP','REJECT')]
    preemptive = [r for r in by_chain[('filter','FORWARD')] if r.target=='ACCEPT'
                  and r.section in ('lan-out','svc-fwd','wg-fwd')]
    dot_early = bool(dot_section and preemptive and min(r.index for r in dot_section)>min(r.index for r in preemptive))
    if dot_early:
        report('DOT_SHADOW','high','Il blocco DoT/853 arriva dopo un ACCEPT di transito.',dot_section+preemptive[:2],'automatic')

    # IPTM-MAC-FWD is a first-match terminal gate; a second FORWARD policy is not always redundant.
    chainjump={r.mac() for r in by_chain[('filter','FORWARD')] if r.target=='IPTM-MAC-FWD' and MAC_RX.fullmatch(r.mac())}
    chaininput={r.mac() for r in by_chain[('filter','INPUT')] if r.target=='IPTM-MAC-IN' and MAC_RX.fullmatch(r.mac())}
    dnsnat={r.mac() for r in by_chain[('nat','PREROUTING')] if r.target=='DNAT' and MAC_RX.fullmatch(r.mac())}
    policy={r.mac() for r in by_chain[('filter','FORWARD')] if r.section.startswith('iot-') and MAC_RX.fullmatch(r.mac())}
    for id, got in [('IOT_FWD_MISSING', policy-chainjump), ('IOT_INPUT_MISSING',policy-chaininput),('IOT_DNAT_MISSING',policy-dnsnat)]:
        if got:
            report(id,'high' if id=='IOT_FWD_MISSING' else 'medium',
                'Alcuni MAC IoT hanno policy FORWARD ma non appartengono al gruppo '+{'IOT_FWD_MISSING':'isolamento forte','IOT_INPUT_MISSING':'controlli INPUT','IOT_DNAT_MISSING':'DNS DNAT'}[id]+'.',
                [r for r in by_chain[('filter','FORWARD')] if r.mac() in got][:4], 'manual',{'mac':sorted(got)})
    if policy & chainjump:
        report('IOT_DUAL_POLICY','medium','Policy IoT per MAC in FORWARD coesiste con il salto IPTM-MAC-FWD: possibile sovrapposizione (non sempre equivalente).',
            [r for r in by_chain[('filter','FORWARD')] if r.mac() in policy & chainjump][:4],'manual')

    appnames={}
    for r in by_chain[('filter','INPUT')]:
        if 'IPTM-app:' in r.text:
            m=re.search(r'IPTM-app:([\w-]+)',r.text)
            if m:
                appnames.setdefault(m.group(1),set()).add((r.proto(), tuple(sorted(r.ports()))))
    dnsprofiles={'adguard','pihole','unbound','dnsmasq'} & set(appnames)
    if len(dnsprofiles)>1:
        report('DNS_PROFILES','medium','Profili DNS sovrapposti: il firewall non dimostra che i programmi siano tutti in ascolto.',
               [r for r in by_chain[('filter','INPUT')] if any('IPTM-app:'+p in r.text for p in dnsprofiles)][:4], 'manual',{'profiles':sorted(dnsprofiles)})

    # Broad structural hazards: report only, do not rewrite custom rules or
    # invent routing/interface identities from an offline iptables-save file.
    global_raw = [r for r in by_chain[('raw','PREROUTING')]
                  if r.target == 'DROP' and r.proto() in ('tcp','udp')
                  and not r.option('-i','--in-interface')]
    if global_raw:
        report('RAW_ALL_INTERFACES','high',
               'Filtro raw applicato su tutte le interfacce: può bloccare LAN, discovery o servizi prima di INPUT/FORWARD.',
               global_raw[:5], 'manual')
    global_snat = [r for r in by_chain[('nat','POSTROUTING')]
                   if r.target in ('MASQUERADE','SNAT') and not r.source()
                   and not r.option('-j','--jump') == 'RETURN']
    if global_snat:
        report('GLOBAL_SNAT','high',
               'NAT senza subnet di origine: valutare Docker, WireGuard, hairpin NAT e traffico locale.',
               global_snat[:5], 'manual')
    generic_host = [r for r in by_chain[('filter','INPUT')]
                    if r.target == 'ACCEPT' and r.proto() in ('tcp','udp')
                    and not r.ports() and r.section != 'spi-in'
                    and not r.option('--ctstate') and not r.option('-i') == 'lo']
    if generic_host:
        report('HOST_PROTOCOL_ALL_PORTS','critical',
               'Tutte le porte TCP/UDP vengono consentite a una sorgente; preferire accessi per porta e interfaccia.',
               generic_host[:5], 'manual')
    broad_forward = [r for r in by_chain[('filter','FORWARD')]
                     if r.target == 'ACCEPT' and not r.option('-o','--out-interface')
                     and not r.option('-d','--destination') and not r.ports()
                     and (r.source() or r.option('-i'))]
    if broad_forward:
        report('FORWARD_UNBOUNDED','high',
               'FORWARD senza destinazione e interfaccia di uscita può consentire transiti tra reti non previsti.',
               broad_forward[:5], 'manual')
    # Direct host SNAT with a same-interface DNS DNAT can be intentional hairpin NAT.
    hostmasq=[r for r in by_chain[('nat','POSTROUTING')] if r.section.startswith('cust-') and r.target=='MASQUERADE' and r.source()]
    if hostmasq:
        report('SINGLE_NIC_SNAT','medium','MASQUERADE per singoli client sulla stessa interfaccia: controllare NAT hairpin e percorsi LAN↔LAN.',hostmasq[:3],'manual')

    # Source-only LAN rules do not authenticate the ingress network on a
    # shared physical NIC: require topology/rp_filter review rather than
    # inventing an interface rule that might lock out remote administrators.
    lan_trust = [r for r in by_chain[('filter','INPUT')] if r.target=='ACCEPT' and
                 r.source() and not r.option('-i','--in-interface') and
                 r.section in ('lockout','svc-in-a','apps','ssh-acc')]
    if lan_trust:
        report('SOURCE_TRUST_NO_INTERFACE','medium',
            'Eccezioni per IP sorgente senza controllo dell’interfaccia: su Single-NIC verificare spoofing LAN/WAN e gateway.',
            lan_trust[:3], 'manual')
    fw_wide = [r for r in by_chain[('filter','FORWARD')] if r.target=='ACCEPT' and
               r.section in ('lan-out','svc-fwd','wg-fwd') and not r.ports() and
               (r.source() or r.option('-i','--in-interface'))]
    if fw_wide:
        report('FORWARD_WIDE_ACCEPT','medium',
            'Transito esteso verso WAN/VPN: le regole DROP che lo seguono potrebbero non essere raggiunte.',
            fw_wide[:3], 'manual')

    # A few combinations require system state that an offline rules file cannot prove.
    vpnwide=[r for r in by_chain[('filter','INPUT')] if r.target=='ACCEPT' and
             r.option('-i') in ('wg0','tun0','tailscale0') and not r.ports()]
    if vpnwide:
        report('VPN_HOST_ANY','medium','La VPN può raggiungere ogni porta dell’host: usare policy granulari se la VPN include client non fidati.',vpnwide,'manual')
    alg=[r for r in by_chain[('raw','PREROUTING')] if r.target=='CT' and r.option('--helper') in ('ftp','sip','tftp')]
    if alg:
        report('ALG_CONNTRACK','medium','Helper FTP/SIP/TFTP in raw senza limiti di rete: mantenerli solo se necessari.',alg[:3],'manual')
    bld=[r for r in by_chain[('filter','OUTPUT')] if r.target=='IPTM-BLD']
    if bld:
        report('OUTPUT_BLOCKLIST','info','Le liste di uscita possono bloccare DNS, aggiornamenti e servizi locali: verificare le esclusioni e gli ipset attivi.',bld,'manual')
    if any(r.target=='DNAT' and r.option('--to-destination').startswith('192.168.') for r in by_chain[('nat','PREROUTING')]):
        report('DNS_REDIR_ROUTING','medium','DNAT verso DNS locale: verificare indirizzo del resolver, percorso di ritorno e regole OUTPUT/INPUT.',(),'manual')
    if any(r.proto()=='udp' and r.target in ('DROP','REJECT') and 443 in r.ports() for r in by_chain[('filter','FORWARD')]):
        report('DOH_QUIC_SCOPE','info','Bloccare QUIC/DoT non impedisce in assoluto DoH via HTTPS TCP/443 e non copre automaticamente IPv6.',(),'manual')
    if len(rules) > 20000:
        raise ValueError('Numero di regole superiore al limite dell’analizzatore (20000)')

    # management allow earlier than inspections (private LAN excepted from blacklist).
    lockout = section_rules[('filter','lockout')]
    sshacc = section_rules[('filter','ssh-acc')]
    if lockout and sshacc and min(r.index for r in sshacc) > min(r.index for r in lockout):
        report('SSH_RATE_SHADOW','high','Il permesso di gestione SSH precede le regole connlimit/recent, rendendole inefficaci sui client autorizzati.',lockout[:2]+sshacc[:2],'automatic')

    # Deduplicate only identical stateless allow/drop rules within the same generated section.
    duplicate_count=0
    seen={}
    for r in rules:
        if r.index in removed or r.index in replaced or not r.section:
            continue
        if r.target not in ('ACCEPT','DROP','REJECT') or any(x in r.text for x in RISKY_STATE):
            continue
        key=(r.table,r.chain,r.section,' '.join(r.tokens))
        if key in seen:
            duplicate_count+=1
            discard(r,'Elimina il duplicato esatto privo di effetti laterali')
        else:
            seen[key]=r.index
    if duplicate_count:
        report('EXACT_DUPLICATE','low',f'{duplicate_count} duplicati identici senza effetti collaterali eliminabili.',(),'automatic')

    if 'filter' in tables and not any(r.chain=='OUTPUT' for r in rules):
        report('OUTPUT_POLICY','info','Controllare anche la policy della catena OUTPUT: può restare ACCEPT volutamente.',(),'manual')
    report('IPV6_SCOPE','info','Il file analizzato è solo IPv4: IPv6 richiede un audit separato di rules.v6 e dell’eventuale disattivazione kernel.',(),'manual')
    report('L2_BOUNDARY','info','L’isolamento MAC funziona sui pacchetti che attraversano IPTM; i dispositivi sullo stesso segmento Ethernet possono comunicare direttamente.',(),'manual')

    # Reordering only complete adjacent owned sections is safe to compose.
    move = []
    def block_span(tag):
        starts=[];ends=[]
        for i, line in enumerate(lines):
            ma=MANAGED_BEGIN.match(line.strip()); mb=MANAGED_END.match(line.strip())
            if ma and ma.group(1)==tag: starts.append(i)
            if mb and mb.group(1)==tag: ends.append(i)
        return (starts[0],ends[0]) if len(starts)==len(ends)==1 and starts[0]<ends[0] else None

    if dot_early:
        dot=block_span('dot')
        anchor=min((r.index for r in preemptive), default=-1)
        if dot and anchor>=0 and dot[0]>anchor:
            for tag in ('lan-out','wg-fwd','svc-fwd'):
                span=block_span(tag)
                if span and span[0]<=anchor<=span[1]:
                    anchor=span[0];break
            move.append((dot[0],dot[1],anchor,'Porta il blocco DoT prima dei permessi FORWARD ampi'))

    if lockout and sshacc:
        ssh=block_span('ssh-acc')
        lock=block_span('lockout')
        if ssh and lock and ssh[0]>lock[0]:
            move.append((ssh[0],ssh[1],lock[0],'Esegue i limiti SSH prima della deroga di gestione LAN'))

    if move:
        # Apply move in descending source order using original indexes mapped by identity.
        moves = sorted(move,key=lambda x:x[0],reverse=True)
        for start,end,anchor,msg in moves:
            if start==anchor:
                continue
            block=[(i,lines[i]) for i in range(start,end+1)]
            # Track by original indices; render in one pass using anchors.
            changes.append({'action':'move','line':start+1,'before_line':anchor+1,'reason':msg})
        moves_map={s:(e,a) for s,e,a,_ in moves}
        insert_map=defaultdict(list)
        moved={}
        for s,e,a,_ in moves:
            insert_map[a].extend(range(s,e+1))
            moved.update({i:True for i in range(s,e+1)})
    else:
        insert_map=defaultdict(list)
        moved={}

    newlines=[]
    for idx,raw in enumerate(lines):
        for src in insert_map[idx]:
            if src not in removed:
                text=replaced.get(src,lines[src].rstrip('\n'))
                newlines.append(text+(('\n' if lines[src].endswith('\n') else '')) if src in replaced else lines[src])
        if idx in moved or idx in removed:
            continue
        if idx in replaced:
            newlines.append(replaced[idx]+('\n' if raw.endswith('\n') else ''))
        else:
            newlines.append(raw)

    # Reparse the proposed document to ensure no broken marker pairs/table structures.
    candidate=''.join(newlines)
    if any(candidate.count(x)!=original.count(x) for x in ('*filter','*nat','COMMIT')):
        raise ValueError('La bozza prodotta non conserva le tabelle del file originale')
    src_lines,__,___,____,_____ = parse(candidate)
    if len(src_lines)!=len(newlines):
        raise ValueError('Incoerenza di generazione')

    # Advisory settings only; user can choose to synchronize when saving draft.
    settings_patch={}
    if broad_lan:
        settings_patch['lan_tcp_accept']=0
    if docker_ports:
        settings_patch['apps_remove']=['docker']
    if raw1900 and ssdp_accept:
        settings_patch['raw_udp_remove']=['1900']
    if open_ssh:
        settings_patch['svc_in_remove_unscoped_ssh']=True
    if docker_host:
        settings_patch['docker_accept']=0  # only if user explicitly opts into full hardening

    return {'ok':True,'source_sha256':hashlib.sha256(original.encode()).hexdigest(),
            'original_rules':len(rules),'new_rules':len([r for r in parse(candidate)[1]]),
            'original_bytes':len(original.encode()),'new_bytes':len(candidate.encode()),
            'changes':changes,'findings':findings,'settings_patch':settings_patch,
            'draft':candidate,'lan_nets':list(map(str,lan)),
            'warnings':['Le modifiche non vengono applicate al kernel. Le impostazioni IPTM possono rigenerare le sezioni gestite.',
                        'Le decisioni sui MAC mancanti, servizi in ascolto, VPN e Docker richiedono inventario locale.']}


def main():
    mode=sys.argv[1] if len(sys.argv)>1 else 'audit'
    if mode not in ('audit','harden','conservative'):
        print(json.dumps({'ok':False,'error':'Modalità non supportata'}));return 2
    data=sys.stdin.buffer.read(MAX_INPUT+1)
    if len(data)>MAX_INPUT or b'\0' in data:
        print(json.dumps({'ok':False,'error':'File non supportato o troppo grande'}));return 2
    try:
        source=data.decode('utf-8-sig')
        if not source.strip() or not source.startswith(('#','*')) or '*filter' not in source or 'COMMIT' not in source:
            raise ValueError('Formato iptables-save non riconosciuto')
        result=analyze(source)
        if mode=='audit':
            result['draft']=source
            result['changes']=[]
            result['new_rules']=result['original_rules']
        if mode=='conservative':
            # Never modify source text in conservative mode: audit-only (no policy changes).
            result['draft']=source
            result['changes']=[]
            result['new_rules']=result['original_rules']
        print(json.dumps(result,ensure_ascii=False))
        return 0
    except Exception as exc:
        print(json.dumps({'ok':False,'error':'Analisi interrotta: '+str(exc)},ensure_ascii=False))
        return 1

if __name__=='__main__':
    sys.exit(main())
