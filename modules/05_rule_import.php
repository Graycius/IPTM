<?php
// ===================== IMPORTAZIONE DELLE REGOLE ESISTENTI =====================
function norm_extra(string $x): string {   // stesso significato = stessa stringa: ignora -m tcp/udp/icmp, default recent/log/connlimit, ordine opzioni nei moduli
    preg_match_all('/"[^"]*"|\'[^\']*\'|\S+/', $x, $m); $w = $m[0]; $t = [];
    for ($i = 0, $n = count($w); $i < $n; $i++) {
        if ($w[$i] === '-m' && in_array($w[$i + 1] ?? '', ['tcp', 'udp', 'icmp'], true)) { $i++; continue; }
        // default xt_recent: mask host e rsource
        if ($w[$i] === '--mask' && ($w[$i + 1] ?? '') === '255.255.255.255') { $i++; continue; }
        if ($w[$i] === '--rsource' || $w[$i] === '--rdest') continue;
        if ($w[$i] === '--log-level' && ($w[$i + 1] ?? '') === '4') { $i++; continue; }
        if ($w[$i] === '--connlimit-saddr') continue;
        if ($w[$i] === '--tarpit') continue;
        $t[] = $w[$i];
    }
    $segs = [[]]; foreach ($t as $k) { if ($k === '-m') $segs[] = []; $segs[count($segs) - 1][] = $k; }
    $out = [];
    foreach ($segs as $seg) {
        if (!$seg) continue; $head = ''; if ($seg[0] === '-m') { $head = '-m ' . ($seg[1] ?? ''); $seg = array_slice($seg, 2); }
        $pairs = []; $cur = null; $neg = '';
        foreach ($seg as $k) { if ($k === '!') { $neg = '! '; continue; } if ($k[0] === '-') { if ($cur !== null) $pairs[] = $cur; $cur = $neg . $k; $neg = ''; } else $cur = ($cur === null ? '' : $cur . ' ') . $k; }
        if ($cur !== null) $pairs[] = $cur; sort($pairs); $out[] = trim($head . ' ' . implode(' ', $pairs));
    }
    return implode(' ', $out);
}
function rkey(string $r): string {   // chiave canonica di una regola (confronto fra regole scritte a mano, generate e lette dal kernel)
    $f = rule_parse($r); $f['extra'] = norm_extra($f['extra']); $f['targs'] = trim($f['targs']); return rule_build($f);
}
const OPT_LABEL = ['antispoof' => 'Anti-spoofing loopback', 'spoof_on' => 'Sorgenti spoofate per interfaccia', 'crowdsec' => 'CrowdSec / blacklist ipset', 'spi' => 'Firewall SPI (established + loopback)',
    'invalid' => 'Scarta pacchetti non validi e scansioni', 'icmp_limit' => 'ICMP con limite per sorgente', 'igmp_accept' => 'Accetta IGMP multicast', 'dos' => 'Anti SYN flood', 'ssh_acc' => 'Limiti SSH per rete',
    'closeports' => 'Scarta porte privilegiate', 'final_drop' => 'Scarta tutto il resto (catch-all)', 'logdrop_on' => 'Catena di log con limiti', 'raw_lo' => 'raw: loopback senza tracking',
    'raw_drop' => 'raw: scarta porte Windows/SSDP', 'dot_block' => 'Blocco DNS-over-TLS', 'conn_limit' => 'Limite connessioni per IP', 'rpfilter' => 'Reverse path filter (raw)', 'iso_on' => 'Isolamento tra reti', 'guest_on' => 'Rete ospiti', 'quic_block' => 'Blocco QUIC', 'lan_cl' => 'Limite connessioni per client', 'svc_ban' => 'Ban automatico servizi', 'bad_mss' => 'Scarta SYN con MSS anomalo', 'udp_rl' => 'Limite flussi UDP per sorgente', 'web_rl' => 'Limite connessioni web dal WAN', 'amp_block' => 'Blocco amplificazione UDP', 'mss' => 'Clamp MSS', 'dns_redirect' => 'Forza DNS locale', 'nat_masq' => 'NAT / Masquerade',
    'portscan' => 'Rilevamento port scan', 'bogon_wan' => 'Filtro bogon dal WAN', 'drop_frag' => 'Scarta frammenti IP', 'lan_flood' => 'Limite connessioni per client LAN',
    'egress_smtp' => 'Blocco SMTP in uscita', 'lockout_on' => 'Anti-lockout gestione', 'stealth' => 'Modalità stealth (solo DROP)', 'synproxy' => 'SYNPROXY anti SYN flood',
    'tarpit' => 'TARPIT su porte chiuse', 'dns_rebind' => 'Protezione DNS rebinding', 'raw_invalid' => 'Scarta INVALID in raw', 'arp_protect' => 'Protezione ARP (sysctl)', 'tcp_fastopen_off' => 'Disabilita TCP Fast Open', 'glob_new_limit' => 'Limite globale nuove connessioni'];

/** Analizza la bozza e elenca regole da ripulire (non modifica). */
function rules_cleanup_scan(array $M): array {
    $BUILTIN_T = ['ACCEPT','DROP','REJECT','RETURN','QUEUE','DNAT','SNAT','MASQUERADE','REDIRECT','LOG','ULOG','NFLOG','MARK','CONNMARK','TOS','DSCP','TCPMSS','CT','CHECKSUM','SET','NETMAP','TEE','IDLETIMER','AUDIT','CLASSIFY','NFQUEUE','TRACE','RATEEST','NOTRACK','SYNPROXY','TARPIT','SECMARK','CONNSECMARK','HMARK','LED','TPROXY','TCPOPTSTRIP'];
    $BAD_TARGET = ['PORTSCAN','PSCAN','SCAN']; // target non supportati / deprecati tipici di guide vecchie
    $findings = []; // list of [cat, severity, table, chain, idx, raw, why, managed]
    $defined = []; // table => chain => 1
    foreach ($M as $ti => $b) {
        if (($b['k'] ?? '') !== 'table') continue;
        $tn = $b['name'];
        foreach (BUILTIN[$tn] ?? [] as $bc) $defined[$tn][$bc] = 1;
        foreach ($b['items'] as $it) {
            if ($it['t'] === 'chain') $defined[$tn][$it['n']] = 1;
        }
    }
    // target/match disponibili sul kernel (best-effort; in CLI web può non vedere /proc)
    $missingTg = []; $missingM = [];
    $availT = []; $availM = [];
    foreach (['/proc/net/ip_tables_targets', '/proc/net/ip6_tables_targets'] as $f) {
        if (!is_file($f)) continue;
        foreach (preg_split('/\s+/', trim((string)@file_get_contents($f))) as $x) if ($x !== '') $availT[$x] = 1;
    }
    foreach (['/proc/net/ip_tables_matches', '/proc/net/ip6_tables_matches'] as $f) {
        if (!is_file($f)) continue;
        foreach (preg_split('/\s+/', trim((string)@file_get_contents($f))) as $x) if ($x !== '') $availM[$x] = 1;
    }
    // arricchisce con helper compat (sudo) se disponibile
    $probeT = ['TARPIT','SYNPROXY','NOTRACK','CT','SET','REJECT','DNAT','SNAT','MASQUERADE','TCPMSS','MARK','NFQUEUE'];
    $probeM = ['recent','conntrack','state','limit','hashlimit','multiport','set','rpfilter','mac','addrtype','comment','tcp','udp','icmp','connlimit','u32','cgroup'];
    try {
        $args = array_merge(array_map(fn($x) => 't:' . $x, $probeT), array_map(fn($x) => 'm:' . $x, $probeM));
        [, $co] = priv('compat', null, $args);
        foreach (explode("
", (string)$co) as $l) {
            $x = preg_split('/\s+/', trim($l));
            if (($x[0] ?? '') === 'target' && ($x[2] ?? '') === 'ok') $availT[$x[1]] = 1;
            if (($x[0] ?? '') === 'target' && ($x[2] ?? '') === 'missing') $missingTg[$x[1]] = 1;
            if (($x[0] ?? '') === 'match' && ($x[2] ?? '') === 'ok') $availM[$x[1]] = 1;
            if (($x[0] ?? '') === 'match' && ($x[2] ?? '') === 'missing') $missingM[$x[1]] = 1;
        }
    } catch (Throwable $e) { /* ignore */ }
    foreach ($probeT as $tg) {
        if (!isset($availT[$tg]) && !isset($missingTg[$tg]) && $availT) {
            // se abbiamo letto /proc e non c'è, marca missing (tranne target core quasi sempre presenti)
            if (!in_array($tg, ['REJECT','DNAT','SNAT','MASQUERADE','CT','SET','MARK','TCPMSS'], true)) $missingTg[$tg] = 1;
        }
    }
    foreach ($M as $ti => $b) {
        if (($b['k'] ?? '') !== 'table') continue;
        $tn = $b['name'];
        $items = $b['items'];
        $seen = []; // chain => key => first idx
        $term = []; // chain => true after catchall terminal
        foreach ($items as $i => $it) {
            if ($it['t'] !== 'rule') continue;
            $raw = $it['r'];
            $on = !empty($it['on']);
            $f = rule_parse($raw);
            $ch = $f['chain'] ?: '?';
            $tg = $f['target'] ?: '';
            $managed = in_region($items, $i);
            $base = ['ti' => $ti, 'i' => $i, 't' => $tn, 'c' => $ch, 'raw' => $raw, 'managed' => $managed, 'on' => $on];

            // disabled rules left around (optional noise)
            if (!$on) {
                $findings[] = $base + ['cat' => 'disabled', 'sev' => 'info', 'why' => 'Regola disattivata: candidata a rimozione se non serve più'];
                continue;
            }

            // duplicate exact (canonical key)
            $key = $ch . '|' . rkey($raw);
            if (isset($seen[$key])) {
                $findings[] = $base + ['cat' => 'duplicate', 'sev' => 'warn', 'why' => 'Duplicato esatto di una regola precedente nella stessa catena'];
                continue;
            }
            $seen[$key] = $i;

            // unreachable after terminal catch-all in same chain
            if (!empty($term[$ch])) {
                $findings[] = $base + ['cat' => 'unreachable', 'sev' => 'warn', 'why' => 'Irraggiungibile: dopo una regola catch-all (ACCEPT/DROP/REJECT) nella stessa catena'];
                continue;
            }
            if (catchall($f) && in_array($tg, ['ACCEPT','DROP','REJECT'], true)) $term[$ch] = true;


            // bad / obsolete targets
            if ($tg !== '' && in_array(strtoupper($tg), $BAD_TARGET, true)) {
                $findings[] = $base + ['cat' => 'bad_target', 'sev' => 'err', 'why' => "Target «{$tg}» non supportato/obsoleto (IPTM usa recent+DROP per port-scan)"];
            }
            // extension target missing in kernel
            if ($tg !== '' && isset($missingTg[$tg])) {
                $findings[] = $base + ['cat' => 'incompatible', 'sev' => 'err', 'why' => "Target «{$tg}» non disponibile in questo kernel (modulo assente o non caricato)"];
            }
            // match usati non disponibili (solo se helper ha detto missing)
            if (preg_match_all('/\s-m\s+([A-Za-z0-9_]+)/', $raw, $mm)) {
                foreach (array_unique($mm[1]) as $mod) {
                    if (isset($missingM[$mod])) {
                        $findings[] = $base + ['cat' => 'incompatible', 'sev' => 'err', 'why' => "Match «{$mod}» non disponibile nel kernel"];
                    }
                }
            }
            // target nella tabella sbagliata
            if ($tn === 'filter' && in_array($tg, ['DNAT', 'SNAT', 'MASQUERADE', 'REDIRECT', 'NOTRACK'], true)) {
                $findings[] = $base + ['cat' => 'incompatible', 'sev' => 'err', 'why' => "Target «{$tg}» non valido in tabella filter (usa nat o raw)"];
            }
            if ($tn === 'nat' && in_array($tg, ['SYNPROXY', 'TARPIT'], true)) {
                $findings[] = $base + ['cat' => 'incompatible', 'sev' => 'err', 'why' => "Target «{$tg}» non appartiene alla tabella nat (usa filter)"];
            }
            if ($tn === 'raw' && in_array($tg, ['DNAT', 'SNAT', 'MASQUERADE', 'SYNPROXY', 'TARPIT'], true)) {
                $findings[] = $base + ['cat' => 'incompatible', 'sev' => 'err', 'why' => "Target «{$tg}» non valido in tabella raw"];
            }
            if ($tn === 'nat' && in_array($tg, ['REJECT', 'DROP'], true) && !str_contains($raw, '-j ACCEPT')) {
                $findings[] = $base + ['cat' => 'incompatible', 'sev' => 'warn', 'why' => "«{$tg}» in tabella nat è spesso rifiutato o inutile: preferisci filter"];
            }

            // jump to undefined user chain
            if ($tg !== '' && !in_array($tg, $BUILTIN_T, true) && empty($defined[$tn][$tg])) {
                // could be chain in another table only for same table jumps
                $findings[] = $base + ['cat' => 'missing_chain', 'sev' => 'err', 'why' => "Salta a catena «{$tg}» non definita in tabella {$tn}"];
            }

            // useless: ACCEPT with no match when policy is already ACCEPT (soft)
            // skip - too aggressive

            // LOG without limit can be "noisy" - soft suggestion only for pure LOG catchall
            if ($tg === 'LOG' && catchall($f) && !str_contains($f['extra'] . $raw, 'limit')) {
                $findings[] = $base + ['cat' => 'noisy', 'sev' => 'info', 'why' => 'LOG su tutto il traffico senza -m limit: può riempire il journal'];
            }
        }
    }
    // orphan user chains IPTM-* never jumped to and not in standard path
    $jumped = [];
    foreach ($M as $b) {
        if (($b['k'] ?? '') !== 'table') continue;
        foreach ($b['items'] as $it) {
            if ($it['t'] !== 'rule' || empty($it['on'])) continue;
            $f = rule_parse($it['r']);
            if ($f['target'] !== '') $jumped[$b['name']][$f['target']] = 1;
        }
    }
    foreach ($M as $ti => $b) {
        if (($b['k'] ?? '') !== 'table') continue;
        foreach ($b['items'] as $i => $it) {
            if ($it['t'] !== 'chain') continue;
            $n = $it['n'];
            if (in_array($n, BUILTIN[$b['name']] ?? [], true)) continue;
            if (!empty($jumped[$b['name']][$n])) continue;
            // empty chain with no rules and never referenced
            $hasRules = false;
            foreach ($b['items'] as $it2) {
                if ($it2['t'] === 'rule' && !empty($it2['on']) && rchain($it2['r']) === $n) { $hasRules = true; break; }
            }
            if (!$hasRules) {
                $findings[] = ['ti' => $ti, 'i' => $i, 't' => $b['name'], 'c' => $n, 'raw' => ':' . $n, 'managed' => false, 'on' => true, 'cat' => 'orphan_chain', 'sev' => 'info', 'why' => "Catena «{$n}» senza regole e mai referenziata"];
            }
        }
    }
    $byCat = [];
    foreach ($findings as $f) $byCat[$f['cat']] = ($byCat[$f['cat']] ?? 0) + 1;
    $incompat = array_values(array_filter($findings, fn($f) => in_array($f['cat'], ['incompatible', 'bad_target', 'missing_chain'], true)));
    return [
        'findings' => $findings,
        'by_cat' => $byCat,
        'total' => count($findings),
        'incompatible' => $incompat,
        'incompatible_n' => count($incompat),
        'modules_missing' => array_keys($missingTg + $missingM),
    ];
}

/** Rimuove dalla bozza le findings selezionate per categoria. Non tocca le regioni gestite salvo se $includeManaged. */
function rules_cleanup_apply(array &$M, array $cats, bool $includeManaged = false): array {
    $scan = rules_cleanup_scan($M);
    $want = array_fill_keys($cats, true);
    // collect indices per table, descending
    $del = []; // ti => [i,…]
    $done = [];
    foreach ($scan['findings'] as $f) {
        if (empty($want[$f['cat']])) continue;
        if (!empty($f['managed']) && !$includeManaged) continue;
        // non eliminare definizioni chain built-in
        if (($f['cat'] ?? '') === 'orphan_chain' && in_array($f['c'] ?? '', BUILTIN[$f['t']] ?? [], true)) continue;
        $del[$f['ti']][] = $f['i'];
        $done[] = $f;
    }
    foreach ($del as $ti => $idxs) {
        $idxs = array_values(array_unique($idxs));
        rsort($idxs, SORT_NUMERIC);
        foreach ($idxs as $i) {
            if (!isset($M[$ti]['items'][$i])) continue;
            array_splice($M[$ti]['items'], $i, 1);
        }
    }
    return ['removed' => count($done), 'items' => $done];
}


/** Elenca regole personalizzate (fuori dai blocchi # >>> IPTM). */
function custom_rules_list(array $M): array {
    $out = [];
    foreach ($M as $ti => $b) {
        if (($b['k'] ?? '') !== 'table') continue;
        $items = $b['items'];
        foreach ($items as $i => $it) {
            if ($it['t'] !== 'rule') continue;
            if (in_region($items, $i)) continue;
            $f = rule_parse($it['r']);
            $out[] = [
                'ti' => $ti, 'i' => $i, 't' => $b['name'], 'c' => $f['chain'] ?: '?',
                'on' => !empty($it['on']), 'raw' => $it['r'], 'f' => $f, 'k' => rkey($it['r']),
            ];
        }
    }
    return $out;
}

/**
 * Prova a integrare regole personalizzate nelle impostazioni generate.
 * Restituisce: integrabili (con patch S), residue, e indici da rimuovere dalla bozza.
 */
function custom_rules_integrate_plan(array $M, array $S): array {
    $list = custom_rules_list($M); $can = []; $left = []; $remove = []; $S2 = $S;
    foreach ($list as $row) {
        if (empty($row['on'])) { $left[] = $row + ['why' => 'disattivata — gestisci da editor o pulizia']; continue; }
        $how = manual_map_row($row, $S2);
        if ($how !== null) { $can[] = $row + ['how' => $how]; $remove[] = [$row['ti'], $row['i']]; }
        else $left[] = $row + ['why' => 'troppo specifica o non mappabile (resta personalizzata)'];
    }
    return ['total_custom' => count($list), 'can' => $can, 'left' => $left, 'remove' => $remove, 'S' => $S2, 'n_can' => count($can), 'n_left' => count($left)];
}

/** Applica il piano: aggiorna S, toglie regole integrate, rigenera blocchi gestiti. */
function custom_rules_integrate_apply(array &$M, array $S, array $plan): array {
    if (empty($plan['can'])) return ['ok' => true, 'msg' => 'Niente da integrare'];
    $S2 = $plan['S'] ?? $S;
    // rimuovi regole integrate (indici decrescenti)
    $byTi = [];
    foreach ($plan['remove'] as [$ti, $i]) $byTi[$ti][] = $i;
    foreach ($byTi as $ti => $idxs) {
        rsort($idxs, SORT_NUMERIC);
        foreach ($idxs as $i) {
            if (isset($M[$ti]['items'][$i])) array_splice($M[$ti]['items'], $i, 1);
        }
    }
    S_put($S2);
    $warn = regen($M, $S2);
    return ['ok' => true, 'msg' => 'Integrate ' . count($plan['can']) . ' regole nelle impostazioni e rigenerati i blocchi IPTM', 'warn' => $warn, 'S' => $S2];
}

