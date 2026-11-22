<?php
// ===================== REGOLE MANUALI: analisi, conversione verificata, opzioni personalizzate =====================
// Una regola manuale (fuori dai blocchi IPTM) può: (a) diventare una opzione/riga già presente, (b) diventare una NUOVA opzione personalizzata
// (settings['custom_opts'], attivabile/disattivabile come le altre), (c) essere eliminata se ridondante. Ogni conversione è PROVATA:
// si rigenera la bozza e si confronta il comportamento (sem_model) con quello attuale; senza equivalenza non viene proposta come «esatta».
function manual_map_row(array $row, array &$S): ?string {   // esprime una regola manuale con le opzioni esistenti: modifica $S e descrive, null se non mappabile
    $f = $row['f']; $tg = $f['target'] ?? ''; $raw = $row['raw'] ?? '';
    $ls = fn(string $k) => preg_split('/[\s,;]+/', trim((string)($S[$k] ?? '')), -1, PREG_SPLIT_NO_EMPTY) ?: [];
    if (runtime_chain($row['c'] ?? '') || runtime_chain($tg)) return null;
    // DNS redirect → dns_redirect + dns_ip
    if ($row['t'] === 'nat' && $tg === 'DNAT' && (($f['dport'] ?? '') === '53' || str_contains((string)($f['dports'] ?? ''), '53'))) {
        if (preg_match('/--to-destination\s+([0-9.]+)(?::53)?/', ($f['targs'] ?? '') . ' ' . ($f['extra'] ?? '') . ' ' . $raw, $m)) {
            $S['dns_redirect'] = 1; $S['dns_ip'] = $m[1];
            if (($f['s'] ?? '') !== '') {
                $nets = $ls('lan_nets');
                if (!in_array($f['s'], $nets, true)) { $nets[] = $f['s']; $S['lan_nets'] = implode(',', $nets); }
            }
            return 'Redirect DNS → Setup (dns_redirect → ' . $m[1] . ')';
        }
    }
    // MASQUERADE su interfaccia (non docker)
    if ($row['t'] === 'nat' && $tg === 'MASQUERADE' && ($f['o'] ?? '') !== '' && !str_starts_with($f['o'], 'docker') && ($f['s'] ?? '') === '') {
        $S['nat_masq'] = 1;
        $ifs = $ls('masq_ifs'); if (!in_array($f['o'], $ifs, true)) { $ifs[] = $f['o']; $S['masq_ifs'] = implode(',', $ifs); }
        if (($S['wan_if'] ?? '') === '') $S['wan_if'] = $f['o'];
        return 'NAT MASQUERADE → Setup (masq su ' . $f['o'] . ')';
    }
    if ($tg === 'TCPMSS' && str_contains($raw, 'clamp-mss-to-pmtu')) { $S['mss'] = 1; return 'TCPMSS clamp → Setup (mss)'; }
    if (in_array($tg, ['CROWDSEC_CHAIN', 'CROWDSEC'], true) || str_starts_with($tg, 'CROWDSEC')) {
        $S['crowdsec'] = 1; return 'CrowdSec → Sicurezza';
    }
    if (($f['i'] ?? '') === 'wg0' && $tg === 'ACCEPT' && ($f['s'] ?? '') === '' && ($f['dport'] ?? '') === '') { $S['wg_on'] = 1; $S['wg_input'] = 1; return 'WireGuard INPUT → VPN'; }
    if (($f['p'] ?? '') === 'udp' && ($f['dport'] ?? '') !== '' && (int)$f['dport'] >= 51820 && (int)$f['dport'] <= 51830 && $tg === 'ACCEPT') {
        $S['wg_on'] = 1; $S['wg_port'] = (int)$f['dport']; return 'Porta WireGuard → VPN (' . $f['dport'] . ')';
    }
    if (str_contains($raw, 'rpfilter')) { $S['rpfilter'] = 1; return 'RPF → Sicurezza (rpfilter)'; }
    if (str_contains($raw, '--helper ftp')) { $S['alg_ftp'] = 1; return 'Helper FTP → Sicurezza'; }
    if (str_contains($raw, '--helper tftp')) { $S['alg_tftp'] = 1; return 'Helper TFTP → Sicurezza'; }
    if (str_contains($raw, '--helper sip')) { $S['alg_sip'] = 1; return 'Helper SIP → Sicurezza'; }
    if (str_contains($raw, '--notrack') && (($f['i'] ?? '') === 'lo' || ($f['o'] ?? '') === 'lo')) { $S['raw_lo'] = 1; return 'NOTRACK loopback → tabella raw'; }
    if ($tg === 'SYNPROXY') { $S['synproxy'] = 1; return 'SYNPROXY → Sicurezza'; }
    if ($tg === 'TARPIT') { $S['tarpit'] = 1; $S['closeports'] = 1; return 'TARPIT → Sicurezza'; }
    if (str_contains($raw, 'IPTM-PSCAN') || str_contains($raw, 'IPTM-PSHIT')) { $S['portscan'] = 1; return 'Port scan → Sicurezza'; }
    if (($f['p'] ?? '') === 'udp' && ($f['dport'] ?? '') === '443' && in_array($tg, ['REJECT', 'DROP'], true)) { $S['quic_block'] = 1; return 'Blocco QUIC → Sicurezza'; }
    if (($f['dport'] ?? '') === '853' && in_array($tg, ['REJECT', 'DROP'], true)) { $S['dot_block'] = 1; return 'Blocco DoT (853) → Setup'; }
    if (($f['dport'] ?? '') === '113' && in_array($tg, ['DROP', 'REJECT'], true)) { $S['ident'] = 1; return 'IDENT 113 → Sicurezza'; }
    if (($f['dport'] ?? '') === '25' && $row['c'] === 'FORWARD' && in_array($tg, ['DROP', 'LOG-DROP', 'REJECT'], true) && ($f['s'] ?? '') === '') {
        $S['egress_smtp'] = 1; return 'Blocca SMTP in uscita → Sicurezza';
    }
    // Port forward DNAT (non DNS)
    if ($row['t'] === 'nat' && $tg === 'DNAT' && preg_match('/--to-destination\s+([0-9.]+)(?::(\d+(?:-\d+|\d*)?))?/', ($f['targs'] ?? '') . ' ' . ($f['extra'] ?? '') . ' ' . $raw, $m)) {
        $eport = $f['dport'] ?: $f['dports']; $proto = $f['p'] ?: 'tcp';
        if ($eport !== '' && $m[1] !== '' && $eport !== '53') {
            $S['fwd'][] = ['on' => 1, 'name' => 'Da regola manuale ' . $eport, 'proto' => in_array($proto, ['tcp', 'udp'], true) ? $proto : 'tcp', 'eport' => $eport, 'ip' => $m[1], 'tport' => $m[2] ?? '', 'src' => $f['s'] ?? ''];
            return "Port forward → Forward ($eport → {$m[1]}" . (($m[2] ?? '') !== '' ? ":{$m[2]}" : '') . ')';
        }
    }
    // servizi ACCEPT semplici
    if ($row['t'] === 'filter' && $tg === 'ACCEPT' && in_array($row['c'], ['INPUT', 'FORWARD'], true)) {
        $extra = trim($f['extra'] ?? '');
        $simple = ($extra === '' || preg_match('/^(-m (tcp|udp|multiport|conntrack|comment)\b|--(dport|dports|sport|ctstate|comment)\b|\s)+$/i', $extra))
            && !str_contains(($f['s'] ?? '') . ($f['d'] ?? '') . ($f['i'] ?? '') . ($f['o'] ?? ''), '!') && (($f['p'] ?? '') === '' || in_array($f['p'], ['tcp', 'udp', 'icmp'], true));
        if ($simple && !preg_match('/ctstate\s+.*ESTABLISHED/', ($f['ctstate'] ?? '') . $extra)) {
            $ports = $f['dport'] ?: $f['dports']; $key = fn($x) => ($x['proto'] ?? '') . '|' . ($x['ports'] ?? '') . '|' . ($x['src'] ?? '') . '|' . ($x['dst'] ?? '');
            $seen = []; foreach (array_merge($S['svc_in'] ?? [], $S['svc_fwd'] ?? []) as $x) $seen[$key($x)] = 1;
            $e = ['on' => 1, 'name' => 'Da regola manuale ' . ($ports !== '' ? $ports : ($f['p'] ?: 'any')), 'iif' => $f['i'] ?? '', 'src' => $f['s'] ?? '', 'dst' => $f['d'] ?? '', 'proto' => $f['p'] ?? '', 'ports' => $ports, 'ct' => $f['ctstate'] ?? '', 'act' => 'ACCEPT', 'after' => 0];
            if (isset($seen[$key($e)])) return 'Già coperta da un servizio nelle impostazioni';
            if ($row['c'] === 'FORWARD') { $e['oif'] = $f['o'] ?? ''; $S['svc_fwd'][] = $e; return 'Servizio FORWARD → Router / transito'; }
            $S['svc_in'][] = $e; return 'Servizio INPUT → Servizi in ingresso';
        }
    }
    $ip = '/^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/'; $noport = ($f['d'] ?? '') === '' && ($f['dport'] ?? '') === '' && ($f['dports'] ?? '') === '';
    // non trattare come «blocco IP» le classiche anti-spoof (! -i lo -s 127/8) né i salti generici
    if ($row['t'] === 'filter' && in_array($tg, ['DROP', 'REJECT'], true) && preg_match($ip, $f['s'] ?? '') && $noport
        && ($f['i'] ?? '') === '' && !str_contains($raw, '! -i') && !str_starts_with($f['s'] ?? '', '127.')) {
        $l = $ls('manual_block'); if (!in_array($f['s'], $l, true)) $l[] = $f['s']; $S['manual_block'] = implode(' ', array_unique($l)); return 'Blocco IP → elenco «blocco manuale»';
    }
    if ($row['t'] === 'filter' && $tg === 'ACCEPT' && preg_match($ip, $f['s'] ?? '') && $noport && ($f['p'] ?? '') === '') {
        $l = $ls('manual_allow'); if (!in_array($f['s'], $l, true)) $l[] = $f['s']; $S['manual_allow'] = implode(' ', array_unique($l)); return 'Consenti IP → elenco «consenti manuale»';
    }
    return null;
}
function manual_sem(array $M): array { return sem_model(parse_rules(ser($M))); }   // comportamento in forma normale
function manual_trial(array $M, array $S, array $drop, ?array $S2 = null): array {   // toglie le regole $drop ([ti,i]), applica $S2, rigenera: restituisce [modello, impostazioni, avvisi]
    $by = []; foreach ($drop as [$ti, $i]) $by[$ti][] = $i;
    foreach ($by as $ti => $ix) { rsort($ix, SORT_NUMERIC); foreach ($ix as $i) if (isset($M[$ti]['items'][$i])) array_splice($M[$ti]['items'], $i, 1); }
    $S2 ??= $S; $w = regen($M, $S2); return [$M, $S2, $w];
}
function copt_clean_name(string $n): string { $n = trim(preg_replace('/[\x00-\x1f#]+/u', ' ', $n)); $n = $n === '' ? 'Opzione personalizzata' : $n; return preg_match('/^.{1,60}/su', $n, $m) ? $m[0] : substr($n, 0, 60); }
function copt_add(array $S, string $name, string $an, array $rules, string $desc = '', bool $on = true): array {   // $rules: [['t' => tabella, 'r' => '-A CHAIN ...'], ...]
    $S['custom_opts'][] = ['id' => substr(sha1($name . microtime(true) . count($S['custom_opts'] ?? [])), 0, 8), 'name' => copt_clean_name($name), 'desc' => preg_match('/^.{1,200}/su', $desc, $dm) ? $dm[0] : '', 'on' => $on ? 1 : 0, 'an' => (in_array($an, ['top', 'est', 'end'], true) || preg_match('/^rk:[0-9a-f]{12}$/', $an)) ? $an : 'end', 'pr' => 50, 'rules' => array_values($rules)];
    return $S;
}
function manual_group_name(array $rows): string {
    $f = $rows[0]['f']; $t = $f['target'] ?? '?'; $ports = $f['dport'] ?: ($f['dports'] ?? ''); $ch = $rows[0]['c'];
    $what = ['ACCEPT' => 'Consenti', 'DROP' => 'Blocca', 'REJECT' => 'Rifiuta', 'LOG' => 'Registra', 'DNAT' => 'Port forward', 'MASQUERADE' => 'Masquerade', 'SNAT' => 'SNAT'][$t] ?? $t;
    return $what . ($ports !== '' ? ' porta ' . $ports : '') . ' (' . ($rows[0]['t'] === 'filter' ? '' : $rows[0]['t'] . ' ') . $ch . ')' . (count($rows) > 1 ? ' +' . (count($rows) - 1) : '');
}
function manual_findings(array $rows): array {   // controlli di qualità sulle regole manuali attive: [riga, gravita', testo]
    $o = []; $sens = [22 => 'SSH', 23 => 'Telnet', 135 => 'RPC', 139 => 'NetBIOS', 445 => 'SMB', 3389 => 'Desktop remoto', 3306 => 'MySQL', 5432 => 'PostgreSQL', 6379 => 'Redis', 27017 => 'MongoDB', 9200 => 'Elasticsearch', 2375 => 'API Docker', 5900 => 'VNC'];
    foreach ($rows as $r) {
        if (empty($r['on'])) continue; $f = $r['f']; $tg = $f['target'] ?? '';
        if (preg_match('/-m state\b/', $r['raw'])) $o[] = [$r, 'info', 'Usa il modulo «state», obsoleto: preferisci «conntrack --ctstate».'];
        if ($tg === 'LOG' && !preg_match('/-m (limit|hashlimit)\b/', $r['raw'])) $o[] = [$r, 'warn', 'LOG senza limite di frequenza: sotto attacco può riempire il disco.'];
        if ($tg === 'ACCEPT' && in_array($r['c'], ['INPUT', 'FORWARD'], true) && ($f['s'] ?? '') === '' && ($f['i'] ?? '') === '') {
            if (catchall($f)) $o[] = [$r, 'bad', 'ACCEPT senza alcuna condizione: lascia passare tutto.'];
            foreach (explode(',', (string)($f['dport'] ?: ($f['dports'] ?? ''))) as $pp) { $pp = trim($pp); if ($pp === '') continue; [$a, $b] = array_pad(explode(':', $pp), 2, $pp);
                foreach ($sens as $pn => $nm) if ((int)$a <= $pn && $pn <= (int)$b) { $o[] = [$r, 'warn', "Apre $nm (porta $pn) a chiunque: nessuna sorgente né interfaccia indicata."]; break; } }
        }
    }
    return $o;
}
function manual_option_index(array $S): array {   // per ogni opzione ON/OFF spenta: le regole che genererebbe se fosse attiva (e i titoli delle sezioni)
    $keyset = function (array $S) { [$sec] = gen_sections($S); $o = []; foreach ($sec as $x) foreach ($x['rules'] as $r) if ($r[0] !== '#') $o[$x['t'] . '|' . rkey($r)] = $x['title']; return $o; };
    $b0 = $keyset($S); $idx = [];
    foreach (SEC_FIELDS as $grp) foreach ($grp as $k => $ty) {
        if ($ty !== 'b' || !empty($S[$k])) continue; $S2 = $S; $S2[$k] = 1; $new = array_diff_key($keyset($S2), $b0);
        if ($new) $idx[$k] = ['rk' => array_fill_keys(array_keys($new), 1), 'titles' => array_values(array_unique($new))];
    }
    return $idx;
}
function manual_keyset(array $S): array { [$sec] = gen_sections($S); $o = []; foreach ($sec as $x) foreach ($x['rules'] as $r) if ($r[0] !== '#') $o[$x['t'] . '|' . rkey($r)] = 1; return $o; }
function manual_prev_rk(array $M, array $r): ?string {   // chiave (abbreviata) della regola che precede $r nella stessa catena
    for ($j = $r['i'] - 1; $j >= 0; $j--) { $it = $M[$r['ti']]['items'][$j] ?? null; if ($it && $it['t'] === 'rule' && !empty($it['on']) && rchain($it['r']) === $r['c']) return 'rk:' . substr(md5(rkey($it['r'])), 0, 12); }
    return null;
}
function manual_analyze(array $M, array $S, int $cap = 600, float $budget = 25.0): array {
    $t0 = microtime(true); $over = fn() => microtime(true) - $t0 > $budget; $partial = false;   // tetto di tempo: oltre, le regole restanti non vengono verificate
    $rows = custom_rules_list($M); $M0 = $M; regen($M0, $S); $base = manual_sem($M0); $drift = $base != manual_sem($M);
    // fast-path: catene runtime (Docker/CrowdSec/…) → keep dedicato, escluse dai trial costosi
    $runtimeKeys = [];
    foreach ($rows as $i => $r) {
        $tg = $r['f']['target'] ?? '';
        if (runtime_chain($r['c'] ?? '') || runtime_chain($tg) || str_starts_with($r['c'] ?? '', 'DOCKER') || str_starts_with($tg, 'DOCKER')) {
            $runtimeKeys[$r['ti'] . ':' . $r['i']] = 1;
        }
    }
    $idx = manual_option_index($S); $byK = []; foreach ($rows as $r) if (!empty($r['on']) && empty($runtimeKeys[$r['ti'] . ':' . $r['i']])) $byK[$r['t'] . '|' . $r['k']][] = $r;
    $optHit = []; foreach ($idx as $k => $o) { if ($over()) break;   // opzione con TUTTE le sue regole presenti a mano = sostituibile in modo esatto
        $rs = []; foreach ($o['rk'] as $rk => $_) { if (empty($byK[$rk])) { $rs = null; break; } $rs = array_merge($rs, $byK[$rk]); }
        if ($rs) { $S2 = $S; $S2[$k] = 1; $dr = array_map(fn($x) => [$x['ti'], $x['i']], $rs);
            $optHit[$k] = ['rows' => $rs, 'titles' => $o['titles'], 'exact' => manual_sem(manual_trial($M, $S, $dr, $S2)[0]) == $base]; }
    }
    $rkOpt = []; foreach ($optHit as $k => $h) if ($h['exact']) foreach ($h['rows'] as $x) $rkOpt[$x['ti'] . ':' . $x['i']] = $k;
    // ridondanza CUMULATIVA (dal fondo), max 120 trial per non sforare il budget su bozze enormi
    $gone = []; $isClean = []; $nc = 0; $cleanCap = 120;
    foreach (array_reverse($rows) as $r) {
        if (empty($r['on']) || isset($runtimeKeys[$r['ti'] . ':' . $r['i']]) || $nc++ >= $cleanCap || $over()) continue;
        $d2 = array_merge($gone, [[$r['ti'], $r['i']]]);
        if (manual_sem(manual_trial($M, $S, $d2)[0]) == $base) { $gone = $d2; $isClean[$r['ti'] . ':' . $r['i']] = 1; }
    }
    // pre-mappa pattern noti (dns, spi, crowdsec, …) senza trial semantico
    $fastMap = []; $Sprobe = $S;
    foreach ($rows as $r) {
        if (empty($r['on']) || isset($runtimeKeys[$r['ti'] . ':' . $r['i']])) continue;
        $why = manual_map_row($r, $Sprobe);
        if ($why !== null) $fastMap[$r['ti'] . ':' . $r['i']] = $why;
    }
    $out = []; $n = 0;
    foreach ($rows as $r) {
        $r['key'] = $r['ti'] . ':' . $r['i'] . ':' . substr(md5($r['raw']), 0, 6); $r['cat'] = 'custom'; $r['exact'] = false; $r['why'] = ''; $r['an'] = 'end'; $d = [[$r['ti'], $r['i']]];
        $rk = $r['ti'] . ':' . $r['i'];
        if (empty($r['on'])) { $r['cat'] = 'clean'; $r['exact'] = true; $r['why'] = 'disattivata: non ha effetto'; }
        elseif (isset($runtimeKeys[$rk])) { $r['cat'] = 'keep'; $r['why'] = 'catena/target runtime (Docker/CrowdSec/fail2ban…): non convertire — la gestisce il servizio'; }
        elseif (!isset($isClean[$rk]) && !isset($fastMap[$rk]) && !isset($rkOpt[$rk]) && ($n++ >= $cap || $over())) { $partial = true; $r['cat'] = 'keep'; $r['why'] = 'non verificata (molte regole: converti le prime e ripeti l\'analisi)'; }
        elseif (isset($isClean[$rk])) { $r['cat'] = 'clean'; $r['exact'] = true; $r['why'] = 'ridondante: toglierla non cambia il comportamento (duplicata, irraggiungibile o già coperta)'; }
        elseif (isset($rkOpt[$rk])) { $k = $rkOpt[$rk]; $r['cat'] = 'optionb'; $r['exact'] = true; $r['opt'] = $k; $r['why'] = 'è l\'opzione «' . implode(' · ', $optHit[$k]['titles']) . '» (' . $k . ')'; }
        elseif (isset($fastMap[$rk]) && !$over()) {
            $S2 = $S; $how = manual_map_row($r, $S2);
            if ($how !== null && manual_sem(manual_trial($M, $S, $d, $S2)[0]) == $base) { $r['cat'] = 'option'; $r['exact'] = true; $r['why'] = $how; $r['an'] = 'map'; }
            elseif ($how !== null) { $r['why'] = 'Possibile opzione (' . $how . ') ma la conversione isolata cambierebbe il comportamento: prova con le regole collegate o usa «forza».'; }
        }
        else {
            $S2 = $S; $how = manual_map_row($r, $S2); $comp = [];
            if ($how !== null) {   // la riga impostazioni può generare anche regole «compagne» (es. port forward = DNAT + FORWARD): se ci sono già a mano vengono assorbite insieme
                $new = array_diff_key(manual_keyset($S2), manual_keyset($S));
                foreach ($rows as $x) if (!empty($x['on']) && ($x['ti'] !== $r['ti'] || $x['i'] !== $r['i']) && isset($new[$x['t'] . '|' . $x['k']])) { $comp[] = $x; $d[] = [$x['ti'], $x['i']]; }
            }
            if ($how !== null && manual_sem(manual_trial($M, $S, $d, $S2)[0]) == $base) { $r['cat'] = 'option'; $r['exact'] = true; $r['why'] = $how . ($comp ? ' (assorbe anche ' . count($comp) . ' regola/e collegata/e)' : ''); $r['absorbs'] = array_map(fn($x) => $x['ti'] . ':' . $x['i'], $comp); }
            elseif ($how !== null) $r['why'] = 'Esiste un\'opzione (' . $how . ') ma la conversione cambierebbe il comportamento (ordine, REJECT→DROP o regole aggiuntive).';
            else foreach ($idx as $k => $o) if (isset($o['rk'][$r['t'] . '|' . $r['k']])) { $r['why'] = 'Genera in parte come l\'opzione «' . implode(' · ', $o['titles']) . '» (' . $k . '): mancano altre regole, non è sostituibile in modo esatto.'; break; }
        }
        $out[$r['key']] = $r;
    }
    foreach ($out as $k => $r) if ($r['cat'] === 'custom' && catchall($r['f']) && in_array($r['f']['target'] ?? '', ['DROP', 'REJECT', 'ACCEPT'], true)) { $out[$k]['cat'] = 'keep'; $out[$k]['why'] = 'regola finale della catena: deve restare in fondo (resta manuale)'; }
    $ab = []; foreach ($out as $r) foreach ($r['absorbs'] ?? [] as $ix) $ab[$ix] = $r['key'];   // regole assorbite da un'altra conversione: non si convertono da sole
    foreach ($out as $k => $r) if (isset($ab[$r['ti'] . ':' . $r['i']]) && $r['cat'] !== 'clean') { $out[$k]['cat'] = 'absorbed'; $out[$k]['exact'] = true; $out[$k]['why'] = 'assorbita dalla conversione della regola collegata'; unset($out[$k]['absorbs']); }
    // opzioni ON/OFF sostituibili: una voce per opzione
    $opts = []; foreach ($optHit as $k => $h) if ($h['exact']) $opts['o:' . $k] = ['id' => 'o:' . $k, 'opt' => $k, 'titles' => $h['titles'], 'rows' => array_map(fn($x) => $x['raw'], $h['rows'])];
    // regole che diventano opzione personalizzata: serie consecutive nella stessa catena (l'ordine relativo resta); se il gruppo non è esatto si prova regola per regola
    $groups = []; $cur = null; $mk = function (array $rs) use (&$groups) { $id = 'g:' . substr(md5(implode('|', array_column($rs, 'key'))), 0, 8); $groups[$id] = ['id' => $id, 'keys' => array_column($rs, 'key'), 'rows' => $rs, 'name' => manual_group_name($rs), 'exact' => false, 'an' => 'end']; };
    $runs = []; foreach ($out as $k => $r) { if ($r['cat'] !== 'custom') { $cur = null; continue; } $ck = $r['ti'] . '|' . $r['c']; if ($cur === null || $runs[$cur]['ck'] !== $ck) { $cur = count($runs); $runs[$cur] = ['ck' => $ck, 'rows' => []]; } $runs[$cur]['rows'][] = $r; }
    $try = function (array $rs) use ($M, $S, $base, $over) {
        if ($over()) return null;
        $pr = manual_prev_rk($M, $rs[0]); foreach (array_filter(['end', 'est', 'top', $pr]) as $an) { $S3 = copt_add($S, 'prova', $an, array_map(fn($r) => ['t' => $r['t'], 'r' => $r['raw']], $rs)); if (manual_sem(manual_trial($M, $S, array_map(fn($r) => [$r['ti'], $r['i']], $rs), $S3)[0]) == $base) return $an; }
        return null;
    };
    foreach ($runs as $run) {
        $an = $try($run['rows']);
        if ($an !== null) { $mk($run['rows']); $id = array_key_last($groups); $groups[$id]['exact'] = true; $groups[$id]['an'] = $an; continue; }
        foreach ($run['rows'] as $r) {   // regola per regola
            $f = $r['f']; if (catchall($f) && in_array($f['target'] ?? '', ['DROP', 'REJECT', 'ACCEPT'], true)) { $out[$r['key']]['why'] = 'regola finale della catena: deve restare in fondo (resta manuale)'; $out[$r['key']]['cat'] = 'keep'; continue; }
            $a1 = $try([$r]); $mk([$r]); $id = array_key_last($groups); $groups[$id]['exact'] = $a1 !== null; $groups[$id]['an'] = $a1 ?? 'end';
            if ($a1 === null) $out[$r['key']]['why'] = 'spostarla in un\'opzione cambierebbe l\'ordine di valutazione rispetto alle altre regole';
        }
    }
    foreach ($groups as $gid => $g) foreach ($g['keys'] as $k) { $out[$k]['exact'] = $g['exact']; $out[$k]['an'] = $g['an']; $out[$k]['gid'] = $gid; }
    return ['rules' => $out, 'groups' => $groups, 'opts' => $opts, 'findings' => manual_findings($rows), 'drift' => $drift, 'total' => count($rows), 'base' => $base, 'partial' => $partial || $over()];
}
function manual_apply(array &$M, array &$S, array $A, array $sel, array $names, bool $force): array {
    $drop = []; $S2 = $S; $nOpt = $nClean = $nCust = 0; $seen = [];
    $take = function (array $r) use (&$drop, &$seen) { if (!isset($seen[$r['ti'] . ':' . $r['i']])) { $seen[$r['ti'] . ':' . $r['i']] = 1; $drop[] = [$r['ti'], $r['i']]; } };
    foreach ($sel as $k) {
        if (isset($A['rules'][$k]) && in_array($A['rules'][$k]['cat'], ['clean', 'option'], true)) {
            $r = $A['rules'][$k]; if ($r['cat'] === 'option') { if (manual_map_row($r, $S2) === null) continue; $nOpt++; foreach ($r['absorbs'] ?? [] as $ix) { [$ta, $ia] = explode(':', $ix); $drop[] = [(int)$ta, (int)$ia]; $seen[$ix] = 1; } } else $nClean++; $take($r);
        } elseif (isset($A['opts'][$k])) {
            $S2[$A['opts'][$k]['opt']] = 1; $nOpt++; foreach ($A['rules'] as $r) if ($r['cat'] === 'optionb' && $r['opt'] === $A['opts'][$k]['opt']) $take($r);
        } elseif (isset($A['groups'][$k])) {
            $g = $A['groups'][$k]; $S2 = copt_add($S2, (string)($names[$k] ?? $g['name']), $g['an'], array_map(fn($r) => ['t' => $r['t'], 'r' => $r['raw']], $g['rows']), 'Creata dall\'analisi delle regole manuali');
            foreach ($g['rows'] as $r) $take($r); $nCust += count($g['rows']);
        }
    }
    if (!$drop) return ['ok' => false, 'msg' => 'Nessuna regola selezionata (o la bozza è cambiata: ripeti l\'analisi).'];
    [$M2, $S3, $w] = manual_trial($M, $S, $drop, $S2); $same = manual_sem($M2) == $A['base'];
    if (!$same && !$force) return ['ok' => false, 'msg' => 'Conversione annullata: cambierebbe il comportamento del firewall. Deseleziona le voci non «esatte» oppure spunta «forza» e controlla le differenze in Applica.'];
    $M = $M2; $S = $S3; S_put($S); save_model();
    return ['ok' => true, 'same' => $same, 'msg' => "Bozza aggiornata: $nOpt in opzioni esistenti, $nCust regole in opzioni personalizzate, $nClean eliminate." . ($same ? ' Comportamento verificato identico.' : ' ⚠ Il comportamento è cambiato (forzato): rivedi le differenze prima di applicare.') . ($w ? ' Avvisi: ' . implode('; ', $w) : '')];
}

function import_analyze(array $M): array {
    $R = [];
    foreach ($M as $ti => $b) if ($b['k'] === 'table') foreach ($b['items'] as $i => $it) if ($it['t'] === 'rule' && $it['on']) { $f = rule_parse($it['r']); $R[] = ['ti' => $ti, 'i' => $i, 't' => $b['name'], 'c' => $f['chain'], 'f' => $f, 'k' => rkey($it['r']), 'raw' => $it['r']]; }
    // --- pulizia: duplicati esatti e regole irraggiungibili (dopo una regola che chiude la catena)
    $last = []; foreach ($R as $r) $last[$r['t'] . '|' . $r['c']] = $r;
    $termCh = []; foreach ($last as $k => $r) if (catchall($r['f']) && in_array($r['f']['target'], ['DROP', 'REJECT', 'ACCEPT'], true)) $termCh[explode('|', $k)[1]] = 1;
    $rem = []; $removed = []; $seen = []; $term = []; $keep = [];
    foreach ($R as $r) {
        $ck = $r['t'] . '|' . $r['c']; $key = $ck . '|' . $r['k'];
        if (!empty($term[$ck])) { $rem[] = [$r['ti'], $r['i']]; $removed[] = $r['t'] . '/' . $r['c'] . ' [irraggiungibile] ' . $r['raw']; continue; }
        if (isset($seen[$key])) { $rem[] = [$r['ti'], $r['i']]; $removed[] = $r['t'] . '/' . $r['c'] . ' [duplicata] ' . $r['raw']; continue; }
        $seen[$key] = 1; $keep[] = $r; if (catchall($r['f']) && (in_array($r['f']['target'], ['DROP', 'REJECT', 'ACCEPT'], true) || isset($termCh[$r['f']['target']]))) $term[$ck] = 1;
    }
    $R = $keep; $GLOBALS['merged_rows'] = 0; $pos = []; $cnt = []; foreach ($R as $n => $r) { $ck = $r['t'] . '|' . $r['c']; $pos[$n] = $cnt[$ck] = ($cnt[$ck] ?? -1) + 1; }
    $sel = fn($t, $c, $cb = null) => array_values(array_filter($R, fn($r) => $r['t'] === $t && $r['c'] === $c && (!$cb || $cb($r['f']))));
    $S = S_def();
    // --- parametri
    $m = $sel('nat', 'POSTROUTING', fn($f) => $f['target'] === 'MASQUERADE' && $f['o'] !== '' && $f['s'] === '' && $f['d'] === '' && $f['extra'] === '');
    if ($m) { $S['masq_ifs'] = implode(',', array_unique(array_map(fn($r) => $r['f']['o'], $m))); $S['wan_if'] = $m[0]['f']['o']; $S['nat_masq'] = 1; }
    $d = $sel('nat', 'PREROUTING', fn($f) => $f['target'] === 'DNAT' && $f['dport'] === '53' && str_starts_with($f['d'], '!'));
    if ($d) { $n = []; foreach ($d as $r) $n[$r['f']['s']] = 1; $S['lan_nets'] = implode(',', array_keys($n)); $S['single_nic'] = 1; if (preg_match('/--to-destination ([\d.]+):53/', $d[0]['f']['targs'], $mm)) $S['dns_ip'] = $mm[1]; $S['dns_redirect'] = 1; }
    $sn = []; $csl = []; $dosFound = false; $in = $sel('filter', 'INPUT'); $fw = $sel('filter', 'FORWARD'); $last = $in ? end($in) : null;
    if ($last && catchall($last['f']) && !in_array($last['f']['target'], ['ACCEPT', 'DROP', 'REJECT', 'RETURN', 'LOG'], true)) $S['drop_chain'] = $last['f']['target'];
    $DT = $S['drop_chain'] ?: 'DROP';
    foreach ($in as $r) { $f = $r['f'];
        if ($f['target'] === 'DROP' && preg_match('/--match-set (\S+) src/', $f['extra'], $mm) && !own_set($mm[1])) { $csl[] = $mm[1]; $S['crowdsec'] = 1; }
        if (catchall($f) && stripos($f['target'], 'crowdsec') !== false && !preg_match('/_LOG$/i', $f['target'])) $S['cs_in'] = $f['target'];
        if ($f['i'] !== '' && $f['s'] !== '' && str_contains($f['s'], ',') && $f['target'] === $DT && $f['extra'] === '' && $f['p'] === '' && $f['d'] === '' && !$S['spoof_on']) { $S['spoof_if'] = $f['i']; $S['spoof_nets'] = $f['s']; $S['spoof_on'] = 1; }
        if ($f['p'] === 'tcp' && $f['dport'] !== '' && $f['s'] !== '') {
            if (preg_match('/--connlimit-above (\d+)/', $f['extra'], $mm)) { $sn[$f['s']] = 1; $S['ssh_acc_port'] = (int)$f['dport']; $S['ssh_conn'] = (int)$mm[1]; }
            if (preg_match('/--name (\S+) --update --seconds (\d+) --hitcount (\d+)/', $f['extra'], $mm)) { $S['ssh_name'] = $mm[1]; $S['ssh_secs'] = (int)$mm[2]; $S['ssh_hits'] = (int)$mm[3]; }
        }
        if ($f['p'] === 'icmp' && $f['target'] === 'ACCEPT' && preg_match('/--hashlimit-upto (\d+\/\w+) --hashlimit-burst (\d+)/', $f['extra'], $mm)) {
            if (str_contains($f['extra'], 'echo-request')) { $S['icmp_echo_rate'] = $mm[1]; $S['icmp_echo_burst'] = (int)$mm[2]; } else { $S['icmp_other_rate'] = $mm[1]; $S['icmp_other_burst'] = (int)$mm[2]; }
        }
        if ($f['p'] === 'tcp' && preg_match('/--syn -m hashlimit --hashlimit-name (\S+) .*--hashlimit-above (\d+)\/sec --hashlimit-burst (\d+)/', $f['extra'], $mm)) { $dosFound = true; $S['dos_name'] = $mm[1]; $S['dos_syn'] = (int)$mm[2]; $S['dos_burst'] = (int)$mm[3]; }
        if ($f['p'] === 'tcp' && preg_match('/^\d+:\d+$/', $f['dport']) && $f['target'] === $DT) $S['close_range'] = $f['dport'];
    }
    if ($csl) $S['cs_set'] = implode(',', array_unique($csl));
    if ($sn) $S['ssh_nets'] = implode(',', array_keys($sn));
    foreach ($fw as $r) if (catchall($r['f']) && stripos($r['f']['target'], 'crowdsec') !== false && !preg_match('/_LOG$/i', $r['f']['target'])) $S['cs_fwd'] = $r['f']['target'];
    $S['cs_docker'] = $sel('filter', 'DOCKER-USER') ? 1 : 0;
    foreach ($sel('raw', 'PREROUTING', fn($f) => $f['target'] === 'DROP' && $f['dports'] !== '') as $r) { if ($r['f']['p'] === 'tcp') $S['raw_tcp'] = $r['f']['dports']; if ($r['f']['p'] === 'udp') $S['raw_udp'] = $r['f']['dports']; }
    if ($S['drop_chain'] !== '') foreach ($sel('filter', $S['drop_chain']) as $r) if (preg_match('/--hashlimit-upto (\S+) --hashlimit-burst (\d+) -m limit --limit (\S+) --limit-burst (\d+) -j LOG/', $r['raw'], $mm) && preg_match('/--log-prefix "([^"]*)"/', $r['raw'], $pm)) { [, $S['ld_src_rate'], $S['ld_src_burst'], $S['ld_glob_rate'], $S['ld_glob_burst']] = $mm; $S['ld_src_burst'] = (int)$S['ld_src_burst']; $S['ld_glob_burst'] = (int)$S['ld_glob_burst']; $S['ld_prefix'] = $pm[1]; }
    // --- opzioni candidate, poi verifica che TUTTE le regole generate esistano nel file
    $cand = $S; foreach (['antispoof', 'spi', 'invalid', 'igmp_accept', 'dot_block', 'mss', 'raw_lo', 'closeports', 'final_drop', 'icmp_limit'] as $o) $cand[$o] = 1;
    $cand['raw_drop'] = ($S['raw_tcp'] !== '' || $S['raw_udp'] !== '') ? 1 : 0; $cand['ssh_acc'] = $S['ssh_nets'] !== '' ? 1 : 0; $cand['dos'] = $dosFound ? 1 : 0; $cand['logdrop_on'] = $S['drop_chain'] !== '' ? 1 : 0;
    $pool = []; foreach ($R as $n => $r) $pool[$r['t'] . '|' . $r['c'] . '|' . $r['k']][] = $n;
    $have = fn($t, $c, $rule) => !empty($pool[$t . '|' . $c . '|' . rkey($rule)]);
    $ok = []; [$secs] = gen_sections($cand);
    foreach ($secs as $s) { $o = sec_opt($s['id']); if ($o === '') continue; $ok[$o] = ($ok[$o] ?? true);
        foreach ($s['rules'] as $r) if ($r[0] !== '#' && !$have($s['t'], rchain($r), $r)) $ok[$o] = false; }
    foreach (OPT_LABEL as $o => $l) $S[$o] = !empty($ok[$o]) ? 1 : 0;
    if (!$S['crowdsec']) $S['cs_docker'] = 0;
    // --- consumo delle regole riconosciute
    [$secs] = gen_sections($S); $absorbed = []; $used = []; $sshIdx = [];
    foreach ($secs as $s) foreach ($s['rules'] as $r) { if ($r[0] === '#') continue; foreach ($pool[$s['t'] . '|' . rchain($r) . '|' . rkey($r)] ?? [] as $n) if (!isset($used[$n])) { $used[$n] = 1; $absorbed[] = [$R[$n]['ti'], $R[$n]['i']]; if ($s['id'] === 'ssh-acc') $sshIdx[] = $R[$n]['i']; break; } }
    $nOpt = count($absorbed);
    // --- le regole semplici rimaste (ACCEPT) diventano righe delle tabelle "servizi" / "transito"
    $left = []; $k = 0; $firstSsh = $sshIdx ? min($sshIdx) : null; $rowsIn = []; $rowsFw = [];
    foreach ($R as $n => $r) {
        if (isset($used[$n])) continue; $f = $r['f'];
        $simple = $r['t'] === 'filter' && in_array($r['c'], ['INPUT', 'FORWARD'], true) && $f['target'] === 'ACCEPT' && $f['targs'] === '' && $f['extra'] === '' && $f['sport'] === '' && $f['sports'] === '' && $f['ports'] === '' && !($f['dport'] !== '' && $f['dports'] !== '')
            && !preg_match('/[!\s]/', $f['i'] . $f['o'] . $f['p'] . $f['dport'] . $f['dports']) && !str_starts_with($f['s'], '!') && !str_starts_with($f['d'], '!') && !str_starts_with($f['ctstate'], '!') && ($f['p'] === '' || in_array($f['p'], ['tcp', 'udp', 'icmp', 'igmp'], true))
            && ($f['dport'] . $f['dports'] === '' || in_array($f['p'], ['tcp', 'udp'], true));
        if ($simple) {
            $k++; $row = ['on' => 1, 'name' => 'Importata ' . $k, 'iif' => $f['i'], 'oif' => $f['o'], 'src' => $f['s'], 'dst' => $f['d'], 'proto' => $f['p'], 'ports' => $f['dport'] . $f['dports'], 'ct' => $f['ctstate'], 'act' => 'ACCEPT'];
            $row['_c'] = $r['c']; $row['_n'] = $pos[$n];
            if ($r['c'] === 'INPUT') { $row['after'] = ($firstSsh !== null && $r['i'] > $firstSsh) ? 1 : 0; unset($row['oif']); $rowsIn[] = $row; } else $rowsFw[] = $row;
            $used[$n] = 1; $absorbed[] = [$r['ti'], $r['i']];
        } else $left[] = $r['t'] . '/' . $r['c'] . ': ' . $r['raw'];
    }
    $fin = function ($rows) { return array_map(function ($r) { $r['name'] = row_name($r); unset($r['_c'], $r['_n']); return $r; }, merge_rows($rows)); };
    $absOpt = $absorbed; $absRows = array_slice($absorbed, $nOpt); $absOpt = array_slice($absorbed, 0, $nOpt);
    $S['svc_in'] = $fin($rowsIn); $S['svc_fwd'] = $fin($rowsFw); $absorbed = array_merge($absorbed, $rem);
    return ['abs_opt' => $absOpt, 'abs_rows' => $absRows, 'abs_dead' => $rem, 'removed' => $removed, 'merged' => $GLOBALS['merged_rows'], 'S' => $S, 'absorbed' => $absorbed, 'left' => $left, 'on' => array_keys(array_filter(array_intersect_key($S, OPT_LABEL))), 'svc' => [count($S['svc_in']), count($S['svc_fwd'])], 'total' => count($R)];
}
function import_variant(array $pl, bool $opts, bool $rows, bool $dead): array {
    $p = $pl; if (!$opts) foreach (OPT_LABEL as $o => $l) $p['S'][$o] = 0; if (!$opts) { $p['S']['cs_docker'] = 0; } if (!$rows) { $p['S']['svc_in'] = []; $p['S']['svc_fwd'] = []; }
    $p['absorbed'] = array_merge($opts ? $pl['abs_opt'] : [], $rows ? $pl['abs_rows'] : [], $dead ? $pl['abs_dead'] : []); if (!$dead) { $p['removed'] = []; $p['merged'] = $rows ? $pl['merged'] : 0; }
    $p['on'] = array_keys(array_filter(array_intersect_key($p['S'], OPT_LABEL))); $p['svc'] = [count($p['S']['svc_in']), count($p['S']['svc_fwd'])];
    return $p;
}
function import_left(array $M, array $p): array {   // regole attive che NON vengono assorbite dal piano
    $gone = []; foreach ($p['absorbed'] as [$ti, $i]) $gone[$ti . ':' . $i] = 1; $o = [];
    foreach ($M as $ti => $b) if ($b['k'] === 'table') foreach ($b['items'] as $i => $it) if ($it['t'] === 'rule' && $it['on'] && !isset($gone[$ti . ':' . $i])) $o[] = $b['name'] . '/' . rchain($it['r']) . ': ' . $it['r'];
    return $o;
}
function import_plan_safe(array $M): array {   // sceglie il livello di importazione piu' completo che NON cambia il comportamento del firewall
    $full = import_analyze($M); $orig = ser($M); $levels = [['completo', true, true, true], ['opzioni + pulizia', true, false, true], ['servizi + pulizia', false, true, true], ['solo pulizia', false, false, true], ['solo impostazioni (regole invariate)', false, false, false]];
    foreach ($levels as $n => [$name, $o, $r, $d]) {
        $p = import_variant($full, $o, $r, $d); $T = $M; import_apply_model($T, $p, false); regen($T, $p['S']);
        if (rules_equiv($orig, ser($T))) { $p['level'] = $name; $p['level_n'] = $n; $p['left'] = import_left($M, $p); return $p; }
    }
    $p = import_variant($full, false, false, false); $p['level'] = 'solo impostazioni (regole invariate)'; $p['level_n'] = 4; $p['left'] = import_left($M, $p); return $p;
}
function import_apply_model(array &$M, array $plan, bool $clean): void {
    $by = []; foreach ($plan['absorbed'] as [$ti, $i]) $by[$ti][] = $i;
    foreach ($by as $ti => $ix) { rsort($ix); foreach ($ix as $i) array_splice($M[$ti]['items'], $i, 1); }
    if ($clean) foreach ($M as &$b) {
        if ($b['k'] !== 'table') continue;
        $keep = false; foreach ($b['items'] as $it) if ($it['t'] === 'rule' && $it['on']) $keep = true;
        if (!$keep) $b['items'] = array_values(array_filter($b['items'], fn($it) => $it['t'] !== 'c' || trim($it['x']) === ''));
    }
}

