<?php
// ===================== MODELLO (parse / serializza) =====================
function parse_rules(string $txt): array {
    static $memo = []; $mk = md5($txt); if (isset($memo[$mk])) return $memo[$mk];
    if (count($memo) > 8) array_shift($memo);
    return $memo[$mk] = parse_rules_raw($txt);
}
function parse_rules_raw(string $txt): array {
    $out = []; $text = []; $cur = null;
    foreach (preg_split('/\r?\n/', $txt) as $ln) {
        $t = trim($ln);
        if ($cur === null) {
            if (preg_match('/^\*(\w+)$/', $t, $m)) { if ($text) { $out[] = ['k' => 'text', 'lines' => $text]; $text = []; } $cur = ['k' => 'table', 'name' => $m[1], 'items' => []]; }
            else $text[] = $ln;
            continue;
        }
        if ($t === 'COMMIT') { $out[] = $cur; $cur = null; continue; }
        if (preg_match('/^:(\S+)\s+(\S+)/', $t, $m)) $cur['items'][] = ['t' => 'chain', 'n' => $m[1], 'p' => $m[2]];
        elseif (preg_match('/^(?:\[\d+:\d+\]\s*)?(-A\s.+)$/', $t, $m)) $cur['items'][] = ['t' => 'rule', 'r' => $m[1], 'on' => true];
        elseif (preg_match('/^#\s?(-A\s.+)$/', $t, $m)) $cur['items'][] = ['t' => 'rule', 'r' => $m[1], 'on' => false];
        else $cur['items'][] = ['t' => 'c', 'x' => $ln];
    }
    if ($cur !== null) $out[] = $cur;
    if ($text) $out[] = ['k' => 'text', 'lines' => $text];
    return $out;
}
function ser(array $m): string {
    $L = [];
    foreach ($m as $b) {
        if ($b['k'] === 'text') { foreach ($b['lines'] as $l) $L[] = $l; continue; }
        $L[] = '*' . $b['name'];
        foreach ($b['items'] as $it) {
            if ($it['t'] === 'chain') $L[] = ':' . $it['n'] . ' ' . $it['p'] . ' [0:0]';
            elseif ($it['t'] === 'rule') $L[] = ($it['on'] ? '' : '# ') . $it['r'];
            else $L[] = $it['x'];
        }
        $L[] = 'COMMIT';
    }
    return rtrim(implode("\n", $L)) . "\n";
}
function tb(array $m, string $n): int { foreach ($m as $k => $b) if ($b['k'] === 'table' && $b['name'] === $n) return $k; return -1; }
function rchain(string $r): string { return preg_match('/^-A\s+(\S+)/', $r, $m) ? $m[1] : ''; }
function chain_rules(array $items, string $ch): array {
    $o = []; foreach ($items as $i => $it) if ($it['t'] === 'rule' && rchain($it['r']) === $ch) $o[] = $i; return $o;
}
function chain_ok(string $table, array $items, string $ch): bool {
    if (in_array($ch, BUILTIN[$table] ?? [], true)) return true;
    foreach ($items as $it) if ($it['t'] === 'chain' && $it['n'] === $ch) return true;
    return false;
}

// regola <-> campi
function rule_parse(string $r): array {
    $f = ['chain' => '', 'i' => '', 'o' => '', 's' => '', 'd' => '', 'p' => '', 'sport' => '', 'dport' => '', 'sports' => '', 'dports' => '', 'ports' => '', 'ctstate' => '', 'extra' => '', 'target' => '', 'targs' => ''];
    preg_match_all('/"[^"]*"|\'[^\']*\'|\S+/', $r, $m); $t = $m[0]; $n = count($t); $ex = []; $neg = false;
    $map = ['-i' => 'i', '--in-interface' => 'i', '-o' => 'o', '--out-interface' => 'o', '-s' => 's', '--source' => 's', '--src' => 's', '-d' => 'd', '--destination' => 'd', '--dst' => 'd',
        '-p' => 'p', '--protocol' => 'p', '--sport' => 'sport', '--source-port' => 'sport', '--dport' => 'dport', '--destination-port' => 'dport',
        '--sports' => 'sports', '--source-ports' => 'sports', '--dports' => 'dports', '--destination-ports' => 'dports', '--ports' => 'ports', '--ctstate' => 'ctstate'];
    for ($k = 0; $k < $n; $k++) {
        $x = $t[$k];
        if ($x === '!') { $neg = true; continue; }
        if ($x === '-A') { $f['chain'] = $t[++$k] ?? ''; continue; }
        if ($x === '-j') { $f['target'] = $t[++$k] ?? ''; $f['targs'] = implode(' ', array_slice($t, $k + 1)); break; }
        if ($x === '-m' && isset($t[$k + 1]) && in_array($t[$k + 1], ['multiport', 'conntrack'], true)) {
            $j = $k + 2; if (($t[$j] ?? '') === '!') $j++;
            $o = $t[$j] ?? '';
            $okopt = $t[$k + 1] === 'multiport' ? in_array($o, ['--dports', '--sports', '--ports', '--destination-ports', '--source-ports'], true) : $o === '--ctstate';
            if ($okopt) { $k++; continue; }
        }
        if (isset($map[$x])) { $v = $t[++$k] ?? ''; $f[$map[$x]] = ($neg ? '! ' : '') . $v; $neg = false; continue; }
        if ($neg) { $ex[] = '!'; $neg = false; }
        $ex[] = $x;
    }
    $f['extra'] = implode(' ', $ex);
    return $f;
}
function rule_build(array $f): string {
    $o = ['-A ' . $f['chain']];
    $add = function ($opt, $v) use (&$o) {
        $v = trim((string)$v); if ($v === '') return;
        if ($v[0] === '!') { $o[] = '!'; $v = ltrim(substr($v, 1)); }
        $o[] = $opt; $o[] = $v;
    };
    $add('-i', $f['i']); $add('-o', $f['o']); $add('-s', $f['s']); $add('-d', $f['d']); $add('-p', $f['p']);
    $add('--sport', $f['sport']); $add('--dport', $f['dport']);
    if (trim($f['sports'] . $f['dports'] . $f['ports']) !== '') { $o[] = '-m multiport'; $add('--sports', $f['sports']); $add('--dports', $f['dports']); $add('--ports', $f['ports']); }
    if (trim($f['ctstate']) !== '') { $o[] = '-m conntrack'; $add('--ctstate', $f['ctstate']); }
    if (trim($f['extra']) !== '') $o[] = trim($f['extra']);
    if (trim($f['target']) !== '') $o[] = trim('-j ' . trim($f['target']) . ' ' . trim($f['targs']));
    return implode(' ', $o);
}
function nt(string $v): string { return $v !== '' && $v[0] === '!' ? 'tutto tranne ' . trim(substr($v, 1)) : $v; }
function act_label(string $tg): array {
    $A = ['ACCEPT' => 'ACCETTA', 'DROP' => 'SCARTA', 'REJECT' => 'RIFIUTA', 'LOG' => 'REGISTRA LOG', 'RETURN' => 'RITORNA', 'DNAT' => 'DNAT', 'SNAT' => 'SNAT', 'MASQUERADE' => 'MASCHERA', 'REDIRECT' => 'REDIRECT', 'TCPMSS' => 'TCPMSS', 'NOTRACK' => 'NOTRACK'];
    if ($tg === '') return ['conta', 'NESSUNA AZIONE'];
    return isset($A[$tg]) ? [$tg, $A[$tg]] : ['jump', 'SALTA A ' . $tg];
}
function describe(array $f): string {
    $w = [];
    if ($f['p'] !== '') $w[] = 'proto ' . strtoupper(nt($f['p']));
    if ($f['i'] !== '') $w[] = 'entra da ' . nt($f['i']);
    if ($f['o'] !== '') $w[] = 'esce da ' . nt($f['o']);
    if ($f['s'] !== '') $w[] = 'da ' . nt($f['s']);
    if ($f['d'] !== '') $w[] = 'verso ' . nt($f['d']);
    if ($f['sport'] !== '') $w[] = 'porta origine ' . nt($f['sport']);
    if ($f['dport'] !== '') $w[] = 'porta dest. ' . nt($f['dport']);
    if ($f['sports'] !== '') $w[] = 'porte origine ' . nt($f['sports']);
    if ($f['dports'] !== '') $w[] = 'porte dest. ' . nt($f['dports']);
    if ($f['ports'] !== '') $w[] = 'porte ' . nt($f['ports']);
    if ($f['ctstate'] !== '') $w[] = 'stato ' . nt($f['ctstate']);
    if ($f['extra'] !== '') $w[] = '+ ' . (strlen($f['extra']) > 70 ? substr($f['extra'], 0, 70) . '…' : $f['extra']);
    $s = $w ? implode(' · ', $w) : 'qualsiasi pacchetto';
    if ($f['targs'] !== '') $s .= '  → ' . (strlen($f['targs']) > 50 ? substr($f['targs'], 0, 50) . '…' : $f['targs']);
    return $s;
}
function catchall(array $f): bool {
    foreach (['i', 'o', 's', 'd', 'p', 'sport', 'dport', 'sports', 'dports', 'ports', 'ctstate', 'extra'] as $k) if ($f[$k] !== '') return false;
    return $f['target'] !== '';
}
/** Posizione di inserimento che non cade MAI dentro un blocco generato «# >>> IPTM»: le regole lì dentro verrebbero cancellate alla prossima rigenerazione. */
function ins_index(array $items, string $ch, string $pos): int {
    $r = ins_index_raw($items, $ch, $pos);
    if ($r > 0 && in_region($items, $r)) {
        // «Dopo l'ultima regola della catena» con l'ultima regola dentro un blocco IPTM: l'inserimento deve
        // avvenire OLTRE il marcatore di chiusura. Arretrare all'apertura del blocco metterebbe, per esempio,
        // il DROP finale davanti a ESTABLISHED/loopback (SPI) o davanti a lan-out, rendendoli irraggiungibili.
        $ix = chain_rules($items, $ch);
        if ($ix && $r === end($ix) + 1) {
            for ($j = $r; $j < count($items); $j++) if ($items[$j]['t'] === 'c' && str_starts_with($items[$j]['x'], '# <<< IPTM:')) return $j + 1;
        }
        // «Prima di» una regola (start, indice N, prima del catch-all finale): arretra all'apertura del blocco.
        for ($j = min($r, count($items)) - 1; $j >= 0; $j--) if ($items[$j]['t'] === 'c' && str_starts_with($items[$j]['x'], '# >>> IPTM:')) return $j;
    }
    return $r;
}
function ins_index_raw(array $items, string $ch, string $pos): int {
    $ix = chain_rules($items, $ch);
    if (!$ix) return count($items);
    $last = end($ix);
    if ($pos === 'start') return $ix[0];
    if ($pos === 'last') return $last + 1;
    if (ctype_digit($pos)) { $n = (int)$pos; return ($n >= 1 && $n <= count($ix)) ? $ix[$n - 1] : $last + 1; }
    // "smart": prima del catch-all finale. Conta solo un target terminale (ACCEPT/DROP/REJECT): un salto a una catena
    // utente (-j IPTM-PS, -j IPTM-WAN-IN) non chiude il flusso, e inserire il DROP finale PRIMA di esso lo oscurerebbe.
    $lf = rule_parse($items[$last]['r']);
    return ($items[$last]['on'] && catchall($lf) && in_array($lf['target'], ['ACCEPT', 'DROP', 'REJECT'], true)) ? $last : $last + 1;
}
function lint_rule(string $r): bool { return (bool)preg_match('/^-A [A-Za-z0-9_.:-]{1,28}( [^\x00-\x1f]*)?$/', $r) && stripos($r, 'COMMIT') === false; }

