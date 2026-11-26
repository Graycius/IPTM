<?php
// ===================== v2: PACKET TRACER =====================
function t_split(string $v): array { $v = trim($v); return ($v !== '' && $v[0] === '!') ? [true, trim(substr($v, 1))] : [false, $v]; }
function t_cidr(string $c, string $ip): bool {
    if ($ip === '' || substr_count($c,'/') > 1) return false; [$n, $p] = array_pad(explode('/', $c), 2, '32'); if(!ctype_digit((string)$p)||(int)$p>32)return false; $a = ip2long($ip); $b = ip2long($n); if ($a === false || $b === false) return false;
    $m = (int)$p === 0 ? 0 : ((-1 << (32 - (int)$p)) & 0xFFFFFFFF); return ($a & $m) === ($b & $m);
}
function t_ip(string $spec, string $ip): bool { [$ng, $v] = t_split($spec); $h = false; foreach (explode(',', $v) as $c) if (t_cidr(trim($c), $ip)) { $h = true; break; } return $ng ? !$h : $h; }
function t_if(string $spec, string $name): bool { [$ng, $v] = t_split($spec); $h = $name !== '' && (str_ends_with($v, '+') ? str_starts_with($name, substr($v, 0, -1)) : $name === $v); return $ng ? !$h : $h; }
function t_port(string $spec, string $port): bool {
    [$neg, $value] = t_split($spec);
    if (!ctype_digit($port) || (int)$port > 65535 || $value === '') return false;
    $matched = false;
    foreach (explode(',', $value) as $range) {
        if (!preg_match('/^(?:[0-9]{1,5}|[0-9]{0,5}:[0-9]{0,5})$/D', $range)) return false;
        if (str_contains($range, ':')) {
            [$lo, $hi] = explode(':', $range, 2);
            $lo = $lo === '' ? 0 : (int)$lo; $hi = $hi === '' ? 65535 : (int)$hi;
        } else { $lo = $hi = (int)$range; }
        if ($lo > $hi || $hi > 65535) return false;
        $matched = $matched || ((int)$port >= $lo && (int)$port <= $hi);
    }
    return $neg ? !$matched : $matched;
}
function t_extra(string $x, array $k, array &$nt): bool {
    $x = trim($x); if ($x === '') return true; $ok = true;
    if (preg_match_all('/(!\s*)?--syn\b/', $x, $m, PREG_SET_ORDER)) foreach ($m as $mm) { $syn = $k['p'] === 'tcp' && $k['state'] === 'NEW'; $ok = $ok && (($mm[1] ?? '') !== '' ? !$syn : $syn); }
    if (preg_match_all('/--tcp-flags (\S+) (\S+)/', $x, $m, PREG_SET_ORDER)) foreach ($m as $mm) {
        $all = ['SYN', 'ACK', 'FIN', 'RST', 'URG', 'PSH']; $fl = $k['p'] === 'tcp' ? ($k['state'] === 'NEW' ? ['SYN'] : ['ACK']) : [];
        $mask = $mm[1] === 'ALL' ? $all : explode(',', $mm[1]); $comp = $mm[2] === 'NONE' ? [] : ($mm[2] === 'ALL' ? $all : explode(',', $mm[2])); $have = array_values(array_intersect($fl, $mask)); sort($have); sort($comp); $ok = $ok && ($have === $comp);
    }
    if (preg_match('/--dst-type (\w+)/', $x, $m)) { $mc = t_cidr('224.0.0.0/4', $k['d']); $bc = $k['d'] === '255.255.255.255'; $ok = $ok && match ($m[1]) { 'LOCAL' => !empty($k['local']), 'MULTICAST' => $mc, 'BROADCAST' => $bc, 'UNICAST' => !$mc && !$bc, default => false }; }
    if (preg_match('/--icmp-type (\S+)/', $x, $m)) $ok = $ok && $k['p'] === 'icmp' && ($k['icmp'] === '' || $k['icmp'] === $m[1]);
    if (preg_match('/--(src|dst)-range (\S+)/', $x, $m)) { [$a, $b] = array_pad(explode('-', $m[2]), 2, ''); $ip = ip2long($m[1] === 'src' ? $k['s'] : $k['d']); $ok = $ok && $ip !== false && $ip >= ip2long($a) && $ip <= ip2long($b); }
    if (preg_match('/(?:^|\s)(!\s*)?-f(?:\s|$)/', $x, $mf)) { if (($mf[1] ?? '') === '') { $ok = false; $nt[] = 'Frammenti IP: la tua connessione non è frammentata, la regola non la riguarda.'; } }
    if (preg_match_all('/-m (\w+)/', $x, $mm)) foreach ($mm[1] as $mod) if (!in_array($mod, ['tcp', 'udp', 'icmp', 'multiport', 'conntrack', 'state', 'comment', 'addrtype', 'iprange', 'set', 'recent', 'hashlimit', 'connlimit', 'string', 'mac', 'owner', 'pkttype', 'length', 'ttl', 'mark', 'limit', 'rpfilter'], true)) { $ok = false; $nt[] = "Modulo «{$mod}» non valutabile: assunto «non riguarda il tuo traffico»."; }
    if (preg_match('/-m rpfilter\b/', $x)) { if (str_contains($x, '--invert')) { $ok = false; $nt[] = 'Reverse path filter: assunto «la sorgente è coerente col routing» (la regola scarta solo i pacchetti spoofati).'; } }
    if (str_contains($x, '-m set')) { $nt[] = 'Set ipset (blocklist/alias): contenuto non valutabile, assunto «nessuna corrispondenza».'; $ok = false; }
    if (preg_match('/--hashlimit-above|--connlimit-above/', $x)) $ok = false;
    if (preg_match('/-m recent/', $x) && preg_match('/--(update|rcheck)/', $x)) $ok = false;
    foreach (['string' => 'payload non valutabile', 'mac' => 'MAC non noto', 'owner' => 'proprietario non noto', 'pkttype' => 'tipo pacchetto non noto', 'length' => 'lunghezza non nota', 'ttl' => 'TTL non noto', 'mark' => 'mark non nota'] as $mod => $why)
        if (preg_match('/-m ' . $mod . '\b/', $x)) { $nt[] = "Modulo «{$mod}»: {$why}, assunto «nessuna corrispondenza»."; $ok = false; }
    if (preg_match('/-m time\b/', $x)) $nt[] = 'Orario: assunto «dentro la finestra» (modulo time).';
    return $ok;
}
function t_rule(array $f, array $k, array &$nt): bool {
    if ($f['i'] !== '' && !t_if($f['i'], $k['i'])) return false; if ($f['o'] !== '' && !t_if($f['o'], $k['o'])) return false;
    if ($f['s'] !== '' && !t_ip($f['s'], $k['s'])) return false; if ($f['d'] !== '' && !t_ip($f['d'], $k['d'])) return false;
    if ($f['p'] !== '') { [$ng, $v] = t_split($f['p']); $h = $v === 'all' || $v === $k['p']; if ($ng ? $h : !$h) return false; }
    foreach ([['sport', 'sport'], ['sports', 'sport'], ['dport', 'dport'], ['dports', 'dport']] as [$a, $b]) if ($f[$a] !== '' && !t_port($f[$a], $k[$b])) return false;
    if ($f['ports'] !== '') {
        [$neg, $ports] = t_split($f['ports']);
        if ($k['sport'] === '' || $k['dport'] === '') { $nt[] = 'Porte non specificate: match multiport non valutabile.'; return false; }
        $matches = t_port($ports, $k['sport']) || t_port($ports, $k['dport']);
        if ($neg ? $matches : !$matches) return false;
    }
    if ($f['ctstate'] !== '') { [$ng, $v] = t_split($f['ctstate']); $st = explode(',', $v); $h = in_array($k['state'], $st, true) || (!empty($k['dnat']) && in_array('DNAT', $st, true)); if ($ng ? $h : !$h) return false; }
    return t_extra($f['extra'], $k, $nt);
}
function t_policy(array $M, string $t, string $c): string { $ti = tb($M, $t); if ($ti >= 0) foreach ($M[$ti]['items'] as $it) if ($it['t'] === 'chain' && $it['n'] === $c) return $it['p'] === '-' ? 'ACCEPT' : $it['p']; return 'ACCEPT'; }
function t_chain(array $M, string $t, string $c, array &$k, array &$steps, array &$nt, int $depth = 0): string {
    if ($depth > 12) {$nt[]='Profondità catena oltre il limite di simulazione.';return 'RETURN';} $ti = tb($M, $t); if ($ti < 0) return 'RETURN'; $n = 0;
    foreach ($M[$ti]['items'] as $it) {
        if ($it['t'] !== 'rule' || rchain($it['r']) !== $c) continue; $n++; if (!$it['on']) continue;
        $f = rule_parse($it['r']); if (!t_rule($f, $k, $nt)) continue; $tg = $f['target']; $steps[] = [$t, $c, $n, $it['r']];
        if ($tg === '' || $tg === 'LOG') continue; if (in_array($tg, ['ACCEPT', 'DROP', 'REJECT', 'RETURN'], true)) return $tg;
        if ($tg === 'DNAT') { if (preg_match('/--to-destination ([\d.]+)(?::(\d+))?/', $f['targs'], $m)) { $k['d'] = $m[1]; if (!empty($m[2])) $k['dport'] = $m[2]; $k['dnat'] = true; } return 'NAT'; }
        if ($tg === 'REDIRECT') { $k['d'] = $k['local_ip'] ?: $k['d']; $k['dnat'] = true; if (preg_match('/--to-ports? (\d+)/', $f['targs'], $m)) $k['dport'] = $m[1]; return 'NAT'; }
        if ($tg === 'SNAT' || $tg === 'MASQUERADE') { $k['snat'] = $tg === 'SNAT' ? (preg_match('/--to-source ([\d.]+)/', $f['targs'], $m) ? $m[1] : '?') : 'IP dell\'interfaccia di uscita'; return 'NAT'; }
        $declared = false; foreach ($M[$ti]['items'] as $x) if ($x['t'] === 'chain' && $x['n'] === $tg) $declared = true;
        if ($declared) { $v = t_chain($M, $t, $tg, $k, $steps, $nt, $depth + 1); if ($v !== 'RETURN') return $v; } else { $nt[]='Target non simulato: '.$tg; }
    }
    return 'RETURN';
}
function trace_packet(array $M, array $P): array {
    $k = ['i' => $P['in'], 'o' => $P['out'], 's' => $P['src'], 'd' => $P['dst'], 'p' => $P['proto'], 'sport' => $P['sport'], 'dport' => $P['dport'], 'state' => $P['state'], 'icmp' => $P['icmp'] ?? '', 'local' => $P['flow'] === 'local', 'dnat' => false, 'local_ip' => $P['local_ip'] ?? ''];
    $steps = []; $nt = []; $isNew = $k['state'] === 'NEW'; $verdict = 'ACCEPT'; $where = '';
    $run = function (string $t, string $c) use (&$M, &$k, &$steps, &$nt, &$verdict, &$where) {
        $v = t_chain($M, $t, $c, $k, $steps, $nt); if ($v === 'DROP' || $v === 'REJECT') { $verdict = $v; $where = "$t/$c"; return false; }
        if ($v === 'RETURN' && $t === 'filter') { $p = t_policy($M, $t, $c); $steps[] = [$t, $c, 0, 'policy ' . $p]; if ($p === 'DROP') { $verdict = 'DROP'; $where = "policy $t/$c"; return false; } }
        return true;
    };
    $stages = $P['flow'] === 'out' ? [['raw', 'OUTPUT'], ['mangle', 'OUTPUT'], ['nat', 'OUTPUT'], ['filter', 'OUTPUT'], ['mangle', 'POSTROUTING'], ['nat', 'POSTROUTING']] : [['raw', 'PREROUTING'], ['mangle', 'PREROUTING'], ['nat', 'PREROUTING']];
    if ($P['flow'] !== 'out') {
        foreach ($stages as [$t, $c]) { if ($t === 'nat' && !$isNew) continue; if (!$run($t, $c)) return compact('verdict', 'where', 'steps', 'nt', 'k');
            if ($t === 'nat' && !empty($k['dnat'])) $k['local'] = in_array($k['d'], $P['local_ips'] ?? [], true); }
        $stages = $k['local'] ? [['mangle', 'INPUT'], ['filter', 'INPUT'], ['nat', 'INPUT']] : [['mangle', 'FORWARD'], ['filter', 'FORWARD'], ['mangle', 'POSTROUTING'], ['nat', 'POSTROUTING']];
    }
    foreach ($stages as [$t, $c]) { if ($t === 'nat' && !$isNew) continue; if (!$run($t, $c)) break; }
    return compact('verdict', 'where', 'steps', 'nt', 'k');
}

/** Public simulation input: strict IPv4 and bounded parameters. */
function iptm_trace_input(array $query,array $ifaces): array {
    $p=[];foreach(['flow'=>'local','in'=>'','out'=>'','src'=>'','dst'=>'','proto'=>'tcp','sport'=>'','dport'=>'','state'=>'NEW'] as $key=>$default){
        $v=$query[$key]??$default;if(!is_string($v)||strlen($v)>100)throw new InvalidArgumentException('Parametro non valido: '.$key);$p[$key]=trim($v);
    }
    if(!in_array($p['flow'],['local','forward','out'],true)||!in_array($p['proto'],['tcp','udp','icmp'],true)||!in_array($p['state'],['NEW','ESTABLISHED'],true))throw new InvalidArgumentException('Percorso, protocollo o stato non valido.');
    foreach(['in','out'] as $key)if($p[$key]!==''&&!array_key_exists($p[$key],$ifaces))throw new InvalidArgumentException('Interfaccia non rilevata: '.$key);
    foreach(['src','dst'] as $key)if(!filter_var($p[$key],FILTER_VALIDATE_IP,FILTER_FLAG_IPV4))throw new InvalidArgumentException('Indicare indirizzi IPv4 validi.');
    foreach(['sport','dport'] as $key)if($p[$key]!==''&&(!ctype_digit($p[$key])||(int)$p[$key]>65535||(int)$p[$key]<1||$p['proto']==='icmp'))throw new InvalidArgumentException('Porta non valida: '.$key);
    $p['local_ips']=[];foreach($ifaces as $addresses)foreach((array)$addresses as $address){$ip=explode('/',(string)$address,2)[0];if(filter_var($ip,FILTER_VALIDATE_IP,FILTER_FLAG_IPV4))$p['local_ips'][]=$ip;}
    $p['local_ip']=$p['local_ips'][0]??'';
    return $p;
}
