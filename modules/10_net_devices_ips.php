<?php
// ===================== v2: CONNESSIONI, DISPOSITIVI, IPS =====================
function conn_parse(string $txt): array {
    $out = [];
    foreach (explode("\n", $txt) as $line) {
        // /proc/net/nf_conntrack includes the family; conntrack -L and
        // /proc/net/ip_conntrack normally start directly with the protocol.
        if (!preg_match('/^(?:(?:ipv4|ipv6)\s+[0-9]+\s+)?([a-zA-Z0-9_-]+)\s+[0-9]+\s+([0-9]+)\s+(.*)$/D', trim($line), $head)) continue;
        $proto = strtolower($head[1]); $tail = $head[3]; $kv = [];
        preg_match_all('/\b(src|dst|sport|dport|bytes|packets)=(\S+)/', $tail, $pairs, PREG_SET_ORDER);
        foreach ($pairs as $pair) $kv[$pair[1]][] = $pair[2];
        $src = $kv['src'][0] ?? ''; $dst = $kv['dst'][0] ?? '';
        if (!filter_var($src, FILTER_VALIDATE_IP) || !filter_var($dst, FILTER_VALIDATE_IP)) continue;
        if ((str_contains($src, ':')) !== (str_contains($dst, ':'))) continue;
        $sport = $kv['sport'][0] ?? ''; $dport = $kv['dport'][0] ?? '';
        foreach ([$sport, $dport] as $port) if ($port !== '' && (!ctype_digit($port) || (int)$port > 65535)) continue 2;
        $state = '';
        if ($proto === 'tcp' && preg_match('/^([A-Z_]+)\s+/', $tail, $match)) $state = $match[1];
        $bytes = 0;
        foreach (array_slice($kv['bytes'] ?? [], 0, 2) as $value) {
            if (!ctype_digit($value)) continue 2;
            $bytes = (int)min(PHP_INT_MAX, (float)$bytes + (float)$value);
            if ($bytes < 0) $bytes = PHP_INT_MAX;
        }
        $out[] = ['proto'=>$proto,'ttl'=>(int)$head[2],'state'=>$state,'src'=>$src,'dst'=>$dst,'sport'=>$sport,'dport'=>$dport,'bytes'=>$bytes];
    }
    return $out;
}
function devices(): array {
    $d = []; [, $o] = run([BIN_IP, '-4', 'neigh', 'show']);
    foreach (explode("\n", $o) as $l) if (preg_match('/^(\S+) dev (\S+) lladdr (\S+) (\S+)/', $l, $m)) $d[$m[1]] = ['ip' => $m[1], 'if' => $m[2], 'mac' => $m[3], 'st' => $m[4], 'name' => ''];
    [, $o] = priv('leases');
    foreach (explode("\n", $o) as $l) if (preg_match('/^\d+ (\S+) (\d+\.\d+\.\d+\.\d+) (\S+)/', $l, $m)) { $d[$m[2]] = ($d[$m[2]] ?? ['ip' => $m[2], 'if' => '', 'st' => 'DHCP']) + []; $d[$m[2]]['mac'] = $m[1]; $d[$m[2]]['name'] = $m[3] === '*' ? '' : $m[3]; }
    uksort($d, fn($a, $b) => ip2long($a) <=> ip2long($b)); return $d;
}
function ips_parse(string $txt): array {   // fast.log di Suricata (IPv4 e IPv6)
    $o = [];
    foreach (array_reverse(explode("\n", trim($txt))) as $l) {
        if (!preg_match('/^(\S+)\s+\[\*\*\]\s+\[[\d:]+\]\s+(.*?)\s+\[\*\*\](?:\s+\[Classification: ([^\]]*)\])?(?:\s+\[Priority: (\d+)\])?\s+\{([\w-]+)\}\s+(\S+?)(?::(\d+))?\s+->\s+(\S+?)(?::(\d+))?\s*$/', $l, $m)) continue;
        $sp = $m[7] ?? ''; $dp = $m[9] ?? ''; $src = $m[6]; $dst = $m[8];
        if (!in_array(strtoupper($m[5]), ['TCP', 'UDP', 'SCTP'], true)) { if ($sp !== '') $src .= ':' . $sp; if ($dp !== '') $dst .= ':' . $dp; $sp = $dp = ''; }
        $o[] = ['t' => $m[1], 'sig' => $m[2], 'cls' => $m[3], 'pri' => $m[4], 'proto' => $m[5], 'src' => $src, 'sport' => $sp, 'dst' => $dst, 'dport' => $dp];
    }
    return $o;
}

