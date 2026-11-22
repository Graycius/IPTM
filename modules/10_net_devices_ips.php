<?php
// ===================== v2: CONNESSIONI, DISPOSITIVI, IPS =====================
function conn_parse(string $txt): array {
    $o = [];
    foreach (explode("\n", $txt) as $l) {
        $t = preg_split('/\s+/', trim($l)); if (count($t) < 6 || !isset($t[2])) continue; preg_match_all('/\b(src|dst|sport|dport|bytes|packets)=(\S+)/', $l, $m, PREG_SET_ORDER); $kv = []; foreach ($m as $x) $kv[$x[1]][] = $x[2];
        $o[] = ['proto' => $t[2], 'ttl' => (int)$t[4], 'state' => ($t[2] === 'tcp' ? $t[5] : ''), 'src' => $kv['src'][0] ?? '', 'dst' => $kv['dst'][0] ?? '', 'sport' => $kv['sport'][0] ?? '', 'dport' => $kv['dport'][0] ?? '', 'bytes' => (int)($kv['bytes'][0] ?? 0) + (int)($kv['bytes'][1] ?? 0)];
    }
    return $o;
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

