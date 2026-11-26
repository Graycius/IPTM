<?php
// ===================== v3.1: RILEVAMENTO DAL SISTEMA (ipset, catene, CrowdSec) =====================
const STD_TARGETS = ['ACCEPT', 'DROP', 'REJECT', 'LOG', 'RETURN', 'DNAT', 'SNAT', 'MASQUERADE', 'REDIRECT', 'TCPMSS', 'MARK', 'NOTRACK', 'CT', 'TOS', 'TTL', 'HL', 'DSCP', 'CLASSIFY', 'CONNMARK', 'CONNSECMARK', 'SECMARK', 'NFLOG', 'NFQUEUE', 'TPROXY', 'TEE', 'SET', 'AUDIT', 'CHECKSUM', 'ECN', 'IDLETIMER', 'LED', 'NETMAP', 'RATEEST', 'SYNPROXY', 'TRACE', 'CLUSTERIP', 'ULOG', 'MIRROR', 'DNPT', 'SNPT', 'TARPIT', 'DELUDE', 'CHAOS', 'ACCOUNT', 'LOGMARK', 'STEAL', 'SYSRQ', 'ECHO', 'IPMARK', 'DNETMAP'];
function ipset_inventory(): array { return kc('ipinv', 'ipset_inventory_raw'); }
function ipset_inventory_raw(): array {
    [$c, $o] = priv('ipset-info'); if ($c !== 0) return ['ok' => false, 'sets' => []]; $sets = []; $cur = null;
    foreach (explode("\n", $o) as $l) {
        if (preg_match('/^Name: (\S+)/', $l, $m)) { $cur = $m[1]; $sets[$cur] = ['name' => $cur, 'type' => '', 'refs' => 0, 'n' => 0]; }
        elseif ($cur && preg_match('/^Type: (\S+)/', $l, $m)) $sets[$cur]['type'] = $m[1]; elseif ($cur && preg_match('/^References: (\d+)/', $l, $m)) $sets[$cur]['refs'] = (int)$m[1]; elseif ($cur && preg_match('/^Number of entries: (\d+)/', $l, $m)) $sets[$cur]['n'] = (int)$m[1];
    }
    return ['ok' => true, 'sets' => $sets];
}
function draft_sets(string $txt): array {
    $o = []; foreach (parse_rules($txt) as $b) if ($b['k'] === 'table') foreach ($b['items'] as $it) if ($it['t'] === 'rule' && $it['on'] && preg_match_all('/--match-set\s+(\S+)/', $it['r'], $m)) foreach ($m[1] as $s) $o[$s] = 1;
    return array_keys($o);
}
function own_set(string $n): bool { return (bool)preg_match('/^(al_|bl_|fq_)|^(geo_block|iptm_manual|iptm_allow)(\.t)?$/', $n); }
function sets_missing(string $txt, array $have): array { $m = []; foreach (draft_sets($txt) as $s) if (!isset($have[$s]) && !own_set($s)) $m[] = $s; return $m; }
function set_hint(array $miss, array $have): string {
    $o = []; foreach ($miss as $s) { $c = array_values(array_filter(array_keys($have), fn($h) => str_starts_with($h, $s) || str_starts_with($s, $h) || (stripos($h, 'crowdsec') !== false && stripos($s, 'crowdsec') !== false))); if ($c) $o[] = "per «{$s}» sono presenti: " . implode(', ', array_slice($c, 0, 4)); }
    return $o ? implode('; ', $o) . '.' : 'Nel sistema non c\'è alcun set simile (il servizio che lo crea è avviato?).';
}
function fix_chain_decls(string $txt): array {   // [testo, catene dichiarate in automatico, catene inesistenti]
    $M = parse_rules($txt); $live = live_dump()['chains'] ?? []; $fixed = []; $missing = [];
    foreach ($M as $ti => $b) {
        if ($b['k'] !== 'table') continue; $decl = []; foreach (BUILTIN[$b['name']] ?? [] as $c) $decl[$c] = 1; foreach ($b['items'] as $it) if ($it['t'] === 'chain') $decl[$it['n']] = 1;
        $own = []; $jump = [];
        foreach ($b['items'] as $it) if ($it['t'] === 'rule' && $it['on']) { $f = rule_parse($it['r']); if (!isset($decl[$f['chain']])) $own[$f['chain']] = 1; $tg = $f['target']; if ($tg !== '' && !isset($decl[$tg]) && !in_array($tg, STD_TARGETS, true)) $jump[$tg] = 1; }
        foreach (array_keys($own + $jump) as $c) {
            if (isset($own[$c]) || isset($live[$b['name']][$c]) || dyn_owner($c) !== '') { $last = 0; foreach ($M[$ti]['items'] as $i => $it) if ($it['t'] === 'chain') $last = $i + 1; array_splice($M[$ti]['items'], $last, 0, [['t' => 'chain', 'n' => $c, 'p' => '-']]); $fixed[] = $b['name'] . '/' . $c; }
            else $missing[] = $b['name'] . '/' . $c;
        }
    }
    return [$fixed ? ser($M) : $txt, $fixed, $missing];
}
function cs_detect(): array {   // set, catena iptables e/o tabella nft del bouncer
    $inv = ipset_inventory(); $s4 = []; $s6 = [];
    foreach (array_keys($inv['sets'] ?? []) as $n) {
        if (preg_match('/^' . CS_V4 . '(-[A-Za-z0-9_.]+)?$/', $n)) $s4[] = $n;
        elseif (preg_match('/^' . CS_V6 . '(-[A-Za-z0-9_.]+)?$/', $n)) $s6[] = $n;
    }
    natsort($s4); natsort($s6); $ch = '';
    foreach (array_keys(live_dump()['chains']['filter'] ?? []) as $c) {
        if (!preg_match('/^crowdsec/i', $c) || preg_match('/_LOG$/i', $c)) continue;
        if ($ch === '' || $c === CS_CHAIN) $ch = $c;
    }
    $st = cs_status();
    $mode = (string)($st['mode'] ?? 'unknown');
    $nft = !empty($st['nft_table']);
    $svc = (string)($st['svc'] ?? '');
    $active = ($svc === 'active');
    $usable = ($ch !== '') || ($nft && $mode === 'nftables') || ($active && in_array($mode, ['nftables', 'ipset'], true));
    return [
        'sets' => array_values($s4),
        'sets6' => array_values($s6),
        'chain' => $ch,
        'mode' => $mode,
        'nft_table' => $nft,
        'svc' => $svc,
        'usable' => $usable,
    ];
}
function cs_status(): array {   // stato servizio, modo bouncer, nft/chain, origini set
    $r = ['svc' => '', 'mode' => 'unknown', 'nft_table' => false, 'chain_v4' => false, 'chain_v6' => false, 'origin' => []];
    [$c, $o] = priv('cs-status');
    if ($c !== 0) return $r;
    foreach (explode("\n", $o) as $l) {
        $l = trim($l);
        if (str_starts_with($l, 'service ')) $r['svc'] = trim(substr($l, 8));
        elseif (str_starts_with($l, 'mode ')) $r['mode'] = trim(substr($l, 5));
        elseif ($l === 'nft_table yes') $r['nft_table'] = true;
        elseif ($l === 'chain_v4 yes') $r['chain_v4'] = true;
        elseif ($l === 'chain_v6 yes') $r['chain_v6'] = true;
        elseif (preg_match('/--match-set (crowdsec6?-blacklists\S*) src/', $l, $m) && preg_match('/--comment (?:"([^"]*)"|(\S+))/', $l, $q)) {
            $r['origin'][$m[1]] = trim($q[1] !== '' ? $q[1] : ($q[2] ?? ''));
        }
    }
    return $r;
}
