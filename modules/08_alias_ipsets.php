<?php
// ===================== v2: ALIAS, LISTE, GEOIP, IPSET =====================
const BL_PRESETS = ['spamhaus' => ['Spamhaus DROP (reti dirottate)', 'https://www.spamhaus.org/drop/drop.txt'], 'firehol1' => ['FireHOL Level 1 (attacchi gravi; reti private escluse)', 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset'],
    'etcomp' => ['Emerging Threats: IP compromessi', 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt'], 'blocklistde' => ['blocklist.de (attaccanti recenti)', 'https://lists.blocklist.de/lists/all.txt'],
    'cins' => ['CINS Army (IP malevoli)', 'https://cinsscore.com/list/ci-badguys.txt'], 'tor' => ['Nodi di uscita Tor (blocca anche gli utenti Tor)', 'https://check.torproject.org/torbulkexitlist'], 'spamhaus_edrop' => ['Spamhaus EDROP', 'https://www.spamhaus.org/drop/edrop.txt'], 'firehol2' => ['FireHOL Level 2', 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset'], 'sshd' => ['blocklist.de SSH', 'https://lists.blocklist.de/lists/ssh.txt'], 'dshield' => ['DShield (SANS top attackers)', 'https://iplists.firehol.org/files/dshield.netset'], 'greensnow' => ['GreenSnow (attaccanti recenti)', 'https://blocklist.greensnow.co/greensnow.txt'], 'ipsum' => ['IPsum level 3 (consolidated)', 'https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt']];
const GEO_NAMES = ['CN' => 'Cina', 'RU' => 'Russia', 'KP' => 'Corea del Nord', 'IR' => 'Iran', 'IN' => 'India', 'BR' => 'Brasile', 'VN' => 'Vietnam', 'ID' => 'Indonesia', 'PK' => 'Pakistan', 'TR' => 'Turchia', 'UA' => 'Ucraina', 'BY' => 'Bielorussia', 'NG' => 'Nigeria', 'KR' => 'Corea del Sud', 'TH' => 'Thailandia', 'EG' => 'Egitto', 'BD' => 'Bangladesh', 'RO' => 'Romania'];
function alias_map(array $S): array {
    $nets = []; $ports = [];
    foreach ($S['aliases'] ?? [] as $a) {
        if (!is_array($a) || !is_string($a['name'] ?? null) || !preg_match('/^[A-Za-z][A-Za-z0-9_-]{1,24}$/D',$a['name']) || !is_string($a['items'] ?? null)) continue;
        $it = preg_split('/[\s,;]+/', trim((string)$a['items']), -1, PREG_SPLIT_NO_EMPTY);
        if (!$it) { $nets[$a['name']] = []; continue; }
        if (v_ok('ports', implode(',', $it))) $ports[$a['name']] = implode(',', $it);
        elseif (!array_filter($it, fn($x) => !v_ok('nets', $x) || str_contains($x, ','))) $nets[$a['name']] = array_values(array_unique($it));
    }
    return ['nets' => $nets, 'ports' => $ports];
}
function v_netal(string $v, array $S): bool {
    if ($v === '' || v_ok('nets', $v)) return true; if (!preg_match('/^@([A-Za-z][A-Za-z0-9_-]{1,24})$/D', $v, $m)) return false;
    return isset(alias_map($S)['nets'][$m[1]]);
}
function list_sets(array $S): array {   // set ipset dinamici scaricati dall'helper
    $o = []; foreach ($S['blocklists'] ?? [] as $b) if (!empty($b['on'])) $o['bl_' . $b['id']] = $b['dir'];
    if (!empty($S['geo_on']) && $S['geo_codes'] !== '') $o['geo_block'] = $S['geo_dir']; return $o;
}
function fq_parse(string $t): array {   // righe "nome azione host1 host2": nome [a-z0-9]{1,12}, azione block|allow
    $o = []; foreach (preg_split('/\R/', $t) as $l) { $x = preg_split('/[\s,;]+/', trim($l), -1, PREG_SPLIT_NO_EMPTY); if (count($x) < 3) continue;
        [$id, $act] = [strtolower($x[0]), strtolower($x[1])]; $hosts = array_values(array_filter(array_slice($x, 2), fn($h) => (bool)preg_match('/^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$/D', $h)));
        if (preg_match('/^[a-z0-9]{1,12}$/D', $id) && in_array($act, ['block', 'allow'], true) && $hosts && !isset($o[$id])) $o[$id] = ['act' => $act, 'hosts' => $hosts]; }
    return $o;
}
function ipset_text(array $S): string {
    $o = []; $swap = function ($set, $items) use (&$o) {
        $o[] = "create $set hash:net family inet hashsize 1024 maxelem 65536 -exist"; $o[] = "create {$set}.t hash:net family inet hashsize 1024 maxelem 65536 -exist"; $o[] = "flush {$set}.t";
        foreach ($items as $i) $o[] = "add {$set}.t $i -exist"; $o[] = "swap {$set}.t $set"; $o[] = "destroy {$set}.t";
    };
    foreach (alias_map($S)['nets'] as $n => $items) $swap('al_' . $n, $items);
    foreach (['iptm_manual' => 'manual_block', 'iptm_allow' => 'manual_allow'] as $set => $key) {
        $l = preg_split('/[\s,;]+/', trim((string)($S[$key] ?? '')), -1, PREG_SPLIT_NO_EMPTY); $swap($set, array_values(array_filter($l, fn($x) => v_ok('nets', $x) && !str_contains($x, ','))));
    }
    foreach (list_sets($S) as $set => $d) $o[] = "create $set hash:net family inet hashsize 4096 maxelem 262144 -exist";
    foreach (fq_parse((string)($S['fqdn_rules'] ?? '')) as $id => $_) $o[] = "create fq_$id hash:net family inet hashsize 1024 maxelem 65536 -exist";
    return implode("\n", $o) . "\n";
}
function lists_conf(array $S): string {
    $o = []; foreach ($S['blocklists'] ?? [] as $b) if (!empty($b['on'])) $o[] = 'bl_' . $b['id'] . ' ' . $b['url'];
    if (!empty($S['geo_on']) && $S['geo_codes'] !== '') { $u = []; foreach (explode(',', strtolower($S['geo_codes'])) as $c) $u[] = 'https://www.ipdeny.com/ipblocks/data/aggregated/' . $c . '-aggregated.zone'; $o[] = 'geo_block ' . implode(' ', $u); }
    return $o ? implode("\n", $o) . "\n" : '';
}
function ipsets_prepare(): void { priv('ipset-load', ipset_text(S_get())); }
