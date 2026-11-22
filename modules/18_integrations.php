<?php
// ===================== INTEGRAZIONI: API read-only, CrowdSec preset, liste extra =====================

/** Token API (settings o file in DATA_DIR). Vuoto = API disabilitata. */
function api_token_get(): string {
    $S = S_get();
    $t = trim((string)($S['api_token'] ?? ''));
    if ($t !== '') return $t;
    $f = DATA_DIR . '/api.token';
    if (is_file($f)) return trim((string)@file_get_contents($f));
    return '';
}

function api_token_set(string $t): void {
    $S = S_get();
    $S['api_token'] = $t;
    S_put($S);
    $f = DATA_DIR . '/api.token';
    if ($t === '') @unlink($f);
    else { @file_put_contents($f, $t . "\n", LOCK_EX); @chmod($f, 0600); }
}

function api_auth_ok(): bool {
    $need = api_token_get();
    if ($need === '') return false;
    $got = '';
    $h = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '';
    if (preg_match('/^\s*Bearer\s+(\S+)/i', $h, $m)) $got = $m[1];
    if ($got === '') $got = (string)($_SERVER['HTTP_X_API_TOKEN'] ?? '');
    return $got !== '' && hash_equals($need, $got);
}

/** Dispaccia ?api=... (solo lettura). Esce con JSON o text/plain metrics. */
function api_dispatch(string $ep): void {
    header('X-Content-Type-Options: nosniff');
    header('Cache-Control: no-store, private');
    header('Referrer-Policy: no-referrer');
    header('X-Frame-Options: DENY');
    if (!api_auth_ok()) {
        http_response_code(401);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['error' => 'unauthorized', 'hint' => 'Usa Authorization: Bearer oppure X-API-Token'], JSON_UNESCAPED_UNICODE);
        exit;
    }
    $ep = strtolower(preg_replace('/[^a-z0-9_-]/', '', $ep) ?? '');
    try {
        $data = match ($ep) {
            'status' => api_payload_status(),
            'conns' => api_payload_conns(),
            'decisions' => api_payload_decisions(),
            'crowdsec' => api_payload_crowdsec(),
            'lists' => api_payload_lists(),
            'metrics' => null, // handled below
            default => null,
        };
        if ($ep === 'metrics') {
            header('Content-Type: text/plain; charset=utf-8');
            echo api_prometheus();
            exit;
        }
        if ($data === null) {
            http_response_code(404);
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode(['error' => 'unknown endpoint', 'endpoints' => ['status', 'conns', 'decisions', 'crowdsec', 'lists', 'metrics']], JSON_UNESCAPED_UNICODE);
            exit;
        }
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store');
        echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    } catch (Throwable $e) {
        http_response_code(500);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['error' => 'server'], JSON_UNESCAPED_UNICODE);
    }
    exit;
}

function api_payload_status(): array {
    $S = S_get();
    $L = function_exists('live_state') ? live_state() : [];
    $pending = function_exists('pending') ? pending() : null;
    return [
        'app' => APP_VERSION,
        'time' => time(),
        'pending' => $pending ? ['until' => $pending['until'] ?? null, 'fam' => $pending['fam'] ?? '4', 'status' => $pending['status'] ?? 'pending'] : null,
        'wan_if' => $S['wan_if'] ?? '',
        'lan_nets' => $S['lan_nets'] ?? '',
        'crowdsec' => !empty($S['crowdsec']),
        'docker_accept' => !empty($S['docker_accept']),
        'wg_on' => !empty($S['wg_on']),
        'live' => [
            'conntrack' => $L['ct'] ?? null,
            'policy_in' => $L['pin'] ?? null,
            'policy_fw' => $L['pfw'] ?? null,
        ],
    ];
}

function api_payload_conns(): array {
    if (function_exists('conntrack_live')) {
        $ct = conntrack_live(80);
        return ['total' => $ct['total'], 'top_src' => $ct['top_src'], 'top_dst' => $ct['top_dst'], 'by_proto' => $ct['by_proto'], 'sample' => array_map(fn($r) => [
            'proto' => $r['proto'], 'src' => $r['src'], 'dst' => $r['dst'], 'sport' => $r['sport'], 'dport' => $r['dport'], 'state' => $r['state'],
        ], $ct['rows'])];
    }
    return ['total' => 0, 'sample' => []];
}

function api_payload_decisions(): array {
    $dec = function_exists('cs_decisions') ? cs_decisions() : [];
    return ['count' => count($dec), 'items' => array_slice($dec, 0, 100)];
}

function api_payload_crowdsec(): array {
    $info = function_exists('cs_info') ? cs_info() : [];
    $st = function_exists('cs_status') ? cs_status() : [];
    return ['info' => $info, 'status' => $st];
}

function api_payload_lists(): array {
    $S = S_get();
    $rows = [];
    foreach ($S['blocklists'] ?? [] as $b) {
        $rows[] = [
            'id' => $b['id'] ?? '',
            'name' => $b['name'] ?? '',
            'on' => !empty($b['on']),
            'dir' => $b['dir'] ?? 'in',
            'url' => $b['url'] ?? '',
        ];
    }
    return ['blocklists' => $rows, 'geo_on' => !empty($S['geo_on']), 'geo_codes' => $S['geo_codes'] ?? ''];
}

function api_prometheus(): string {
    $lines = [];
    $lines[] = '# HELP iptm_up iptables-manager is up';
    $lines[] = '# TYPE iptm_up gauge';
    $lines[] = 'iptm_up 1';
    $ct = @file_get_contents('/proc/sys/net/netfilter/nf_conntrack_count');
    $mx = @file_get_contents('/proc/sys/net/netfilter/nf_conntrack_max');
    if ($ct !== false) {
        $lines[] = '# HELP iptm_conntrack_count current conntrack entries';
        $lines[] = '# TYPE iptm_conntrack_count gauge';
        $lines[] = 'iptm_conntrack_count ' . (int)$ct;
    }
    if ($mx !== false) {
        $lines[] = '# HELP iptm_conntrack_max max conntrack entries';
        $lines[] = '# TYPE iptm_conntrack_max gauge';
        $lines[] = 'iptm_conntrack_max ' . (int)$mx;
    }
    $fileTxt = rules_live();
    $draftTxt = get_draft();
    $lines[] = '# HELP iptm_draft_dirty 1 if draft differs from rules.v4';
    $lines[] = '# TYPE iptm_draft_dirty gauge';
    $lines[] = 'iptm_draft_dirty ' . (rules_equiv($fileTxt, $draftTxt) ? 0 : 1);
    if (function_exists('cs_decisions')) {
        $n = count(cs_decisions());
        $lines[] = '# HELP iptm_crowdsec_decisions active CrowdSec decisions';
        $lines[] = '# TYPE iptm_crowdsec_decisions gauge';
        $lines[] = 'iptm_crowdsec_decisions ' . $n;
    }
    $S = S_get();
    $bln = 0;
    foreach ($S['blocklists'] ?? [] as $b) if (!empty($b['on'])) $bln++;
    $lines[] = '# HELP iptm_blocklists_enabled number of enabled IP blocklists';
    $lines[] = '# TYPE iptm_blocklists_enabled gauge';
    $lines[] = 'iptm_blocklists_enabled ' . $bln;
    $lines[] = '# HELP iptm_info build info';
    $lines[] = '# TYPE iptm_info gauge';
    $lines[] = 'iptm_info{version="' . addcslashes(APP_VERSION, '"\\') . '"} 1';
    $lines[] = '';
    return implode("\n", $lines);
}

/** Preset bouncer: INPUT + FORWARD (se routing) + DOCKER-USER. */
function cs_bouncer_setup_recommended(): array {
    $args = ['INPUT'];
    if ((int)@file_get_contents('/proc/sys/net/ipv4/ip_forward') === 1) $args[] = 'FORWARD';
    // DOCKER-USER se catena esiste o Docker installato
    $hasDocker = false;
    [$c] = function_exists('run') ? run(['/sbin/iptables', '-S', 'DOCKER-USER']) : [1];
    if ($c === 0) $hasDocker = true;
    if (!$hasDocker && (is_dir('/var/lib/docker') || is_file('/usr/bin/docker'))) $hasDocker = true;
    if ($hasDocker) $args[] = 'DOCKER-USER';
    $args[] = 'DROP';
    [$rc, $o, $e] = priv('cs-bouncer-setup', null, $args);
    return [$rc, trim($o . "\n" . $e)];
}

/** Suggerisce ui_nets limitato a LAN + rete WireGuard. */
function wg_mgmt_nets_suggest(array $S): string {
    $parts = [];
    foreach (explode(',', (string)($S['lan_nets'] ?? '')) as $n) {
        $n = trim($n);
        if ($n !== '') $parts[] = $n;
    }
    $wg = trim((string)($S['wg_net'] ?? ''));
    if ($wg !== '') $parts[] = $wg;
    elseif (!empty($S['wg_on'])) $parts[] = '10.6.0.0/24'; // default tipico
    $parts[] = '127.0.0.0/8';
    return implode(',', array_unique($parts));
}


/** Export impostazioni come YAML leggibile (gruppi servizi / policy). */
function policy_export_yaml(?array $S = null): string {
    $S = $S ?? S_get();
    $esc = function ($v) {
        if (is_bool($v)) return $v ? 'true' : 'false';
        if (is_int($v) || is_float($v)) return (string)$v;
        if (is_array($v)) return null;
        $s = (string)$v;
        if ($s === '') return '""';
        if (preg_match('/[\s:#\[\]{}\'"\\\\]/', $s) || $s !== trim($s)) return '"' . addcslashes($s, "\\\"\n") . '"';
        return $s;
    };
    $lines = ['# IPTM policy export ' . date('c') . ' app=' . APP_VERSION, 'version: ' . APP_VERSION, 'network:'];
    foreach (['wan_if' => 'wan', 'lan_if' => 'lan', 'lan_nets' => 'lan_nets', 'nat_masq' => 'nat_masq'] as $k => $lab) {
        if (!array_key_exists($k, $S)) continue;
        $v = $S[$k];
        $e = $esc(is_bool($v) || is_int($v) ? $v : (string)$v);
        if ($e !== null) $lines[] = "  $lab: $e";
    }
    $lines[] = 'services:';
    $svcKeys = ['ssh_port','web_ports','dns_local','dns_ip','wg_on','wg_net','docker_accept','lan_tcp_accept','coap_accept','bcast_accept'];
    foreach ($svcKeys as $k) {
        if (!array_key_exists($k, $S)) continue;
        $v = $S[$k];
        if (is_array($v)) $v = empty($v) ? '[]' : json_encode($v, JSON_UNESCAPED_UNICODE);
        elseif (is_bool($v)) $v = $v ? 1 : 0;
        elseif ($v === null) $v = '';
        $e = $esc($v);
        if ($e !== null) $lines[] = "  $k: $e";
    }
    $lines[] = 'security:';
    foreach (['crowdsec','stealth','synproxy','dos','portscan','log_in','log_out'] as $k) {
        if (!array_key_exists($k, $S)) continue;
        $lines[] = '  ' . $k . ': ' . $esc(!empty($S[$k]));
    }
    $lines[] = 'blocklists:';
    foreach ($S['blocklists'] ?? [] as $b) {
        if (empty($b['on'])) continue;
        $lines[] = '  - id: ' . $esc($b['id'] ?? '');
        $lines[] = '    name: ' . $esc($b['name'] ?? '');
        $lines[] = '    dir: ' . $esc($b['dir'] ?? 'in');
    }
    $lines[] = 'apps:';
    foreach ($S['apps'] ?? [] as $id => $on) {
        if (!$on) continue;
        $lines[] = '  - ' . $esc($id);
    }
    $lines[] = 'aliases:';
    foreach ($S['aliases'] ?? [] as $a) {
        $lines[] = '  - name: ' . $esc($a['name'] ?? '');
        $lines[] = '    items: ' . $esc($a['items'] ?? '');
    }
    return implode("\n", $lines) . "\n";
}

/** Conntrack live summary for stats/API. */
function conntrack_live(int $limit = 40): array {
    $rows = [];
    [$c, $o] = function_exists('priv') ? priv('conns') : [1, ''];
    if ($c !== 0 || trim($o) === '') {
        // fallback
        $o = @shell_exec('conntrack -L 2>/dev/null') ?: '';
    }
    $src = []; $dst = []; $proto = [];
    foreach (preg_split('/\r?\n/', trim($o)) as $line) {
        if ($line === '') continue;
        $r = ['raw' => $line, 'proto' => '', 'src' => '', 'dst' => '', 'sport' => '', 'dport' => '', 'state' => ''];
        if (preg_match('/^(tcp|udp|icmp)\s+/i', $line, $m)) $r['proto'] = strtolower($m[1]);
        if (preg_match('/\bsrc=(\S+)/', $line, $m)) $r['src'] = $m[1];
        if (preg_match('/\bdst=(\S+)/', $line, $m)) $r['dst'] = $m[1];
        if (preg_match('/\bsport=(\d+)/', $line, $m)) $r['sport'] = $m[1];
        if (preg_match('/\bdport=(\d+)/', $line, $m)) $r['dport'] = $m[1];
        if (preg_match('/\b(?:state|tcp)\s*=?\s*([A-Z_]+)/', $line, $m)) $r['state'] = $m[1];
        $rows[] = $r;
        if ($r['src'] !== '') $src[$r['src']] = ($src[$r['src']] ?? 0) + 1;
        if ($r['dst'] !== '') $dst[$r['dst']] = ($dst[$r['dst']] ?? 0) + 1;
        if ($r['proto'] !== '') $proto[$r['proto']] = ($proto[$r['proto']] ?? 0) + 1;
    }
    arsort($src); arsort($dst); arsort($proto);
    return [
        'total' => count($rows),
        'top_src' => array_slice($src, 0, 10, true),
        'top_dst' => array_slice($dst, 0, 10, true),
        'by_proto' => $proto,
        'rows' => array_slice($rows, 0, $limit),
    ];
}

/** Imposta bouncer in mode=ipset (set-only: non inserisce regole, gestisce solo i set). */
function cs_bouncer_set_only(): array {
    [$rc, $o, $e] = priv('cs-bouncer-set', null, ['mode', 'ipset']);
    return [$rc, trim($o . "\n" . $e) . "\nNota: mode=ipset = il bouncer aggiorna solo gli ipset; le regole -m set devono essere già in IPTM."];
}


/** Rileva WAN e propone limiti SQM (senza speedtest lungo). */
function sqm_autodetect(): array {
    $out = [
        'ok' => false, 'iface' => '', 'link_mbit' => 0, 'overhead' => 'ethernet',
        'suggest_down' => 0, 'suggest_up' => 0, 'notes' => [], 'raw' => '',
    ];
    [$c, $o] = priv('sqm-probe');
    $out['raw'] = trim($o);
    $map = [];
    foreach (preg_split('/\r?\n/', trim($o)) as $line) {
        if (preg_match('/^(\S+)\s+(.+)$/', $line, $m)) $map[$m[1]] = trim($m[2]);
    }
    $iface = $map['iface'] ?? '';
    if ($iface === '' || $iface === 'unknown') {
        $S = S_get();
        $iface = trim((string)($S['wan_if'] ?? ''));
        if ($iface === '') {
            foreach (array_keys(sys_ifaces()) as $i) { $iface = $i; break; }
        }
        $out['notes'][] = 'Interfaccia da impostazioni/prima NIC (default route non trovata).';
    }
    $out['iface'] = $iface;
    $out['link_mbit'] = (int)($map['link_mbit'] ?? 0);
    $ov = $map['overhead'] ?? 'ethernet';
    if (!in_array($ov, ['none', 'ethernet', 'pppoe-v4', 'pppoe-ptm', 'bridged-ptm', 'conservative'], true)) $ov = 'ethernet';
    $out['overhead'] = $ov;

    $sd = (int)($map['suggest_down_mbit'] ?? 0);
    $su = (int)($map['suggest_up_mbit'] ?? 0);
    // Una misura effettuata mentre CAKE è attivo NON è un nuovo massimo di linea.
    // Non usare sqm-calibrate.last per Autoconfigura, o il 92% può essere
    // riapplicato a velocità già limitate e ridurre la banda ad ogni ciclo.

    // Preferisci valori già in settings se ragionevoli
    $S = S_get();
    $cur_d = (int)($S['sqm']['down'] ?? 0);
    $cur_u = (int)($S['sqm']['up'] ?? 0);
    if ($cur_d > 0 && $cur_u > 0) {
        $sd = $cur_d; $su = $cur_u;
        $out['notes'][] = 'Limiti esistenti conservati: nessuna ricalibrazione da velocità già sottoposta a CAKE.';
    }

    // Hint da bw_on policer se presente
    // Stima conservativa se link gigabit verso modem: non inventare 1000 Mbit
    if ($sd <= 0 && $out['link_mbit'] >= 1000) {
        $out['notes'][] = 'Link ≥1 Gbit (tipico LAN→modem): inserisci le velocità del contratto ISP oppure lascia i valori attuali.';
        if ($cur_d >= 1 && $cur_u >= 1) {
            $sd = $cur_d; $su = $cur_u;
            $out['notes'][] = 'Mantengo i limiti già configurati.';
        } else {
            // default generici FTTH/FTTC comuni in IT se sconosciuti
            $sd = 100; $su = 20;
            $out['notes'][] = 'Proposta generica 100/20 Mbit (modifica con i valori del contratto).';
        }
    } elseif ($sd <= 0) {
        if ($cur_d >= 1 && $cur_u >= 1) {
            $sd = $cur_d; $su = $cur_u;
            $out['notes'][] = 'Nessuna stima link: uso valori già impostati.';
        } else {
            $sd = 50; $su = 10;
            $out['notes'][] = 'Nessuna stima: proposta 50/10 Mbit (modifica con velocità reali al 90–95%).';
        }
    } else {
        $out['notes'][] = 'Stima da velocità di link (90% down, ~40% up asimmetrico). Verifica col contratto.';
    }

    // Applica margine anti-bufferbloat (già 90% se da link; se da utente lascia)
    $out['suggest_down'] = max(1, $sd);
    $out['suggest_up'] = max(1, $su);
    $out['ok'] = ($iface !== '');
    // Profili consigliati
    $out['diffserv'] = 'diffserv4';
    $out['ack_filter'] = 1;
    $out['nat'] = 1;
    $out['prio_interactive'] = 1;
    $out['prio_voip'] = 1;
    $out['prio_games'] = 1;
    $out['prio_bulk_low'] = 1;
    return $out;
}

/** Applica autoconfig SQM e aggiorna settings. */
function sqm_autoconfig_apply(bool $enable = true): array {
    $det = sqm_autodetect();
    if (!$det['ok']) return [1, 'Autodetect fallito: interfaccia WAN sconosciuta.', $det];
    $S = S_get();
    $q = ($S['sqm'] ?? []) + (S_def()['sqm'] ?? []);
    $q['on'] = $enable ? 1 : 0;
    $q['iface'] = $det['iface'];
    $q['down'] = (int)$det['suggest_down'];
    $q['up'] = (int)$det['suggest_up'];
    $q['overhead'] = $det['overhead'];
    $q['diffserv'] = $det['diffserv'];
    $q['ack_filter'] = $det['ack_filter'];
    $q['nat'] = $det['nat'];
    $q['prio_interactive'] = $det['prio_interactive'];
    $q['prio_voip'] = $det['prio_voip'];
    $q['prio_games'] = $det['prio_games'];
    $q['prio_bulk_low'] = $det['prio_bulk_low'];
    $q['auto'] = 1;
    if ($enable && !empty($S['sqm']['on']) &&
        (string)($S['sqm']['iface'] ?? '') === (string)$q['iface'] &&
        (int)($S['sqm']['down'] ?? 0) === (int)$q['down'] &&
        (int)($S['sqm']['up'] ?? 0) === (int)$q['up']) {
        return [0, 'Limiti SQM già configurati: conservati senza riapplicare CAKE. Per modificare la banda usa valori indipendenti nella configurazione manuale.', $det];
    }
    $S['sqm'] = $q;
    if (!$enable) {
        [$c, $o, $e] = priv('sqm-off');
        if ($c === 0) S_put($S);
        return [$c, $c === 0 ? 'SQM disattivato.' : trim($o . $e), $det];
    }
    [$c, $o, $e] = priv('sqm-set', null, [
        $q['iface'], (string)$q['up'], (string)$q['down'],
        $q['diffserv'], (string)$q['ack_filter'], (string)$q['nat'],
        $q['overhead'], (string)($q['wash'] ?? 0),
    ]);
    if ($c === 0) {
        S_put($S); // commit only after helper successfully applies CAKE
        $msg = 'Autoconfig OK: ' . $q['iface'] . ' ' . $q['down'] . '/' . $q['up'] . ' Mbit, '
            . $q['diffserv'] . ', framing ' . $q['overhead'] . '.';
        if ($det['notes']) $msg .= ' ' . implode(' ', $det['notes']);
    } else {
        $msg = 'CAKE non applicato: ' . trim($o . ' ' . $e);
        if ($det['notes']) $msg .= ' — Note: ' . implode(' ', $det['notes']);
    }
    return [$c, $msg, $det];
}


/** Esegue speedtest via helper e restituisce Mbit/s. */
function sqm_speedtest(): array {
    [$c, $o] = priv('sqm-speedtest');
    $r = ['ok' => false, 'down' => 0, 'up' => 0, 'method' => 'none', 'raw' => trim($o)];
    foreach (preg_split('/\r?\n/', trim($o)) as $line) {
        if (preg_match('/^method\s+(\S+)/', $line, $m)) $r['method'] = $m[1];
        if (preg_match('/^down_mbit\s+(\d+)/', $line, $m)) $r['down'] = (int)$m[1];
        if (preg_match('/^up_mbit\s+(\d+)/', $line, $m)) $r['up'] = (int)$m[1];
    }
    $r['ok'] = $c === 0 && $r['method'] === 'ookla' && $r['down'] >= 2 && $r['up'] >= 1;
    return $r;
}

/** Rileva lo shaping effettivo dall'helper (tc/config in uso), non dai valori UI potenzialmente obsoleti. */
function sqm_effective_from_status(string $status): array {
    // Configured rates are NOT proof that CAKE and the IFB redirect are active.
    if (!preg_match('/^verified=1\s*$/m', $status)) return [];
    $first = strtok($status, "\n");
    if (!is_string($first) || !preg_match('/^iface ([A-Za-z0-9_.-]{1,15}) up=([0-9]{1,6})mbit down=([0-9]{1,6})mbit(?:\s|$)/', trim($first), $m)) return [];
    $up = (int)$m[2]; $down = (int)$m[3];
    if ($up < 1 || $down < 1 || $up > 100000 || $down > 100000) return [];
    $out = ['iface' => $m[1], 'up' => $up, 'down' => $down, 'on' => 1];
    if (preg_match('/(?:^|\s)diffserv=(diffserv3|diffserv4|diffserv8|besteffort)(?:\s|$)/', $first, $v)) $out['diffserv'] = $v[1];
    if (preg_match('/(?:^|\s)overhead=(none|ethernet|pppoe-v4|pppoe-ptm|bridged-ptm|conservative)(?:\s|$)/', $first, $v)) $out['overhead'] = $v[1];
    return $out;
}

/** Sincronizza solo campi SQM osservati; non altera profili DSCP o altre impostazioni. */
function sqm_sync_effective(): array {
    [$rc, $status, $error] = priv('sqm-status');
    if ($rc !== 0) return [1, 'Stato SQM non disponibile: ' . trim($error)];
    $live = sqm_effective_from_status($status);
    if (!$live) return [1, 'Nessuna configurazione SQM attiva valida: impostazioni inalterate.'];
    $S = S_get();
    $q = is_array($S['sqm'] ?? null) ? $S['sqm'] : [];
    $changes = [];
    foreach ($live as $k => $v) {
        if (($q[$k] ?? null) !== $v) { $q[$k] = $v; $changes[] = $k; }
    }
    if (!$changes) return [0, 'Valori SQM già sincronizzati con lo stato effettivo.'];
    $S['sqm'] = $q;
    S_put($S);
    return [0, 'Sincronizzati dall’helper: ' . implode(', ', $changes) . '.'];
}

/** Calibrazione immediata (speedtest + applica CAKE). */
function sqm_calibrate_now(bool $enable_timer = false): array {
    // Il timer è già stato avviato dall'azione dedicata; evita il doppio restart.
    [$c, $o, $e] = priv('sqm-calibrate', null, ['force']);
    $msg = trim($o . "\n" . $e);
    $S = S_get();
    // rileggi last file
    $last = @file_get_contents(DATA_DIR . '/sqm-calibrate.last') ?: '';
    $parsed = [];
    foreach (preg_split('/\r?\n/', $last) as $line) {
        if (str_contains($line, '=')) {
            [$k, $v] = array_pad(explode('=', $line, 2), 2, '');
            $parsed[$k] = $v;
        }
    }
    $observedOnly = $c === 0 && (str_starts_with(trim($o), 'observed-only:') || str_starts_with(trim($o), 'candidate-pending:') || str_starts_with(trim($o), 'unchanged '));
    if ($observedOnly) {
        // Do NOT record a new calibration or claim new rates were applied.
        // Tests run under an existing CAKE limit are observational only.
        return [0, 'Calibrazione osservazionale: ' . trim($o) . "\nLimiti invariati: la capacità misurata non giustifica un aumento oppure la misura non è completa.",
            ['mode'=>'observation-only']];
    }
    if ($c === 0) {
        // Lo speedtest può restituire "unchanged" senza riscrivere il file .last.
        // La sorgente attendibile è lo stato qdisc/configurazione dell'helper.
        [$statusRc, $statusOut] = priv('sqm-status');
        $live = $statusRc === 0 ? sqm_effective_from_status($statusOut) : [];
        if ($live) {
            if (!is_array($S['sqm'] ?? null)) $S['sqm'] = [];
            foreach ($live as $k => $v) $S['sqm'][$k] = $v;
            $S['sqm']['on'] = 1;
            $S['sqm']['mode'] = 'cake';
            $S['sqm']['auto'] = 1;
            $S['sqm']['autocal'] = $enable_timer || !empty($S['sqm']['autocal']) ? 1 : 0;
            $S['sqm']['last_cal'] = time();
            S_put($S);
            $parsed['applied_down'] = (string)$live['down'];
            $parsed['applied_up'] = (string)$live['up'];
            $parsed['iface'] = $live['iface'];
            $msg .= "\nValori applicati e sincronizzati in impostazioni: " . $live['down'] . "/" . $live['up'] . " Mbit su " . $live['iface'];
        } else {
            $c = 1;
            $msg .= "\nImpossibile confermare i limiti effettivi SQM: impostazioni non aggiornate.";
        }
    }
    return [$c, $msg !== '' ? $msg : ($c === 0 ? 'Calibrazione completata.' : 'Calibrazione fallita.'), $parsed];
}

function sqm_autocal_set(bool $on, int $interval = 60): array {
    $S = S_get();
    $interval = max(15, min(1440, $interval));
    [$c, $o, $e] = priv($on ? 'sqm-autocal-on' : 'sqm-autocal-off', null, $on ? [(string)$interval] : []);
    if ($c === 0) {
        $S['sqm']['autocal'] = $on ? 1 : 0;
        if ($on) $S['sqm']['interval_min'] = $interval;
        S_put($S);
    }
    return [$c, trim($o . "\n" . $e)];
}
