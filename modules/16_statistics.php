<?php
// Chart UI is centralized in 38_visual_engine.php; keep old public signatures.
function chart_esc(string $s): string { return iptm_visual_escape($s); }
function chart_n(float $v): string { return iptm_visual_number($v); }
function chart_bars_svg(array $rows, array $o = []): string { return iptm_visual_chart('bar', $rows, $o); }
function chart_trend_svg(array $rows, array $o = []): string { return iptm_visual_chart('line', $rows, $o); }
function chart_hbar_svg(array $rows, array $o = []): string { return iptm_visual_chart('hbar', $rows, $o); }
function chart_donut_svg(array $parts, array $o = []): string { return iptm_visual_chart('donut', $parts, $o); }
// Kept for compatibility with external report callers.
function chart_donut_slice(float $cx, float $cy, float $r, float $rw, float $start, float $sweep, string $color, string $title): string {
    return '<path d="'.iptm_visual_arc($cx, $cy, $r+$rw/2, $r-$rw/2, $start, $sweep).'" fill="'.iptm_visual_escape(iptm_visual_color($color, 'var(--chart-blue)')).'"><title>'.iptm_visual_escape($title).'</title></path>';
}

/** Human-readable chart labels; do not display raw iptables commands in charts. */
function iptm_stat_rule_label(string $rule, string $fallback=''): string {
    if ($rule==='') return $fallback!==''?$fallback:'Regola firewall';
    preg_match('/(?:^|\s)-j\s+([A-Z][A-Z0-9_-]*)/',$rule,$jump);
    preg_match('/(?:^|\s)-A\s+([A-Za-z0-9_][A-Za-z0-9_.-]*)(?:\s|$)/',$rule,$chain);
    preg_match('/(?:^|\s)-p\s+(ipv6-icmp|icmpv6|tcp|udp|icmp)(?:\s|$)/i',$rule,$proto);
    preg_match('/--dport(?:s)?\s+([0-9,:-]+)/',$rule,$ports);
    $names=['DROP'=>'Bloccati','REJECT'=>'Rifiutati','ACCEPT'=>'Consentiti','LOG'=>'Registrati','DNAT'=>'Inoltrati','MASQUERADE'=>'NAT in uscita'];
    $act=$names[$jump[1]??'']??'Regola personalizzata';
    $short=$act;
    if (!empty($proto[1])) $short.=' · '.strtoupper($proto[1]);
    if (!empty($ports[1])) $short.=' · porta '.substr($ports[1],0,22);
    if (!empty($chain[1])) $short.=' · '.$chain[1];
    return $short;
}
/** Present a short, locally inferred device category beside a private IP. */
function iptm_stat_ip_label(string $ip): string {
    if (!function_exists('iptm_ip_context_inventory') || !function_exists('iptm_ip_context_label')) return $ip;
    $known=iptm_ip_context_inventory();
    $row=$known[$ip]??[];
    if (is_array($row) && !empty($row['kind'])) {
        $name=['iot'=>'IoT','trusted'=>'Fidato','guest'=>'Ospite','unknown'=>'Client'][$row['kind']]??'Client';
        return $ip.' · '.$name;
    }
    if ($ip==='127.0.0.1'||$ip==='::1') return $ip.' · Locale';
    return $ip;
}
/** Raccoglie dati per la pagina statistiche. */
function stats_gather(): array {
    $out = [
        'ok' => false,
        'conn_total' => 0,
        'conn_by_proto' => [],
        'conn_by_state' => [],
        'top_src' => [],
        'top_bytes' => [],
        'impact' => null,
        'vnstat' => null,
        'ct_count' => 0,
        'ct_max' => 0,
    ];
    $out['ct_count'] = (int)@file_get_contents('/proc/sys/net/netfilter/nf_conntrack_count');
    $out['ct_max'] = max(1, (int)@file_get_contents('/proc/sys/net/netfilter/nf_conntrack_max'));

    if (function_exists('impact_analyze')) {
        $out['impact'] = impact_analyze();
        $out['ok'] = !empty($out['impact']['ok']);
    }

    [$c, $o] = priv('conns');
    if ($c === 0 && function_exists('conn_parse')) {
        $cn = conn_parse($o);
        $out['conn_total'] = count($cn);
        $byP = []; $byS = []; $src = []; $tb = [];
        foreach ($cn as $x) {
            $p = $x['proto'] ?: '?';
            $byP[$p] = ($byP[$p] ?? 0) + 1;
            $st = $x['state'] ?: '—';
            $byS[$st] = ($byS[$st] ?? 0) + 1;
            $src[$x['src']] = ($src[$x['src']] ?? 0) + 1;
            $tb[$x['src']] = ($tb[$x['src']] ?? 0) + (int)$x['bytes'];
        }
        arsort($byP); arsort($byS); arsort($src); arsort($tb);
        foreach ($byP as $k => $v) $out['conn_by_proto'][] = ['label' => $k, 'value' => $v];
        foreach ($byS as $k => $v) $out['conn_by_state'][] = ['label' => $k, 'value' => $v];
        foreach (array_slice($src, 0, 12, true) as $k => $v) $out['top_src'][] = ['label' => iptm_stat_ip_label((string)$k), 'value' => $v];
        foreach (array_slice($tb, 0, 12, true) as $k => $v) $out['top_bytes'][] = ['label' => iptm_stat_ip_label((string)$k), 'value' => $v];
        $out['ok'] = true;
    }

    // vnStat (se installato)
    [$vc, $vj] = priv('vnstat-json');
    if ($vc === 0 && $vj) {
        $j = json_decode($vj, true);
        if (is_array($j)) {
            $ifaces = [];
            foreach (($j['interfaces'] ?? []) as $iface) {
                $name = $iface['name'] ?? ($iface['id'] ?? '?');
                $days = [];
                foreach (($iface['traffic']['day'] ?? []) as $d) {
                    $days[] = [
                        'label' => sprintf('%02d/%02d', $d['date']['day'] ?? 0, $d['date']['month'] ?? 0),
                        'rx' => (float)($d['rx'] ?? 0),
                        'tx' => (float)($d['tx'] ?? 0),
                    ];
                }
                $days = array_slice($days, -14);
                $ifaces[] = ['name' => $name, 'days' => $days];
            }
            $out['vnstat'] = $ifaces;
        }
    }
    return $out;
}


function pg_async_skeleton(string $page, string $title): bool {
    if (($_GET['fragment'] ?? '') === $page) return false;
    echo '<section class="card iptm-loading"><h2>' . h($title) . '</h2><p role=status aria-live=polite>Caricamento dati in corso. Il menu e le altre funzioni restano disponibili.</p>'
       . '<div class=iptm-skeleton aria-hidden=true><i></i><i></i><i></i></div>'
       . '<button type=button class="s" data-async-retry>Riprova</button></section>';
    echo '<section id=iptm-async-content data-fragment="' . h($page) . '" aria-live=polite></section>';
    return true;
}

function pg_stats() {
    if (pg_async_skeleton('stats', 'Statistiche e grafici')) return;
    $G = stats_gather();
    echo '<div class=card><h2>Statistiche e grafici</h2>';
    echo '<p class=mut>Vista d\'insieme su connessioni attive, contatori delle regole e traffico (vnStat se installato). I grafici sono generati in locale (SVG), senza servizi esterni. '
        . '<a href="?p=operations">Centro operativo sicurezza</a> · <a href="?p=impact">Impatto regole</a> · <a href="?p=conns">Connessioni</a> · <a href="?p=monitor">Monitoraggio</a></p>';

    $pct = $G['ct_max'] > 0 ? round(100 * $G['ct_count'] / $G['ct_max'], 1) : 0;
    echo '<div class=row data-iptm-layout="ui-34311ab5e4">';
    $box = function ($lab, $val, $hint = '') {
        echo '<div data-iptm-layout="ui-4ee9d5f739"><div class=mut>' . h($lab) . '</div>'
            . '<div data-iptm-layout="ui-7ece54214c">' . h((string)$val) . '</div>'
            . ($hint !== '' ? '<div class=mut>' . h($hint) . '</div>' : '') . '</div>';
    };
    $box('Conntrack', number_format($G['ct_count']) . ' / ' . number_format($G['ct_max']), $pct . '% tabella');
    $box('Flussi attivi', number_format($G['conn_total']));
    if (!empty($G['impact']['ok'])) {
        $t = $G['impact']['totals'];
        $box('Regole con hit', number_format($t['hit']) . ' / ' . number_format($t['rules']));
        $box('Pkts bloccati', number_format($t['drop_pkts']));
        $box('Pkts accettati', number_format($t['accept_pkts']));
    }
    echo '</div></div>';

    // Conntrack usage bar
    echo '<div class=card><h3>Uso tabella conntrack</h3>';
    echo chart_bars_svg([
        ['label' => 'in uso', 'value' => $G['ct_count']],
        ['label' => 'liberi', 'value' => max(0, $G['ct_max'] - $G['ct_count'])],
    ], ['color' => $pct > 85 ? '#ef4444' : ($pct > 60 ? '#f59e0b' : '#22c55e'), 'h' => 160, 'title' => 'conntrack']);
    echo '</div>';

    echo '<div class=row style="display:flex;flex-wrap:wrap;gap:16px">';
    echo '<div class=card data-iptm-layout="ui-cdf0df1292"><h3>Connessioni per protocollo</h3>';
    echo chart_donut_svg($G['conn_by_proto'], ['center' => (string)$G['conn_total']]);
    echo '</div>';
    echo '<div class=card data-iptm-layout="ui-cdf0df1292"><h3>Connessioni per stato</h3>';
    echo chart_donut_svg($G['conn_by_state'], ['center' => (string)$G['conn_total']]);
    echo '</div></div>';

    echo '<div class=row style="display:flex;flex-wrap:wrap;gap:16px">';
    echo '<div class=card data-iptm-layout="ui-dcf83a3abd"><h3>Top sorgenti (n. flussi)</h3>';
    echo chart_hbar_svg($G['top_src'], ['color' => '#3b82f6', 'label_w' => 130]);
    echo '</div>';
    
    if (function_exists('conntrack_live')) {
        $ct = conntrack_live(15);
        echo '<div class=card><h3>Conntrack live (' . (int)$ct['total'] . ' flussi)</h3>';
        echo '<p class=mut><a href="?p=conns">Pagina connessioni completa →</a></p>';
        if ($ct['by_proto']) {
            $pb = [];
            foreach ($ct['by_proto'] as $k => $v) $pb[] = ['label' => $k, 'value' => (float)$v];
            echo chart_donut_svg($pb, ['size' => 120]);
        }
        echo '<div style="display:flex;gap:16px;flex-wrap:wrap">';
        echo '<div><b>Top sorgenti</b><table>';
        foreach ($ct['top_src'] as $ip => $n) echo '<tr><td>' . h($ip) . '</td><td>' . (int)$n . '</td></tr>';
        echo '</table></div><div><b>Top destinazioni</b><table>';
        foreach ($ct['top_dst'] as $ip => $n) echo '<tr><td>' . h($ip) . '</td><td>' . (int)$n . '</td></tr>';
        echo '</table></div></div>';
        echo '<table><tr><th>proto</th><th>src</th><th>dst</th><th>porte</th><th>stato</th></tr>';
        foreach ($ct['rows'] as $r) {
            echo '<tr><td>' . h($r['proto']) . '</td><td>' . h($r['src']) . '</td><td>' . h($r['dst']) . '</td><td>'
                . h($r['sport'] . '→' . $r['dport']) . '</td><td>' . h($r['state']) . '</td></tr>';
        }
        echo '</table></div>';
    }

echo '<div class=card data-iptm-layout="ui-dcf83a3abd"><h3>Top sorgenti (byte)</h3>';
    echo chart_hbar_svg($G['top_bytes'], ['color' => '#a855f7', 'label_w' => 130]);
    echo '</div></div>';

    if (!empty($G['impact']['ok'])) {
        $drops = [];
        foreach (array_slice($G['impact']['top_drop'] ?? [], 0, 10) as $x) {
            $lab = iptm_stat_rule_label((string)($x['r']??''),(string)($x['t']??''));
            $drops[] = ['label' => $lab ?: ($x['t'] ?? '?'), 'value' => (float)($x['p'] ?? 0)];
        }
        $acc = [];
        foreach (array_slice($G['impact']['top_accept'] ?? [], 0, 10) as $x) {
            $lab = iptm_stat_rule_label((string)($x['r']??''),(string)($x['t']??''));
            $acc[] = ['label' => $lab ?: ($x['t'] ?? '?'), 'value' => (float)($x['p'] ?? 0)];
        }
        echo '<div class=card><h3>Regole DROP/REJECT più attive (pacchetti)</h3>';
        echo chart_hbar_svg($drops, ['color' => '#ef4444', 'label_w' => 200, 'max' => 10]);
        echo '<p class=mut><a href="?p=impact">Dettaglio impatto regole →</a></p></div>';
        echo '<div class=card><h3>Regole ACCEPT più usate (pacchetti)</h3>';
        echo chart_hbar_svg($acc, ['color' => '#22c55e', 'label_w' => 200, 'max' => 10]);
        echo '</div>';
    }

    if (function_exists('stats_history_load')) {
        $hist = stats_history_load(7);
        if ($hist) {
            $byH = [];
            foreach ($hist as $r) {
                $k = date('d/m H:00', (int)$r['ts']);
                $byH[$k] = $r;
            }
            $rowsCt = []; $rowsDr = [];
            foreach ($byH as $lab => $r) {
                $rowsCt[] = ['label' => $lab, 'value' => (float)$r['ct']];
                $rowsDr[] = ['label' => $lab, 'value' => (float)$r['drop_pkts']];
            }
            echo '<div class=card><h3>Storico (campioni locali, 7 giorni)</h3>';
            echo '<p class=mut>Aggiornato aprendo Dashboard/Statistiche (max ogni 15 min).</p>';
            echo '<p class=mut>Conntrack in uso</p>' . chart_trend_svg(array_slice($rowsCt, -48), ['color' => '#3b82f6', 'h' => 175, 'title' => 'Conntrack in uso nel tempo']);
            echo '<p class=mut>Pacchetti DROP (contatore al campionamento)</p>' . chart_trend_svg(array_slice($rowsDr, -48), ['color' => '#ef4444', 'h' => 175, 'title' => 'Contatore cumulativo DROP nel tempo']);
            echo '</div>';
        }
    }

    if ($G['vnstat']) {
        foreach ($G['vnstat'] as $iface) {
            $rx = []; $tx = [];
            foreach ($iface['days'] as $d) {
                // vnstat json: usually KiB
                $rx[] = ['label' => $d['label'], 'value' => $d['rx']];
                $tx[] = ['label' => $d['label'], 'value' => $d['tx']];
            }
            echo '<div class=card><h3>Traffico giornaliero · ' . h($iface['name']) . ' <span class=mut>(vnStat)</span></h3>';
            echo '<p class=mut>Ricevuti (rx)</p>' . chart_trend_svg($rx, ['color' => '#06b6d4', 'h' => 175, 'title' => 'Traffico giornaliero ricevuto']);
            echo '<p class=mut>Inviati (tx)</p>' . chart_trend_svg($tx, ['color' => '#f59e0b', 'h' => 175, 'title' => 'Traffico giornaliero inviato']);
            echo '</div>';
        }
    } else {
        echo '<div class=card><h3>Traffico di rete (vnStat)</h3><p class=mut>vnStat non disponibile. Installalo da <a href="?p=progs">Programmi</a> per vedere i grafici giornalieri per interfaccia.</p></div>';
    }
}
