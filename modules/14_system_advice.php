<?php
// ===================== ANALISI SISTEMA → PROPOSTE OPZIONI =====================
// Scansiona interfacce, forwarding, software, porte in ascolto, CrowdSec/Docker/WG
// e confronta con le impostazioni attuali per proporre opzioni da attivare.

/**
 * @return list<array{id:string,cat:string,title:string,why:string,priority:int,active:bool,keys:array,apps:list<string>}>
 */
function sys_propose(?array $S = null): array {
    $S ??= S_get();
    $P = [];
    $add = function (string $id, string $cat, string $title, string $why, int $prio, bool $active, array $keys = [], array $apps = []) use (&$P) {
        $P[] = compact('id', 'cat', 'title', 'why', 'prio', 'active', 'keys', 'apps') + ['priority' => $prio];
    };

    // --- rete ---
    $if = function_exists('sys_ifaces') ? sys_ifaces() : [];
    $ifNames = array_keys($if);
    $nIf = count(array_filter($ifNames, fn($n) => $n !== 'lo' && !str_starts_with($n, 'docker') && !str_starts_with($n, 'veth') && !str_starts_with($n, 'br-')));
    $fw = trim((string)@file_get_contents('/proc/sys/net/ipv4/ip_forward'));
    $lan = trim((string)($S['lan_nets'] ?? ''));
    $wan = trim((string)($S['wan_if'] ?? ''));

    if ($lan === '' && $if) {
        // proponi prima rete privata vista
        $guess = '';
        foreach ($if as $name => $ips) {
            if ($name === 'lo') continue;
            foreach ($ips as $ip) {
                if (preg_match('/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/', $ip)) {
                    $guess = preg_replace('/\.\d+$/', '.0/24', $ip);
                    break 2;
                }
            }
        }
        $add('setup:lan', 'Setup', 'Imposta rete LAN',
            $guess !== '' ? "Rilevata rete privata: suggerita $guess (modificabile in Setup)." : 'Nessuna LAN in impostazioni: i filtri «solo LAN» e anti-lockout non funzionano bene.',
            1, false, $guess !== '' ? ['lan_nets' => $guess] : []);
    }
    if ($nIf >= 2 && $wan === '') {
        // interfaccia con IP pubblico o default route non rilevabile facilmente: suggerisci setup
        $add('setup:wan', 'Setup', 'Definisci interfaccia WAN',
            "Ci sono $nIf interfacce utili ma WAN non è impostata: i filtri lato Internet restano spenti.",
            1, false, []);
    }
    if ($fw === '1' && empty($S['nat_masq']) && $wan !== '') {
        $add('setup:nat', 'Setup', 'Abilita NAT (MASQUERADE)',
            'ip_forward=1 e WAN impostata: tipico di un router. NAT masquerade sulla WAN consente alla LAN di uscire in Internet.',
            1, !empty($S['nat_masq']), ['nat_masq' => 1, 'masq_ifs' => $wan, 'mss' => 1]);
    }
    if ($fw === '1' && empty($S['mss'])) {
        $add('setup:mss', 'Setup', 'TCPMSS clamp',
            'Con routing attivo evita problemi MTU/VPN/PPPoE (clamp-mss-to-pmtu).',
            2, !empty($S['mss']), ['mss' => 1]);
    }

    // --- sicurezza base (sempre utile) ---
    $base = [
        'spi' => ['Firewall SPI', 'Accetta connessioni stabilite e loopback; base di qualsiasi firewall stateful.'],
        'antispoof' => ['Anti-spoofing loopback', 'Scarta 127.0.0.0/8 che non arriva da lo.'],
        'invalid' => ['Scarta pacchetti non validi', 'INVALID, NEW senza SYN, flag TCP anomali.'],
        'final_drop' => ['Drop finale INPUT/FORWARD', 'Chiude esplicitamente ciò che non è permesso (policy sicura).'],
        'icmp_limit' => ['Limite ICMP', 'Ping utile ma non flood.'],
    ];
    foreach ($base as $k => [$title, $why]) {
        $add("sec:$k", 'Sicurezza base', $title, $why, 1, !empty($S[$k]), [$k => 1]);
    }
    if ($lan !== '') {
        $add('sec:lockout', 'Sicurezza base', 'Anti-lockout (gestione dalla LAN)',
            'La LAN può sempre raggiungere SSH e la pagina web di gestione.',
            1, !empty($S['lockout_on']), ['lockout_on' => 1, 'mgmt_ports' => $S['mgmt_ports'] ?: '22,80,443']);
    }

    // --- hardening consigliato se è un host esposto / router ---
    $adv = [
        'dos' => ['Anti SYN-flood', 'Limita nuovi SYN verso il router.'],
        'portscan' => ['Rilevamento port scan', 'Banna chi tocca troppe porte chiuse.'],
        'drop_frag' => ['Scarta frammenti IP', 'Rari nel traffico legittimo.'],
        'bad_mss' => ['Scarta SYN con MSS anomalo', 'Tipico di scansioni.'],
        'amp_block' => ['Anti amplificazione UDP', 'Blocca risposte non richieste da porte note (DNS, NTP, …) dal WAN.'],
    ];
    if ($wan !== '' || $fw === '1') {
        foreach ($adv as $k => [$title, $why]) {
            $add("sec:$k", 'Hardening', $title, $why, 2, !empty($S[$k]), [$k => 1]);
        }
        $add('sec:ssh_limit', 'Hardening', 'Limite tentativi SSH',
            'Riduce brute-force su porta 22 dal WAN.',
            2, !empty($S['ssh_limit']), ['ssh_limit' => 1, 'ssh_port' => (int)($S['ssh_port'] ?: 22)]);
    }

    // --- CrowdSec ---
    $csInst = is_file('/usr/bin/cscli') || is_file('/usr/local/bin/cscli')
        || is_file('/lib/systemd/system/crowdsec.service') || is_file('/etc/systemd/system/crowdsec.service');
    if ($csInst || !empty($S['crowdsec'])) {
        $add('sec:crowdsec', 'Protezioni', 'Collega CrowdSec al firewall',
            'CrowdSec risulta installato: il bouncer può filtrare INPUT/FORWARD (e Docker se presente).',
            1, !empty($S['crowdsec']), ['crowdsec' => 1, 'cs_docker' => !empty($S['cs_docker']) ? 1 : (is_file('/usr/bin/docker') ? 1 : 0)]);
    }

    // --- Docker ---
    if (is_file('/usr/bin/docker') || is_file('/usr/bin/dockerd') || is_dir('/var/lib/docker')) {
        $add('info:docker', 'Sistema', 'Docker rilevato',
            'Le catene DOCKER* restano gestite da Docker. Usa «Porte software» / port-forward per i servizi; abilita CrowdSec su DOCKER-USER se attivo.',
            3, true, []);
        if (!empty($S['crowdsec']) && empty($S['cs_docker'])) {
            $add('sec:cs_docker', 'Protezioni', 'CrowdSec anche su DOCKER-USER',
                'Con Docker, il bouncer può filtrare il traffico pubblicato dai container.',
                2, !empty($S['cs_docker']), ['cs_docker' => 1]);
        }
    }

    // --- WireGuard ---
    $wg = false;
    foreach ($ifNames as $n) if (preg_match('/^wg\d+$/', $n)) $wg = true;
    if ($wg || is_file('/usr/bin/wg') || !empty($S['wg_on'])) {
        $add('vpn:wg', 'VPN', 'WireGuard',
            $wg ? 'Interfaccia wg* attiva: apri la porta UDP e accetta traffico da wg.' : 'WireGuard installato: abilita le regole dedicate (pagina VPN).',
            1, !empty($S['wg_on']), ['wg_on' => 1, 'wg_input' => 1, 'wg_port' => (int)($S['wg_port'] ?: 51820)]);
    }

    // --- software / porte (riusa catalogo apps) ---
    if (function_exists('apps_detect')) {
        $det = apps_detect($S);
        foreach ($det as $id => $a) {
            if (!$a['installed'] && !$a['listening']) continue;
            $add('app:' . $id, 'Software · ' . $a['cat'], $a['name'],
                ($a['why'] ? $a['why'] . ' — ' : '') . 'Porte: ' . $a['ports'] . ($a['note'] ? '. ' . $a['note'] : ''),
                $a['listening'] ? 1 : 2,
                !empty($a['enabled']),
                [],
                [$id]);
        }
    }

    // --- DNS locale in ascolto ---
    $listen = function_exists('apps_listen_map') ? apps_listen_map() : ['tcp' => [], 'udp' => []];
    if ((!empty($listen['udp']['53']) || !empty($listen['tcp']['53'])) && empty($S['dns_redirect']) && $lan !== '') {
        $dnsIp = '';
        foreach ($if as $name => $ips) {
            foreach ($ips as $ip) {
                if (preg_match('/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/', $ip)) { $dnsIp = $ip; break 2; }
            }
        }
        if ($dnsIp !== '') {
            $add('setup:dns', 'Setup', 'Redirect DNS della LAN al resolver locale',
                "La macchina ascolta sulla porta 53. Puoi forzare i client LAN a usarla ($dnsIp).",
                2, !empty($S['dns_redirect']), ['dns_redirect' => 1, 'dns_ip' => $dnsIp]);
        }
    }

    // --- policy live troppo aperta ---
    if (function_exists('live_state')) {
        $L = live_state();
        if (!empty($L['ok'])) {
            foreach (['INPUT', 'FORWARD'] as $ch) {
                if (($L['pol'][$ch] ?? '') === 'ACCEPT' && empty($S['final_drop'])) {
                    $add('sec:final_drop_live', 'Sicurezza base', "Policy $ch = ACCEPT",
                        "Il kernel ha policy $ch ACCEPT senza drop finale gestito: meglio final_drop.",
                        1, !empty($S['final_drop']), ['final_drop' => 1]);
                }
            }
        }
    }

    // ordina: non attive prima, poi priorità, poi categoria
    usort($P, function ($a, $b) {
        $aa = $a['active'] ? 1 : 0;
        $ba = $b['active'] ? 1 : 0;
        return [$aa, $a['priority'], $a['cat'], $a['title']] <=> [$ba, $b['priority'], $b['cat'], $b['title']];
    });
    return $P;
}

/** Applica proposte selezionate alle impostazioni; ritorna [S, nKeys, nApps]. */
function sys_propose_apply(array $S, array $selectedIds): array {
    $byId = [];
    foreach (sys_propose($S) as $p) $byId[$p['id']] = $p;
    $nKeys = 0; $apps = array_values((array)($S['apps'] ?? []));
    foreach ($selectedIds as $id) {
        $id = (string)$id;
        if (!isset($byId[$id])) continue;
        $p = $byId[$id];
        foreach ($p['keys'] as $k => $v) {
            if (($S[$k] ?? null) !== $v) { $S[$k] = $v; $nKeys++; }
        }
        foreach ($p['apps'] as $aid) {
            if (!in_array($aid, $apps, true)) $apps[] = $aid;
        }
    }
    $S['apps'] = array_values(array_unique($apps));
    return [$S, $nKeys, count($apps)];
}

function pg_advise() {
    $S = S_get();
    $ro = ($_SESSION['role'] ?? 'viewer') === 'viewer';
    $props = sys_propose($S);
    $todo = array_values(array_filter($props, fn($p) => !$p['active'] && ($p['keys'] || $p['apps'])));
    $done = array_values(array_filter($props, fn($p) => $p['active']));
    $info = array_values(array_filter($props, fn($p) => !$p['active'] && !$p['keys'] && !$p['apps']));

    echo '<div class=card><h2>Analisi sistema → opzioni consigliate</h2>';
    echo '<p class=mut>Scansione di interfacce, IP forwarding, software installato, porte in ascolto, CrowdSec/Docker/WireGuard e confronto con le impostazioni attuali. '
        . 'Seleziona le proposte e salva: si aggiornano le impostazioni e la <b>bozza</b>; il kernel cambia solo dopo <b>Applica</b>.</p>';
    echo '<p>Proposte attivabili: <b>' . count($todo) . '</b> · Già attive: <b>' . count($done) . '</b>'
        . ' · LAN: <code>' . h(trim((string)($S['lan_nets'] ?? '')) ?: '—') . '</code>'
        . ' · WAN: <code>' . h(trim((string)($S['wan_if'] ?? '')) ?: '—') . '</code></p>';
    echo '<p class=ops><a class=s href="?p=advise&refresh=1">🔄 Riesegui analisi</a> '
        . '<a class=s href="?p=system">Rilevamento tecnico</a> '
        . '<a class=s href="?p=apps">Porte software</a></p>';
    echo '</div>';

    if ($ro) {
        echo '<div class=card><p class=mut>Solo lettura (viewer).</p></div>';
        return;
    }

    if (!$todo) {
        echo '<div class=card><p>✅ Nessuna nuova opzione ovvia da attivare. Il sistema risulta già allineato alle rilevazioni, oppure completa Setup (LAN/WAN).</p></div>';
    } else {
        echo '<form method=post>' . fh('p=advise') . '<input type=hidden name=action value=advise_apply>';
        echo '<div class=card><h3>Da attivare</h3>';
        echo '<p><button type=button class=s onclick="document.querySelectorAll(\'.pcb\').forEach(c=>c.checked=true)">Seleziona tutto</button> '
            . '<button type=button class=s onclick="document.querySelectorAll(\'.pcb\').forEach(c=>c.checked=false)">Nessuna</button></p>';
        echo '<table><tr><th></th><th>Priorità</th><th>Categoria</th><th>Opzione</th><th>Perché</th></tr>';
        $prioLab = [1 => 'alta', 2 => 'media', 3 => 'bassa'];
        foreach ($todo as $p) {
            $pr = $prioLab[$p['priority']] ?? (string)$p['priority'];
            // default: seleziona priorità alta
            $chk = $p['priority'] <= 1 ? ' checked' : '';
            echo '<tr><td><input type=checkbox class=pcb name="sel[]" value="' . h($p['id']) . '"' . $chk . '></td>'
                . '<td>' . h($pr) . '</td><td>' . h($p['cat']) . '</td>'
                . '<td><b>' . h($p['title']) . '</b><br><small class=mut><code>' . h($p['id']) . '</code></small></td>'
                . '<td>' . h($p['why']) . '</td></tr>';
        }
        echo '</table>';
        echo '<p class=sticky><button>💾 Attiva selezionate (bozza)</button> '
            . '<button class=g name=apply value=1>🚀 Attiva e applica</button> '
            . '<span class=mut>Le opzioni finiscono in impostazioni + blocchi IPTM; le porte software in apps[].</span></p>';
        echo '</div></form>';
    }

    if ($done) {
        echo '<details class=card><summary><b>Già attive</b> <span class=mut>(' . count($done) . ')</span></summary><ul>';
        foreach ($done as $p) echo '<li><b>' . h($p['title']) . '</b> <span class=mut>— ' . h($p['cat']) . '</span></li>';
        echo '</ul></details>';
    }
    if ($info) {
        echo '<details class=card><summary><b>Note informative</b></summary><ul>';
        foreach ($info as $p) echo '<li><b>' . h($p['title']) . '</b> — ' . h($p['why']) . '</li>';
        echo '</ul></details>';
    }
}


