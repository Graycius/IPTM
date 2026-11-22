<?php
// ===================== COMPATIBILITA' LEGACY, PROGRAMMI, MONITORAGGIO =====================
function ipt_usage(string $txt): array {   // match e target (non standard, non catene utente) usati dalle regole
    preg_match_all('/^:(\S+)/m', $txt, $dc); preg_match_all('/\s-m\s+([A-Za-z0-9_]+)/', $txt, $mm); preg_match_all('/\s-j\s+([A-Za-z0-9_-]+)/', $txt, $tt);
    $m = array_values(array_unique($mm[1])); $t = array_values(array_filter(array_diff(array_unique($tt[1]), ['ACCEPT', 'DROP', 'RETURN', 'QUEUE'], $dc[1]), fn($x) => strpos($x, '-') === false && dyn_owner($x) === '')); sort($m); sort($t); return [$m, $t];
}
function compat_report(string $txt): array {
    return kc('compat:' . md5($txt), function () use ($txt) {
        [$m, $t] = ipt_usage($txt); $args = array_merge(array_map(fn($x) => "m:$x", $m), array_map(fn($x) => "t:$x", $t));
        [$c, $o] = priv('compat', null, $args); $r = ['ok' => $c === 0, 'kernel' => '', 'ipt' => '', 'backend' => '', 'tables' => [], 'matches' => [], 'targets' => [], 'ipset' => false, 'nft' => 0, 'nftsvc' => ''];
        foreach (explode("\n", $o) as $l) {
            $x = preg_split('/\s+/', trim($l), 3);
            if ($x[0] === 'kernel') $r['kernel'] = $x[1] ?? ''; elseif ($x[0] === 'iptables') $r['ipt'] = trim(substr($l, 9)); elseif ($x[0] === 'backend') $r['backend'] = $x[1] ?? '';
            elseif ($x[0] === 'table') $r['tables'][$x[1]] = ($x[2] ?? '') === 'ok'; elseif ($x[0] === 'table6') $r['tables']['IPv6 ' . $x[1]] = ($x[2] ?? '') === 'ok';
            elseif ($x[0] === 'match') $r['matches'][$x[1]] = ($x[2] ?? '') === 'ok'; elseif ($x[0] === 'target') $r['targets'][$x[1]] = ($x[2] ?? '') === 'ok';
            elseif ($x[0] === 'ipset') $r['ipset'] = ($x[1] ?? '') === 'ok'; elseif ($x[0] === 'nft-rules') $r['nft'] = (int)($x[1] ?? 0); elseif ($x[0] === 'nftables-service') $r['nftsvc'] = $x[1] ?? '';
        }
        return $r;
    });
}
function compat_card(string $txt): string {
    $r = compat_report($txt); if (!$r['ok']) return '<div class=card><h3>Compatibilità iptables-legacy</h3><p class=mut>Verifica non disponibile (helper/sudo?).</p></div>';
    $y = fn($b, $soft = false) => $b ? '<span data-iptm-layout="ui-041b0f9fbd">✔</span>' : ($soft ? '<span class=mut>✘ n/d</span>' : '<span data-iptm-layout="ui-48916a3891">✘ mancante</span>');
    $o = '<div class=card><h3>Compatibilità iptables-legacy</h3><table><tr><td>Backend attivo</td><td><b>' . h($r['backend']) . '</b> ' . ($r['backend'] === 'legacy' ? '✔' : '⚠ non è legacy: cambialo da Rete o dall\'installer') . ' <span class=mut>' . h($r['ipt']) . '</span></td></tr><tr><td>Kernel</td><td>' . h($r['kernel']) . '</td></tr>';
    $o .= '<tr><td>Tabelle</td><td>' . implode(' · ', array_map(function ($k, $v) use ($y) {
        $soft = str_starts_with((string)$k, 'IPv6');
        return h($k) . ' ' . $y($v, $soft);
    }, array_keys($r['tables']), $r['tables'])) . '</td></tr><tr><td>ipset</td><td>' . $y($r['ipset']) . '</td></tr>';
    foreach (['matches' => 'Match usati dalla bozza', 'targets' => 'Target usati dalla bozza'] as $k => $lbl) {
        $o .= '<tr><td>' . $lbl . '</td><td>';
        if (!$r[$k]) { $o .= '--'; }
        else {
            $parts = [];
            foreach ($r[$k] as $n => $v) {
                $parts[] = h($n) . ' ' . $y($v) . (!$v && $n === 'TARPIT' ? ' <span class=mut>(xtables-addons)</span>' : '') . (!$v && $n === 'PORTSCAN' ? ' <span class=mut>(non usato da IPTM; rimuovi regole manuali -j PORTSCAN)</span>' : '');
            }
            $o .= implode(' · ', $parts);
        }
        $o .= '</td></tr>';
    }
    $o .= '</table>';
    if ($r['backend'] === 'legacy' && $r['nft'] > 0) $o .= '<div class="msg err">nftables contiene ' . (int)$r['nft'] . ' righe di regole: con il backend legacy i pacchetti attraversano ENTRAMBI i sistemi. Svuota la configurazione nft o disabilita nftables.service.</div>';
    if ($r['backend'] === 'legacy' && $r['nftsvc'] === 'enabled') $o .= '<p class=mut>nftables.service è abilitato: se /etc/nftables.conf è vuoto non crea problemi.</p>';
    return $o . '</div>';
}
function tool_defs(): array {
    return ['fail2ban' => ['fail2ban', 'Banna chi sbaglia password (SSH/Dropbear): azione iptables, compatibile con legacy.', 'nets'],
        'crowdsec' => ['CrowdSec + bouncer', 'Reputazione collettiva: il bouncer crea i set ipset (uno per origine) e la catena CROWDSEC_CHAIN. Richiede il repository ufficiale se assente.', ''],
        'suricata' => ['Suricata (IDS)', 'Rileva attacchi sul traffico dell\'interfaccia scelta. Usa almeno 1 GB di RAM.', 'iface'],
        'vnstat' => ['vnStat', 'Statistiche di traffico giornaliere per interfaccia.', 'iface'],
        'wireguard' => ['WireGuard + qrencode', 'Strumenti per la VPN: poi configura il server dalla pagina Rete → VPN WireGuard.', ''],
        'tcpdump' => ['tcpdump', 'Cattura dei pacchetti dalla pagina Monitoraggio.', ''],
        'conntrack' => ['conntrack', 'Strumenti per la tabella di tracking (elenco e cancellazione connessioni).', ''],
        'xtables' => ['xtables-addons (TARPIT)', 'Moduli extra iptables: TARPIT e altri. Necessario per l\'opzione TARPIT in Sicurezza. Richiede headers del kernel per DKMS.', ''],
        'psad' => ['PSAD (Port Scan Detector)', 'Analizza i log iptables, rileva scansioni di porte e può bannare automaticamente gli scanner.', ''],
        'arpwatch' => ['arpwatch', 'Monitora la tabella ARP della LAN: avvisa su nuovi MAC e possibili spoofing.', 'iface'],
        'unattended' => ['Aggiornamenti automatici', 'unattended-upgrades: applica automaticamente le patch di sicurezza Debian/Ubuntu.', ''],
        'auditd' => ['Auditd · audit configurazioni', 'Registra modifiche a rules.v4/v6, configurazioni WireGuard e SSH. Gli eventi recenti sono consultabili qui; non modifica le regole firewall.', ''],
        'lynis' => ['Lynis · audit hardening', 'Esegue un controllo di sicurezza in sola lettura su sistema, servizi, kernel e configurazioni; non applica correzioni automatiche. Il report resta nel registro del programma.', ''],
        'unbound' => ['Unbound · resolver DNS locale', 'Resolver ricorsivo DNSSEC su loopback porta 5335, con configurazione isolata e validata prima del riavvio. Si integra con Pi-hole FTL tramite upstream locale.', ''],
        'ipset' => ['ipset · insiemi firewall', 'Utilità per gli insiemi iptables, utilizzata anche dai bouncer CrowdSec.', ''],
        'clamav' => ['ClamAV · scanner leggero', 'Installa clamscan e freshclam senza avviare clamd, particolarmente pesante su macchine con poca RAM. Nessuna scansione automatica.', ''],
        'clamavd' => ['ClamAV · demone opzionale', 'Solo se serve il socket clamd per proxy e scansioni continue. Richiede molta RAM; verifica prima la memoria libera.', ''],
        'debsums' => ['Debsums · integrità pacchetti', 'Verifica i checksum locali dei file installati da APT. Dopo l’installazione usa debsums -s da SSH; nessuna scansione avviata.', ''],
        'aide' => ['AIDE · integrità file', 'Rileva modifiche ai file rispetto a un database iniziale. Prima scansione e baseline richiedono scelta esplicita e possono durare molto.', ''],
        'needrestart' => ['Needrestart · processi obsoleti', 'Individua servizi che usano ancora vecchie librerie dopo aggiornamenti; non riavvia automaticamente IPTM o il firewall.', ''],
        'dnscrypt' => ['DNSCrypt-Proxy · upstream DNS cifrato', 'Proxy DNS cifrato DNSCrypt / DoH su loopback 127.0.0.1:5053. Configurazione con sorgenti firmate, selezione resolver, filtri privacy e cache; integrabile direttamente con Pi-hole o a monte di Unbound.', '']];
}
/** Opzioni firewall → programmi richiesti (per suggerimenti e coda installazione). */
function required_tools(array $S): array {
    $need = [];
    if (!empty($S['crowdsec'])) $need['crowdsec'] = 'Integrazione CrowdSec attiva in Sicurezza';
    if (!empty($S['tarpit'])) $need['xtables'] = 'Opzione TARPIT attiva (richiede xtables-addons)';
    if (!empty($S['arp_protect'])) $need['arpwatch'] = 'Protezione ARP consigliata con arpwatch per monitoraggio attivo';
    if (!empty($S['portscan'])) $need['psad'] = 'Port-scan del firewall + PSAD per analisi log e ban automatici';
    if (!empty($S['wg_on'])) $need['wireguard'] = 'Regole VPN WireGuard attive';
    return $need;
}
function tools_status(): array {
    return kc('tools', function () {
        [$c, $o, $e] = priv('tool-status');
        $r = []; $GLOBALS['_iptm_tools_status_error'] = '';
        if ($c !== 0) {
            $detail = trim((string)($e !== '' ? $e : $o));
            $GLOBALS['_iptm_tools_status_error'] = 'Comando tool-status non riuscito (exit ' . $c . '). ' . substr($detail, 0, 400);
            return [];
        }
        foreach (explode("\n", trim($o)) as $l) {
            if (trim($l) === '') continue;
            $x = preg_split('/\s+/', trim($l));
            if (count($x) !== 5 || !isset(tool_defs()[$x[0]]) || !in_array($x[1], ['installed', 'absent', 'partial', 'unknown'], true)
                || !in_array($x[3], ['yes', 'no', 'unknown'], true) || !in_array($x[4], ['idle', 'running', 'unknown'], true) || isset($r[$x[0]])) {
                $GLOBALS['_iptm_tools_status_error'] = 'Risposta tool-status non valida: helper non aggiornato o output inatteso.';
                return [];
            }
            $r[$x[0]] = ['inst' => $x[1] === 'installed', 'partial' => $x[1] === 'partial', 'known' => $x[1] !== 'unknown',
                'svc' => $x[2], 'cand' => $x[3] === 'yes', 'cand_known' => $x[3] !== 'unknown',
                'run' => $x[4] === 'running', 'run_known' => $x[4] !== 'unknown'];
        }
        if (array_diff(array_keys(tool_defs()), array_keys($r))) {
            $GLOBALS['_iptm_tools_status_error'] = 'Elenco dei programmi incompleto: controlla versioni app/helper o timeout.';
            return [];
        }
        return $r;
    });
}
function tools_logs(): array {
    return kc('tool_logs', function () {
        [$c, $o] = priv('tool-logs'); $r = [];
        if ($c !== 0) return $r;
        if (preg_match_all('/^IPTM_BEGIN_([a-z0-9_-]+)\R(.*?)^IPTM_END_\1\s*$/ms', $o, $m, PREG_SET_ORDER)) {
            foreach ($m as $x) $r[$x[1]] = trim($x[2]);
        }
        return $r;
    });
}
function pg_progs() {
    $S = S_get(); $st = tools_status(); $logs = []; $ro = ($_SESSION['role'] ?? 'viewer') === 'viewer'; $if = array_keys(sys_ifaces());
    if(!$ro) echo '<form method=post>'.fh('p=progs').'<input type=hidden name=action value=modules_repair><button type=submit class=s>Verifica/ripara moduli PHP dopo aggiornamento</button></form>';
    echo '<div class=card><h2>Programmi di sicurezza e monitoraggio</h2><p class=mut>Installazione e configurazione guidate (apt). Ogni configurazione viene verificata prima dell\'attivazione. I servizi con catene proprie (fail2ban, bouncer CrowdSec) vengono riavviati dopo ogni «Applica».</p>';
    if ($why = ($GLOBALS['_iptm_tools_status_error'] ?? '')) {
        echo '<div class="msg err"><b>Rilevamento non disponibile.</b> Non significa che i programmi siano assenti. Aggiorna la diagnosi dal wizard prima di installare. ' . h($why) . '</div>';
        echo '<p class=mut>Verifica via SSH: sudo /usr/local/sbin/iptm-helper version; sudo /usr/local/sbin/iptm-helper tool-status. Verifica anche permessi sudo dell’utente web. Nessuna installazione viene avviata da questa pagina finché lo stato è ignoto.</p></div>';
        return;
    }
    // Repository discovery and systemd are independent probes.  Unknown repository
    // state is not proof that an APT installation is impossible.  An explicit
    // admin request can attempt installation and display apt's real result.
    $statusUnknown = (bool)array_filter($st, fn($t) => empty($t['known']) || empty($t['run_known']) || empty($t['cand_known']));
    if ($statusUnknown) echo '<div class="msg warn">Alcune verifiche APT/systemd non sono disponibili. Puoi tentare manualmente l’installazione di un programma non presente quando APT non è verificato: nessun pacchetto viene installato senza conferma. I risultati e gli errori APT sono nel registro.</div>';
    [$hvRc, $hvOutput] = priv('version');
    $hv = trim($hvOutput);
    if ($hvRc !== 0 || $hv !== APP_VERSION) {
        echo '<div class="msg warn">Versioni non allineate: app ' . h(APP_VERSION)
            . ', helper ' . h($hvRc === 0 && $hv !== '' ? $hv : 'non rilevabile')
            . '. Verifica il percorso dell’helper e aggiorna entrambi i componenti tramite SSH.</div>';
    }
    $logs = tools_logs();
    $need = required_tools($S); $running = array_filter($st, fn($x) => !empty($x['run']));
    // Suggerimenti da opzioni firewall attive
    $missing = [];
    foreach ($need as $tk => $why) {
        $t = $st[$tk] ?? ['inst' => false, 'known' => false];
        if (!empty($t['known']) && empty($t['inst'])) $missing[$tk] = $why;
    }
    if ($missing) {
        echo '<div class="msg warn"><b>Opzioni firewall attive che richiedono programmi non installati:</b><ul data-iptm-layout="ui-4087b25a64">';
        foreach ($missing as $tk => $why) echo '<li><b>' . h(tool_defs()[$tk][0] ?? $tk) . '</b> — ' . h($why) . '</li>';
        echo '</ul>';
        if (!$ro) {
            echo '<form method=post data-iptm-layout="mt10">' . fh('p=progs') . '<input type=hidden name=action value=tool_queue>';
            foreach (array_keys($missing) as $tk) echo '<input type=hidden name="tools[]" value="' . h($tk) . '">';
            echo '<button class=g>Installa tutti i programmi richiesti (in coda)</button></form>';
        }
        echo '</div>';
    }
    if ($running) {
        echo '<div class="msg ok"><b>Installazione in corso…</b> La pagina si aggiorna automaticamente ogni 4 secondi.<ul data-iptm-layout="ui-4087b25a64">';
        foreach ($running as $tk => $t) echo '<li>' . h(tool_defs()[$tk][0] ?? $tk) . '</li>';
        echo '</ul></div>';
    }
    // Coda multipla
    if (!$ro && !$running) {
        echo '<form method=post id=qform>' . fh('p=progs') . '<input type=hidden name=action value=tool_queue></form>';
        echo '<p class=mut>Seleziona più programmi per richiedere l’installazione tramite APT. Un repository non verificato non equivale a pacchetto assente: il tentativo esplicito registra l’esito reale. ClamAV daemon e AIDE sono opzionali: valuta memoria e carico prima di abilitarli.</p>';
    }
    echo '<div class="msg"><b>Componenti gestiti da DietPi:</b> Pi-hole, Docker e servizi preinstallati non sono reinstallati automaticamente da questa pagina per evitare di sovrascrivere configurazioni esistenti. Per verificarli apri <a href="?p=health">Salute DietPi</a> e <a href="?p=postcheck">Controllo servizi</a>. Per nuove installazioni usa <code>dietpi-software</code>.</div>';
    echo '<div data-iptm-layout="scroll"><table><tr>' . (!$ro && !$running ? '<th></th>' : '') . '<th>Programma</th><th>Stato</th><th>Azioni</th></tr>';
    foreach (tool_defs() as $k => [$name, $desc, $arg]) {
        $t = $st[$k] ?? ['inst' => false, 'svc' => '?', 'cand' => false, 'run' => false];
        $sug = isset($need[$k]) && !empty($t['known']) && empty($t['inst']);
        if (empty($t['known'])) {
            $state = 'Stato installazione non verificabile';
        } elseif (!empty($t['run'])) {
            $state = '<b data-iptm-layout="ui-407c560c17">operazione in corso…</b>';
        } elseif (!empty($t['inst'])) {
            $state = '✔ installato' . ($t['svc'] !== '-' ? ' · servizio: <b>' . h($t['svc']) . '</b>' : '');
        } else {
            $state = !empty($t['partial']) ? '⚠ installazione parziale (componente mancante)' : 'non installato';
            if (empty($t['cand_known'])) $state .= ' <span class=mut>(repository non verificato)</span>';
            elseif (empty($t['cand'])) $state .= ' <span class=mut>(pacchetto non nei repository)</span>';
        }
        if ($sug) $state = '<span class="b b-jump">richiesto</span> ' . $state;
        echo '<tr id="tool-' . h($k) . '"' . ($sug ? ' data-iptm-layout="ui-5a53d8fdf9"' : '') . '>';
        if (!$ro && !$running) echo '<td><input type=checkbox form=qform name="tools[]" value="' . h($k) . '"' . ($sug ? ' checked' : '') . (!empty($t['inst']) || (!empty($t['cand_known']) && empty($t['cand'])) ? ' disabled' : '') . '></td>';
        echo '<td>';
        if (!$ro && !$running && empty($t['inst']) && (!empty($t['cand']) || empty($t['cand_known'])) && $arg==='') {
            echo '<form method=post style="display:inline">'.fh('p=progs').'<input type=hidden name=action value=tool_install><input type=hidden name=tool value="'.h($k).'"><button class="s sm" title="Installa programma">'.h($name).'</button></form>';
        } else echo '<a href="?p=progs#tool-' . h($k) . '"><b>' . h($name) . '</b></a>';
        echo '<br><span class=mut>' . $desc . '</span></td><td>' . $state . '</td><td>';
        if (!$ro && !$t['run'] && (!empty($t['inst']) || !empty($t['cand']) || empty($t['cand_known']))) {
            if ($k === 'wireguard' && $t['inst']) {
                echo '<a class="btn s sm" href="?p=vpn">Apri gestione VPN</a>';
            } else {
                echo '<form method=post class=ops style="display:inline">' . fh('p=progs') . '<input type=hidden name=action value=tool_install><input type=hidden name=tool value="' . h($k) . '">';
                if ($arg === 'iface') echo sel('arg', array_combine($if, $if), $S['wan_if'] ?? '') . ' ';
                if ($arg === 'nets') echo '<input name=arg value="' . h($S['lan_nets'] ?? '') . '" placeholder="reti da non bannare" data-iptm-layout="mw220"> ';
                $toolActionLabel = match ($k) {
                    'lynis' => $t['inst'] ? 'Esegui audit' : 'Installa e analizza',
                    'auditd' => $t['inst'] ? 'Aggiorna audit' : 'Installa e attiva',
                    default => $t['inst'] ? 'Riconfigura' : 'Installa',
                };
                echo '<button class="' . ($t['inst'] ? 's' : 'g') . ' sm">' . h($toolActionLabel) . '</button></form>';
            }
            if ($t['inst'] && $t['svc'] !== '-' && $k !== 'wireguard') echo ' <form method=post class=ops style="display:inline">' . fh('p=progs') . '<input type=hidden name=action value=tool_svc><input type=hidden name=tool value="' . h($k) . '">' . sel('act', ['restart' => 'Riavvia', 'start' => 'Avvia', 'stop' => 'Ferma']) . ' <button class="s sm">Esegui</button></form>';
        }
        echo '</td></tr>';
        $lg = $logs[$k] ?? ''; if (trim($lg) !== '') echo '<tr><td colspan=' . (!$ro && !$running ? 4 : 3) . '><details' . ($t['run'] ? ' open' : '') . '><summary>Registro di ' . h($name) . '</summary><pre data-iptm-layout="ui-e9391a53f7">' . h($lg) . '</pre></details></td></tr>';
    }
    echo '</table></div>';
    if (!$ro && !$running) echo '<p class=sticky><button class=g form=qform>▶ Installa selezionati (coda)</button></p>';
    if ($running) echo '<script>setTimeout(function(){location.reload()},4000)</script>';
    echo '</div>';
}
function cs_decisions(): array {
    [$c, $o] = priv('cs-decisions'); if ($c !== 0 || trim($o) === '') return []; $rows = []; $hd = null;
    foreach (explode("\n", trim($o)) as $l) { $f = str_getcsv($l, ',', '"', ''); if ($hd === null) { $hd = array_flip($f); continue; } $g = fn($k) => $f[$hd[$k] ?? -1] ?? ''; $rows[] = ['ip' => $g('ip'), 'reason' => $g('reason'), 'action' => $g('action'), 'exp' => $g('expiration'), 'src' => $g('source')]; }
    return $rows;
}
function pg_monitor() {
    $ro = ($_SESSION['role'] ?? 'viewer') === 'viewer'; $st = tools_status(); $S = S_get(); $load = sys_getloadavg() ?: [0, 0, 0];
    $mi = []; foreach (@file('/proc/meminfo', FILE_IGNORE_NEW_LINES) ?: [] as $l) if (preg_match('/^(\w+):\s+(\d+)/', $l, $m)) $mi[$m[1]] = (int)$m[2] * 1024;
    $up = (int)@explode(' ', (string)@file_get_contents('/proc/uptime'))[0]; $tp = is_readable('/sys/class/thermal/thermal_zone0/temp') ? round((int)file_get_contents('/sys/class/thermal/thermal_zone0/temp') / 1000, 1) . ' °C' : 'n/d';
    $mu = ($mi['MemTotal'] ?? 0) ? round(100 * (1 - ($mi['MemAvailable'] ?? 0) / $mi['MemTotal'])) : 0;
    echo '<div class=tiles>' . tile('Carico (1/5/15 min)', h(implode(' · ', array_map(fn($x) => number_format($x, 2), $load)))) . tile('Memoria usata', $mu . '%', '<div class=bar><i style="width:' . $mu . '%"></i></div>') . tile('Uptime', h(floor($up / 86400) . ' g ' . floor($up % 86400 / 3600) . ' h')) . tile('Temperatura CPU', h($tp)) . '</div>';
    [, $wo] = priv('watch-status'); echo '<div class=card><h2>Controlli di salute</h2><p class=mut>Eseguiti anche ogni 5 minuti dal timer iptm-watch: la notifica parte solo quando un controllo peggiora o rientra.</p><table>';
    foreach (array_filter(explode("\n", trim($wo))) as $l) { $x = explode(' ', $l, 3); echo '<tr><td>' . ($x[0] === 'OK' ? '✔' : ($x[0] === 'WARN' ? '⚠' : '✘')) . '</td><td>' . h($x[2] ?? '') . '</td></tr>'; }
    echo '</table></div>';
    if (!empty($st['vnstat']['inst'])) { [, $vj] = priv('vnstat-json'); $j = json_decode($vj, true);
        echo '<div class=card><h3>Traffico (vnStat, ultimi 14 giorni)</h3>';
        foreach ($j['interfaces'] ?? [] as $if) { echo '<h4>' . h($if['name'] ?? '') . '</h4><table><tr><th>Giorno</th><th>Ricevuti</th><th>Inviati</th></tr>';
            foreach (array_reverse($if['traffic']['day'] ?? []) as $d) echo '<tr><td>' . sprintf('%04d-%02d-%02d', $d['date']['year'] ?? 0, $d['date']['month'] ?? 0, $d['date']['day'] ?? 0) . '</td><td>' . hb((int)($d['rx'] ?? 0)) . '</td><td>' . hb((int)($d['tx'] ?? 0)) . '</td></tr>'; echo '</table>'; }
        echo '</div>'; }
    if (!empty($st['fail2ban']['inst'])) { [, $fo] = priv('f2b-status'); echo '<div class=card><h3>fail2ban</h3>';
        $any = false; foreach (array_filter(explode("\n", trim($fo))) as $l) { $x = preg_split('/\s+/', trim($l)); if (($x[0] ?? '') !== 'jail') continue; $any = true; $ips = array_slice($x, 3);
            echo '<p><b>' . h($x[1]) . '</b> · bannati ora: ' . h($x[2] ?? '0') . '</p>'; if ($ips) { echo '<table>'; foreach ($ips as $ip) echo '<tr><td>' . iptm_ip_html((string)$ip) . '</td><td>' . ($ro ? '' : '<form method=post class=ops>' . fh('p=monitor') . '<input type=hidden name=action value=f2b_unban><input type=hidden name=jail value="' . h($x[1]) . '"><input type=hidden name=ip value="' . h($ip) . '"><button class="s sm">Sbanna</button></form>') . '</td></tr>'; echo '</table>'; } }
        echo $any ? '' : '<p class=mut>Nessuna jail attiva.</p>'; echo '</div>'; }
    if (!empty($st['crowdsec']['inst'])) { $dec = cs_decisions(); echo '<div class=card><h3>CrowdSec — decisioni attive</h3>';
        if (!$ro) echo '<form method=post class=ops>' . fh('p=monitor') . '<input type=hidden name=action value=cs_ban><input name=ip placeholder="IP o CIDR da bannare" required data-iptm-layout="mw200"> <input name=dur value="4h" data-iptm-layout="mw80" pattern="[0-9]{1,5}[smhd]"> <button class=d>Banna con CrowdSec</button></form>';
        echo '<table><tr><th>IP</th><th>Origine</th><th>Motivo</th><th>Azione</th><th>Scade</th><th></th></tr>';
        foreach (array_slice($dec, 0, 100) as $d) echo '<tr><td>' . iptm_ip_html((string)$d['ip']) . '</td><td>' . h($d['src']) . '</td><td>' . h($d['reason']) . '</td><td>' . h($d['action']) . '</td><td>' . h($d['exp']) . '</td><td>' . ($ro ? '' : '<form method=post class=ops>' . fh('p=monitor') . '<input type=hidden name=action value=cs_unban><input type=hidden name=ip value="' . h($d['ip']) . '"><button class="s sm">Rimuovi</button></form>') . '</td></tr>';
        echo '</table>' . ($dec ? '' : '<p class=mut>Nessuna decisione attiva.</p>') . '</div>'; }
    if (!empty($st['tcpdump']['inst']) && !$ro) { $if = array_keys(sys_ifaces()); $g = fn($k, $d = '') => trim((string)($_GET[$k] ?? $d));
        echo '<div class=card><h3>Cattura pacchetti (tcpdump)</h3><form method=get class=row><input type=hidden name=p value=monitor><input type=hidden name=cap value=1>
<label class=fl><span>Interfaccia</span>' . sel('if', array_combine($if, $if), $g('if', $S['wan_if'] ?? '')) . '</label><label class=fl><span>Protocollo</span>' . sel('pr', ['any' => 'qualsiasi', 'tcp' => 'tcp', 'udp' => 'udp', 'icmp' => 'icmp', 'arp' => 'arp'], $g('pr', 'any')) . '</label>
<label class=fl><span>Host (IPv4)</span><input name=host value="' . h($g('host')) . '" data-iptm-layout="ui-5e96948257"></label><label class=fl><span>Porta</span><input name=port value="' . h($g('port')) . '" data-iptm-layout="mw80"></label>
<label class=fl><span>Pacchetti</span><input name=n value="' . h($g('n', '50')) . '" data-iptm-layout="ui-b7386e12f2"></label><label class=fl><span>Secondi</span><input name=sec value="' . h($g('sec', '10')) . '" data-iptm-layout="ui-d4462d0a38"></label><button>Avvia</button></form>';
        if ($g('cap') === '1') { [$c, $o, $e] = priv('capture', null, [$g('if'), $g('pr', 'any'), $g('host'), $g('port'), $g('n', '50'), $g('sec', '10')]); echo '<pre>' . h($c === 0 ? ($o ?: '(nessun pacchetto)') : 'Parametri non validi o errore: ' . trim($o . $e)) . '</pre>'; }
        echo '</div>'; }
}
function wg_info(): array {
    return kc('wg', function () { [$c, $o] = priv('wg-status'); $r = ['inst' => false, 'init' => false, 'svc' => '', 'cfg' => [], 'peers' => [], 'live' => [], 'source' => 'iptm', 'clientfiles' => [], 'ifaces' => [], 'manager' => '', 'dietpi_tool' => false, 'dietpi_list' => []];
        foreach (explode("\n", trim($o)) as $l) {
            $x = preg_split('/\s+/', trim($l), 5);
            if (($x[0] ?? '') === 'installed') $r['inst'] = ($x[1] ?? '') === 'yes';
            elseif (($x[0] ?? '') === 'init') $r['init'] = ($x[1] ?? '') === 'yes';
            elseif (($x[0] ?? '') === 'source') $r['source'] = $x[1] ?? 'dietpi';
            elseif (($x[0] ?? '') === 'service') $r['svc'] = $x[1] ?? '';
            elseif (($x[0] ?? '') === 'manager') $r['manager'] = $x[1] ?? '';
            elseif (($x[0] ?? '') === 'dietpi-tool') $r['dietpi_tool'] = ($x[1] ?? '') === 'yes';
            elseif (($x[0] ?? '') === 'dietpi-list') $r['dietpi_list'][] = substr($l, strlen('dietpi-list '));
            elseif (($x[0] ?? '') === 'cfg') $r['cfg'][$x[1] ?? ''] = $x[2] ?? '';
            elseif (($x[0] ?? '') === 'peer') $r['peers'][] = ['name' => $x[1] ?? '', 'ip' => $x[2] ?? '', 'pub' => $x[3] ?? ''];
            elseif (($x[0] ?? '') === 'clientfile') $r['clientfiles'][] = $x[1] ?? '';
            elseif (($x[0] ?? '') === 'iface') { if (($x[1] ?? '') !== '') $r['ifaces'][] = $x[1]; }
            elseif (($x[0] ?? '') === 'live') {
                $y = preg_split('/\s+/', trim($l));
                $r['live'][$y[1] ?? ''] = ['hs' => (int)($y[2] ?? 0), 'rx' => (int)($y[3] ?? 0), 'tx' => (int)($y[4] ?? 0), 'iface' => $y[5] ?? 'wg0'];
            }
        }
        return $r; });
}
function wg_preferred_iface(array $detected, string $saved = 'wg0'): string {
    $valid = array_values(array_unique(array_filter($detected, fn($x) => is_string($x) && preg_match('/^[A-Za-z0-9_.-]{1,15}$/', $x))));
    if (in_array($saved, $valid, true)) return $saved;
    if ($valid) return $valid[0];
    return preg_match('/^[A-Za-z0-9_.-]{1,15}$/', $saved) ? $saved : 'wg0';
}
function pg_vpn() {
    $S = S_get(); $w = wg_info(); $ro = ($_SESSION['role'] ?? 'viewer') === 'viewer'; $show = (string)($_GET['show'] ?? '');
    echo '<div class=card><h2>VPN WireGuard</h2>';
    if (!$w['inst']) {
        echo '<p>WireGuard non risulta installato (nessun <code>wg</code>, conf in <code>/etc/wireguard</code>, interfaccia o pacchetto rilevato).</p>';
        echo '<p class=mut>Su DietPi: <code>dietpi-software</code> → installa <b>WireGuard</b> (o <code>dietpi-vpn</code>). Poi ricarica questa pagina. In alternativa: <a href="?p=progs">Programmi</a>.</p></div>';
        return;
    }
    if (($w['source'] ?? '') === 'dietpi' || ($w['source'] ?? '') === 'system') {
        $mgr = !empty($w['dietpi_tool']) ? 'dietpi-wireguard (gestore nativo DietPi)' : ($w['source'] === 'dietpi' ? 'DietPi' : 'sistema');
        echo '<div class="msg ok">WireGuard rilevato: <b>' . h($mgr) . '</b>';
        if (!empty($w['ifaces'])) echo ' · interfacce: <code>' . h(implode(', ', $w['ifaces'])) . '</code>';
        echo ' · servizio: ' . h($w['svc'] ?: '?') . '. IPTM gestisce le regole firewall; configurazioni e chiavi esterne non vengono sovrascritte.</div>';
    }
    if (!$w['init']) {
        if (!empty($w['dietpi_tool'])) {
            echo '<p class=mut>Il gestore DietPi è presente ma non risultano interfacce configurate. Inizializza il server con <code>dietpi-wireguard init</code> oppure apri <code>dietpi-wireguard</code>; poi ricarica questa pagina. IPTM non crea un secondo file in parallelo.</p>';
        } else {
            echo '<p class=mut>Crea il server (interfaccia wg0, rete /24 dedicata ai client). Il nome pubblico è l\'indirizzo o il DDNS con cui i client raggiungono il router.</p>';
            if (!$ro) echo '<form method=post class=row>' . fh('p=vpn') . '<input type=hidden name=action value=wg_init><label class=fl><span>Porta UDP</span><input name=port value="51820" data-iptm-layout="ui-d5528ca698"></label><label class=fl><span>Rete VPN (/24)</span><input name=net value="10.8.0.0/24" data-iptm-layout="ui-5e96948257"></label><label class=fl><span>Indirizzo pubblico</span><input name=ep placeholder="vpn.esempio.org" required data-iptm-layout="mw240"></label><label class=fl><span>DNS per i client (opz.)</span><input name=dns value="' . h($S['dns_ip'] ?? '') . '" data-iptm-layout="ui-5e96948257"></label><button class=g>Crea server</button></form>';
        }
        echo '</div>'; return;
    }
    $srcNote = (($w['source'] ?? '') !== 'iptm') ? ' <span class="b b-jump">gestito da DietPi / esistente</span>' : '';
    echo '<p>Servizio: <b>' . h($w['svc'] ?: '?') . '</b>' . $srcNote . ' · Rete <b>' . h($w['cfg']['NET'] ?? '—') . '</b> · porta <b>' . h($w['cfg']['PORT'] ?? '—') . '</b> · endpoint <b>' . h($w['cfg']['ENDPOINT'] ?? '—') . '</b></p>';
    if (($w['source'] ?? '') !== 'iptm' && empty($w['cfg'])) {
        echo '<p class=mut>WireGuard risulta già configurato (DietPi o altro). Le regole firewall (porta e inoltro) si impostano qui sotto; la gestione dei peer resta quella di DietPi.</p>';
    }
    $wgSelected = wg_preferred_iface($w['ifaces'] ?? [], (string)($S['wg_if'] ?? 'wg0'));
    $wgIfaces = array_values(array_unique(array_merge($w['ifaces'] ?: [], [$wgSelected])));
    $wgOpts = array_combine($wgIfaces, $wgIfaces);
    if (!$ro) echo '<form method=post class=ops>' . fh('p=vpn') . '<input type=hidden name=action value=wg_svc>' . sel('iface', $wgOpts, $wgSelected) . ' ' . sel('act', ['restart' => 'Riavvia', 'start' => 'Avvia', 'stop' => 'Ferma']) . ' <button class="s sm">Esegui</button></form>';
    if (!empty($w['dietpi_tool']) && $w['dietpi_list']) echo '<details class=card><summary><b>Client rilevati da DietPi</b> <span class=mut>dietpi-wireguard list</span></summary><pre>' . h(implode("\n", $w['dietpi_list'])) . '</pre><p class=mut>Per creare, disabilitare, abilitare o rimuovere client usa il gestore nativo <code>dietpi-wireguard</code>; IPTM lascia intatti file e chiavi esterni.</p></details>';
    echo '<form method=post class=acc data-iptm-layout="mt12">' . fh('p=vpn') . '<input type=hidden name=action value=settings_save><input type=hidden name=sec value=vpn><h3>Regole firewall della VPN</h3>'
        . dd('Interfaccia WireGuard', sel('wg_if', $wgOpts, $wgSelected), 'Scegli wg0, wg1 o l’interfaccia rilevata da DietPi. Le regole generate useranno questa interfaccia.')
        . opt_rows($S, [['wg_on', 'r', 'Apri la porta UDP WireGuard', 'Genera le regole nella bozza (poi applica).'], ['wg_port', 't', 'Porta UDP', 'Deve coincidere con quella del server.', '110px'], ['wg_lan', 'r', 'I client raggiungono LAN e Internet'], ['wg_input', 'r', 'I client raggiungono anche il router (SSH, interfaccia web)']]) . '<p class=sticky><button>Salva nella bozza</button></p></form>';
    echo '<h3>Client</h3><div data-iptm-layout="scroll"><table><tr><th>Nome</th><th>IP VPN</th><th>Ultimo contatto</th><th>Traffico</th><th></th></tr>';
    foreach ($w['peers'] as $p) { $lv = $w['live'][$p['pub']] ?? null; $hs = $lv && $lv['hs'] > 0 ? date('Y-m-d H:i:s', $lv['hs']) : '—';
        echo '<tr><td><b>' . h($p['name']) . '</b></td><td>' . h($p['ip']) . '</td><td>' . h($hs) . '</td><td>' . ($lv ? '↓ ' . hb($lv['rx']) . ' ↑ ' . hb($lv['tx']) : '—') . '</td><td class=ops>';
        if (!$ro && ($w['source'] ?? 'iptm') === 'iptm') echo '<a class="btn s sm" href="?p=vpn&show=' . h($p['name']) . '">Configurazione / QR</a><form method=post>' . fh('p=vpn') . '<input type=hidden name=action value=wg_del><input type=hidden name=name value="' . h($p['name']) . '"><button class="d sm">Elimina</button></form>'; 
        echo '</td></tr>'; }
    echo '</table></div>' . ($w['peers'] ? '' : '<p class=mut>Nessun client.</p>');
    if (!$ro && ($w['source'] ?? 'iptm') === 'iptm') echo '<form method=post class=row data-iptm-layout="mt10">' . fh('p=vpn') . '<input type=hidden name=action value=wg_add><label class=fl><span>Nome client</span><input name=name pattern="[a-z0-9_-]{1,20}" required placeholder="telefono" data-iptm-layout="ui-eb9e070a2e"></label><label class=fl><span>Traffico</span>' . sel('mode', ['full' => 'Tutto attraverso la VPN', 'lan' => 'Solo VPN e LAN']) . '</label><label class=fl><span>Reti LAN (se «Solo VPN e LAN»)</span><input name=lan value="' . h($S['lan_nets'] ?? '') . '" data-iptm-layout="mw220"></label><button class=g>Aggiungi client</button></form>';
    if ($show !== '' && !$ro && ($w['source'] ?? 'iptm') === 'iptm' && preg_match('/^[a-z0-9_-]{1,20}$/', $show)) { [$c, $cf] = priv('wg-peer-conf', null, [$show]); [$c2, $qr] = priv('wg-peer-qr', null, [$show]);
        if ($c === 0) { echo '<div class=card><h3>Configurazione di ' . h($show) . '</h3><p class=mut>Contiene la chiave privata del client: mostrala solo al diretto interessato.</p>' . ($c2 === 0 && trim($qr) !== '' ? '<img alt="QR" data-iptm-layout="ui-d3daf13173" src="data:image/svg+xml;base64,' . base64_encode($qr) . '">' : '<p class=mut>QR non disponibile (qrencode).</p>') . '<pre>' . h($cf) . '</pre></div>'; } }
    echo '</div>';
}
function dns_info(): array {
    return kc('dns_status', function () {
        [$c, $o] = priv('dns-status'); $r = [];
        if ($c !== 0) return ['error' => trim($o)];
        foreach (explode("\n", trim($o)) as $l) { $p = strpos($l, "\t"); if ($p !== false) $r[substr($l, 0, $p)] = substr($l, $p + 1); }
        return $r;
    });
}
/** Disegna il percorso DNS per una modalita' (unbound|dnscrypt|layered|external|none) con lo stato reale di ogni servizio. */
function dns_flow_html(string $mode, array $d, array $st, bool $hidden): string {
    $node = function (string $title, string $sub, ?array $s = null, bool $main = false): string {
        $cls = 'dns-node' . ($main ? ' dns-node-main' : '') . ($s === null ? '' : ($s['ok'] ? ' dns-node-ok' : ' dns-node-bad'));
        return '<div class="' . $cls . '"><b>' . h($title) . '</b><small>' . h($sub) . '</small>' . ($s === null ? '' : '<em>' . h($s['label']) . '</em>') . '</div>';
    };
    $ar = '<span class=dns-arrow>→</span>';
    $c = $node('Client LAN', 'DNS porta 53');
    $p = $node('Pi-hole / FTL', 'Filtri e cache', $st['pi'], true);
    $ub = $node('Unbound', '127.0.0.1:5335 · ricorsivo', $st['ub']);
    $dc = $node('DNSCrypt-Proxy', '127.0.0.1:5053', $st['dc']);
    $up = trim((string)($d['pihole_upstreams'] ?? ''));
    $chains = [
        'unbound'  => [$c, $p, $ub, $node('Server DNS autoritativi', 'ricorsione dalla radice')],
        'dnscrypt' => [$c, $p, $dc, $node('Resolver cifrati', 'DNSCrypt / DoH')],
        'layered'  => [$c, $p, $ub, $dc, $node('Resolver cifrati', 'DNSCrypt / DoH')],
        'external' => [$c, $p, $node('Upstream esterno', $up !== '' ? substr($up, 0, 60) : 'non rilevato')],
        'none'     => [$c, $node('Pi-hole non rilevato', 'nessun filtro DNS locale')],
    ];
    return '<div class="dns-flow" data-mode="' . h($mode) . '"' . ($hidden ? ' hidden' : '') . '>' . implode($ar, $chains[$mode] ?? $chains['none']) . '</div>';
}

/** Lightweight Pi-hole list manager, independent of DNS status probes. */
function pg_pihole_lists(): void {
    $ro = ($_SESSION['role'] ?? 'viewer') === 'viewer';
    $cached=$_SESSION['iptm_pihole_verified']??null;
    if (!is_array($cached) || (int)($cached['at']??0)<time()-600 ||
        !is_array($cached['statuses']??null)) $cached=null;
    // Display only the previous API observation. A refresh is still necessary
    // to establish whether the lists have changed in the meantime.
    $savedStatus=$cached?json_encode($cached['statuses'],JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT):'';
    $savedUrl=$cached?(string)($cached['url']??''):'';
    echo '<div class="hero"><div class=hico>📋</div><div><h2>Pi-hole · Whitelist, regex e adlist (API v6)</h2><p>Compatibile con la REST API Pi-hole v6: le liste esistenti non vengono modificate, nessuna scrittura SQL nel DB Gravity.</p></div></div>';
    [$code,$out,$err] = priv('maintenance',null,['pihole-catalog']);
    $data=$code===0 ? json_decode($out,true) : null;
    $items=is_array($data)&&is_array($data['lists']??null) ? $data['lists'] : [];
    $patterns=is_array($data)&&is_array($data['regex_patterns']??null) ? $data['regex_patterns'] : [];
    if($code!==0||!$items) echo '<div class="msg err">Catalogo non disponibile: '.h(trim($err.' '.$out)).'</div>';
    echo '<div class="card"><h2>Connessione API locale</h2><p>Pi-hole v6 usa una sessione temporanea. Puoi memorizzare la password applicativa cifrata nell’archivio root. Il collegamento API resta locale. Una password immessa per una singola operazione prevale su quella memorizzata.</p>';
    [$secretRc,$secretOut]=priv('pihole-secret',null,['status']);
    $credentialState=$secretRc===0?json_decode($secretOut,true):null;
    echo '<p class=mut>Credenziale memorizzata: <b>'.($secretRc===0&&is_array($credentialState)?(!empty($credentialState['stored'])?'sì, cifrata':'nessuna'):'stato non verificabile').'</b>.</p>';
    if(!$ro) {
        echo '<form method=post>'.fh('p=piholelists').'<input type=hidden name=action value=pihole_credentials>';
        echo '<label class=fl>Password applicativa Pi-hole (salvataggio richiede HTTPS sul pannello)<input type=password name=pihole_credential minlength=8 maxlength=256 autocomplete=new-password></label>';
        echo '<div class=ops><button name=credential_op value=save>Memorizza cifrata</button><button class=s name=credential_op value=clear formnovalidate>Elimina credenziale</button></div></form>';
    }
    echo '<p class=mut><b>Attenzione HTTPS:</b> il collegamento IPTM &rarr; Pi-hole resta locale, ma la password inserita nel browser richiede HTTPS per essere protetta durante il tragitto browser &rarr; IPTM. Non inserire credenziali Pi-hole su un pannello IPTM aperto via HTTP.</p>';
    echo '<p class=mut><b>HTTP 401:</b> apri Pi-hole v6, vai nelle impostazioni API e genera una password applicativa. Inseriscila qui; la password IPTM e la password di accesso al browser non sono automaticamente valide per l&#39;API Pi-hole. Una verifica fallita lascia tutte le liste nello stato <b>Non verificato</b>.</p>';
    if($ro) echo '<p class=mut>Account di sola lettura: operazioni non disponibili.</p>';
    else {
        echo '<form id=plRead method=post>'.fh('p=piholelists').'<input type=hidden name=action value=dns_pihole_export>';
        echo '<label class=fl>Indirizzo API Pi-hole su questo host<input name=pihole_api_url value="http://127.0.0.1:8089" maxlength=90 required></label>';
        echo '<label class=fl>Password applicativa Pi-hole (facoltativa se già salvata)<input id=plReadPass name=pihole_api_password type=password maxlength=256 autocomplete=off></label>';
        echo '<div class=ops><button type=button class=s id=plLoad>Verifica adlist e regex presenti</button><button type=submit class=s>Esporta whitelist e regex in JSON</button></div>';
        echo '<p id=plReadStatus role=status class=mut data-iptm-status-url="'.h($savedUrl).'" data-iptm-saved-status="'.h($savedStatus).'">'.($cached?'Ultima verifica Pi-hole salvata nella sessione ('.date('H:i',(int)$cached['at']).'): ripeti la lettura per lo stato aggiornato. ':'Stato non verificato. ').'Premi «Verifica adlist e regex presenti»; IPTM non modifica Pi-hole.</p></form>';
    }
    echo '</div>';
    [$rdCode,$rdOut,$rdErr]=priv('maintenance',null,['rethink-catalog']);
    $rdData=$rdCode===0?json_decode($rdOut,true):[];
    $rdLists=is_array($rdData)&&is_array($rdData['lists']??null)?$rdData['lists']:[];
    echo '<div class=card><h2>Catalogo RethinkDNS · selezione libera</h2><p>Le fonti presenti nel catalogo sono sempre selezionabili, anche se temporaneamente non raggiungibili. La disponibilità e il contenuto verranno verificati da Pi-hole quando tenta di scaricarle.</p>';
    if(!$ro)echo '<form method=post>'.fh('p=piholelists').'<input type=hidden name=action value=dns_rethink_refresh><button class=s>Aggiorna catalogo RethinkDNS</button></form>';
    echo '<p class=mut>Selezionabili: '.count($rdLists).' / '.count($rdLists).'. Le liste possono essere importate nel modulo sottostante, senza duplicare le fonti già presenti.</p></div>';
    echo '<div class=card><h2>Importa whitelist e regex</h2><p>Carica un file TXT/CSV/JSON (max 1 MiB) oppure incolla domini. L’anteprima confronta le voci con quelle già presenti tramite API. L’importazione aggiunge soltanto le nuove voci.</p>';
    if(!$ro) {
        echo '<form id=plImport method=post enctype="multipart/form-data">'.fh('p=piholelists').'<input type=hidden name=action value=dns_pihole_import>';
        echo '<label class=fl>API locale<input name=pihole_api_url value="http://127.0.0.1:8089" maxlength=90 required></label>';
        echo '<label class=fl>Password applicativa Pi-hole<input id=plImportPass name=pihole_api_password type=password maxlength=256 autocomplete=off></label><p class=mut>Lascia il campo vuoto per usare la password applicativa salvata nel vault root, se presente. Non viene inserita nelle impostazioni IPTM.</p>';
        echo '<label class=fl>File whitelist (TXT / CSV / JSON)<input type=file name=pihole_whitelist_file accept=".txt,.csv,.json,text/plain,text/csv,application/json"></label>';
        echo '<label class=fl>Oppure incolla domini (uno per riga)<textarea name=whitelist rows=5 maxlength=1048576 placeholder="example.org&#10;sub.example.net"></textarea></label>';
        echo '<div class=grid2><label class=fl>Regex whitelist (allow)<textarea name=allow_regex rows=3 maxlength=524288 placeholder="(^|\\.)example\\.org$"></textarea></label>';
        echo '<label class=fl>Regex blocco (deny)<textarea name=deny_regex rows=3 maxlength=524288 placeholder="(^|\\.)ads\\.example\\.net$"></textarea></label></div>';
        echo '<h3>Adlist RethinkDNS · scelta multipla</h3><p class=mut>Stesso stile delle adlist: verde = già attiva, ambra = installata ma disabilitata, grigio = da aggiungere. Il controllo «Verifica adlist e regex presenti» legge anche lo stato RethinkDNS tramite l’API Pi-hole. La raggiungibilità delle fonti non condiziona la selezione.</p>';
        echo '<label class=fl>Filtra RethinkDNS<input id=plRethinkFilter type=search placeholder="Cerca nome, gruppo o stato" autocomplete=off></label>';
        echo '<label class=fl>Visualizza RethinkDNS<select id=plRethinkStateFilter><option value=all>Tutte</option><option value=present>Già presenti</option><option value=new>Da aggiungere</option><option value=unknown>Non verificate</option></select></label>';
        echo '<div class=ops><button type=button class=s id=plRethinkAll>Seleziona tutte</button><button type=button class=s id=plRethinkClear>Deseleziona</button> <span id=plRethinkCount role=status aria-live=polite>0 selezionate</span></div>';
        echo '<div class=iptm-rd-grid id=plRethinkGrid>';
        foreach($rdLists as $rd) {
            if(!is_array($rd)||!preg_match('/^rd[a-f0-9]{16}$/D',(string)($rd['id']??'')))continue;
            echo '<label class="iptm-rd-item plRethinkItem" data-state="unknown" data-availability="available" >';
            echo '<input type=checkbox name="rethink_ids[]" value="'.h($rd['id']).'">';
            echo '<span><b>'.h($rd['name']??'RethinkDNS').'</b><small>'.h($rd['group']??'').'</small>';
            echo '<small class="plStatus" data-state="unknown">Non verificato su Pi-hole</small>';
            echo '<small class="iptm-rd-availability">'.h('Fonte selezionabile · disponibilità non verificata').'</small></span></label>';
        }
        echo '</div>';
        echo '<h3>Catalogo adlist · selezione multipla</h3>';
        echo '<p class=mut>'.count($items).' fonti candidate: non tutte sono necessariamente raggiungibili, compatibili o prive di sovrapposizioni. Non ne viene selezionata alcuna per impostazione predefinita.</p>';
        echo '<label class=fl>Filtra le liste<input id=plFilter type=search placeholder="Cerca nome, categoria o ID" autocomplete=off></label>';
        echo '<p><button type=button class=s id=plAll>Seleziona tutte ('.count($items).')</button> <button type=button class=s id=plClear>Deseleziona tutte</button> <span id=plCount role=status aria-live=polite>0 selezionate</span></p>';
        echo '<label class=fl>Visualizza per stato<select id=plStateFilter><option value=all>Tutte</option><option value=present>Già presenti</option><option value=new>Da aggiungere</option><option value=unknown>Non verificate</option></select></label><p class=mut>Legenda: <b data-iptm-layout="ui-6d76cb30ec">verde = già attiva</b>; <b data-iptm-layout="ui-b745286a9e">ambra = già presente ma disattivata</b>; grigio = nuova; senza accesso API lo stato resta non verificato.</p>';
        echo '<div id=plGrid style="display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:8px;max-height:400px;overflow:auto;padding:8px 0">';
        foreach($items as $item) {
            if(!is_array($item))continue;
            $id=(string)($item['id']??'');
            if(!preg_match('/^[A-Za-z0-9_.-]{1,48}$/D',$id))continue;
            $label=(string)($item['description']??$id);$cat=(string)($item['category']??'');
            echo '<label class=plItem style="display:flex;gap:8px;align-items:flex-start"><input type=checkbox name="adlists[]" value="'.h($id).'"><span><b>'.h($label).'</b><small style="display:block">'.h($cat.' · '.$id).'</small><small class=plStatus data-state=unknown>Non verificato</small></span></label>';
        }
        echo '</div><h3>Regex note · catalogo opt-in</h3>';
        echo '<p class=mut>'.count($patterns).' pattern per famiglie di domini pubblicitari, analytics e diagnostici. Sintassi e casi di esempio verificati; <b>non</b> è garantita l’assenza di falsi positivi. I pattern “alto rischio” possono interrompere app o servizi. Nessuna regex preselezionata.</p>';
        echo '<p><button type=button class=s id=plRxAll>Seleziona tutte le regex</button> <button type=button class=s id=plRxClear>Deseleziona regex</button> <span id=plRxCount role=status>0 regex selezionate</span></p>';
        echo '<div id=plRegex style="display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:7px;max-height:370px;overflow:auto">';
        foreach($patterns as $rx) {
            if(!is_array($rx) || !preg_match('/^[a-z0-9-]{1,40}$/D',(string)($rx['id']??'')))continue;
            echo '<label class=plRegexItem><input type=checkbox name="regex_presets[]" value="'.h($rx['id']).'"> <b>'.h($rx['label']??'').'</b> · '.h($rx['category']??'').' · rischio '.h($rx['risk']??'').'<small style="display:block"><code>'.h($rx['pattern']??'').'</code></small><small class=plStatus data-state=unknown>Non verificato</small></label>';
        }
        echo '</div>';
        echo '<p class=mut>Applica esegue subito le verifiche interne e invia le modifiche all’API Pi-hole. L’anteprima è facoltativa.</p>';
        echo '<p class=mut>Oltre 10 adlist, le liste nuove vengono preparate disabilitate automaticamente e senza aggiornare Gravity.</p>';
        echo '<label style="display:flex;gap:8px;align-items:center;margin:8px 0"><input type=checkbox name=apply_gravity value=1> Aggiorna Gravity dopo aggiunte adlist (solo fino a 10 fonti)</label>';
        echo '<p class=mut>Il backup API contiene solo whitelist, regex e adlist preesistenti. Pi-hole gestisce tutte le scritture tramite API; un errore fra richieste può lasciare inserimenti parziali, segnalati con conteggi e snapshot. Nessun elemento già presente viene cancellato.</p>';
        echo '<p id=plImportError class="msg err" role=alert hidden></p>';
        echo '<div class=ops><button type=submit class=s name=import_action value=preview>Mostra anteprima</button> '
           . '<button type=submit class=g name=import_action value=apply>Applica davvero su Pi-hole</button></div>';
        echo '<p class=mut>Le risposte indicano chiaramente anteprima, importazione riuscita o errore. Non ripetere una scrittura prima di verificare il risultato.</p></form>';
    }
    echo '</div>';

}

function pg_dns() {
    $d = dns_info(); $ro = ($_SESSION['role'] ?? 'viewer') === 'viewer';
    $pi = ($d['pihole_installed'] ?? '') === 'yes'; $ub = ($d['unbound_installed'] ?? '') === 'yes'; $dc = ($d['dnscrypt_installed'] ?? '') === 'yes';
    $ubReady = $ub && ($d['unbound_active'] ?? '') === 'active' && ($d['unbound_profile'] ?? '') === 'yes' && ($d['unbound_check'] ?? '') === 'ok' && ($d['unbound_dnssec'] ?? '') === 'yes';
    $dcReady = $dc && ($d['dnscrypt_state'] ?? '') === 'active' && ($d['dnscrypt_check'] ?? '') === 'ok' && ($d['dnscrypt_listener_safe'] ?? '') === 'yes' && ($d['dnscrypt_managed'] ?? '') === 'yes';
    $dcDirectReady = $dcReady && !(($d['pihole_dnssec_env'] ?? '') === 'yes' && in_array(strtolower((string)($d['pihole_dnssec'] ?? '')), ['false', '0', 'no'], true));
    $S = S_get();
    // Configurazione EFFETTIVA: dagli upstream realmente impostati in Pi-hole e dal forward Unbound -> DNSCrypt
    $upNow = (string)($d['pihole_upstreams'] ?? '');
    $has5335 = (bool)preg_match('/[#:]5335\b/', $upNow); $has5053 = (bool)preg_match('/[#:]5053\b/', $upNow);
    $actual = !$pi ? 'none' : ($has5335 ? ((($d['unbound_dnscrypt_forward'] ?? '') === 'yes') ? 'layered' : 'unbound') : ($has5053 ? 'dnscrypt' : 'external'));
    $stOf = function (bool $inst, string $act, bool $ready): array {
        if (!$inst) return ['ok' => false, 'label' => 'non installato'];
        $a = $act === 'active' ? 'attivo' : ($act === '' ? 'stato n/d' : 'non attivo');
        if ($act === 'active' && !$ready) $a .= ' · da verificare';
        return ['ok' => $act === 'active' && $ready, 'label' => $a];
    };
    $st = ['pi' => $stOf($pi, (string)($d['pihole_active'] ?? ''), true), 'ub' => $stOf($ub, (string)($d['unbound_active'] ?? ''), $ubReady), 'dc' => $stOf($dc, (string)($d['dnscrypt_state'] ?? ''), $dcReady)];
    echo '<div class="hero ' . (($pi && ($d['pihole_active'] ?? '') === 'active') ? 'ok' : 'warn') . '"><div class=hico>🌐</div><div><h2>DNS &amp; Privacy</h2><p>Un solo centro di controllo per Pi-hole, Unbound e DNSCrypt-Proxy. Le configurazioni sono validate e salvate con backup prima dei riavvii.</p></div></div>';
    if (isset($d['error'])) echo '<div class="msg err">' . h($d['error']) . '</div>';
    echo '<nav class="iptm-dns-shortcuts" aria-label="Funzioni DNS"><a href="?p=piholehealth"><strong>Diagnostica Pi-hole</strong><span>Web e listener</span></a><a href="?p=piholelists"><strong>Liste e whitelist</strong><span>Adlist e regex</span></a><a href="?p=unbound"><strong>Hardening Unbound</strong><span>Profili e rollback</span></a><a href="?p=dnsaudit"><strong>Privacy DNS</strong><span>Verifica perdite DNS</span></a></nav>';
    echo '<div class=tiles iptm-dns-metrics>'
        . tile('Pi-hole / FTL', $pi ? h($d['pihole_active'] ?? 'installato') : 'non installato', h(($d['pihole_version'] ?? '') ?: 'Filtro DNS locale'))
        . tile('Unbound', $ub ? h($d['unbound_active'] ?? 'installato') : 'non installato', h(($d['unbound_version'] ?? '') ?: 'Resolver ricorsivo'))
        . tile('DNSCrypt-Proxy', $dc ? h($d['dnscrypt_state'] ?? 'installato') : 'non installato', h(($d['dnscrypt_version'] ?? '') ?: 'DNS cifrato'))
        . tile('DNSSEC Unbound', h($d['unbound_dnssec'] ?? 'n/d'), h(($d['unbound_anchor'] ?? '') ?: 'Trust anchor non rilevato'))
        . tile('DNSSEC Pi-hole / FTL', h(($d['pihole_dnssec'] ?? 'n/d') === 'yes' ? 'attivo' : (($d['pihole_dnssec'] ?? 'n/d') === 'no' ? 'non attivo' : 'n/d')), h(($d['pihole_dnssec_env'] ?? '') === 'yes' ? 'gestito da FTLCONF_*' : 'validazione FTL'))
        . tile('Upstream Pi-hole', h(($d['pihole_upstreams'] ?? '') ?: 'non rilevato'), h(($d['pihole_env_override'] ?? '') === 'yes' ? 'gestito da FTLCONF_*' : 'gestione locale'))
        . '</div>';
    echo '<div class="card iptm-dns-health"><h2>Pi-hole non raggiungibile?</h2><p>Se il DNS funziona ma la dashboard Pi-hole non si apre, controlla i listener 8089/8489 e il reindirizzamento HTTP senza modificare FTL.</p><p><a class="btn s" href="?p=piholehealth">Apri diagnosi accessibilità Pi-hole</a></p></div>';
    echo '<div class=card><h2>Pi-hole · Gestione liste</h2><p>Importa whitelist TXT/CSV/JSON, regex allow/deny e scegli anche tutte le 50 adlist (oltre 10 vengono aggiunte disabilitate, senza aggiornare Gravity) dal catalogo. Il modulo è separato dai test DNS per essere più rapido.</p><p><a class="btn g" href="?p=piholelists">Apri gestione whitelist e adlist</a></p></div>';
    echo '<div class=card id=dns-architecture><h2>Architettura DNS</h2><p class=mut>Seleziona uno dei tre percorsi. Il servizio DNS per i client rimane Pi-hole sulla porta 53; gli upstream restano confinati al loopback.</p>';
    $flowNames = ['unbound' => 'Pi-hole → Unbound', 'dnscrypt' => 'Pi-hole → DNSCrypt-Proxy', 'layered' => 'Pi-hole → Unbound → DNSCrypt-Proxy', 'external' => 'Pi-hole → upstream esterno (nessuna delle tre architetture è applicata)', 'none' => 'Pi-hole non rilevato'];
    echo '<div id=dns-flow-wrap data-actual="' . h($actual) . '" data-flow-labels="' . h(json_encode($flowNames, JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT)) . '"><p class=mut id=dns-flow-cap>Configurazione effettiva rilevata: <b>' . h($flowNames[$actual]) . '</b>' . (($d['pihole_env_override'] ?? '') === 'yes' ? ' (upstream governato da FTLCONF_*: il valore reale potrebbe differire dal file)' : '') . '</p>';
    foreach (['unbound', 'dnscrypt', 'layered', 'external', 'none'] as $fm) { if (in_array($fm, ['external', 'none'], true) && $fm !== $actual) continue; echo dns_flow_html($fm, $d, $st, $fm !== $actual); }
    echo '</div>';
    if ($pi && !$ro) {
        $blocked = (($d['pihole_env_override'] ?? '') === 'yes') || (($d['pihole_toml_valid'] ?? '') === 'no') || (($d['pihole_config'] ?? '') !== '/etc/pihole/pihole.toml');
        if ($blocked) {
            echo '<div class="msg warn">Pi-hole non è modificabile da IPTM: configurazione non standard, TOML non valido oppure upstream governato da <code>FTLCONF_*</code>. Le opzioni sono mostrate sotto ma l’applicazione va effettuata dalla fonte di configurazione originale.</div>';
        }
        $currentMode = in_array($actual, ['unbound', 'dnscrypt', 'layered'], true) ? $actual : ($ubReady ? 'unbound' : 'dnscrypt');   // se nessuna delle tre e' applicata, preseleziono la prima pronta
        $profiles = [
            'unbound' => ['1 · Ricorsivo con DNSSEC', 'Pi-hole → Unbound. Ricorsione DNS e validazione DNSSEC con trust anchor locale.', $ubReady, $ub ? 'Richiede Unbound attivo, profilo IPTM, configurazione valida e DNSSEC verificato.' : 'Unbound non installato. Installalo da Programmi prima di applicare.'],
            'dnscrypt' => ['2 · DNS cifrato', 'Pi-hole → DNSCrypt-Proxy. Trasporto DNS cifrato e validazione DNSSEC di Pi-hole FTL.', $dcDirectReady, !$dc ? 'DNSCrypt-Proxy non installato.' : (($d['pihole_dnssec_env'] ?? '') === 'yes' && in_array(strtolower((string)($d['pihole_dnssec'] ?? '')), ['false','0','no'], true) ? 'Pi-hole DNSSEC è disabilitato da FTLCONF_dns_dnssec.' : 'Richiede DNSCrypt attivo su 127.0.0.1:5053 (TCP/UDP, socket systemd o listener nativo), profilo IPTM, TOML valido e FTL attivo.')],
            'layered' => ['3 · Doppio livello', 'Pi-hole → Unbound → DNSCrypt-Proxy. Trasporto cifrato upstream e validazione DNSSEC Unbound.', $ubReady && $dcReady, 'Richiede Unbound e DNSCrypt entrambi configurati, attivi e verificati.'],
        ];
        if (!isset($profiles[$currentMode])) $currentMode = $ubReady ? 'unbound' : 'dnscrypt';
        // The wizard can preselect a choice, never apply it via GET.
        $requested = (string)($_GET['dns_target'] ?? '');
        if (array_key_exists($requested, $profiles)) $currentMode = $requested;
        echo '<form method=post class="card dns-stack-form">' . fh('p=dns') . '<input type=hidden name=action value=dns_stack><h3>Scegli la configurazione DNS</h3><fieldset class=dns-profile-fieldset><legend class=mut>Seleziona una sola architettura</legend><div class=dns-profile-grid>';
        foreach ($profiles as $value => [$title, $desc, $ready, $prereq]) {
            $status = $ready ? '<span class="b b-ACCEPT">Pronta</span>' : '<span class="b b-LOG">Da verificare</span>';
            echo '<label class=dns-profile-option><input type=radio name=dns_stack_mode value="' . h($value) . '"' . ($currentMode === $value ? ' checked' : '') . '><span class=dns-profile-body><strong>' . h($title) . '</strong><span class=dns-profile-desc>' . h($desc) . '</span><span class=dns-profile-prereq>' . $status . ' ' . h($prereq) . '</span></span></label>';
        }
        echo '</div></fieldset><p class=mut>Puoi selezionare anche un profilo non ancora pronto: l’applicazione verrà rifiutata con il prerequisito mancante, senza cambiare l’upstream. Prima del cambio IPTM crea un backup, valida servizi e listener, verifica DNSSEC e risoluzione; in caso di errore esegue il rollback.</p>';
        if (!$blocked) echo '<button class=g>Allinea e applica configurazione selezionata</button>';
        else echo '<p class=msg warn>Selezione in sola lettura: correggi prima la variabile FTLCONF_* o la configurazione esterna di Pi-hole.</p>';
        echo '</form>';
    } else {
        echo '<div class=grid data-iptm-layout="ui-c53ea1da23"><div class=card><h3>1 · Ricorsivo con DNSSEC</h3><p>Pi-hole → Unbound. Ricorsione DNS e validazione DNSSEC con trust anchor locale.</p></div><div class=card><h3>2 · DNS cifrato</h3><p>Pi-hole → DNSCrypt-Proxy. Trasporto cifrato e DNSSEC FTL.</p></div><div class=card><h3>3 · Doppio livello</h3><p>Pi-hole → Unbound → DNSCrypt. DNSSEC Unbound e trasporto cifrato.</p></div></div>';
        if (!$pi) echo '<div class=msg>Pi-hole non rilevato. Installa Pi-hole tramite DietPi-Software o Programmi prima di scegliere la catena.</div>';
    }
    echo '</div>';
    echo '<div class=card><h2>Pi-hole / FTL</h2>';
    if ($pi) {
        echo '<p>Configurazione: <code>' . h($d['pihole_config'] ?? '/etc/pihole/pihole.toml') . '</code> · Servizio: <b>' . h($d['pihole_active'] ?? 'n/d') . '</b> · Versione: <b>' . h($d['pihole_version'] ?? 'n/d') . '</b></p><p>Upstream attuale: <code>' . h($d['pihole_upstreams'] ?? 'non rilevato') . '</code> · DNSSEC FTL: <b>' . h($d['pihole_dnssec'] ?? 'n/d') . '</b>' . (($d['pihole_dnssec_env'] ?? '') === 'yes' ? ' (gestito da FTLCONF_*)' : '') . '</p>';
        if (($d['pihole_env_override'] ?? '') === 'yes') echo '<div class="msg warn">L’upstream è sovrascritto da <code>FTLCONF_dns_upstreams</code>. Pi-hole considera il valore in sola lettura: modifica Docker/ambiente di servizio, non il TOML.</div>';
        if (($d['pihole_toml_valid'] ?? '') === 'no') echo '<div class="msg err">Il file pihole.toml non supera il parser TOML; IPTM non tenterà di correggerlo automaticamente.</div>';
        if (!$ro) echo '<form method=post class=ops>' . fh('p=dns') . '<input type=hidden name=action value=dns_service><input type=hidden name=service value=pihole-FTL><button class=s>Riavvia FTL</button></form>';
    } else echo '<p class=mut>Pi-hole non installato. Il rilevamento si basa su FTL e sui percorsi standard Pi-hole v6.</p>';
    echo '</div>';
    echo '<div class=card><h2>Unbound · resolver DNSSEC</h2>';
    if ($ub) {
        echo '<p>Servizio: <b>' . h($d['unbound_active'] ?? 'n/d') . '</b> · Profilo IPTM: <b>' . (($d['unbound_profile'] ?? '') === 'yes' ? 'presente' : 'assente') . '</b> · Porta: <code>' . h($d['unbound_port'] ?? 'n/d') . '</code> · Listener: <code>' . h($d['unbound_listener'] ?? 'non rilevato') . '</code></p>';
        echo '<p>Config check: <b>' . h($d['unbound_check'] ?? 'n/d') . '</b> · DNSSEC: <b>' . h($d['unbound_dnssec'] ?? 'n/d') . '</b></p>';
        if (($d['unbound_check'] ?? '') !== 'ok') echo '<div class="msg err">unbound-checkconf non ha superato il controllo. La catena DNS non verrà modificata finché non è corretto.</div>';
        if (($d['unbound_dnssec'] ?? '') !== 'yes') echo '<div class="msg warn">Trust anchor DNSSEC non rilevato o non leggibile. La validazione DNSSEC non è considerata attiva.</div>';
        if (!$ro && (($d['unbound_profile'] ?? '') !== 'yes' || ($d['unbound_check'] ?? '') !== 'ok' || ($d['unbound_dnssec'] ?? '') !== 'yes')) echo '<form method=post class=ops>' . fh('p=dns') . '<input type=hidden name=action value=dns_unbound_profile><button class=g>Configura profilo Unbound</button></form>';
        if (!$ro) echo '<form method=post class=ops>' . fh('p=dns') . '<input type=hidden name=action value=dns_service><input type=hidden name=service value=unbound><button class=s>Riavvia Unbound</button></form>';
    } else {
        echo '<p>Unbound non installato.</p><a class=btn href="?p=progs">Apri Programmi per installare Unbound</a>';
    }
    echo '</div>';
    echo '<div class=card><h2>DNSCrypt-Proxy · DNS cifrato</h2>';
    if ($dc) {
        $dcMode = (string)($d['dnscrypt_mode'] ?? 'auto');
        echo '<p>Versione: <b>' . h($d['dnscrypt_version'] ?? 'n/d') . '</b> · Stato: <b>' . h($d['dnscrypt_state'] ?? 'n/d') . '</b> · Ascolto: <code>' . h($d['dnscrypt_listen'] ?? 'non rilevato') . '</code></p><p>Protocollo: <b>' . h($d['dnscrypt_protocol'] ?? 'n/d') . '</b> · Resolver: <code>' . h(($d['dnscrypt_servers'] ?? '') ?: 'pool automatico · filtri DNSSEC/no-log/no-filter') . '</code> · Config check: <b>' . h($d['dnscrypt_check'] ?? 'n/d') . '</b> · Profilo IPTM (' . (($d['dnscrypt_socket'] ?? '') === 'yes' ? 'socket systemd' : 'listener nativo') . '): <b>' . (($d['dnscrypt_managed'] ?? '') === 'yes' ? 'sì' : 'no') . '</b></p>';
        if (($d['dnscrypt_check'] ?? '') !== 'ok') echo '<div class="msg warn">Il file DNSCrypt non supera il controllo. Correggi la configurazione prima di allineare Pi-hole.</div>';
        if (($d['dnscrypt_managed'] ?? '') !== 'yes') echo '<div class="msg warn">' . (($d['dnscrypt_socket'] ?? '') === 'yes' ? 'La socket systemd non è ancora configurata su 127.0.0.1:5053. Salva il profilo DNSCrypt qui sotto per creare un drop-in loopback verificato.' : 'Il profilo IPTM non è ancora applicato. Su questo sistema DNSCrypt-Proxy non ha una socket systemd: IPTM lo lega direttamente a 127.0.0.1:5053 nel file di configurazione. Salva il profilo DNSCrypt qui sotto per applicarlo con backup e verifica.') . '</div>';
        if (($d['dnscrypt_listener_safe'] ?? '') !== 'yes') echo '<div class="msg err">I listener TCP e UDP su 5053 non risultano entrambi limitati al loopback (127.0.0.1; ::1 è ammesso) oppure il servizio non è attivo. IPTM non userà DNSCrypt come upstream finché il profilo non sarà applicato e verificato: usa «Salva e valida DNSCrypt».</div>';
        if (!$ro) {
            echo '<form method=post class=card>' . fh('p=dns') . '<input type=hidden name=action value=dnscrypt_config><h3>Configurazione DNSCrypt</h3><label class=fl><span>Protocollo upstream</span><select name=dnscrypt_proto><option value=auto' . ($dcMode === 'auto' ? ' selected' : '') . '>DNSCrypt + DNS-over-HTTPS (automatico)</option><option value=dnscrypt' . ($dcMode === 'dnscrypt' ? ' selected' : '') . '>Solo DNSCrypt</option><option value=doh' . ($dcMode === 'doh' ? ' selected' : '') . '>Solo DNS-over-HTTPS</option></select></label><small class=mut>Usa il pool dei resolver provenienti da fonti firmate, con selezione automatica dei server che dichiarano supporto DNSSEC, no-log e no-filter. I nomi personalizzati sono esclusi perché, secondo DNSCrypt-Proxy, la selezione esplicita dei server disattiva i filtri require_* delle fonti. IPTM espone DNSCrypt solo su 127.0.0.1:5053 (TCP/UDP): con la socket systemd usa BindToDevice=lo, senza socket systemd lega direttamente il servizio al loopback. La cifratura del trasporto non equivale a validazione DNSSEC: nel profilo diretto la abilita Pi-hole FTL.</small><p><button class=g>Salva e valida DNSCrypt</button></p></form>';
            echo '<form method=post class=ops>' . fh('p=dns') . '<input type=hidden name=action value=dns_service><input type=hidden name=service value=dnscrypt-proxy><button class=s>Riavvia DNSCrypt</button></form>';
        }
    } else {
        echo '<p>DNSCrypt-Proxy non installato. IPTM lo configura solo su loopback, sulla porta 5053; non apre porte DNS sulla WAN.</p><a class=btn href="?p=progs">Apri Programmi per installare DNSCrypt-Proxy</a>';
    }
    echo '</div>';
    $dnsBody = dd_radio($S, 'dns_redirect', 'Forza i client LAN al DNS locale', 'Reindirizza le query DNS porta 53 al server indicato.')
        . dd_in($S, 'dns_ip', 'IP del DNS locale', '192.168.1.165', 'Indica l’indirizzo LAN di Pi-hole o altro resolver.', '220px')
        . dd_radio($S, 'dot_block', 'Blocca DNS-over-TLS (porta 853)', 'Riduce l’elusione del resolver locale via DoT; non blocca DoH su HTTPS né VPN.')
        . '<p class=mut>Queste impostazioni generano le regole DNS nel firewall; salva la bozza e poi applica con rollback.</p>';
    echo '<div class=card><h2>Forzatura DNS e protezione client</h2>' . s_form('setup', $dnsBody, 'p=dns', true) . '</div>';
    if (!$ro) echo '<div class=card><h2>Test e diagnosi</h2><p>Verifica la risoluzione locale su Pi-hole, Unbound e DNSCrypt, la configurazione e il flag DNSSEC ove supportato.</p><form method=post class=ops>' . fh('p=dns') . '<input type=hidden name=action value=dns_test><button class=g>Esegui test DNS completo</button></form>' . (!empty($d['dns_tests']) ? '<pre>' . h($d['dns_tests']) . '</pre>' : '') . '</div>';
    echo '<h2 class=dh>Backup, esportazione e ripristino</h2>';
    echo '<div class=card><h2>Backup unico delle configurazioni DNS</h2>';
    echo '<p>Include configurazioni Pi-hole v5/v6, DNSCrypt, Unbound e dnsmasq nei percorsi standard; <code>gravity.db</code> viene acquisito tramite backup SQLite online. Non include log, cronologia delle richieste né directory arbitrarie. Il backup web viene cifrato in OpenPGP AES-256 con passphrase locale; contiene password, token e chiavi private. Per esportare da browser usa HTTPS. Conserva la passphrase separatamente.</p>';
    if (!$ro) {
        echo '<form method=post>'.fh('p=dns').'<input type=hidden name=action value=dns_bundle_export><label class=fl>Passphrase nuova (minimo 14 caratteri)<input type=password name=dnsbundle_password minlength=14 maxlength=256 autocomplete=new-password required></label><label class=fl>Ripeti passphrase<input type=password name=dnsbundle_password2 minlength=14 maxlength=256 autocomplete=new-password required></label><p><button class=s>Esporta backup DNS cifrato (.zip.gpg)</button></p></form>';
        echo '<form method=post enctype="multipart/form-data" class="iptm-classic-form">'.fh('p=dns').'<input type=hidden name=action value=dns_bundle_import><label class=fl>Backup DNS .zip.gpg oppure ZIP legacy (fino a 12 MiB via browser)<input type=file name=dnsbundle accept=".zip,.gpg,application/zip,application/octet-stream" required></label><label class=fl>Passphrase del backup cifrato (.gpg)<input type=password name=dnsbundle_password_import autocomplete=off maxlength=256></label><p class=mut>Gli ZIP non cifrati possono contenere credenziali. Usa HTTPS; il ripristino crea un backup e non riavvia i servizi.</p><p><button class=s>Controlla archivio</button> <button class=g name=dnsbundle_apply value=1>Ripristina dal file</button></p><progress class=iptm-progress hidden></progress><span role=status class=mut></span></form>';
        if (!empty($_SESSION['dns_bundle_preview']) && time()-($_SESSION['dns_bundle_preview']['time']??0)<600)
            echo '<p class=mut>Ultima anteprima: '.(int)$_SESSION['dns_bundle_preview']['n'].' file verificati. Ricarica lo stesso ZIP per eseguire il ripristino.</p>';
    }
    echo '<p class=mut>Il ripristino della banca dati gravity.db richiede <b>Pi-hole FTL fermo</b> per evitare la sostituzione del database in uso; i servizi non sono avviati o riavviati automaticamente. Per bundle grandi usa la CLI root. Un errore tenta il ripristino dai backup precedenti.</p></div>';
    echo '<details class=card><summary>Dettagli tecnici e file gestiti</summary><ul><li>Pi-hole FTL v6: <code>/etc/pihole/pihole.toml</code>, upstream modificato con CLI ufficiale, rispettando FTLCONF_*.</li><li>Unbound: <code>/etc/unbound/unbound.conf.d/iptm-local-recursive.conf</code>.</li><li>DNSCrypt: <code>/etc/dnscrypt-proxy/dnscrypt-proxy.toml</code>; socket activation systemd gestita da IPTM con TCP/UDP vincolati a 127.0.0.1:5053 e BindToDevice=lo.</li><li>Catena Unbound → DNSCrypt: <code>/etc/unbound/unbound.conf.d/iptm-dnscrypt-forward.conf</code>.</li><li>Ascolti privati: Unbound 5335, DNSCrypt 5053, Pi-hole FTL 53.</li></ul></details>';
}

function pg_system() {
    global $M; $inv = ipset_inventory(); $L = live_dump(); $S = S_get(); $txt = ser($M); $used = $inv['ok'] ? draft_sets($txt) : []; $det = cs_detect(); $cst = cs_status(); $prob = [];
    if ($inv['ok']) foreach (sets_missing($txt, $inv['sets']) as $m) $prob[] = "Il set «{$m}» è usato dalla bozza ma non esiste nel sistema.";
    [, $fx, $ms] = fix_chain_decls($txt); foreach ($fx as $f) $prob[] = "La catena $f esiste nel kernel (creata da un programma) ma non è dichiarata nella bozza: verrà dichiarata in automatico all'applicazione."; foreach ($ms as $m) $prob[] = "La bozza salta alla catena $m che non esiste né nel kernel né nella bozza.";
    if ($S['crowdsec']) {
        foreach (array_filter(explode(',', $S['cs_set'])) as $x) if ($inv['ok'] && !isset($inv['sets'][$x])) $prob[] = "CrowdSec: il set diretto «{$x}» non esiste (i set numerati compaiono solo con decisioni attive): svuota il campo, basta il bouncer.";
        if ($L['ok'] && !isset($L['chains']['filter'][CS_CHAIN]) && ($cst['svc'] ?? '') === 'active') $prob[] = "CrowdSec: il bouncer è attivo ma la catena " . CS_CHAIN . " non esiste (la ricrea al riavvio: «Applica» lo fa in automatico; se persiste controlla la chiave API con cscli bouncers list).";
    }
    echo compat_card($txt);
    echo '<div class=card><h2>Rilevamento sistema</h2><p class=mut><a href="?p=advise"><b>🔎 Analisi sistema</b></a> — proposte automatiche di opzioni da attivare. · Catene e ipset presenti ora nel kernel, confrontati con la bozza. Dopo un riavvio di CrowdSec, Docker o dei tuoi script i nomi possono cambiare.</p>';
    if (!$L['ok'] && !$inv['ok']) echo '<div class="msg err">Kernel non leggibile (helper/sudo?).</div>';
    echo $prob ? '<div class="msg err">' . implode('<br>', array_map('h', $prob)) . '</div>' : '<p>✅ Nessuna incongruenza tra bozza, ipset e catene del sistema.</p>';
    if ($det['sets'] || $det['chain']) {
        echo '<h3>CrowdSec rilevato</h3><p>Servizio: <b>' . h($cst['svc'] ?: '?') . '</b> · Set IPv4: <b>' . h(implode(', ', $det['sets']) ?: 'nessuno') . '</b> · Set IPv6: <b>' . h(implode(', ', $det['sets6']) ?: 'nessuno') . '</b> · Catena: <b>' . h($det['chain'] ?: 'nessuna') . '</b></p><form method=post>' . fh('p=system') . '<input type=hidden name=action value=cs_autodetect><button>🔧 Collega il firewall a CrowdSec</button></form>';
    }
    echo '</div><div class=card><h3>ipset presenti (' . count($inv['sets']) . ')</h3><div data-iptm-layout="scroll"><table><tr><th>Nome</th><th>Tipo</th><th>Voci</th><th>Riferimenti</th><th>Nella bozza</th><th>Origine</th></tr>';
    foreach ($inv['sets'] as $n => $x) { $og = own_set($n) ? 'iptables-manager' : (stripos($n, 'crowdsec') !== false ? 'CrowdSec' . (isset($cst['origin'][$n]) ? ' (' . $cst['origin'][$n] . ')' : '') : (stripos($n, 'f2b') !== false ? 'fail2ban' : '—'));
        echo '<tr><td><b>' . h($n) . '</b></td><td>' . h($x['type']) . '</td><td>' . number_format($x['n']) . '</td><td>' . $x['refs'] . '</td><td>' . (in_array($n, $used, true) ? '✔' : '—') . '</td><td>' . $og . '</td></tr>'; }
    echo $inv['sets'] ? '' : '<tr><td colspan=6 class=mut>Nessun ipset (o ipset non installato).</td></tr>'; echo '</table></div></div>';
    $cnt = []; foreach ($L['rules'] ?? [] as $r) $cnt[$r['t'] . '|' . $r['c']] = ($cnt[$r['t'] . '|' . $r['c']] ?? 0) + 1; $dc = []; foreach ($M as $b) if ($b['k'] === 'table') foreach ($b['items'] as $it) if ($it['t'] === 'chain') $dc[$b['name']][$it['n']] = 1;
    echo '<div class=card><h3>Catene nel kernel</h3><div data-iptm-layout="scroll"><table><tr><th>Tabella</th><th>Catena</th><th>Regole</th><th>Gestore</th><th>Dichiarata nella bozza</th></tr>';
    foreach ($L['chains'] ?? [] as $t => $cs) foreach (array_keys($cs) as $c) { if (in_array($c, BUILTIN[$t] ?? [], true)) continue; echo '<tr><td>' . h($t) . '</td><td><b>' . h($c) . '</b></td><td>' . ($cnt[$t . '|' . $c] ?? 0) . '</td><td>' . h(dyn_owner($c) ?: (str_starts_with($c, 'IPTM-') ? 'iptables-manager' : '—')) . '</td><td>' . (!empty($dc[$t][$c]) ? '✔' : '—') . '</td></tr>'; }
    echo '</table></div></div>';
}


