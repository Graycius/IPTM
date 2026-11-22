<?php
// ===================== MIGLIORAMENTI UX / OPS (badge, search, backup, history, checklist) =====================

/** Campiona statistiche su disco (max 1 ogni ~15 min). */
function stats_history_sample(): void {
    if (!function_exists('stats_gather')) return;
    $dir = DATA_DIR . '/stats';
    @mkdir($dir, 0700, true);
    $mutex = @fopen($dir . '/sample.lock', 'c');
    if (!$mutex || !@flock($mutex, LOCK_EX | LOCK_NB)) { if (is_resource($mutex)) fclose($mutex); return; }
    try {
    $lock = $dir . '/.last_sample';
    $last = is_file($lock) ? (int)@file_get_contents($lock) : 0;
    if (time() - $last < 900) return;
    $G = stats_gather();
    $row = [
        'ts' => time(),
        'ct' => (int)($G['ct_count'] ?? 0),
        'ct_max' => (int)($G['ct_max'] ?? 0),
        'conns' => (int)($G['conn_total'] ?? 0),
        'drop_pkts' => (int)($G['impact']['totals']['drop_pkts'] ?? 0),
        'accept_pkts' => (int)($G['impact']['totals']['accept_pkts'] ?? 0),
        'rules_hit' => (int)($G['impact']['totals']['hit'] ?? 0),
    ];
    $day = date('Y-m-d', $row['ts']);
    $f = $dir . "/day-$day.jsonl";
    @file_put_contents($f, json_encode($row, JSON_UNESCAPED_UNICODE) . "\n", FILE_APPEND | LOCK_EX);
    atomic_data_write($lock, (string)time(), 0600);
    if (function_exists('ops_notify_watch')) ops_notify_watch();
    // Rotazione statistiche centralizzata: iptm-retention.timer (minimo 14 giorni).
    } finally { @flock($mutex, LOCK_UN); @fclose($mutex); }
}

/** Legge storia statistiche (punti aggregati per ora, ultimi N giorni). */
function stats_history_load(int $days = 7): array {
    $dir = DATA_DIR . '/stats';
    $out = [];
    for ($i = $days - 1; $i >= 0; $i--) {
        $day = date('Y-m-d', time() - $i * 86400);
        $f = $dir . "/day-$day.jsonl";
        if (!is_file($f)) continue;
        foreach (file($f, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $line) {
            $j = json_decode($line, true);
            if (is_array($j)) $out[] = $j;
        }
    }
    return $out;
}

/** Backup rules.v4 con etichetta utente. */
function backup_named(string $label): array {
    $label = trim(preg_replace('/[^\p{L}\p{N}\-_. ]+/u', '', $label) ?? '');
    if ($label === '') return [1, 'Etichetta vuota o non valida'];
    $label = substr(str_replace(' ', '_', $label), 0, 40);
    $src = rules_live();
    if ($src === '') return [1, 'rules.v4 vuoto o non leggibile'];
    $dir = DATA_DIR . '/backups';
    @mkdir($dir, 0700, true);
    $name = 'rules.v4.' . date('Ymd-His') . '.' . $label;
    $path = $dir . '/' . $name;
    if (@file_put_contents($path, $src) === false) return [1, 'Scrittura backup fallita'];
    @chmod($path, 0600);
    return [0, $name];
}

/** A retired IoT Warden must never be re-executed from POST_SCRIPT. */
function iptm_post_legacy_script(string $script): bool {
    return preg_match('~(?:^|/)iot_warden\.sh$~iD', trim($script)) === 1;
}

/** Checklist post-apply: servizi e script da conf. */
function post_apply_checklist(): array {
    $c = post_conf();
    $items = [];
    $configured = preg_split('/\s+/', trim((string)($c['services'] ?? ''))) ?: [];
    // Rispecchia il comportamento dell'helper: riavvia i bouncer attivi anche
    // quando non sono elencati esplicitamente in POST_SERVICES.
    foreach (['crowdsec-firewall-bouncer', 'fail2ban'] as $managed) {
        $state = function_exists('svc_state') ? svc_state($managed) : [];
        if (($state['active'] ?? '') === 'active' && !in_array($managed, $configured, true)) $configured[] = $managed;
    }
    foreach ($configured as $u) {
        if ($u === '') continue;
        $st = function_exists('svc_state') ? svc_state($u) : ['inst' => false, 'active' => 'unknown', 'enabled' => 'unknown'];
        $active = ($st['active'] ?? '') === 'active';
        $unknownDocker = $u === 'docker' && !(bool)($st['inst'] ?? false)
            && (is_executable('/usr/bin/docker') || is_executable('/usr/local/bin/docker') || is_executable('/snap/bin/docker'));
        $items[] = [
            'type' => 'service', 'id' => $u, 'label' => $u,
            'ok' => $active ? true : ($unknownDocker ? null : false),
            'detail' => ($st['inst'] ?? false) ? ('active=' . ($st['active'] ?? '?') . ' enabled=' . ($st['enabled'] ?? '?'))
                : ($unknownDocker ? 'CLI Docker disponibile; daemon/socket non verificati'
                    : 'unità non rilevata: verificare la configurazione post-apply'),
        ];
    }
    $script = trim((string)($c['script'] ?? ''));
    if ($script !== '') {
        $legacy = iptm_post_legacy_script($script);
        $ok = !$legacy && is_file($script) && is_executable($script);
        $items[] = [
            'type' => $legacy ? 'legacy' : 'script',
            'id' => $script, 'label' => $legacy ? 'Attivatore IoT precedente' : $script,
            'ok' => $legacy ? null : $ok,
            'detail' => $legacy
                ? 'POST_SCRIPT contiene un attivatore ritirato: IPTM non lo esegue. Rimuovilo da Amministrazione → Post-apply.'
                : ($ok ? 'Eseguibile; proprietà e permessi ricontrollati da root prima dell’esecuzione'
                    : (is_file($script) ? 'non eseguibile' : 'non presente')),
        ];
    }
    // Il motore MAC/VLAN IPTM non ricrea IOT_FW o IOT_DNS: sono
    // esclusivamente nomi di catene del vecchio Warden. Non segnalarli.
    $S = S_get();
    $iotMac = ($S['iot_strategy'] ?? '') === 'iptm_mac';
    $iotVlan = (bool)array_filter($S['custom_opts'] ?? [], fn($co) => !empty($co['iptm_zone_v1']));
    [$sc, $live, $se] = priv('save');
    $haveLive = $sc === 0 && preg_match('/^\*filter\s*$/m', $live) && preg_match('/^COMMIT\s*$/m', $live);
    if ($iotMac) {
        $active = $haveLive &&
            preg_match('/^:IPTM-MAC-IN\s/m', $live) &&
            preg_match('/^:IPTM-MAC-FWD\s/m', $live) &&
            preg_match('/^-A INPUT .* -j IPTM-MAC-IN(?:\s|$)/m', $live) &&
            preg_match('/^-A FORWARD .* -j IPTM-MAC-FWD(?:\s|$)/m', $live);
        $items[] = [
            'type' => 'iot', 'id' => 'mac', 'label' => 'Zona IoT MAC IPTM',
            'ok' => $haveLive ? ($active ? true : null) : null,
            'detail' => !$haveLive ? 'Stato del firewall non leggibile; verifica dal gateway'
                : ($active ? 'Catene IPTM-MAC-IN/FWD e relativi agganci presenti nel kernel'
                    : 'Policy configurata, ma non rilevata nel kernel: potrebbe essere ancora in bozza; vai su Applica con rollback'),
        ];
    } elseif ($iotVlan) {
        $items[] = [
            'type' => 'iot', 'id' => 'vlan', 'label' => 'Zona IoT VLAN IPTM', 'ok' => null,
            'detail' => 'Policy VLAN gestita da IPTM: verifica bozza e catene nella pagina Zone, non dal vecchio Warden',
        ];
    }
    // Mostra solo le catene runtime realmente create da servizi esterni;
    // un'assenza non è un problema se il daemon usa nftables o non ha container.
    foreach (['DOCKER'=>'Docker', 'DOCKER-USER'=>'Docker', 'CROWDSEC_CHAIN'=>'CrowdSec'] as $ch => $owner) {
        if (!$haveLive) continue;
        $found = preg_match('/^:' . preg_quote($ch, '/') . '\s/m', $live) ||
            preg_match('/-j\s+' . preg_quote($ch, '/') . '(?:\s|$)/m', $live);
        if (!$found) continue;
        $items[] = ['type'=>'chain','id'=>$ch,'label'=>'catena '.$ch,
            'ok'=>true,'detail'=>'gestita da '.$owner.' · presente nel kernel'];
    }
    if (!$haveLive) $items[] = ['type'=>'info','id'=>'firewall','label'=>'Lettura catene kernel',
        'ok'=>null,'detail'=>'iptables-save non disponibile: elenco catene runtime non verificabile ('.trim($se).')'];
    return $items;
}

function pg_postcheck() {
    $items = post_apply_checklist();
    $admin = ($_SESSION['role'] ?? 'viewer') === 'admin';
    echo '<div class=card><h2>Checklist post-apply</h2>';
    echo '<p class=mut>Controlla servizi, catene e zone IoT.</p>';
    echo '<table><tr><th>Voce</th><th>Stato</th><th>Dettaglio</th><th>Azioni</th></tr>';
    foreach ($items as $it) {
        $ok = $it['ok'];
        $st = $ok === null ? '<span class="b b-jump">da verificare</span>'
            : ($ok ? '<span class="b b-ACCEPT">ok</span>' : '<span class="b b-jump">da verificare</span>');
        echo '<tr><td>' . h($it['label']) . '</td><td>' . $st . '</td><td class=mut>' . h($it['detail']) . '</td><td class=ops>';
        if ($admin && $it['type'] === 'service') {
            echo '<form method=post class=inl>' . fh('p=postcheck') . '<input type=hidden name=action value=postcheck_restart><input type=hidden name=unit value="' . h($it['id']) . '"><button class=s>Riavvia</button></form>';
        } elseif ($admin && $it['type'] === 'script') {
            echo '<form method=post class=inl>' . fh('p=postcheck') . '<input type=hidden name=action value=postcheck_script><button class=s>Esegui ora</button></form>';
        } elseif ($it['type'] === 'legacy') {
            echo '<a class="btn s" href="?p=admin">Configurazione</a>';
        } elseif ($it['type'] === 'iot') {
            echo '<a class="btn s" href="?p=zones">Zone IoT</a>';
        }
        echo '</td></tr>';
    }
    echo '</table>';
    if ($admin) echo '<form method=post class=ops>' . fh('p=postcheck') . '<input type=hidden name=action value=postcheck_all><button class=g>Riavvia servizi post-apply configurati</button></form>';
    echo '<p class=mut>Le zone IoT non richiedono script esterni. Docker e CrowdSec possono creare proprie regole.</p></div>';
}

/** Ricerca globale pagine + opzioni + frammenti regole in bozza. */
function pg_search() {
    global $draftTxt, $M;
    $q = trim((string)($_GET['q'] ?? $_POST['q'] ?? ''));
    echo '<div class=card><h2>Ricerca</h2>';
    echo '<form method=get class=row><input type=hidden name=p value=search><label class=fl data-iptm-layout="ui-83725d2c6e"><span>Cerca nel menu, nelle opzioni e nella bozza</span>'
        . '<input name=q value="' . h($q) . '" placeholder="es. 5683, WireGuard, synflood, Shelly" autofocus></label>'
        . '<p><button>Cerca</button></p></form>';
    if ($q === '') { echo '<p class=mut>Cerca per porta, opzione o interfaccia.</p></div>'; return; }
    $ql = strtolower($q);
    $hits = [];
    // menu
    global $MENU;
    if (is_array($MENU ?? null)) {
        foreach ($MENU as $sec => $pack) {
            foreach ($pack[1] as $pid => $lab) {
                if (str_contains(strtolower($lab), $ql) || str_contains($pid, $ql)) {
                    $hits[] = ['type' => 'pagina', 'title' => $lab, 'href' => '?p=' . urlencode($pid), 'why' => 'menu'];
                }
            }
        }
    }
    // opzioni settings
    $S = S_get();
    foreach ($S as $k => $v) {
        if (is_array($v)) continue;
        $blob = $k . ' ' . (string)$v;
        if (str_contains(strtolower($blob), $ql)) {
            $hits[] = ['type' => 'impostazione', 'title' => $k . ' = ' . (is_string($v) ? $v : json_encode($v)), 'href' => '?p=security', 'why' => 'settings'];
        }
    }
    // regole bozza
    $n = 0;
    foreach (explode("\n", (string)$draftTxt) as $line) {
        if ($n >= 40) break;
        if ($line !== '' && str_contains(strtolower($line), $ql)) {
            $hits[] = ['type' => 'regola', 'title' => $line, 'href' => '?p=raw', 'why' => 'bozza'];
            $n++;
        }
    }
    // apps catalog
    if (function_exists('apps_detect')) {
        $det = apps_detect();
        foreach ($det as $id => $app) {
            $blob = $id . ' ' . ($app['name'] ?? '') . ' ' . ($app['ports'] ?? '') . ' ' . ($app['label'] ?? '');
            if (str_contains(strtolower($blob), $ql)) {
                $hits[] = ['type' => 'app', 'title' => ($app['name'] ?? $app['label'] ?? $id), 'href' => '?p=apps', 'why' => 'porte software'];
            }
        }
    }
    echo '<p><b>' . count($hits) . '</b> risultati per «' . h($q) . '»</p>';
    if (!$hits) echo '<p class=mut>Nessun risultato.</p>';
    else {
        echo '<table><tr><th>Tipo</th><th>Risultato</th><th></th></tr>';
        foreach ($hits as $h) {
            echo '<tr><td class=mut>' . h($h['type']) . '</td><td><code data-iptm-layout="ui-092af903b2">' . h(substr($h['title'], 0, 200)) . '</code></td>'
                . '<td><a class="btn s" href="' . h($h['href']) . '">Apri</a></td></tr>';
        }
        echo '</table>';
    }
    echo '</div>';
}

/** Il banner di reset viene chiuso con un marker anche se il file originale non è eliminabile. */
function reset_notice_is_dismissed(): bool {
    $flag = DATA_DIR . '/post-update-reset.flag';
    $dismissed = DATA_DIR . '/post-update-reset.dismissed';
    if (!is_file($flag)) return true;
    $id = trim((string)@file_get_contents($flag));
    return $id !== '' && is_file($dismissed) && hash_equals(trim((string)@file_get_contents($dismissed)), $id);
}
function reset_notice_dismiss(): bool {
    $flag = DATA_DIR . '/post-update-reset.flag';
    if (!is_file($flag)) return true;
    $id = trim((string)@file_get_contents($flag));
    if ($id === '') $id = (string)@filemtime($flag);
    $tmp = DATA_DIR . '/.post-update-reset-dismissed.' . bin2hex(random_bytes(5));
    if (@file_put_contents($tmp, $id . "\n", LOCK_EX) === false) { @unlink($tmp); return false; }
    @chmod($tmp, 0600);
    if (!@rename($tmp, DATA_DIR . '/post-update-reset.dismissed')) { @unlink($tmp); return false; }
    @unlink($flag);
    return true;
}
/** Stato persistente della notifica: non dipende dai cookie/sessioni del browser. */
function update_notice_seen_version(): string {
    static $cached = null;
    if ($cached !== null) return $cached;
    // La directory dati può essere root-only: delega anche la lettura all'helper privilegiato.
    [$c, $o] = priv('notice-status');
    $v = $c === 0 ? trim($o) : '';
    return $cached = (preg_match('/^\d+(?:\.\d+){1,3}$/', $v) ? $v : '');
}
function update_notice_mark_seen(string $version): bool {
    if (!preg_match('/^\d+(?:\.\d+){1,3}$/', $version)) return false;
    // DATA_DIR può essere root-owned o personalizzata: scrittura atomica tramite helper privilegiato.
    [$c] = priv('notice-ack', null, [$version]);
    return $c === 0;
}
/** Estende runtime_chain con prefissi da conf (RUNTIME_CHAINS=IOT_,FOO_). */
function runtime_chain_conf_prefixes(): array {
    static $p = null;
    if ($p !== null) return $p;
    $p = [];
    $c = @file_get_contents('/etc/iptables-manager.conf') ?: '';
    if (preg_match('/^RUNTIME_CHAINS="([^"]*)"/m', $c, $m)) {
        foreach (preg_split('/[\s,]+/', $m[1]) ?: [] as $x) {
            $x = trim($x);
            if ($x !== '') $p[] = $x;
        }
    }
    return $p;
}


/** Estrae dal kernel le catene/regole runtime e le innesta nel testo da applicare. */
function rules_inject_runtime(string $txt, ?string $kernel = null): array {
    if ($kernel === null) {
        [$sc, $kernel] = priv('save');
        if ($sc !== 0 || trim((string)$kernel) === '') return [$txt, [], 'kernel non leggibile'];
    }
    $K = parse_rules($kernel);
    $D = parse_rules($txt);
    $added = [];
    // mappa table -> items del draft
    $dt = [];
    foreach ($D as $i => $b) {
        if (($b['k'] ?? '') === 'table') $dt[$b['name']] = $i;
    }
    foreach ($K as $kb) {
        if (($kb['k'] ?? '') !== 'table') continue;
        $tn = $kb['name'];
        // raccogli catene runtime e regole associate
        $rtChains = [];
        $rtRules = []; // chain => [rules]
        $jumps = []; // built-in chain rules that jump to runtime
        foreach ($kb['items'] as $it) {
            if ($it['t'] === 'chain' && runtime_chain($it['n'])) {
                $rtChains[$it['n']] = $it;
            }
            if ($it['t'] === 'rule' && !empty($it['on'])) {
                $ch = rchain($it['r']);
                if (runtime_chain($ch)) {
                    $rtRules[$ch][] = $it['r'];
                } elseif (preg_match('/\s-j\s+(\S+)/', $it['r'], $m) && runtime_chain($m[1])) {
                    // jump da catena normale verso runtime (DOCKER-USER, CROWDSEC, IOT_DNS…)
                    $jumps[] = $it['r'];
                } elseif (function_exists('runtime_rule') && runtime_rule($it['r'])) {
                    $jumps[] = $it['r'];
                }
            }
        }
        if (!$rtChains && !$jumps) continue;
        if (!isset($dt[$tn])) {
            // crea tabella vuota nel draft
            $D[] = ['k' => 'table', 'name' => $tn, 'items' => []];
            $dt[$tn] = count($D) - 1;
        }
        $di = $dt[$tn];
        $haveChain = [];
        $haveRule = [];
        foreach ($D[$di]['items'] as $it) {
            if ($it['t'] === 'chain') $haveChain[$it['n']] = 1;
            if ($it['t'] === 'rule' && !empty($it['on'])) $haveRule[rules_normalize_line($it['r'])] = 1;
        }
        foreach ($rtChains as $n => $it) {
            if (empty($haveChain[$n])) {
                $D[$di]['items'][] = ['t' => 'chain', 'n' => $n, 'p' => $it['p'] ?? '-'];
                $haveChain[$n] = 1;
                $added[] = "$tn:$n (catena)";
            }
            foreach ($rtRules[$n] ?? [] as $raw) {
                $key = rules_normalize_line($raw);
                if (isset($haveRule[$key])) continue;
                $D[$di]['items'][] = ['t' => 'rule', 'r' => $raw, 'on' => true];
                $haveRule[$key] = 1;
                $added[] = "$tn:" . cut40($raw);
            }
        }
        foreach ($jumps as $raw) {
            $key = rules_normalize_line($raw);
            if (isset($haveRule[$key])) continue;
            $D[$di]['items'][] = ['t' => 'rule', 'r' => $raw, 'on' => true];
            $haveRule[$key] = 1;
            $added[] = "$tn:jump " . cut40($raw);
        }
    }
    if (!$added) return [$txt, [], ''];
    $out = function_exists('ser') ? ser($D) : $txt;
    return [$out, $added, ''];
}

/** Notifica eventi conntrack se configurati. */
function ops_notify_watch(): void {
    if (!function_exists('notify')) return;
    $c = notify_cfg();
    $ev = $c['ev'] ?? [];
    // conntrack alto
    if (in_array('ct_high', $ev, true)) {
        $ct = (int)@file_get_contents('/proc/sys/net/netfilter/nf_conntrack_count');
        $mx = max(1, (int)@file_get_contents('/proc/sys/net/netfilter/nf_conntrack_max'));
        if ($ct / $mx >= 0.85) {
            $lock = DATA_DIR . '/.notify_ct';
            $last = is_file($lock) ? (int)@file_get_contents($lock) : 0;
            if (time() - $last > 1800) {
                notify('ct_high', "Conntrack al " . round(100 * $ct / $mx) . "% ($ct / $mx)");
                atomic_data_write($lock, (string)time(), 0600);
            }
        }
    }
}

// Operational summaries integrated from the useful concepts of CrowdSec Manager,
// EveBox, Scirius and Cockpit. All data is local, bounded and escaped.
function iptm_operator_insights(string $mode): void {
    if (!in_array($mode, ['crowdsec','suricata','network'], true)) return;
    [$code, $output] = priv('operator-insights', null, [$mode]);
    $data = $code === 0 ? json_decode($output, true) : null;
    echo '<section class="card iptm-insights"><h3>Centro operativo · '.h(ucfirst($mode)).'</h3>';
    if (!is_array($data) || empty($data['ok']) || empty($data['available'])) {
        echo '<p class="mut">Dati locali non disponibili. Nessuna modifica eseguita.</p></section>';return;
    }
    if ($mode === 'crowdsec') {
        echo '<div class="tiles">'.tile('Decisioni', isset($data['decisions_count'])?(string)(int)$data['decisions_count']:'—','Decisioni correnti')
             .tile('Avvisi',isset($data['alerts_count'])?(string)(int)$data['alerts_count']:'—','Alert recenti').'</div>';
        foreach (['scenarios'=>'Scenari principali','origins'=>'Origini decisioni'] as $key=>$heading) {
            echo '<h4>'.h($heading).'</h4><table><tr><th>Categoria</th><th>Numero</th></tr>';
            foreach (array_slice((array)($data[$key]??[]),0,8) as $pair) {
                if (!is_array($pair)||count($pair)!==2)continue;
                echo '<tr><td>'.h((string)$pair[0]).'</td><td>'.(int)$pair[1].'</td></tr>';
            }
            echo '</table>';
        }
    } elseif ($mode === 'suricata') {
        echo '<p>Eventi EVE analizzati: <b>'.(int)($data['events']??0).'</b> · righe non valide: '.(int)($data['invalid_lines']??0).'</p>';
        foreach (['top_sids'=>'SID più frequenti','categories'=>'Categorie degli avvisi','hour_buckets'=>'Andamento orario'] as $key=>$heading) {
            echo '<h4>'.h($heading).'</h4><table><tr><th>Gruppo</th><th>Alert</th></tr>';
            foreach (array_slice((array)($data[$key]??[]),0,12) as $pair) {
                if (!is_array($pair)||count($pair)!==2)continue;
                echo '<tr><td>'.h((string)$pair[0]).'</td><td>'.(int)$pair[1].'</td></tr>';
            }
            echo '</table>';
        }
    } elseif ($mode === 'network') {
        echo '<p class="mut">Rilevamento locale NetworkManager; nessun segreto esportato. Le attivazioni restano protette dai checkpoint D-Bus.</p>';
        echo '<div data-iptm-layout="scroll"><table><tr><th>Scheda</th><th>Tipo</th><th>Stato</th></tr>';
        foreach (array_slice((array)($data['devices']??[]),0,128) as $dev) {
            if (!is_array($dev))continue;
            echo '<tr><td>'.h((string)($dev['device']??'')).'</td><td>'.h((string)($dev['type']??'')).'</td><td>'.h((string)($dev['state']??'')).'</td></tr>';
        }
        echo '</table></div>';
    }
    echo '</section>';
}
