<?php
// ===================== v3: PAGINE =====================
function pg_apply_extra() {
    global $M; $R = dyn_report($M); $pc = post_conf();
    $hasS = is_file(DATA_DIR . '/settings.json'); $hasReg = str_contains(ser($M), '# >>> IPTM:');
    if ($hasS && $hasReg) {
        $M2 = $M; regen($M2, S_get());
        if (!rules_equiv(ser($M2), ser($M))) { [$ad, $rm] = model_delta(ser($M), ser($M2)); echo '<div class="msg err">⚠ La bozza contiene blocchi gestiti che NON corrispondono alle impostazioni salvate (rigenerandoli: +' . $ad . ' / −' . $rm . ' regole). Un «Salva» nelle pagine di impostazioni li sovrascriverebbe: controlla prima la differenza qui sotto.<form method=post data-iptm-layout="mt8">' . fh('p=apply') . '<input type=hidden name=action value=regen_now><button class=s>↻ Rigenera la bozza dalle impostazioni</button></form></div>'; }
    } elseif ($hasS && !$hasReg && gen_sections(S_get())[0]) {
        echo '<div class="msg err">⚠ Le impostazioni gestite esistono ma la bozza/il file non contiene i blocchi generati (forse hai scartato la bozza dopo l\'importazione). Un «Salva» verrebbe rifiutato per proteggere le tue regole. Per riallineare: Importa regole → «Azzera impostazioni» e reimporta.</div>';
    }
    echo '<div class=card><h3>Cosa succede alle regole create da altri programmi</h3><p class=mut>Caricare un file sostituisce <b>tutte</b> le tabelle: ciò che Docker, CrowdSec, fail2ban o i tuoi script aggiungono a runtime sparisce finché non viene ricreato. Dopo ogni applicazione l\'helper riavvia i servizi e lancia lo script indicati qui sotto: se mancano, i client perdono la connessione.</p>';
    if (!$R['ok']) echo '<p class=mut>Stato del kernel non leggibile.</p>';
    elseif (!$R['chains'] && !$R['hooks']) echo '<p>✅ Nel kernel non risulta nulla che manchi dalla bozza.</p>';
    else {
        echo '<table><tr><th>Catena creata a runtime</th><th>Regole</th><th>Gestita da</th></tr>'; $sug = [];
        foreach ($R['chains'] as $c => $x) { echo '<tr><td>' . h($c) . ' <small class=mut>(' . h($x['t']) . ')</small></td><td>' . $x['n'] . '</td><td>' . ($x['owner'] ? h($x['owner']) : '<span class=mut>sconosciuto</span>') . '</td></tr>'; if ($x['owner']) $sug[$x['owner']] = 1; }
        echo '</table>' . ($R['hooks'] ? '<p>Inoltre <b>' . $R['hooks'] . '</b> regole nelle catene principali (agganci a runtime) non sono nella bozza.</p>' : '');
        $cache = is_file(DATA_DIR . '/suggest.json') ? (json_decode((string)file_get_contents(DATA_DIR . '/suggest.json'), true) ?: []) : []; $scr = $cache['scripts'] ?? []; foreach ($cache['services'] ?? [] as $sv) $sug[$sv] = 1;
        $miss = array_diff(array_keys($sug), preg_split('/\s+/', trim($pc['services']), -1, PREG_SPLIT_NO_EMPTY), ['crowdsec-firewall-bouncer', 'fail2ban']);   // questi due li riavvia sempre l'helper dopo «Applica»
        if ($miss || ($scr && $pc['script'] === '')) echo '<div class="msg ok">ℹ Suggerimento: altri servizi da riavviare dopo l\'applicazione (aggiungili nel campo qui sotto): <b>' . h(implode(' ', $miss) ?: '—') . '</b>' . ($scr && $pc['script'] === '' ? '<br>Script che citano queste catene: <code>' . h(implode(' · ', array_slice($scr, 0, 4))) . '</code>' : '') . '</div>';
    }
    echo '<form method=post class=row>' . fh('p=apply') . '<input type=hidden name=action value=post_set><label class=fl><span>Servizi da riavviare dopo «Applica»</span><input name=services value="' . h($pc['services']) . '" placeholder="docker crowdsec-firewall-bouncer"><small>Nomi delle unità systemd, separati da spazio.</small></label>
<label class=fl><span>Script da eseguire dopo «Applica»</span><input name=script value="' . h($pc['script']) . '" placeholder="/usr/local/bin/iot-firewall.sh"><small>Percorso assoluto; deve essere di root e non scrivibile da altri.</small></label>
<div class=fl><span>&nbsp;</span><span class=ops data-iptm-layout="ui-491198ddb7"><button>💾 Salva</button><button class=s name=action value=post_test>▶ Esegui ora</button><button class=s name=action value=post_scan title="Cerca gli script che citano queste catene (qualche secondo)">🔎 Cerca script</button></span></div></form></div>';
}

function cs_info(): array {
    return kc('csinfo', function () {
        $r = ['installed' => false, 'version' => '', 'agent' => '', 'bouncer' => '', 'agent_enabled' => '', 'bouncer_enabled' => '', 'bouncer_mode' => '', 'ipsets' => '', 'helper' => 'ok'];
        try {
            [$c, $o, $e] = priv('cs-info');
            if ($c !== 0) {
                // helper vecchio senza cs-info: prova rilevamento minimale
                $r['helper'] = 'old';
                if (is_file('/usr/bin/cscli') || is_file('/usr/local/bin/cscli')) $r['installed'] = true;
                return $r;
            }
            foreach (explode("\n", trim($o)) as $l) {
                $x = preg_split('/\s+/', trim($l), 2); if (count($x) < 2) continue;
                if ($x[0] === 'installed') $r['installed'] = ($x[1] === 'yes');
                elseif (array_key_exists($x[0], $r) || in_array($x[0], ['version', 'agent', 'bouncer', 'agent_enabled', 'bouncer_enabled', 'bouncer_mode', 'ipsets'], true)) $r[$x[0]] = $x[1];
            }
        } catch (Throwable $ex) {
            $r['helper'] = 'err';
        }
        return $r;
    });
}
function pg_crowdsec() {
    $S = S_get(); $ro = ($_SESSION['role'] ?? 'viewer') === 'viewer';
    $info = ['installed' => false, 'version' => '', 'agent' => '', 'bouncer' => '', 'agent_enabled' => '', 'bouncer_enabled' => '', 'bouncer_mode' => '', 'ipsets' => '', 'helper' => 'ok'];
    try { $info = array_merge($info, cs_info()); } catch (Throwable $ex) { $info['helper'] = 'err'; }
    $tab = (string)($_GET['t'] ?? 'stato'); if (!in_array($tab, ['stato', 'decisioni', 'collezioni', 'allowlist', 'metriche', 'acquis', 'logaudit', 'firewall', 'avanzate', 'ecosistema'], true)) $tab = 'stato';
    echo '<div class="tiles iptm-crowdsec-metrics">'
        . tile('CrowdSec agent', h($info['agent'] ?: 'n/d'), 'Motore di analisi degli eventi', $info['agent'] === 'active' ? 'ok' : 'warn')
        . tile('Firewall bouncer', h($info['bouncer'] ?: 'n/d'), 'Applicazione delle decisioni', $info['bouncer'] === 'active' ? 'ok' : 'warn')
        . tile('Modalità', h($info['bouncer_mode'] ?: 'n/d'), 'Integrazione firewall', '')
        . '</div>';
    echo '<section class="card iptm-crowdsec-workspace"><h2>CrowdSec</h2><p class="mut">Analisi eventi, decisioni e sorgenti log. I componenti firewall si configurano anche in <a href="?p=security">Firewall → Policy</a>.</p>';
    if (($info['helper'] ?? '') === 'old') {
        echo '<div class="msg err">Helper di sistema non aggiornato (manca <code>cs-info</code>). Aggiorna anche <code>iptm-helper</code> con lo stesso zip della release corrente.</div>';
    }
    if (!$info['installed']) {
        echo '<div class="msg err">CrowdSec non risulta installato. Vai in <a href="?p=progs">Strumenti → Programmi</a> e installa «CrowdSec + bouncer».</div></section>';
        return;
    }
    $pill = function ($id, $label) use ($tab) {
        return '<a class="' . ($tab === $id ? 'on' : '') . '" href="?p=crowdsec&t=' . $id . '">' . $label . '</a>';
    };
    echo '<nav class="tabs iptm-crowdsec-tabs" aria-label="Funzioni CrowdSec">' . $pill('stato', 'Stato') . $pill('decisioni', 'Decisioni') . $pill('collezioni', 'Collezioni') . $pill('allowlist', 'Allowlist') . $pill('metriche', 'Metriche') . $pill('acquis', 'Sorgenti log') . $pill('logaudit', 'Analisi parser log') . $pill('firewall', 'Firewall') . $pill('avanzate', 'Regole avanzate') . $pill('ecosistema', 'Integrazioni') . '</nav>';

    if ($tab === 'ecosistema') {
        if(!$ro){
            echo '<section class="card"><h3>Importazione multipla feed CrowdSec</h3><p class="mut">Scarica fino a 8 feed HTTPS approvati, deduplica IP/CIDR ed esclude indirizzi non pubblici. Le decisioni richiedono una conferma SHA-256 separata e hanno durata limitata.</p>';
            echo '<form method="post">'.fh('p=crowdsec&t=ecosistema').'<input type="hidden" name="action" value="cs_feed_stage">';
            echo '<label>URL HTTPS (uno per riga)<textarea name="feed_urls" rows="5" required maxlength="2000" placeholder="https://raw.githubusercontent.com/.../feed.txt"></textarea></label>';
            echo '<label>Durata<select name="feed_duration"><option>1h</option><option selected>4h</option><option>12h</option><option>24h</option><option>48h</option></select></label><button class="s">Scarica, filtra e prepara anteprima</button></form>';
            $feed=$_SESSION['iptm_feed_plan']??null;
            if(is_array($feed)&&time()-(int)($feed['created']??0)<900){
                $hash=(string)($feed['sha256']??'');
                echo '<form method="post">'.fh('p=crowdsec&t=ecosistema').'<input type="hidden" name="action" value="cs_feed_apply"><input type="hidden" name="feed_hash" value="'.h($hash).'"><p><b>'.(int)($feed['total']??0).' IP/CIDR</b> · SHA-256: <code>'.h($hash).'</code></p><button class="g">Conferma importazione cscli</button></form>';
            }
            echo '</section>';
        }

        [$intRc, $intOut] = priv('security-integrations');
        $int = $intRc === 0 ? json_decode($intOut, true) : null;
        if (is_array($int) && isset($int['capabilities'])) {
            echo '<h4>Rilevamento locale componenti</h4><table><tr><th>Componente</th><th>Binario locale</th></tr>';
            foreach (['crowdsec'=>'CrowdSec CLI','suricata'=>'Suricata','suricata_update'=>'suricata-update','evebox'=>'EveBox','crowdsec_manager'=>'CrowdSec Manager','crowdsec_blocklist_import'=>'Blocklist import'] as $key=>$label) {
                echo '<tr><td>'.h($label).'</td><td>'.(!empty($int['capabilities'][$key])?'presente':'non rilevato').'</td></tr>';
            }
            echo '</table>';
        }

        [$bridgeRc, $bridgeOut] = priv('integration-status');
        $bridge = $bridgeRc === 0 ? json_decode($bridgeOut, true) : null;
        if (is_array($bridge)) {
            echo '<h3>Stato operativo locale</h3><table><tr><th>Servizio</th><th>Controllo</th></tr>';
            foreach (['crowdsec'=>'cscli', 'suricata'=>'suricata', 'networkmanager'=>'installed'] as $service=>$property) {
                echo '<tr><td>'.h($service).'</td><td>'.(!empty($bridge[$service][$property])?'rilevato':'non disponibile').'</td></tr>';
            }
            echo '</table><p class=mut>Feed: staging da console root, importazione con conferma SHA-256, scadenza temporale, protezione reti locali. Nessun download automatico.</p>';
        }
        echo '<h3>Estensioni CrowdSec · integrazione verificabile</h3>';
        echo '<p class="mut">L\'interfaccia IPTM mantiene il controllo su cscli e bouncer iptables. Questi progetti sono opzionali e non sono installati o eseguiti automaticamente.</p>';
        echo '<table><tr><th>Progetto</th><th>Funzionalità</th><th>Modalità sicura IPTM</th></tr>';
        echo '<tr><td><a target="_blank" rel="noopener noreferrer" href="https://github.com/hhftechnology/crowdsec_manager">CrowdSec Manager</a></td><td>Dashboard, decisioni, alert, allowlist, scenari, hub</td><td>Frontend alternativo; nessun secondo writer sulle policy firewall senza audit</td></tr>';
        echo '<tr><td><a target="_blank" rel="noopener noreferrer" href="https://github.com/wolffcatskyy/crowdsec-blocklist-import">crowdsec-blocklist-import</a></td><td>Feed IP, deduplica, sincronizzazione</td><td>Importazione solo su richiesta, anteprima, esclusione LAN/management, backup e scadenza decisioni</td></tr></table>';
        echo '<p class="mut">Prima di importare feed massivi: verifica licenze, memoria e dimensione degli ipset, disponibilità di cscli, e che il bouncer non blocchi la rete di gestione. I feed non vengono applicati da questa pagina.</p>';
    }

    if ($tab === 'stato' || $tab === 'metriche') (function_exists('iptm_operator_insights') ? iptm_operator_insights('crowdsec') : null);

    if ($tab === 'stato') {
        $badge = fn($s) => $s === 'active' ? '<span class="b b-ACCEPT">active</span>' : '<span class="b b-DROP">' . h($s ?: '?') . '</span>';
        echo '<h3>Servizi</h3><table><tr><th>Componente</th><th>Stato</th><th>Abilitato</th></tr>';
        echo '<tr><td>Agent (crowdsec)</td><td>' . $badge($info['agent']) . '</td><td>' . h($info['agent_enabled']) . '</td></tr>';
        echo '<tr><td>Bouncer firewall</td><td>' . $badge($info['bouncer']) . '</td><td>' . h($info['bouncer_enabled']) . '</td></tr></table>';
        echo '<p class=mut>Versione: <b>' . h($info['version'] ?: '—') . '</b> · Mode bouncer: <b>' . h($info['bouncer_mode'] ?: '—') . '</b> · ipset: <code>' . h($info['ipsets'] ?: '—') . '</code></p>';
        if (!$ro) {
            echo '<form method=post class=ops>' . fh('p=crowdsec&t=stato') . '<input type=hidden name=action value=cs_svc>';
            echo sel('act', ['restart' => 'Riavvia', 'reload' => 'Ricarica', 'start' => 'Avvia', 'stop' => 'Ferma'], 'restart') . ' ';
            echo sel('tgt', ['both' => 'Agent + bouncer', 'agent' => 'Solo agent', 'bouncer' => 'Solo bouncer'], 'both');
            echo ' <button class=s>Esegui</button></form>';
            echo '<form method=post class=ops data-iptm-layout="mt8">' . fh('p=crowdsec&t=stato') . '<input type=hidden name=action value=cs_hub_update><button class=g>Aggiorna hub CrowdSec</button></form>';
            echo '<form method=post class=ops data-iptm-layout="mt8">' . fh('p=crowdsec&t=stato') . '<input type=hidden name=action value=cs_bouncer_setup_rec><button class=g>⚙ Preset bouncer (INPUT+FORWARD+DOCKER-USER)</button></form>';
            echo '<p class=mut>Il preset scrive <code>mode: iptables</code>, le catene consigliate (incluso DOCKER-USER se presente) e riavvia agent+bouncer.</p>';
        }
        [, $bo] = priv('cs-bouncers');
        echo '<h3>Bouncers registrati</h3><pre>' . h(trim($bo) !== '' ? $bo : '(nessuno o output non disponibile)') . '</pre>';
        [, $cs] = priv('cs-status');
        if (trim($cs) !== '') echo '<h3>Catena / set (cs-status)</h3><pre>' . h($cs) . '</pre>';
    }

    if ($tab === 'decisioni') {
        $dec = cs_decisions();
        if (!$ro) {
            echo '<form method=post class=ops>' . fh('p=crowdsec&t=decisioni') . '<input type=hidden name=from_cs value=1><input type=hidden name=action value=cs_ban>';
            echo '<input name=ip placeholder="IP o CIDR" required data-iptm-layout="mw200"> <input name=dur value="4h" data-iptm-layout="mw80" pattern="[0-9]{1,5}[smhd]" title="es. 4h, 30m, 2d"> <button class=d>Banna</button></form>';
        }
        echo '<div data-iptm-layout="scroll"><table><tr><th>IP</th><th>Origine</th><th>Motivo</th><th>Azione</th><th>Scade</th><th></th></tr>';
        foreach (array_slice($dec, 0, 150) as $d) {
            echo '<tr><td>' . h($d['ip']) . '</td><td>' . h($d['src']) . '</td><td>' . h($d['reason']) . '</td><td>' . h($d['action']) . '</td><td>' . h($d['exp']) . '</td><td>';
            if (!$ro) echo '<form method=post class=ops>' . fh('p=crowdsec&t=decisioni') . '<input type=hidden name=from_cs value=1><input type=hidden name=action value=cs_unban><input type=hidden name=ip value="' . h($d['ip']) . '"><button class="s sm">Rimuovi</button></form>';
            echo '</td></tr>';
        }
        echo '</table></div>' . ($dec ? '' : '<p class=mut>Nessuna decisione attiva.</p>');
    }

    if ($tab === 'collezioni') {
        [, $col] = priv('cs-collections');
        $suggested = ['crowdsecurity/linux', 'crowdsecurity/sshd', 'crowdsecurity/iptables', 'crowdsecurity/http-cve', 'crowdsecurity/nginx', 'crowdsecurity/apache2', 'crowdsecurity/base-http-scenarios', 'crowdsecurity/http-dos'];
        echo '<p class=mut>Le collezioni raggruppano parser e scenari. Dopo install/rimozione l\'agent viene ricaricato.</p>';
        if (!$ro) {
            echo '<form method=post class=ops>' . fh('p=crowdsec&t=collezioni') . '<input type=hidden name=action value=cs_collection_install>';
            echo '<input name=name list=cscols placeholder="crowdsecurity/sshd" required data-iptm-layout="ui-0b5f5d0c43"> <button class=g>Installa collezione</button></form>';
            echo '<datalist id=cscols>'; foreach ($suggested as $s) echo '<option value="' . h($s) . '">'; echo '</datalist>';
            echo '<p class=mut>Suggerite: ' . implode(', ', array_map(fn($s) => '<code>' . h($s) . '</code>', $suggested)) . '</p>';
        }
        echo '<h3>Collezioni installate</h3><pre>' . h(trim($col) !== '' ? $col : '(nessuna o cscli non risponde)') . '</pre>';
        if (!$ro && trim($col) !== '') {
            // try to extract names for remove buttons from raw lines
            $names = [];
            foreach (explode("\n", $col) as $line) {
                if (preg_match('#(crowdsecurity/[A-Za-z0-9_.-]+|[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)#', $line, $m)) $names[$m[1]] = 1;
            }
            if ($names) {
                echo '<h3>Rimuovi</h3><div class=ops style="flex-wrap:wrap;display:flex;gap:6px">';
                foreach (array_keys($names) as $n) {
                    echo '<form method=post>' . fh('p=crowdsec&t=collezioni') . '<input type=hidden name=action value=cs_collection_remove><input type=hidden name=name value="' . h($n) . '"><button class="s sm">' . h($n) . '</button></form>';
                }
                echo '</div>';
            }
        }
        [, $sc] = priv('cs-scenarios');
        echo '<h3>Scenari</h3><pre data-iptm-layout="ui-dd2ca23bad">' . h(trim($sc) !== '' ? $sc : '—') . '</pre>';
    }

    if ($tab === 'logaudit') {
        echo '<h3>Integrazioni log CrowdSec — inventario read-only</h3>';
        echo '<p class=mut>Confronta i log esistenti con collezioni ufficiali del CrowdSec Hub. Il risultato non garantisce che un parser sia installato né modifica acquisizioni. Prima di installare verifica la disponibilità con <code>cscli collections list -a</code>.</p>';
        [$rc, $output, $err] = priv('cs-log-discover');
        $audit = $rc === 0 ? json_decode($output, true) : null;
        if (!is_array($audit) || empty($audit['ok'])) {
            echo '<div class="msg err">Inventario non disponibile: '.h(trim($err ?: $output)).'</div>';
        } else {
            echo '<p>Catalogo Hub locale: <b>'.h($audit['hub_status'] ?? 'non disponibile').'</b>.</p><table><tr><th>Servizio</th><th>Log presente</th><th>Collezione ufficiale</th><th>Stato Hub</th></tr>';
            foreach ((array)($audit['sources'] ?? []) as $r) {
                $coll=(string)($r['collection'] ?? '');
                $state=!empty($r['collection_installed'])?'Installata':(!empty($r['collection_available_locally'])?'Disponibile (non installata)':'Non verificata localmente');
                echo '<tr><td>'.h($r['service']??'').'</td><td>'.h(implode(', ',(array)($r['paths']??[])) ?: ($r['journal_hint']??'Non individuato')).'</td><td><code>'.h($coll).'</code></td><td>'.h($state).'</td></tr>';
            }
            echo '</table><p class=mut>Nessuna collezione è installata automaticamente. Per ogni sorgente verifica prima il formato effettivo dei log e l’acquisizione CrowdSec corrispondente.</p>';
        }
    }

    if ($tab === 'allowlist') {
        [, $al] = priv('cs-allowlist');
        if (!$ro) {
            echo '<form method=post class=ops>' . fh('p=crowdsec&t=allowlist') . '<input type=hidden name=action value=cs_allow_add>';
            echo '<input name=ip placeholder="IP o CIDR da non bannare mai" required data-iptm-layout="mw220"> <input name=dur value="8760h" data-iptm-layout="mw80" pattern="[0-9]{1,5}[smhd]"> <button class=g>Aggiungi allow</button></form>';
            echo '<p class=mut>Durata predefinita 8760h ≈ 1 anno. Utile per la tua WAN/VPN o scanner di monitoraggio.</p>';
        }
        echo '<h3>Allowlist / decisioni allow</h3><pre>' . h(trim($al) !== '' ? $al : '(vuota)') . '</pre>';
        if (!$ro) {
            echo '<form method=post class=ops>' . fh('p=crowdsec&t=allowlist') . '<input type=hidden name=action value=cs_allow_del>';
            echo '<input name=ip placeholder="IP da togliere" required data-iptm-layout="mw200"> <button class=s>Rimuovi allow</button></form>';
        }
    }

    if ($tab === 'metriche') {
        [, $met] = priv('cs-metrics');
        [, $alr] = priv('cs-alerts');
        echo '<h3>Metriche</h3><pre data-iptm-layout="ui-73faaab036">' . h(trim($met) !== '' ? $met : '—') . '</pre>';
        echo '<h3>Alert recenti</h3><pre data-iptm-layout="ui-73faaab036">' . h(trim($alr) !== '' ? $alr : '—') . '</pre>';
    }

    if ($tab === 'acquis') {
        [, $acq] = priv('cs-acquis');
        echo '<p class=mut>Sorgenti di acquisizione log (journald, file, …). Modifica avanzata via SSH; da Programmi → CrowdSec viene creato <code>acquis.d/iptm-kernel.yaml</code> per i log del kernel.</p>';
        echo '<pre data-iptm-layout="ui-1ebb464fcb">' . h(trim($acq) !== '' ? $acq : '(nessun file leggibile)') . '</pre>';
    }

    if ($tab === 'avanzate') {
        $recommended = [
            'crowdsecurity/linux' => 'Base Linux (SSH, sudo…)',
            'crowdsecurity/iptables' => 'Log iptables / kernel',
            'crowdsecurity/http-cve' => 'CVE HTTP noti',
            'crowdsecurity/nginx' => 'Nginx',
            'crowdsecurity/apache2' => 'Apache',
            'crowdsecurity/sshd' => 'SSH dedicato',
            'crowdsecurity/postfix' => 'Postfix / mail',
            'crowdsecurity/mysql' => 'MySQL / MariaDB',
        ];
        if (!$ro) {
            echo '<h3>Collezioni consigliate</h3><p class=mut>Installa con un click. Poi usa «Hub upgrade» per aggiornare gli scenari.</p><div class=ops style="flex-wrap:wrap;display:flex;gap:6px;margin-bottom:12px">';
            foreach ($recommended as $id => $label) {
                echo '<form method=post>' . fh('p=crowdsec&t=avanzate') . '<input type=hidden name=action value=cs_collection_install><input type=hidden name=name value="' . h($id) . '"><button class="s sm" title="' . h($id) . '">' . h($label) . '</button></form>';
            }
            echo '</div>';
            echo '<form method=post class=ops>' . fh('p=crowdsec&t=avanzate') . '<input type=hidden name=action value=cs_hub_upgrade><button class=g>Hub update + upgrade scenari</button></form>';
        }
        [, $sc] = priv('cs-scenarios');
        echo '<h3>Scenari installati</h3><pre data-iptm-layout="ui-1934322bc0">' . h(trim($sc) !== '' ? $sc : '—') . '</pre>';
        if (!$ro) {
            echo '<div class=row><form method=post class=ops>' . fh('p=crowdsec&t=avanzate') . '<input type=hidden name=action value=cs_scenario_enable>';
            echo '<input name=name placeholder="crowdsecurity/ssh-bf" required data-iptm-layout="ui-63b0844a71"> <button class=g>Abilita scenario</button></form>';
            echo '<form method=post class=ops>' . fh('p=crowdsec&t=avanzate') . '<input type=hidden name=action value=cs_scenario_disable>';
            echo '<input name=name placeholder="crowdsecurity/ssh-bf" required data-iptm-layout="ui-63b0844a71"> <button class=s>Disabilita scenario</button></form></div>';
            echo '<p class=mut>Nome hub completo, es. <code>crowdsecurity/ssh-bf</code>.</p>';
        }
        [, $par] = priv('cs-parsers');
        echo '<h3>Parsers / postoverflows</h3><pre data-iptm-layout="ui-63246f7e21">' . h(trim($par) !== '' ? $par : '—') . '</pre>';
        [, $bg] = priv('cs-bouncer-get');
        $bcfg = [];
        foreach (explode("\n", trim($bg)) as $l) {
            $x = preg_split('/\s+/', trim($l), 2);
            if (count($x) >= 2 && $x[0] !== '###') $bcfg[$x[0]] = $x[1];
        }
        echo '<h3>Impostazioni bouncer firewall</h3><table><tr><th>Chiave</th><th>Valore</th></tr>';
        foreach (['mode', 'deny_action', 'deny_log', 'update_frequency', 'iptables_chains', 'blacklists_ipv4', 'blacklists_ipv6'] as $k) {
            echo '<tr><td><code>' . h($k) . '</code></td><td>' . h($bcfg[$k] ?? '—') . '</td></tr>';
        }
        echo '</table>';
        if (!$ro) {
            echo '<form method=post class=row data-iptm-layout="mt10">' . fh('p=crowdsec&t=avanzate') . '<input type=hidden name=action value=cs_bouncer_set><input type=hidden name=key value=deny_action>';
            echo '<label class=fl><span>Azione di blocco</span>' . sel('val', ['DROP' => 'DROP (silenzioso)', 'REJECT' => 'REJECT (avvisa)', 'TARPIT' => 'TARPIT'], $bcfg['deny_action'] ?? 'DROP') . '</label>';
            echo '<div class=fl><span>&nbsp;</span><button class=g>Applica deny_action</button></div></form>';
            echo '<form method=post class=row>' . fh('p=crowdsec&t=avanzate') . '<input type=hidden name=action value=cs_bouncer_set><input type=hidden name=key value=deny_log>';
            echo '<label class=fl><span>Log dei blocchi</span>' . sel('val', ['true' => 'Attivo', 'false' => 'Disattivo'], $bcfg['deny_log'] ?? 'false') . '</label>';
            echo '<div class=fl><span>&nbsp;</span><button class=s>Applica deny_log</button></div></form>';
            echo '<form method=post class=row>' . fh('p=crowdsec&t=avanzate') . '<input type=hidden name=action value=cs_bouncer_set><input type=hidden name=key value=update_frequency>';
            echo '<label class=fl><span>Frequenza aggiornamento set</span><input name=val value="' . h($bcfg['update_frequency'] ?? '10s') . '" pattern="[0-9]{1,4}[smh]" data-iptm-layout="ui-48a49aa0a8"></label>';
            echo '<div class=fl><span>&nbsp;</span><button class=s>Applica update_frequency</button></div></form>';
        }
        [, $sim] = priv('cs-simulation', null, ['status']);
        echo '<h3>Modalità simulazione</h3><p class=mut>In simulazione CrowdSec rileva e registra ma <b>non banna</b>.</p>';
        echo '<pre>' . h(trim($sim) !== '' ? $sim : '—') . '</pre>';
        if (!$ro) {
            echo '<form method=post class=ops>' . fh('p=crowdsec&t=avanzate') . '<input type=hidden name=action value=cs_simulation>';
            echo '<button class=s name=sim value=on>Attiva simulazione</button> <button class=g name=sim value=off>Disattiva (ban reali)</button></form>';
        }
        echo '<p class=mut>Catene iptables del bouncer: scheda <a href="?p=crowdsec&t=firewall">Firewall</a> e Sicurezza → Firewall.</p>';
    }

    if ($tab === 'firewall') {
        [, $bst] = priv('cs-bouncer-status');
        $mode = ''; $chainOk = false; $apiOk = false; $jumps = [];
        foreach (explode("\n", trim($bst)) as $l) {
            if (str_starts_with($l, 'mode ')) $mode = trim(substr($l, 5));
            if ($l === 'CROWDSEC_CHAIN yes') $chainOk = true;
            if (str_starts_with($l, 'api_key set')) $apiOk = true;
            if (str_starts_with($l, 'jump ')) { $p = explode(' ', $l); $jumps[$p[1] ?? ''] = ($p[2] ?? '') === 'yes'; }
        }
        echo '<h3>Stato bouncer iptables</h3>';
        echo '<table><tr><th>Voce</th><th>Valore</th></tr>';
        echo '<tr><td>Mode</td><td><b>' . h($mode ?: '?') . '</b> ' . ($mode === 'iptables' ? '<span class="b b-ACCEPT">ok</span>' : '<span class="b b-DROP">non iptables</span>') . '</td></tr>';
        echo '<tr><td>API key</td><td>' . ($apiOk ? '<span class="b b-ACCEPT">impostata</span>' : '<span class="b b-DROP">mancante</span>') . '</td></tr>';
        echo '<tr><td>CROWDSEC_CHAIN</td><td>' . ($chainOk ? '<span class="b b-ACCEPT">presente</span>' : '<span class="b b-DROP">assente</span>') . '</td></tr>';
        $dockerExpected=!empty(S_get()['cs_docker']);
        foreach (['INPUT', 'FORWARD', 'DOCKER-USER'] as $c) {
            $present=!empty($jumps[$c]);
            $status=$present?'<span class="b b-ACCEPT">presente</span>'
              : (($c==='DOCKER-USER'&&!$dockerExpected)
                    ? '<span class="b b-jump">non richiesto</span>'
                    : '<span class="b b-DROP">assente · verificare</span>');
            echo '<tr><td>Salto '.h($c).'</td><td>'.$status.'</td></tr>';
        }
        echo '</table>';
        echo '<details><summary>Diagnostica completa</summary><pre data-iptm-layout="ui-dd2ca23bad">' . h(trim($bst) !== '' ? $bst : '—') . '</pre></details>';

        if (!$ro) {
            echo '<h3>Configura bouncer iptables</h3>';
            echo '<p class=mut>Imposta <code>mode: iptables</code>, genera la chiave API se manca, configura le catene, riavvia agent e bouncer e verifica <code>CROWDSEC_CHAIN</code>.</p>';
            echo '<form method=post class=acc>' . fh('p=crowdsec&t=firewall') . '<input type=hidden name=action value=cs_bouncer_setup>';
            echo '<div class=row>';
            echo '<label class=fl><span>Catene da proteggere</span>';
            foreach (['INPUT' => 'INPUT (traffico verso il router)', 'FORWARD' => 'FORWARD (traffico in transito)', 'DOCKER-USER' => 'DOCKER-USER (container)'] as $c => $lab) {
                $chk = ($c === 'INPUT' || ($c === 'FORWARD' && !empty($jumps['FORWARD'])) || ($c === 'DOCKER-USER' && !empty($S['cs_docker']))) ? ' checked' : '';
                if ($c === 'INPUT') $chk = ' checked';
                echo '<label style="display:block;margin:4px 0"><input type=checkbox name="ch_' . h(str_replace('-', '_', $c)) . '" value=1' . $chk . '> ' . h($lab) . '</label>';
            }
            echo '</label>';
            echo '<label class=fl><span>Azione di blocco</span>' . sel('deny', ['DROP' => 'DROP (consigliato)', 'REJECT' => 'REJECT', 'TARPIT' => 'TARPIT'], 'DROP') . '</label>';
            echo '</div>';
            echo '<p class=sticky><button class=g>Configura bouncer iptables</button></p></form>';
            if ($mode !== 'iptables' && $mode !== '') {
                echo '<form method=post class=ops>' . fh('p=crowdsec&t=firewall') . '<input type=hidden name=action value=cs_bouncer_mode><button class=s>Forza solo mode=iptables</button></form>';
                echo '<form method=post class=ops data-iptm-layout="ui-301647f506">' . fh('p=crowdsec&t=firewall') . '<input type=hidden name=action value=cs_bouncer_set_only><button class=s>Mode ipset (set-only)</button></form>';
                echo '<p class=mut>mode=<b>ipset</b>: il bouncer aggiorna solo i set; non inserisce regole nelle catene. Utile se IPTM già ha le match-set.</p>';
            }
        }

        echo '<h3>Integrazione con la bozza firewall</h3>';
        echo '<p class=mut>Dopo il setup del bouncer, abilita l\'integrazione cosi\' che ad ogni «Applica» le catene vengano ripassate al bouncer (che altrimenti perde gli agganci).</p>';
        $b = opt_rows($S, [
            ['crowdsec', 'r', 'Abilita l\'integrazione con il firewall', 'Indica al bouncer su quali catene agganciarsi e lo riavvia dopo ogni «Applica». I set li gestisce il bouncer.'],
            ['cs_docker', 'r', 'Includi anche DOCKER-USER'],
        ]);
        echo s_form('security', $b, 'p=crowdsec&t=firewall', true);
        echo '<p class=mut>I set <code>crowdsec-blacklists-N</code> compaiono solo quando ci sono decisioni attive: e\' normale vederli vuoti all\'inizio.</p>';
    }
    echo '</section>';
}

function sec_audit_card(): void {   // verifica di sola lettura della configurazione di sistema (SSH, account, porte, aggiornamenti)
    [$c, $o] = priv('sec-audit'); if ($c !== 0 || trim($o) === '') return;
    $rows = ''; $ok = 0; $warn = 0; $ic = ['OK' => '✅', 'WARN' => '⚠️', 'INFO' => 'ℹ️'];
    foreach (explode("\n", trim($o)) as $l) { $f = explode("\t", $l, 3); if (count($f) < 3 || !isset($ic[$f[0]])) continue; if ($f[0] === 'OK') $ok++; if ($f[0] === 'WARN') $warn++; $rows .= '<tr><td>' . $ic[$f[0]] . '</td><td><b>' . h($f[1]) . '</b></td><td>' . h($f[2]) . '</td></tr>'; }
    if ($rows === '') return;
    echo '<div class=card><h2>Verifica del sistema</h2><p class=mut>Controlli di sola lettura (nulla viene modificato): ' . $ok . ' ok · ' . $warn . ' da rivedere. Le correzioni su SSH e account vanno fatte a mano: qui non si toccano per non rischiare di chiuderti fuori.</p><div data-iptm-layout="scroll"><table>' . $rows . '</table></div></div>';
}

function sysctl_audit_info(): array {
    return kc('sysctl_audit', function () {
        [$c, $o] = priv('sysctl-audit'); $j = json_decode($o, true);
        return $c === 0 && is_array($j) ? $j : ['ok' => false, 'error' => trim($o)];
    });
}
function sysctl_maintenance_card(bool $readonly): void {
    [$ac,$ao,$ae] = priv('maintenance', null, ['sysctl-audit']);
    $audit = json_decode($ao, true);
    echo '<div class=card><h2>Audit sysctl e manutenzione controllata</h2>';
    if ($ac !== 0 || !is_array($audit)) echo '<p class=mut>Audit non disponibile: ' . h(trim($ao . $ae)) . '</p>';
    else {
        echo '<p>File effettivi esaminati: <b>' . (int)count($audit['effective_files'] ?? []) . '</b> · Chiavi rilevate: <b>' . (int)($audit['keys'] ?? 0) . '</b> · Definizioni duplicate/sovrascritte: <b>' . (int)($audit['duplicate_or_override_keys'] ?? 0) . '</b></p>';
        foreach (array_slice($audit['conflicts'] ?? [], 0, 12) as $conflict) {
            $defs = [];
            foreach ($conflict['definitions'] ?? [] as $def) $defs[] = (string)($def['file'] ?? '?') . ':' . (int)($def['line'] ?? 0) . ' = ' . (string)($def['value'] ?? '');
            echo '<p class=mut><code>' . h($conflict['key'] ?? '') . '</code> · ' . h(implode(' → ', $defs)) . '</p>';
        }
        if (count($audit['conflicts'] ?? []) > 12) echo '<p class=mut>Altre definizioni duplicate non mostrate.</p>';
    }
    echo '<p class=mut>Il testo grigio nel campo è solo un esempio: non viene inviato. Inserisci valori reali e verifica le chiavi disponibili sul kernel prima di applicare.</p>';
    echo '<p class=mut>Il motore accetta solo famiglie di chiavi allowlistate, esegue prima un dry-run, salva backup e rollback runtime in caso di errore. Questo pannello è avanzato: non sostituisce ancora tutti i vecchi percorsi sysctl generati dalle opzioni di hardening.</p>';
    if (!$readonly) {
        echo '<form method=post>' . fh('p=harden') . '<input type=hidden name=action value=sysctl_maintenance_apply>';
        echo '<label class=fl><span>Configurazione sysctl (una assegnazione chiave = valore per riga)</span><textarea name=sysctl_payload rows=7 maxlength=65536 required placeholder="net.ipv4.tcp_syncookies = 1&#10;net.ipv4.conf.all.rp_filter = 2"></textarea></label>';
        echo '<label style="display:flex;gap:8px;align-items:center;margin:10px 0"><input type=checkbox name=apply_sysctl value=1><b>Applica davvero al kernel e a /etc/sysctl.d/98-iptm-hardening.conf</b></label>';
        echo '<button class=s>Valida / applica sysctl</button></form>';
    } else echo '<p>Account in sola lettura: applicazione disabilitata.</p>';
    echo '</div>';
}

function pg_harden() {
    $S = S_get(); $H = $S['harden']; $rows = '';
    foreach (HARDEN as $id => [$l, $d, $kv]) {
        $st = harden_state($kv);
        $bd = $st['na'] ? '<span class="b b-jump" title="Il kernel non espone queste impostazioni (es. IPv6 disattivato o modulo non caricato): non c\'è nulla da applicare.">non applicabile</span>'
            : ($st['on'] ? '<span class="b b-ACCEPT">attivo ora</span>' . ($st['skipped'] ? ' <small class=mut>(' . $st['skipped'] . ' voce/i non presenti nel kernel, ignorate)</small>' : '') : '<span class="b b-jump">richiesto, non attivo</span>');
        $why = $st['diff'] ? '<small class=mut>Valori diversi nel kernel: ' . h(implode(' · ', $st['diff'])) . '. Un altro file in /etc/sysctl.d o /etc/sysctl.conf potrebbe sovrascriverli.</small>' : '';
        $rows .= '<div class=dd><label>' . h($l) . '</label><div><label><input type=checkbox name="h[' . $id . ']" value=1' . (!empty($H[$id]) ? ' checked' : '') . '> Desiderato</label> ' . $bd . '<small>' . h($d) . '</small>' . $why . '</div></div>';
    }
    $cur = trim((string)@file_get_contents('/proc/sys/net/ipv4/conf/all/rp_filter'));
    $rpf = dd('Verifica indirizzo di ritorno (rp_filter)', sel('rpf', ['0' => 'Disattivato', '2' => 'Loose (consigliato per router/VPN)', '1' => 'Strict (solo host non-router)'], (string)($H['rpf'] ?? '2')) . ' <small class=mut>attuale: ' . h($cur) . '</small>', 'Scarta i pacchetti con sorgente non raggiungibile da quell\'interfaccia. «Strict» può rompere routing asimmetrico e WireGuard: sui router usa Loose.');
    echo '<div class=card><h2>Hardening del kernel (rete)</h2><p class=mut>La casella indica la configurazione desiderata, non lo stato già applicato. Se il valore nel kernel è diverso, la pagina lo segnala. Evita conflitti con file sysctl gestiti da DietPi o altri strumenti.</p><p class=mut>Impostazioni <code>sysctl</code> raccomandate dalle guide CIS e da progetti di hardening noti. Vengono salvate in <code>/etc/sysctl.d/98-iptm-hardening.conf</code> e restano dopo il riavvio.</p><form method=post>' . fh('p=harden') . '<input type=hidden name=action value=harden_apply>' . $rows . $rpf . '<p><button>💾 Salva e applica</button></p></form></div>';
    sec_audit_card();
    // Advanced duplicate sysctl editor retired from UI; core hardening controls remain.
}



/** Post-upgrade feature adoption wizard: plan-only, no live changes. */
function iptm_migration_catalog(): array {
    return [
      'lan' => ['Rete / NetworkManager', 'Bond, VLAN, multi-NIC e indirizzi aggiuntivi', 'p=multinic', 'network'],
      'dhcp' => ['DHCP', 'Pi-hole primario e secondo DHCP isolato', 'p=multinic', 'network'],
      'dns' => ['DNS e privacy', 'Pi-hole, Unbound, DNSCrypt e controlli TLS', 'p=dns', 'dns'],
      'firewall' => ['Firewall e NAT', 'IPv4 multi-subnet, anti-lockout, ACL e port forwarding', 'p=security', 'network'],
      'qos' => ['CAKE e IFB', 'Shaping, watchdog e limiti confermati', 'p=sqm', 'network'],
      'dscp' => ['Priorità DSCP', 'Priorità IPv4 upload e download, da verificare prima di attivare', 'p=sqm', 'network'],
      'crowdsec' => ['CrowdSec', 'Log e parser installati, bouncer separato', 'p=crowdsec', 'security'],
      'suricata' => ['Suricata', 'IDS/IPS: interfacce e regole da validare', 'p=ips', 'security'],
      'iot' => ['Zone e IoT', 'Migrazione IoT Warden, VLAN e inventario MAC', 'p=zones', 'network'],
      'antidpi' => ['Anti-DPI', 'Conservazione dei profili, nessun NFQUEUE abilitato dal wizard', 'p=dns', 'security'],
      'wireguard' => ['WireGuard', 'Inventario tunnel e conservazione delle chiavi', 'p=vpn', 'network'],
      'retention' => ['Backup e retention', 'Verifica degli snapshot prima della pulizia legacy', 'p=config', 'system'],
      'sysctl' => ['Sysctl e IPv6', 'Esamina le differenze senza cambiare connettività', 'p=health', 'system'],
    ];
}
function pg_upgrade_wizard(): void {
    $cat=iptm_migration_catalog();
    $saved=DATA_DIR.'/feature-migration-plan.json';
    $cur=null;
    if (is_file($saved) && !is_link($saved) && filesize($saved)<65536)
        $cur=json_decode((string)file_get_contents($saved),true);
    $preview=$_SESSION['iptm_feature_migration_preview']??null;
    $ro=($_SESSION['role']??'viewer')!=='admin';
    echo '<div class="iptm-task-intro"><div><span class="iptm-eyebrow">AGGIORNAMENTO / MIGRAZIONE</span><h2>Wizard delle nuove funzioni</h2><p>Inventario → Selezione → Anteprima → Piano salvato → Configurazione e verifica. Nessuna policy viene attivata in questa pagina.</p></div><a class="btn s" href="?p=update">Aggiornamenti</a></div>';
    echo '<div class="iptm-safety-note"><strong>Preflight obbligatorio</strong><span>Verifica backup, SSH, DNS dei client, DHCP, NAT, watchdog e stato Apply. Un piano salvato non è una conferma di sicurezza e non riavvia alcun servizio.</span></div>';
    echo '<div class="card"><h3>1 · Rilevamento</h3><p>Release attiva <code>'.h(APP_VERSION).'</code>. Il rilevamento indica solo disponibilità software: non certifica che i servizi funzionino.</p>';
    echo '<p class="mut">Configurazioni legacy e regole manuali non vengono cancellate. Usa la conversione assistita, confronta i risultati e conserva il backup precedente.</p>';
    echo '<div class="ops"><a class="btn s" href="?p=health">Audit DietPi</a><a class="btn s" href="?p=piholehealth">Pi-hole e DNS</a><a class="btn s" href="?p=manual">Regole legacy</a><a class="btn s" href="?p=sqm">QoS e watchdog</a><a class="btn s" href="?p=config">Verifica backup</a></div></div>';
    echo '<div class="card"><h3>2 · Scegli cosa configurare</h3><form method="post" action="?p=upgrade-wizard">'.fh('p=upgrade-wizard').'<input type="hidden" name="action" value="feature_migration_preview">';
    $chosen=is_array($preview)?($preview['selected']??[]):(is_array($cur)?($cur['selected']??[]):[]);
    foreach ($cat as $id=>$item) {
        $checked=in_array($id,(array)$chosen,true)?' checked':'';
        echo '<label class="iptm-migration-option" style="display:flex;gap:12px;align-items:flex-start;padding:12px;border-bottom:1px solid var(--line,#ccc)"><input type="checkbox" name="features[]" value="'.h($id).'"'.$checked.' style="width:18px;height:18px;flex:none;margin:3px 0"><span><b>'.h($item[0]).'</b><small style="display:block;opacity:.8">'.h($item[1]).'</small></span></label>';
    }
    if (!$ro) echo '<p><button type="submit">Genera anteprima di migrazione</button></p>';
    echo '</form></div>';
    if (is_array($preview)) {
       echo '<div class="card"><h3>3 · Anteprima (nessuna applicazione)</h3><p>Funzioni selezionate: <b>'.count($preview['selected']??[]).'</b>. Ogni funzione va configurata e verificata singolarmente, mediante le proprie pagine.</p><ul>';
       foreach ($preview['selected']??[] as $id) if (isset($cat[$id])) echo '<li>'.h($cat[$id][0]).' · <a href="?'.h($cat[$id][2]).'">Apri configurazione</a></li>';
       echo '</ul><p class="mut">Le configurazioni e i segreti esistenti rimangono invariati; nessun file legacy viene cancellato.</p>';
       if (!$ro) echo '<form method="post" action="?p=upgrade-wizard">'.fh('p=upgrade-wizard').'<input type="hidden" name="action" value="feature_migration_save"><button type="submit">Salva piano (NON applica alla rete)</button></form>';
       echo '</div>';
    }
    if (is_array($cur)) echo '<div class="card"><h3>4 · Piano salvato</h3><p>Il piano è registrato come bozza di migrazione; le funzioni non sono attivate automaticamente.</p><p>Creato: <code>'.h((string)($cur['created']??'')).'</code> · Selezionate: '.count($cur['selected']??[]).'</p></div>';
    echo '<div class="card"><h3>5 · Conferma operativa e pulizia legacy</h3><p>Esegui manualmente i controlli DNS dei client, NAT/FORWARD, DHCP, CAKE/IFB, backup e Apply. Soltanto dopo conferma e test post-riavvio valuta il ritiro delle funzioni legacy con gli strumenti specifici.</p><p class="mut">Pulizia automatica di file sconosciuti, catene attive, cron, script IoT Warden e vecchie release bloccata per motivi di sicurezza.</p></div>';
}
