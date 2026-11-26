<?php
// IPTM 4: pg_health section moved verbatim; no runtime behavior changed.
function pg_health(): void {
    $ro=($_SESSION['role']??'')!=='admin';
    echo '<div class=hero><h2>Salute del sistema · Preflight &amp; Commit</h2><p>Firewall, servizi e diagnostica.</p></div>';
    pg_health_policy();
    // IPTM6 port: optional one-click diagnostic; no new confirmation, no extra
    // work on normal page loads and no privileged actions beyond read-only CLI.
    echo '<section class="card" id="compat6-readiness" aria-labelledby="compat6-title"><h3 id="compat6-title">Integrità di rete e servizi</h3>';
    echo '<p>Verifica CrowdSec, Suricata, DNS, IPv6 e recupero. Nessuna modifica.</p>';
    echo '<p><a class="btn s" href="?p=health&amp;compat6=1#compat6-readiness">Verifica integrazioni ora</a></p>';
    if (($_GET['compat6'] ?? '') === '1') {
        [$c6rc,$c6out,$c6err] = priv('compat6-readiness',null,['report']);
        $c6 = $c6rc === 0 ? json_decode($c6out,true) : null;
        if (!is_array($c6) || empty($c6['ok'])) {
            echo '<p role="status" class="msg warn">Controllo non disponibile: '.h(substr((string)($c6['error']??$c6err?:$c6out),0,230)).'.</p>';
        } else {
            $cc = $c6['counts'] ?? [];
            echo '<p role="status"><strong>Rilevati:</strong> '.(int)($cc['ok']??0).' OK · '.(int)($cc['warn']??0).' da verificare · '.(int)($cc['info']??0).' informativi.</p>';
            echo '<div class="iptm-table-scroll"><table><thead><tr><th scope="col">Area</th><th scope="col">Controllo</th><th scope="col">Stato</th><th scope="col">Esito</th></tr></thead><tbody>';
            foreach (array_slice(iptm_view_rows($c6['checks']??[]),0,25) as $row) {
                $st=(string)($row['status']??'info');
                $label=$st==='ok'?'OK':($st==='warn'?'Verificare':'Informazione');
                $style=$st==='ok'?'b-ACCEPT':($st==='warn'?'b-DROP':'b-jump');
                echo '<tr><td>'.h($row['group']??'').'</td><th scope="row">'.h($row['title']??'').'</th><td><span class="b '.$style.'">'.h($label).'</span></td><td>'.h($row['detail']??'').'</td></tr>';
            }
            echo '</tbody></table></div><p class="mut">'.h((string)($c6['limits']??'')).'</p>';
        }
    }
    echo '</section>';
    // Audit read-only implemented in the maintenance engine and testable in isolation.
    [$preRc, $preOut, $preErr] = priv('maintenance', null, ['preflight']);
    $pre = $preRc === 0 ? json_decode($preOut, true) : null;
    echo '<div class=card><h3>Preflight sistema (sola lettura)</h3>';
    if (is_array($pre) && iptm_view_rows($pre['checks']??[])) {
        $counts = $pre['counts'] ?? [];
        echo '<p>OK: '.(int)($counts['ok']??0).' · Da verificare: '.(int)($counts['warn']??0)
            .' · Errori: '.(int)($counts['error']??0).'. Nessuna configurazione modificata.</p>';
        echo '<details><summary>Apri tutti i controlli e le spiegazioni</summary><table><tr><th>Controllo</th><th>Stato</th><th>Dettaglio / soluzione</th></tr>';
        foreach (array_slice(iptm_view_rows($pre['checks']), 0, 100) as $c) {
            $lev = (string)($c['status'] ?? 'warn');
            echo '<tr><td>'.h($c['name']??'').'</td><td>'.h(strtoupper($lev)).'</td><td>'.h($c['detail']??'').'</td></tr>';
        }
        echo '</table></details>';
    } else echo '<p class=mut>Preflight non disponibile: '.h(substr($preErr?:$preOut,0,240)).'.</p>';
    echo '</div>';
    // Avoid a full synchronous DietPi audit on every health page refresh.
    // Lynis runs asynchronously and can saturate small CPUs while this page renders.
    $runDietpiAudit=(string)($_GET['dietpi_audit']??'')==='1';
    if(!$runDietpiAudit) echo '<div class="card"><h3>Analisi approfondita DietPi</h3><p>Avvia un controllo completo su richiesta.</p><a class="btn s" href="?p=health&amp;dietpi_audit=1">Esegui ora analisi DietPi</a></div>';
    $j=$runDietpiAudit?iptm_security_read('dietpi-audit'):['ok'=>false,'error'=>'Audit su richiesta non avviato'];
    if (!empty($j['ok'])) {
        echo '<div class=card><h3>Componenti disponibili</h3><div class=ops data-iptm-layout="ui-4d69a74d8b">';
        $links = ['clamdscan'=>'clamav', 'freshclam'=>'clamav', 'ipset'=>'ipset',
                  'dnscrypt-proxy'=>'dnscrypt', 'unbound-checkconf'=>'unbound', 'suricata'=>'suricata',
                  'cscli'=>'crowdsec', 'lynis'=>'lynis', 'wg'=>'wireguard'];
        foreach (($j['tools']??[]) as $k=>$v) {
            if ($k === 'mitmdump') continue; // MITM is out of scope.
            $dest = $links[$k] ?? null;
            $href = $dest !== null ? '?p=progs#tool-'.$dest : '?p=postcheck';
            echo '<a class="b '.($v?'b-ACCEPT':'b-REJECT').'" href="'.h($href).'" title="'.($v?'Verifica componente':'Apri verifica o installazione').'">'
                 . h($k).' '.($v?'presente':'assente').($v?'':($dest !== null?' · installa →':' · verifica →')).'</a> ';
        }
        echo '</div><h3>Controlli di configurazione</h3><table><tr><th>Controllo</th><th>Esito</th></tr>';
        foreach (($j['config_checks']??[]) as $k=>$v) echo '<tr><td>'.h($k).'</td><td>'.($v===0?'OK':'<a href="?p=zero&amp;check='.rawurlencode((string)$k).'" title="Apri wizard di configurazione">Da verificare → Wizard</a>').'</td></tr>';
        echo '</table>';
        if (!empty($j['permission_findings'])) {
            echo '<h3>Permessi e privacy delle configurazioni</h3><ul>';
            foreach (array_slice((array)$j['permission_findings'],0,25) as $f)
                echo '<li><code>'.h($f['path']??'').'</code>: '.h($f['risk']??'').'</li>';
            echo '</ul>';
        }
        echo '</div>';
    } elseif($runDietpiAudit) echo '<div class="msg warn">Analisi DietPi non completata: controlla log e timeout, senza dedurre che il programma sia assente.</div>';
    echo '<div class=card><h3>Programmi assenti — installazione da IPTM</h3>';
    $toolInventoryRequested=(string)($_GET['tools_inventory']??'')==='1';
    if(!$toolInventoryRequested) echo '<p class="mut">Il rilevamento APT/systemd completo è facoltativo: durante Lynis potrebbe rallentare o bloccare la pagina. <a class="btn s" href="?p=health&amp;tools_inventory=1">Verifica programmi ora</a></p>';
    $ts=$toolInventoryRequested?tools_status():[];
    if(!$toolInventoryRequested) echo '<p class="mut">Inventario non richiesto, nessuna assenza presunta.</p>';
    elseif ($why=($GLOBALS['_iptm_tools_status_error']??'')) echo '<div class="msg warn">Rilevamento non disponibile: '.h($why).'. Nessuna assenza presunta.</div>';
    else {
        $missingTools=[];
        foreach (tool_defs() as $name=>$def) {
            if (!empty($ts[$name]['known']) && empty($ts[$name]['inst'])) $missingTools[]=$name;
        }
        if ($missingTools) {
            echo '<p>Programmi non installati o incompleti (verificati da helper):</p><ul>';
            foreach ($missingTools as $name) {
                $def=tool_defs()[$name]; $can=($_SESSION['role']??'')==='admin' && (!empty($ts[$name]['cand']) || empty($ts[$name]['cand_known']));
                echo '<li><a href="?p=progs#tool-'.h($name).'">'.h($def[0]).'</a> — ';
                if ($can && $def[2] === '')
                    echo '<form method=post style="display:inline">'
                      .fh('p=progs').'<input type=hidden name=action value=tool_install><input type=hidden name=tool value="'.h($name).'">'
                      .'<button class="s sm" type=submit>Installa ora</button></form>';
                else echo $can ? 'Apri Programmi per configurare e installare' : 'Repository non disponibile o stato non verificato: apri Programmi per tentare l’installazione manuale';
                echo '</li>';
            }
            echo '</ul>';
        } else echo '<p>Nessun programma mancante tra quelli gestiti da IPTM.</p>';
    }
    echo '<p class=mut>Pi-hole e Docker sono gestiti da DietPi: non vengono reinstallati con apt automaticamente. Controlla <code>dietpi-software</code> e la pagina <a href="?p=postcheck">Servizi</a>. Strumenti come iptables/ip6tables sono componenti fondamentali da non sostituire durante la verifica. MITM non viene installato.</p></div>';
    $lyStatus=iptm_security_read('lynis-status');
    // A completed audit gets its own immutable report: no stale /var/log/lynis-report.dat.
    $ly=iptm_security_read('lynis-suggestions');
    $state=(string)($lyStatus['state']??'unknown');
    $running=$state==='running';
    $findings=is_array($ly['suggestions']??null)?$ly['suggestions']:[];
    echo '<div class=card id="iptm-lynis"><h3>Lynis · Audit completo e interventi guidati</h3>';
    echo '<p>L’audit non modifica il sistema. Puoi continuare a usare IPTM.</p>';
    if (!$ro) echo '<div class=ops><form method=post class="iptm-classic-form">'.fh('p=health').'<input type=hidden name=action value=lynis_run><button class=g '.($running?'disabled':'').'>'.($running?'Audit già in corso':'Esegui audit completo').'</button></form>'
        .'<form method=post class="iptm-classic-form">'.fh('p=health').'<input type=hidden name=action value=lynis_update><button class=s '.($running?'disabled':'').'>Aggiorna Lynis (apt)</button></form></div>';
    $labels=['idle'=>'Nessun audit avviato','running'=>'Audit in esecuzione','done'=>'Audit completato',
             'done_warnings'=>'Completato con avvisi','failed'=>'Audit non completato','interrupted'=>'Audit interrotto','unknown'=>'Stato non disponibile'];
    echo '<p id="iptm-lynis-state" role=status><strong>'.h($labels[$state]??$state).'</strong> · '.h((string)($lyStatus['summary']??'')).'</p>';
    if ($running) echo '<div id="iptm-lynis-running"><progress aria-label="Lynis in esecuzione (durata non prevedibile)"></progress><p class=mut>Audit in background: tempo trascorso <span id="iptm-lynis-elapsed">'.(int)($lyStatus['elapsed_seconds']??0).'</span> secondi. Nessun timeout browser; avanzamento indeterminato, senza percentuali inventate.</p></div>';
    if (!$ro) echo '<p class=mut>Lo stato viene aggiornato senza ricaricare la pagina. <a href="?p=health#iptm-lynis">Ricarica i risultati</a> dopo il completamento.</p>';
    if (isset($lyStatus['exit_code']) && $lyStatus['exit_code']!==null) echo '<p class=mut>Codice Lynis: '.(int)$lyStatus['exit_code'].' · rilievi rilevati: '.(int)($lyStatus['suggestions_count']??0).'.</p>';
    if ($state==='interrupted' || $state==='failed') echo '<p class=mut>Verifica il log specifico dell’audit sul DietPi. Non sono mostrati risultati provenienti da un audit precedente come se fossero nuovi.</p>';
    if (!empty($ly['report_found'])) {
        $meta=(array)($ly['metadata']??[]);
        if (isset($meta['hardening_index'])) echo '<p><strong>Hardening Index:</strong> '.h($meta['hardening_index']).'</p>';
        echo '<h4>Azioni suggerite da Lynis ('.count($findings).')</h4><p class=mut>Apri una raccomandazione, consulta l’impatto e scegli se pianificarla o segnarla come verificata manualmente. Lo stato di revisione non modifica il sistema.</p>';
        $groups=[];
        foreach ($findings as $finding) $groups[(string)($finding['group']??'Altro')][]=$finding;
        foreach ($groups as $group=>$entries) {
            echo '<details class="iptm-lynis-group"><summary><strong>'.h($group).'</strong> · '.count($entries).' rilievi</summary>';
            foreach ($entries as $finding) {
                $code=(string)($finding['code']??'');$kind=(string)($finding['type']??'');
                $title=(string)($finding['title']??$code);$review=(string)($finding['review']??'open');
                $href=(string)($finding['link']??'?p=health');
                if (!preg_match('/^\?p=[a-z]+$/D',$href))$href='?p=health';
                echo '<details class="iptm-lynis-item"><summary>'.h($code).' · '.h($title).' <small>('.h($kind).' · '.h($review).')</small></summary>';
                echo '<p>'.h((string)($finding['text']??'')).'</p><p><strong>Come intervenire:</strong> '.h((string)($finding['guidance']??'')).'</p>';
                echo '<p><a class="btn s" href="'.h($href).'">Apri sezione IPTM pertinente</a></p>';
                if (!$ro && !empty($ly['audit_id'])) {
                    echo '<form method=post class="iptm-classic-form">'.fh('p=health').'<input type=hidden name=action value=lynis_mark>'
                        .'<input type=hidden name=lynis_job value="'.h($ly['audit_id']).'">'
                        .'<input type=hidden name=finding value="'.h((string)($finding['id']??'')).'">'
                        .'<label>Stato revisione '.sel('review',['open'=>'Da valutare','planned'=>'Intervento pianificato','reviewed'=>'Verificato manualmente'],$review).'</label>'
                        .'<button class=s type=submit>Memorizza decisione</button></form>';
                }
                echo '</details>';
            }
            echo '</details>';
        }
    } elseif ($running) echo '<p class=mut>Il rapporto verrà mostrato quando l’audit sarà terminato.</p>';
    elseif($state==='idle') echo '<p class=mut>Nessun rapporto disponibile: avvia il primo audit completo.</p>';
    if (!$ro) echo '<details><summary>Hardening facoltativo aggiuntivo (indipendente dai rilievi Lynis)</summary>'
        .'<form method=post class="iptm-classic-form">'.fh('p=health').'<input type=hidden name=action value=lynis_safe_apply>'
        .'<label><input type=checkbox name="fix[]" value=aslr> ASLR kernel</label> '
        .'<label><input type=checkbox name="fix[]" value=suid> Disabilita core dump SUID</label>'
        .'<p><label><input type=checkbox name=apply_fix value=1> Applica dopo controllo esplicito (senza spunta: solo anteprima)</label></p>'
        .'<button class=s>Verifica / applica selezione</button></form></details>';
    echo '</div>';
}
/** Insert one managed IPv6 zone block ahead of existing accepts; never edits live rules. */
