<?php
// ===================== v2: PAGINE =====================
function sel(string $n, array $o, string $cur = '', string $extra = ''): string {
    $h = '<select name="' . h($n) . '" ' . $extra . '>'; foreach ($o as $k => $v) { $val = is_int($k) ? $v : $k; $h .= '<option value="' . h($val) . '"' . ((string)$val === $cur ? ' selected' : '') . '>' . h($v) . '</option>'; } return $h . '</select>';
}
function tile(string $l, string $v, string $sub = '', string $cls = ''): string { return '<article class="tile ' . $cls . '"><h3 class=l>' . h($l) . '</h3><div class=v>' . $v . '</div><div class=l>' . $sub . '</div></article>'; }
function blk_btn(string $ip, string $back): string {
    if (!v_ok('ip', $ip) || $ip === '' || preg_match('/^(10\.|192\.168\.|127\.|172\.(1[6-9]|2\d|3[01])\.)/', $ip)) return '';
    return '<form method=post style="display:inline">' . fh($back) . '<input type=hidden name=action value=block_ip><input type=hidden name=ip value="' . h($ip) . '"><button class="s sm" title="Aggiungi ai blocchi manuali">⛔</button></form>';
}
function svc_state(string $u): array {   // [inst, active, enabled] dei servizi aggiuntivi, via helper (veloce: niente apt)
    static $m = null;
    if ($m === null) { $m = []; [$c, $o] = priv('svc-state'); if ($c === 0) foreach (explode("\n", trim($o)) as $l) { $x = preg_split('/\s+/', trim($l)); if (count($x) >= 4) $m[$x[0]] = ['inst' => $x[1] === 'yes', 'active' => $x[2], 'enabled' => $x[3]]; } }
    return $m[$u] ?? ['inst' => false, 'active' => '', 'enabled' => ''];
}
function dash_form(string $act, string $label, string $cls = '', array $f = []): string {   // piccolo modulo a un pulsante
    $x = ''; foreach ($f as $k => $v) $x .= '<input type=hidden name=' . h($k) . ' value="' . h($v) . '">';
    return '<form method=post class=inl>' . fh('p=status') . '<input type=hidden name=action value=' . h($act) . '>' . $x . '<button class="' . h($cls) . '">' . h($label) . '</button></form>';
}

/** Minimal, read-only privileged query through the command whitelist. */
function iptm_security_read(string $action): array {
    [$rc,$o]=priv('security',null,[$action]);
    $j=json_decode($o,true);
    return $rc===0 && is_array($j) ? $j : ['ok'=>false,'error'=>'Diagnosi non disponibile'];
}
/** Read-only inventory: a failed lookup must never be interpreted as "Warden absent". */
function iptm_warden_state(): array {
    [$rc,$out] = priv('iot-warden',null,['inventory']);
    $json=json_decode($out,true);
    return $rc===0 && is_array($json) && !empty($json['ok']) ? $json : ['ok'=>false,'error'=>'Inventario IoT Warden non disponibile'];
}
/** Scrub ONLY the two exact legacy chains from an iptables-save model. Never touch running rules. */
function iptm_warden_scrub_model(array $model): array {
    $targets=['IOT_DNS','IOT_FW']; $removed=0;
    foreach ($model as &$table) {
        if (($table['k']??'')!=='table') continue;
        $new=[];
        foreach ((array)($table['items']??[]) as $it) {
            $drop=false;
            if (($it['t']??'')==='chain') $drop=in_array($it['n']??'', $targets, true);
            elseif (($it['t']??'')==='rule') {
                $raw=(string)($it['r']??'');
                $drop=in_array(rchain($raw),$targets,true)
                    || (bool)preg_match('/(?:^|\s)-(?:j|g)\s+(?:IOT_DNS|IOT_FW)(?:\s|$)/',$raw);
            } elseif (($it['t']??'')==='c') {
                $raw=(string)($it['x']??'');
                if ($raw!=='' && $raw[0]!=='#' && preg_match('/\bIOT_(?:DNS|FW)\b/',$raw))
                    throw new RuntimeException('Riga iptables non riconosciuta contenente una catena Warden: rimozione manuale richiesta.');
            }
            if ($drop) $removed++; else $new[]=$it;
        }
        $table['items']=$new;
    }
    unset($table);
    return [$model,$removed];
}
function pg_config(): void {
    $ro=($_SESSION['role']??'')!=='admin';
    echo '<div class=hero><h2>Configurazione portabile</h2><p>Esporta o importa le impostazioni. Il firewall attivo non cambia.</p></div>';
    echo '<div class=card><h3>Esporta</h3><p>Contiene reti, regole e impostazioni IPTM. Non include password o chiavi. Custodisci il file.</p>';
    if (!$ro) echo '<p><a class=btn href="?dl=config-bundle">Scarica configurazione JSON</a></p>';
    echo '</div><div class=card><h3>Importa in bozza</h3><p>Importa nella bozza e verifica il file. Credenziali e firewall attivo restano invariati. Per attivare, premi Applica.</p>';
    if (!$ro) echo '<form method=post enctype="multipart/form-data" class="iptm-classic-form">'.fh('p=config').'<input type=hidden name=action value=config_bundle_import><input type=file name=config accept=".json,application/json" required><p><button class=g>Importa e verifica</button></p><progress max=100 class=iptm-progress hidden></progress><span role=status class=mut></span></form>';
    echo '</div>';
}
function pg_dnsaudit(): void {
    echo '<div class=hero><h2>Diagnosi DNS e privacy</h2><p>Controlla DNS e privacy senza modificare la rete.</p></div>';
    $j=iptm_security_read('dns-audit');
    if (empty($j['ok'])) { echo '<div class="msg err">Diagnosi DNS non disponibile.</div>';return; }
    echo '<div class=card><h3>Stato componenti</h3><table><tr><th>Servizio</th><th>Stato</th></tr>';
    foreach ((array)($j['services']??[]) as $k=>$v) echo '<tr><td>'.h($k).'</td><td>'.h($v).'</td></tr>';
    echo '</table><p>Resolver del router: <code>'.h(implode(', ',$j['host_resolver']??[])).'</code></p></div>';
    echo '<div class=card><h3>Incongruenze / limiti</h3>';
    foreach (($j['findings']??[]) as $x) echo '<p><strong>'.h(strtoupper($x['level']??'info')).':</strong> '.h($x['message']??'').'</p>';
    echo '<p class=mut>'.h($j['limits']??'').'</p></div>';
}
function pg_piholehealth(): void {
    $j = iptm_security_read('pihole-health');
    echo '<div class="hero"><div class=hico>🩺</div><div><h2>Accessibilità di Pi-hole</h2><p>Controlla Pi-hole, web e DNS.</p></div></div>';
    if (empty($j['ok'])) { echo '<div class="msg err">Diagnosi non disponibile: '.h($j['error']??'helper/sudo non raggiungibile').'</div>'; return; }
    echo '<div class="card"><h3>Servizi e porte</h3><table><tr><th>Controllo</th><th>Stato</th><th>Dettaglio</th></tr>';
    foreach ((array)($j['checks'] ?? []) as $row) {
        $s = (string)($row['status'] ?? 'unknown'); $label = $s==='ok'?'OK':($s==='error'?'Da correggere':'Da verificare dalla LAN');
        echo '<tr><td>'.h($row['name']??'').'</td><td><span class="b '.($s==='ok'?'b-ACCEPT':($s==='error'?'b-DROP':'b-jump')).'">'.h($label).'</span></td><td>'.h($row['detail']??'').'</td></tr>';
    }
    echo '</table></div><div class="card"><h3>Interpretazione</h3><p>'.h($j['summary']??'').'</p>';
    foreach ((array)($j['warnings']??[]) as $message) echo '<p class="mut">⚠ '.h($message).'</p>';
    echo '<p class="mut">Il test locale non verifica l’accesso dalla LAN. Controlla le porte 8089/8489 dal PC.</p>';
    echo '<details><summary>Come verificare da un dispositivo LAN</summary><p>Non sostituire con un test sul router: usa l’indirizzo reale del DietPi dal tuo PC.</p><pre>dig @IP_DIETPI example.org A
curl -I http://IP_DIETPI:8089/admin/
curl -k -I https://IP_DIETPI:8489/admin/</pre><p>La porta deve essere aperta e il servizio in ascolto.</p></details>';
    echo '<p><a class="btn s" href="?p=dnsaudit">Audit DNS e privacy</a> <a class="btn s" href="?p=apply">Verifica regole INPUT</a></p></div>';
}
/** Security-only Preflight & Commit. Deliberately separate from CAKE/QoS. */
function iptm_health_policy_catalog(): array {
    return [
        'spi' => ['Firewall stateful SPI', 'alto', 'DROP INPUT/FORWARD; richiede accesso LAN verificabile', true],
        'antispoof' => ['Anti-spoofing loopback', 'basso', 'Blocca indirizzi loopback su interfacce non locali', true],
        'invalid' => ['Scarta pacchetti INVALID', 'medio', 'Attenzione a VPN e traffico asimmetrico', true],
        'icmp_limit' => ['Limite ICMP', 'basso', 'Mantiene disponibili ICMP e diagnostica', true],
        'dos' => ['Protezione SYN flood', 'medio', 'Dipende dal supporto xt_recent / kernel', true],
        'ssh_limit' => ['Limite tentativi SSH', 'medio', 'Verificare la porta di gestione', true],
        'final_drop' => ['Scarto finale', 'alto', 'Richiede anti-lockout LAN e accesso di emergenza', true],
        'lockout_on' => ['Accesso gestione dalla LAN', 'basso', 'Protegge le porte di gestione definite in Setup', true],
        'conn_limit' => ['Limite connessioni', 'medio', 'Possibili effetti su app ad alta concorrenza', false],
        'web_rl' => ['Rate limit web', 'alto', 'Verifica reverse proxy e WAN/LAN condivise', false],
        'amp_block' => ['Anti-amplificazione', 'medio', 'Verifica DNS, NTP e servizi LAN', false],
        'portscan' => ['Protezione port scan', 'alto', 'Può bloccare client legittimi su interfacce condivise', false],
    ];
}
function iptm_health_policy_selected(mixed $input): array {
    if (!is_array($input) || count($input) > 32) throw new RuntimeException('Selezione opzioni non valida.');
    $catalog = iptm_health_policy_catalog(); $selected=[];
    foreach ($input as $key) {
        if (!is_string($key) || !array_key_exists($key, $catalog))
            throw new RuntimeException('Opzione non autorizzata nel preflight.');
        $selected[$key]=true;
    }
    return array_keys($selected);
}
function iptm_health_policy_candidate(array $original, array $selected): array {
    $candidate=$original;
    foreach (iptm_health_policy_catalog() as $k => $_) $candidate[$k]=in_array($k,$selected,true)?1:0;
    $notes=[]; $candidate=iptm_safe_settings($candidate,$notes);
    $blocked=[];
    foreach ($selected as $key) if (empty($candidate[$key])) $blocked[]=$key;
    return [$candidate,$notes,$blocked];
}
function iptm_health_policy_preview(array $original, array $selected, string $originalDraft): array {
    [$candidate,$notes,$blocked]=iptm_health_policy_candidate($original,$selected);
    $errors=[];
    if (empty($original['lan_nets']) && (!empty($candidate['spi']) || !empty($candidate['final_drop'])))
        $errors[]='Rete LAN non configurata: non attivare DROP/SPI prima di definire il CIDR in Setup.';
    if ((!empty($candidate['spi']) || !empty($candidate['final_drop'])) && empty($candidate['lockout_on']))
        $errors[]='Anti-lockout LAN obbligatorio con SPI e scarto finale.';
    if ($blocked) $errors[]='Opzioni rifiutate per proteggere la rete: '.implode(', ',$blocked).'. Disattivale e ripeti.';
    $model=parse_rules($originalDraft);
    $warnings=regen($model,$candidate); $txt=ser($model);
    if (strlen($txt)>2097152 || trim($txt)==='') $errors[]='Bozza di regole non valida o troppo grande.';
    $unsafe=iptm_reject_unsafe_rules($txt); if ($unsafe!=='') $errors[]=$unsafe;
    if (!$errors) {
        $pf=apply_preflight($txt);
        if (($pf['block']??'')!=='') $errors[]=(string)$pf['block'];
        $warnings=array_merge($warnings,(array)($pf['warn']??[]));
        [$rc,$out,$err]=priv('test',$txt);
        if ($rc!==0) $errors[]='iptables-restore --test non superato: '.herr(substr($out.$err,0,600));
    }
    return ['candidate'=>$candidate,'txt'=>$txt,'errors'=>$errors,'warnings'=>array_merge($notes,$warnings),
        'blocked'=>$blocked,'changed'=>array_keys(array_filter(iptm_health_policy_catalog(),
            fn($k)=>!empty($candidate[$k])!==!empty($original[$k]),ARRAY_FILTER_USE_KEY))];
}
function iptm_health_policy_marker(): string { return DATA_DIR.'/health-policy-commit.json'; }
function iptm_health_policy_marker_read(): ?array {
    $f=iptm_health_policy_marker();
    if (is_link($f)) return ['invalid'=>true];
    if (!is_file($f)) return null;
    $raw=@file_get_contents($f);
    if (!is_string($raw) || strlen($raw)>2048) return ['invalid'=>true];
    $x=json_decode($raw,true);
    return is_array($x) && isset($x['token']) && preg_match('/^[a-f0-9]{32}$/D',(string)$x['token']) ? $x : ['invalid'=>true];
}
function iptm_health_policy_restore_draft(array $p): bool {
    $saved=(string)($p['original_draft']??'');
    if ($saved==='') return false;
    // Only replace the trial draft. Never overwrite another user's intervening edits.
    $actual=get_draft();
    if (!hash_equals((string)($p['trial_hash']??''),hash('sha256',$actual))) return false;
    return put_draft($saved);
}
function pg_health_policy(): void {
    $ro=($_SESSION['role']??'')!=='admin'; $S=S_get(); $cat=iptm_health_policy_catalog();
    $preview=$_SESSION['health_policy_preview']??null;
    $active=$_SESSION['health_policy_active']??null;
    $pd=pending(); $marker=iptm_health_policy_marker_read();
    echo '<section id="health-policy" class="card" data-iptm-layout="ui-063a3b197d"><h2>Preflight &amp; Commit · Sicurezza del sistema</h2>';
    echo '<p>Configura e prova le protezioni dalla pagina <b>Sistema → Salute DietPi</b>. La procedura prepara una bozza modificabile, esegue un test reale di sintassi con iptables-restore, applica con watchdog e richiede una conferma entro il timeout scelto. <b>QoS e CAKE non vengono modificati.</b></p>';
    // Emergency path is explicit and works even if the session that created
    // the policy trial was lost. It never overrides the kernel restore test.
    if (!$ro && is_array($pd) && empty($pd['invalid']) &&
        ($pd['status']??'')==='recovery_required' &&
        preg_match('/^[a-f0-9]{32}$/D',(string)($pd['txid']??''))) {
        echo '<div class="msg warn"><b>Recupero manuale assistito (transazione scaduta)</b><p>Se «Ripristina da Salute» non funziona, puoi ritentare il rollback anche senza la sessione della prova originaria. Non disattiva il watchdog e non ignora set CrowdSec assenti, lock o snapshot non validi. Serve console di recupero indipendente dalla LAN.</p>';
        echo '<form method="post">'.fh('p=health').'<input type="hidden" name="action" value="health_recovery_retry"><input type="hidden" name="recovery_txid" value="'.h((string)$pd['txid']).'">';
        echo '<button class="d" type="submit">Ritenta recupero protetto</button></form>';
        echo '<p>Se fallisce il test iptables-restore o mancano IPSet, lo stato rimane pendente. Non usare «Forza Apply» per aggirare l’errore.</p></div>';
    }
    if ($marker!==null && $pd) {
        $seconds=max(0,(int)$pd['until']-time());
        echo '<div class="msg warn"><b>Firewall in prova</b> · rollback programmato tra <strong id="iptm-health-seconds" data-until="'.(int)$pd['until'].'">'.$seconds.' s</strong>. Verifica da un secondo dispositivo: accesso IPTM, SSH, Pi-hole, DNS, HTTPS, navigazione e VPN.</div>';
        if (!$ro) {
            $owns=is_array($active) && !empty($active['txid']) && !empty($marker['token']) && hash_equals((string)$active['txid'],(string)$marker['token']) && hash_equals((string)$active['txid'],(string)($pd['txid']??''));
            echo '<div class=ops>';
            if ($owns && $seconds>0 && empty($pd['invalid']))
                echo '<form method=post>'.fh('p=health').'<input type=hidden name=action value=health_policy_confirm><button class=g>Conferma definitivamente</button></form>';
            else echo '<span class=mut>Conferma disponibile solo nella sessione che ha avviato la prova e prima della scadenza.</span>';
            echo '<form method=post>'.fh('p=health').'<input type=hidden name=action value=health_policy_revert><button class=d>Ripristina subito</button></form></div>';
        }
        echo '<p class=mut>Se il browser perde la connessione, non confermare da un’altra pagina: il watchdog deve poter ripristinare il firewall precedente. Un timeout non dimostra da solo che il recupero sia riuscito.</p>';

        echo '</section>';return;
    }
    if ($marker!==null && !$pd) {
        echo '<div class="msg warn">Una prova precedente non è più pendente. Il watchdog potrebbe essere intervenuto: verifica lo stato effettivo del kernel prima di un’altra modifica.</div>';
        if (!$ro) echo '<form method=post>'.fh('p=health').'<input type=hidden name=action value=health_policy_revert><button class=s>Archivia la prova conclusa e ripristina la bozza se ancora intatta</button></form>';
    }
    if (!empty($pd)) {echo '<div class="msg warn">Altra transazione firewall già aperta: completa o ripristina la modifica prima di usare questo modulo.</div></section>';return;}
    $selected=is_array($preview) && isset($preview['selected']) && is_array($preview['selected']) ? $preview['selected'] : array_keys(array_filter($cat,fn($r)=>!empty($r[3])));
    if (!$ro) {
        echo '<form method=post id="iptm-health-policy-form">'.fh('p=health').'<input type=hidden name=action value=health_policy_preview>';
        echo '<div class="ops"><button type=submit class=s name=preset value=restrictive>Profilo restrittivo · verifica</button><button type=submit class=s name=preset value=current>Impostazioni correnti · verifica</button></div>';
        echo '<table><thead><tr><th>Protezione</th><th>Rischio</th><th>Attiva nella bozza</th><th>Stato attuale / effetto</th></tr></thead><tbody>';
        foreach($cat as $k=>[$label,$risk,$hint,$default]) {
            $checked=in_array($k,$selected,true);$current=!empty($S[$k]);
            echo '<tr><td><b>'.h($label).'</b></td><td>'.h($risk).'</td><td><label><input type=checkbox data-suggest="'.($default?'1':'0').'" data-current="'.($current?'1':'0').'" name="sec_flags[]" value="'.h($k).'"'.($checked?' checked':'').'> '.($checked?'In proposta':'Opzionale').'</label></td><td class=mut>'.($current?'Attiva':'Disattiva').' · '.h($hint).'</td></tr>';
        }
        echo '</tbody></table><p class=mut>Le opzioni pericolose (SYNPROXY, rpfilter rigido, NOTRACK e filtri WAN non sicuri) restano escluse dal backend. Prima di abilitare DROP o SPI definisci la LAN in Setup; una simulazione non può provare la connettività del browser remoto.</p>';
        echo '<div class=ops><button class=g>1. Verifica bozza, compatibilità e rischio</button></div></form>';

    } else echo '<p class=mut>La modifica della policy richiede un account amministratore.</p>';
    if (is_array($preview) && $marker===null) {
        echo '<div class="card" data-iptm-layout="ui-c53ea1da23"><h3>Risultato preflight della proposta</h3>';
        foreach ((array)($preview['errors']??[]) as $e) echo '<p class="msg err">'.h($e).'</p>';
        foreach (array_slice((array)($preview['warnings']??[]),0,12) as $e) echo '<p class="mut">⚠ '.h($e).'</p>';
        if (empty($preview['errors'])) {
            echo '<p class="msg ok">Preflight e test iptables superati al momento della verifica. '.count($preview['changed']??[]).' opzioni modificate. Nessuna regola caricata nel kernel.</p>';
            echo '<details><summary>Opzioni cambiate rispetto alle impostazioni esistenti</summary><p>'.h(implode(', ',(array)($preview['changed']??[]))?:'Nessuna opzione differente').'</p></details>';
            if (!$ro) echo '<form method=post class=ops>'.fh('p=health').'<input type=hidden name=action value=health_policy_trial>'
                .'<label>Ripristina se non confermo entro <input name=secs type=number min=30 max=600 value=120 required data-iptm-layout="ui-7e2b8e250b"> secondi</label>'
                .'<button class=g>2. Applica in prova con rollback</button></form>';
        } else echo '<p class=mut>Correggi la selezione e ripeti il preflight. Non è possibile applicare la bozza.</p>';
        echo '</div>';
    }
    echo '<p class=mut>Impostazioni salvate e regole attive vengono modificate definitivamente solo dopo la conferma. Le altre funzioni di sistema (DNS, Suricata, CrowdSec, IPv6, sysctl) sono sottoposte a controlli separati e non sono attivate da questa procedura.</p>';
    echo '<div class=ops><a class="btn s" href="?p=security">Policy dettagliata</a><a class="btn s" href="?p=apply">Diff regole e ripristino</a><a class="btn s" href="?p=piholehealth">Diagnostica Pi-hole</a><a class="btn s" href="?p=dnsaudit">Audit DNS</a></div></section>';
}
// IPTM 4: pg_health moved to modules/36_health_pages.php (loaded before POST controller).
function iptm_zone_v6_merge(string $current, string $iface, array $rules): string {
    if (strlen($current) > 2097152 || !preg_match('/^[A-Za-z0-9_.:-]{1,15}$/D',$iface)) throw new RuntimeException('Regole IPv6 o interfaccia non valide');
    if (!str_contains($current, '*filter') || !preg_match('/(?m)^:INPUT [A-Z]+ \[.*\]$/', $current) ||
        !preg_match('/(?m)^:FORWARD [A-Z]+ \[.*\]$/', $current)) throw new RuntimeException('Inizializza il firewall IPv6 dalla pagina IPv6 prima di creare la zona');
    // A second zone replaces, never stacks stale chains or jumps from previous configuration.
    $current = preg_replace('/(?m)^# IPTM6-ZONE-START\n.*?^# IPTM6-ZONE-END\n/s', '', $current, 1, $old);
    if (!is_string($current)) throw new RuntimeException('Blocco IPv6 precedente non valido');
    if (str_contains($current, 'IPTM6-IOT-') || $old > 1) throw new RuntimeException('Vecchie regole IPTM6-IOT non riconosciute: intervenire manualmente');
    foreach ($rules as $r) if (!is_string($r) || !preg_match('~^-A IPTM6-IOT-(?:IN|FWD) [-!a-zA-Z0-9_:/. ,]+$~D',$r))
        throw new RuntimeException('Regola IPv6 non riconosciuta');
    $lines = preg_split('/\r?\n/', $current);
    $within = false; $start = -1; $chains = 0; $end = -1;
    foreach ($lines as $i => $line) {
        if ($line === '*filter') { if ($within) throw new RuntimeException('Sezioni filter duplicate'); $within = true; continue; }
        if ($within && str_starts_with($line, ':')) { $start = $i + 1; $chains++; continue; }
        if ($within && $line === 'COMMIT') { $end = $i; break; }
        if ($within && !str_starts_with($line, ':') && $line !== '' && !str_starts_with($line, '#')) break;
    }
    if ($end < 0) { // Re-find COMMIT if normal rules occurred after chain declarations.
        for ($i=$start; $i<count($lines); $i++) if ($lines[$i] === 'COMMIT') { $end=$i; break; }
    }
    if ($start < 0 || $end < $start || !$chains) throw new RuntimeException('Sezione ip6tables filter non standard');
    // Chain definitions must precede any -A rule, including rules inserted by IPTM.
    $insert=['# IPTM6-ZONE-START',':IPTM6-IOT-IN - [0:0]',':IPTM6-IOT-FWD - [0:0]',
        '-A INPUT -i '.$iface.' -j IPTM6-IOT-IN','-A FORWARD -i '.$iface.' -j IPTM6-IOT-FWD',
        '-A FORWARD -o '.$iface.' -m conntrack --ctstate NEW -j REJECT --reject-with icmp6-adm-prohibited'];
    $insert=array_merge($insert,$rules,['# IPTM6-ZONE-END']);
    array_splice($lines,$start,0,$insert);
    return implode("\n",$lines);
}

/** Managed, replay-safe IPv6 rules for MAC policy without VLAN; only draft editing. */
function iptm_mac_v6_merge(string $current, array $rules): string {
    if (strlen($current)>2097152 || count($rules)<1 || count($rules)>256) throw new RuntimeException('Bozza IPv6 o piano MAC non valido');
    if (str_contains($current, '# IPTM6-ZONE-START') || str_contains($current, 'IPTM6-IOT-'))
        throw new RuntimeException('Esiste una policy IPv6 per zona: rimuovila e applica il rollback prima di passare alla modalità MAC');
    $current = preg_replace('/(?ms)^# IPTM6-MAC-START\n.*?^# IPTM6-MAC-END\n?/', '', $current, 1);
    if (!is_string($current) || str_contains($current, '# IPTM6-MAC-START')) throw new RuntimeException('Bozza IPv6 MAC non riconosciuta');
    foreach ($rules as $r) if (!is_string($r) || !preg_match('/^-A (?:INPUT|FORWARD) -i [A-Za-z0-9_.:-]{1,15} -m mac --mac-source (?:[a-f0-9]{2}:){5}[a-f0-9]{2} (?:-p ipv6-icmp --icmpv6-type (?:133|135|136) -j ACCEPT|-j REJECT)$/D',$r))
        throw new RuntimeException('Regola MAC IPv6 fuori elenco consentito');
    $lines=preg_split('/\r?\n/',$current);
    $filter=false;$start=-1;$end=-1;$lastChain=-1;
    foreach ($lines as $i=>$line) {
        if ($line==='*filter') {if ($filter) throw new RuntimeException('Tabella IPv6 filter duplicata');$filter=true;$start=$i;continue;}
        if (!$filter) continue;
        if ($line==='COMMIT') {$end=$i;break;}
        if (preg_match('/^:[A-Za-z0-9_.:-]+ /',$line)) $lastChain=$i;
    }
    if ($start<0 || $end<0 || $lastChain<0 || $lastChain>=$end) throw new RuntimeException('Bozza IPv6 filter incompleta');
    $insert=array_merge(['# IPTM6-MAC-START'],$rules,['# IPTM6-MAC-END']);
    array_splice($lines,$lastChain+1,0,$insert);
    return implode("\n",$lines);
}

// IPTM 4: pg_zones moved to modules/35_iot_zones_pages.php (loaded before POST controller).
/** One concise network navigation on the dashboard; route IDs stay unchanged. */
function iptm_dashboard_network_links(): void {
    $links = [
        ['multinic', '01', 'Interfacce'],
        ['zones', '02', 'Zone'],
        ['dns', '03', 'DNS'],
        ['access', '04', 'Accessi'],
        ['security', '05', 'Firewall'],
        ['apply', '06', 'Applica'],
    ];
    echo '<h2 class="dh iptm-flow-title">Gestisci la rete</h2><nav class="iptm-network-flow" aria-label="Gestisci la rete">';
    foreach ($links as [$route, $number, $label]) {
        echo '<a href="?p='.h($route).'" aria-label="'.h($label).'">'
           . '<span class="iptm-flow-number" aria-hidden="true">'.h($number).'</span>'
           . '<span class="iptm-flow-label">'.h($label).'</span>'
           . '<span class="iptm-flow-chevron" aria-hidden="true">›</span></a>';
    }
    echo '</nav>';
}

function pg_status() {
    if (pg_async_skeleton('status', 'Dashboard firewall')) return;
    global $draftTxt, $M; $S = S_get(); $L = live_state(4.0); $if = sys_ifaces();
    // No historical sampling, full statistics or slow external service probes during the dashboard fragment.
    $bk = 'verificabile in Rilevamento sistema';
    $fw = trim((string)@file_get_contents('/proc/sys/net/ipv4/ip_forward')); $cc = (int)@file_get_contents('/proc/sys/net/netfilter/nf_conntrack_count'); $cm = max(1, (int)@file_get_contents('/proc/sys/net/netfilter/nf_conntrack_max'));
    $warn = []; $mod = $draftTxt !== rules_live(); // expensive rule generation belongs in the Rules page
    $pin = $L['ok'] ? ($L['pol']['INPUT'] ?? '?') : 'n/d'; $pfw = $L['ok'] ? ($L['pol']['FORWARD'] ?? '?') : 'n/d'; $closed = $pin === 'DROP';
    $nrules = $L['ok'] ? count($L['rules']) : 0;
    if (!empty($S['stealth']) || !empty($S['synproxy']) || !empty($S['tarpit'])) $secLvl = 'Paranoico';
    elseif (!empty($S['ident']) || !empty($S['multicast']) || !empty($S['portscan'])) $secLvl = 'Rigoroso';
    elseif (!empty($S['icmp_limit']) && !empty($S['dos'])) $secLvl = 'Consigliato';
    else $secLvl = 'Base';
    $lvlTxt = ['Base' => 'solo le regole essenziali', 'Consigliato' => 'protezione bilanciata per casa e ufficio', 'Rigoroso' => 'più restrittivo: blocca anche scansioni e tentativi sospetti', 'Paranoico' => 'massima protezione (stealth, anti-flood, tarpit)'][$secLvl];
    $next = ['Base' => ['standard', 'Consigliato'], 'Consigliato' => ['strict', 'Rigoroso']][$secLvl] ?? null;
    $hv = 'verifica in Programmi'; $pn = pending();
    // Leave CrowdSec / Suricata / systemd state checks to their dedicated pages.

    // ---- cosa richiede attenzione (ordine = priorità)
    $I = [];
    if (!empty($_SESSION['settings_migrated'])) {
        $mig = $_SESSION['settings_migrated']; unset($_SESSION['settings_migrated']);
        $I[] = ['ok', 'Impostazioni migrate automaticamente dallo schema ' . (int)$mig['from'] . ' allo schema ' . (int)$mig['to']
            . ' (app ' . APP_VERSION . '). Backup in data/backups/settings.migrate-*.json.'
            . (empty($mig['log']) ? '' : ' Dettagli: ' . implode('; ', array_slice($mig['log'], 0, 6))), ''];
    }
    if (!$L['ok']) $I[] = ['warn', 'Stato firewall non disponibile. Non significa che sia spento.', '<a class="btn s" href="?p=system">Diagnostica firewall</a>'];
    if ($pn) $I[] = ['bad', "Regole in prova. Conferma entro " . max(0, (int)$pn['until'] - time()) . " secondi, altrimenti saranno ripristinate.", dash_form('confirm', '✔ Conferma', '') . dash_form('revert', 'Annulla', 's')];
    $adm_ok = ($_SESSION['role'] ?? 'viewer') !== 'viewer';
    if ($L['ok'] && $nrules === 0) $I[] = ['bad', "Nessuna regola attiva: firewall non filtrante.", '<a class=btn href="?p=apply">Applica la bozza</a> ' . ($adm_ok ? dash_form('fw_restore_saved', '🛟 Ripristina regole salvate', 's') : '')];
    elseif ($L['ok'] && !$closed) $I[] = ['warn', "Ingressi consentiti (INPUT = " . $pin . ").", '<a class=btn href="?p=zero">Configurazione guidata</a>'];
    if ($mod && !$pn) $I[] = ['warn', "Modifiche non applicate.", '<a class=btn href="?p=apply">Rivedi e applica</a>'];
    // Full watch-status is intentionally not part of the low-latency Dashboard.
    $verdict = 'ok'; foreach ($I as $x) { if ($x[0] === 'bad') { $verdict = 'bad'; break; } if ($x[0] === 'warn') $verdict = 'warn'; }
    $hd = ['ok' => ['✅', 'Tutto in ordine', 'Regole applicate.'], 'warn' => ['⚠️', 'C\'è qualcosa da sistemare', 'Controlla gli avvisi.'], 'bad' => ['⛔', 'Serve un intervento', 'Controlla gli avvisi.']][$verdict];
    iptm_dashboard_network_links();
    echo '<div class="iptm-dashboard-kicker"><span>Stato</span><a href="?p=stats">Statistiche</a></div>';
    // ---- 1) stato in sintesi: 4 riquadri
    $pct = round($cc * 100 / $cm, 1);
    $wan = ($S['wan_if'] ?? '') !== '' ? 'WAN ' . $S['wan_if'] : 'WAN non impostata'; $lan = ($S['lan_nets'] ?? '') !== '' ? ' · LAN ' . $S['lan_nets'] : '';
    echo '<section class="tiles iptm-dashboard-metrics" aria-label="Indicatori principali firewall">'
        . tile('Firewall', $L['ok'] ? ($closed ? 'Attivo' : 'Aperto') : 'n/d', $L['ok'] ? ($nrules . ' regole · ' . ($closed ? 'ingresso chiuso di default' : 'ingresso aperto')) : 'verifica runtime non disponibile', $closed ? 'ok' : 'warn')
        . tile('Modifiche', $mod ? 'Da applicare' : 'Applicate', $mod ? '<a href="?p=apply">rivedi e applica →</a>' : 'la bozza coincide con il file attivo', $mod ? 'warn' : 'ok')
        . tile('Connessioni', number_format($cc), '<div class=bar role=progressbar aria-label="Utilizzo del connection tracking" aria-valuemin="0" aria-valuemax="100" aria-valuenow="' . min(100, $pct) . '"><i aria-hidden="true" style="width:' . min(100, $pct) . '%"></i></div>' . $pct . '% di ' . number_format($cm))
        . tile('Rete', $fw === '1' ? 'Router attivo' : 'Solo host', h($wan . $lan) . ' · ' . count($if) . ' interfacce', $fw === '1' ? 'ok' : '')
        . '</section>';

    echo '<div class="hero iptm-dashboard-health ' . $verdict . '"><div class=hico aria-hidden="true">' . $hd[0] . '</div><div><h2>' . h($hd[1]) . '</h2><p>' . h($hd[2]) . '</p><p class=mut>Livello «' . h($secLvl) . '» (' . h($lvlTxt) . ') · ' . ($L['ok'] ? $nrules . ' regole attive · ingresso ' . ($closed ? 'chiuso di default' : 'aperto') : 'runtime da verificare') . '</p></div></div>';
    if ($I) { echo '<h2 class="dh iptm-alert-title" id=attention-title>Avvisi</h2><ul class=issues aria-labelledby=attention-title>'; foreach ($I as [$lv, $t, $a]) echo '<li class="iss ' . $lv . '"><span>' . h($t) . '</span><span class=iact>' . $a . '</span></li>'; echo '</ul>'; }


    $nman = 0; if ($nman > 0 && ($_SESSION['role'] ?? 'viewer') !== 'viewer') echo '<p class=mut data-iptm-layout="ui-5c2df38eed">🔎 Nella bozza ci sono <b>' . $nman . '</b> regole manuali: <a href="?p=manual">analizza e converti in opzioni</a> (verifica che il comportamento resti identico).</p>';
    // ---- 2) protezioni aggiuntive: una sola riga compatta
    echo '<h2 class=dh>Protezioni aggiuntive</h2><div class=chips>'
       . '<a class=chip3 href="?p=crowdsec"><b>CrowdSec</b> <span class=mut>Apri →</span></a>'
       . '<a class=chip3 href="?p=ips"><b>Suricata</b> <span class=mut>Apri →</span></a>'
       . '<a class=chip3 href="?p=progs"><b>fail2ban · Auditd</b> <span class=mut>Apri →</span></a></div>';

    // ---- 3) livello di protezione + profili rapidi
    echo '<h2 class=dh>Livello di protezione</h2><div class=card><p data-iptm-layout="ui-3e47b193f8"><b>' . h($secLvl) . '</b> <span class=mut>— ' . h($lvlTxt) . '</span></p>';
    if (($_SESSION['role'] ?? 'viewer') !== 'viewer') {
        echo '<form method=post class=ops aria-label="Profili rapidi di protezione" style="display:flex;flex-wrap:wrap;gap:8px;margin:0">' . fh('p=status')
            . '<button class=s name=action value=profile_home aria-label="Applica il profilo Casa alla bozza">🏠 Casa</button>'
            . '<button class=s name=action value=profile_office aria-label="Applica il profilo Ufficio alla bozza">🏢 Ufficio</button>'
            . '<span class=mut>Profilo Rigoroso non disponibile su bond0.</span></form>';
        if ($next) echo '<div data-iptm-layout="mt8">' . dash_form('sec_preset', 'Passa al livello ' . $next[1], 's', ['level' => $next[0]]) . ' <span class=mut>' . h(['standard' => 'limita ping e flood, chiude le porte inutilizzate', 'strict' => 'blocca anche scansioni di porte e frammenti sospetti'][$next[0]]) . '</span></div>';
        echo '<p class=mut data-iptm-layout="ui-e9adfef7e5">I profili non modificano le regole manuali. Premi <b>Applica</b> per attivarli.</p>';
    }
    echo '</div>';

    // Controlli essenziali direttamente in dashboard: bozza oppure applicazione protetta da rollback.
    if (($_SESSION['role'] ?? 'viewer') !== 'viewer') {
        echo '<details class=card data-iptm-layout="mt10"><summary><b>🛡 Protezione rapida</b> <span class=mut></span></summary>';
        echo s_form('security', opt_rows($S, [
            ['spi', 'r', 'Firewall con policy predefinite sicure'],
            ['antispoof', 'r', 'Anti-spoofing'],
            ['invalid', 'r', 'Blocca pacchetti non validi e scansioni TCP'],
            ['dos', 'r', 'Protezione SYN flood'],
            ['ssh_limit', 'r', 'Limita tentativi SSH dal WAN'],
            ['portscan', 'r', 'Rilevamento port scan e ban'],
            ['crowdsec', 'r', 'Integrazione CrowdSec (richiede bouncer installato)'],
            ['final_drop', 'r', 'Blocca tutto il traffico non autorizzato']
        ]), 'p=status', true);
        echo '<p class=mut>Salva la bozza, poi premi <b>Applica</b>. Il ripristino automatico protegge la connessione.</p></details>';
    }


    // Detailed charts do multiple kernel traversals; compute them only on the Statistics page.
    echo '<div class=card><h3>Statistiche</h3><p class=mut>Traffico, blocchi e storico.</p>'
       . '<a class="btn s" href="?p=stats">Apri statistiche</a></div>';

    // ---- dettagli tecnici (richiudibili)
    echo '<details class=card><summary><b>Dettagli tecnici</b> <span class=mut></span></summary>';
    echo '<p class=mut>Versione: app <code>' . h(APP_VERSION) . '</code> · build <code>' . h(APP_BUILD) . '</code> · helper <code>' . h($hv) . '</code> · policy INPUT/FORWARD: <code>' . h($pin . ' / ' . $pfw) . '</code> · backend iptables: <code>' . h($bk) . '</code></p>';
    echo '<h3>Interfacce</h3><table><tr><th>Nome</th><th>Indirizzi IPv4</th></tr>'; foreach ($if as $n => $a) echo '<tr><td><b>' . h($n) . '</b></td><td>' . h(implode(', ', $a) ?: '—') . '</td></tr>'; echo '</table>';
    if ($L['ok']) {
        $r = $L['rules']; usort($r, fn($a, $b) => $b['p'] <=> $a['p']);
        echo '<h3>Regole più usate</h3><div data-iptm-layout="scroll"><table><tr><th>Pacchetti</th><th>Byte</th><th>Tabella</th><th>Regola</th></tr>';
        foreach (array_slice($r, 0, 10) as $x) echo '<tr><td>' . number_format($x['p']) . '</td><td>' . hb($x['b']) . '</td><td>' . h($x['t']) . '</td><td><code style="display:block">' . h($x['r']) . '</code></td></tr>'; echo '</table></div>';
    }
    echo '</details>';
}

function iptm_page_update(): void {   // distribuzione nativa modulare
    $ro = ($_SESSION['role'] ?? 'viewer') === 'viewer'; [, $hv] = priv('version'); $hv = trim($hv) ?: '?';
    $bk = glob(DATA_DIR . '/iptables-manager.php.bak-*') ?: []; rsort($bk);
    echo '<div class=card><h2>Aggiornamento completo da web</h2><p>Versione installata: applicazione <code>' . h(APP_VERSION) . '</code> · build <code>' . h(APP_BUILD) . '</code> · helper <code>' . h($hv) . '</code>.</p>';
    echo '<p class=mut>Carica lo ZIP di aggiornamento. Integrità e backup vengono verificati automaticamente. <b>Sicurezza:</b> usa solo pacchetti affidabili: il download HTTP non ne autentica la provenienza.</p>';
    if ($ro) echo '<div class="msg err">Account in sola lettura.</div>';
    else echo '<form method=post action="?p=update" enctype="multipart/form-data" class="iptm-classic-form">' . fh('p=update') . '<input type=hidden name=action value=update_apply>'
        . '<label class=fl><span>ZIP installabile: Native Update (max 8 MiB; PHP: ' . h(ini_get('upload_max_filesize')) . ')</span><input type=file name=pkg accept=".zip" required></label>'
        . '<p class=mut><b>Non caricare</b> il Kit completo, Sorgenti e test, README o uno ZIP che contiene altri ZIP. Se hai scaricato il Kit, estrailo sul computer e seleziona soltanto l’archivio Native Update.</p>'
        . '<label><input type=checkbox name=force value=1> Consenti soltanto la stessa versione (es. nuova build della versione corrente); non permette downgrade</label>'
        . '<p><button class=g type=submit >Installa pacchetto completo</button></p></form>';
    if (!$ro) echo '<details class=card><summary><b>Alternativa: scarica lo ZIP da URL HTTP/HTTPS</b></summary>'
        . '<p class=mut>Per server di aggiornamento attendibili, anche HTTP sulla LAN. Nessun hash da digitare. Fino a 3 redirect HTTP vengono verificati singolarmente: indirizzi locali speciali e passaggi HTTPS verso HTTP sono bloccati. HTTP non protegge contro manomissioni sulla rete.</p>'
        . '<form method=post action="?p=update" class="iptm-classic-form">' . fh('p=update')
        . '<input type=hidden name=action value=update_url_apply>'
        . '<label class=fl><span>URL completo dello ZIP (HTTP o HTTPS, max 8 MiB)</span><input name=package_url type=url maxlength=1500 placeholder="http://192.168.1.10/releases/IPTM.zip" required></label>'
        . '<label class=fl><span>SHA-256 pubblicato dall’autore (facoltativo, consigliato per HTTP)</span><input name=sha maxlength=64 pattern="[a-fA-F0-9]{64}" placeholder="64 caratteri esadecimali"></label>'
        . '<label><input type=checkbox name=force value=1> Consenti soltanto la stessa versione, mai downgrade</label>'
        . '<p><button class=g type=submit >Scarica e installa</button></p></form></details>';
    echo '<p class=mut>Installazioni precedenti al multi-NIC: nessuna seconda scheda richiesta per installare l’aggiornamento; configurazione WAN, DHCP, indirizzi IP e firewall conservati. Gli updater modulari supportano solo il formato nativo e verificano la unità di recupero prima di confermare il risultato. Le release successive utilizzano un archivio nativo e il journal di recovery. Nessuna regola firewall viene cambiata aprendo questa pagina.</p></div>';
    [$cr, $co, $ce] = priv('upgrade-cleanup', null, ['report']);
    $clean = $cr === 0 ? json_decode($co, true) : null;
    echo '<div class="card"><h3>Pulizia automatica post-aggiornamento</h3>';
    echo '<p class="mut">Durante ogni aggiornamento IPTM identifica le unità obsolete non più utilizzate, archivia le originali e ritira le unità inattive riconosciute. I servizi necessari, attivi o personalizzati non vengono interrotti: il rapporto evidenzia gli eventuali interventi non sicuri.</p>';
    if (is_array($clean) && !empty($clean['ok'])) {
        echo '<p>Ultimo controllo: <b>'.h((string)($clean['state']??'non eseguito')).'</b></p>';
        $ret = (array)($clean['retired']??[]);
        $arc = (array)($clean['archived']??[]);
        $pre = (array)($clean['preserved']??[]);
        $converted = (array)($clean['converted']??[]);
        echo '<p>Unità ritirate: '.count($ret).' · copie archiviate: '.count($arc).' · configurazioni convertite: '.count($converted).' · componenti protetti: '.count($pre).'</p>';
        if (!empty($clean['reason'])) echo '<p class="mut">Rinvio: '.h((string)$clean['reason']).'</p>';
        $reasons=(array)($clean['preserved_reasons']??[]);
        if ($reasons) {
            echo '<details class="iptm-cleanup-residuals"><summary>Unità ancora necessarie o non ritirabili ('.count($reasons).')</summary><ul>';
            foreach (array_slice($reasons,0,48,true) as $unit=>$why) echo '<li><code>'.h((string)$unit).'</code> — '.h((string)$why).'</li>';
            echo '</ul></details>';
        }
        if (!empty($clean['snapshot'])) echo '<p class="mut">Snapshot protetto: <code>'.h((string)$clean['snapshot']).'</code></p>';
    } else echo '<p class="mut">Nessun rapporto disponibile; il primo aggiornamento nativo genera il rapporto.</p>';
    if (!$ro) echo '<form method="post">'.fh('p=update').'<button class="s" type="submit" name="action" value="upgrade_cleanup_run">Riesegui pulizia verificata</button></form>';
    echo '</div>';
    echo '<div class=card><h3>Configurazione di avvio (non toccata dagli aggiornamenti)</h3><p class=mut>Per cambiarla crea <code>' . h(WEB_CONF) . '</code>, ad esempio <code>{"ALLOWED_NETS":["192.168.1.0/24"],"ROLLBACK_SECS":120}</code>. Chiavi ammesse: ALLOWED_NETS, ROLLBACK_SECS, MIN_PW, IDLE_SECS, DATA_DIR, RULES_FILE, HELPER, BIN_IP, BIN_SUDO. Prima di ogni aggiornamento viene salvata anche una copia di impostazioni, utenti e bozza in <code>' . h(DATA_DIR) . '/backups/pre-update-*</code>.</p><table>'
        . '<tr><td>File personalizzato</td><td>' . (is_file(WEB_CONF) ? '✔ presente' : 'non presente (valori predefiniti)') . '</td></tr>'
        . '<tr><td>ALLOWED_NETS</td><td><code>' . h(implode(', ', ALLOWED_NETS)) . '</code></td></tr><tr><td>ROLLBACK_SECS</td><td>' . ROLLBACK_SECS . '</td></tr><tr><td>IDLE_SECS</td><td>' . IDLE_SECS . '</td></tr><tr><td>MIN_PW</td><td>' . MIN_PW . '</td></tr><tr><td>DATA_DIR</td><td><code>' . h(DATA_DIR) . '</code></td></tr></table></div>';
    if ($bk) { echo '<div class=card><h3>Copie della versione precedente</h3><p class=mut>Per tornare indietro via SSH: copia il file scelto in <code>' . h((string)($_SERVER['SCRIPT_FILENAME'] ?? '/var/www/html/iptables-manager.php')) . '</code>.</p><ul>'; foreach (array_slice($bk, 0, 3) as $f) echo '<li><code>' . h($f) . '</code></li>'; echo '</ul></div>'; }
}

function pg_manual() {   // analisi delle regole manuali: conversione verificata in opzioni esistenti o nuove opzioni personalizzate
    global $M; $S = S_get(); $A = manual_analyze($M, $S); $ro = ($_SESSION['role'] ?? 'viewer') === 'viewer'; $R = $A['rules'];
    $by = fn(string $c) => array_filter($R, fn($r) => $r['cat'] === $c); $nOpt = count($A['opts']) ? array_sum(array_map(fn($o) => count($o['rows']), $A['opts'])) : 0;
    $rowsOpt = $by('option'); $clean = $by('clean'); $keep = $by('keep'); $ex = array_filter($A['groups'], fn($g) => $g['exact']); $nEx = array_sum(array_map(fn($g) => count($g['rows']), $ex));
    echo '<div class=card><h2>Regole manuali: analisi e conversione</h2>';
    if (!$A['total']) echo '<p>✅ Non ci sono regole manuali: tutto il firewall è gestito da opzioni.</p>';
    else echo '<p>Nella bozza ci sono <b>' . $A['total'] . '</b> regole scritte a mano (fuori dai blocchi gestiti). <b>' . ($nOpt + count($rowsOpt)) . '</b> si possono sostituire con opzioni già presenti, <b>' . $nEx . '</b> diventare nuove opzioni personalizzate, <b>' . count($clean) . '</b> eliminare perché inutili, <b>' . count($keep) . '</b> restano manuali.</p>'
        . '<p class=mut>Ogni proposta è <b>provata</b>: la bozza viene rigenerata e il comportamento confrontato con quello attuale. Le voci «esatte» non cambiano il comportamento del firewall. Nulla viene applicato finché non premi <b>Applica</b>.</p>';
    if (!empty($A['partial'])) echo '<div class="msg err">Analisi parziale: troppe regole per verificarle tutte in pochi secondi. <b>Converti le voci esatte proposte</b>, poi ricarica: l\'analisi riparte sulle restanti. Docker/CrowdSec/IOT restano manuali di proposito.</div>' . '<p><form method=post>' . fh('p=manual') . '<input type=hidden name=action value=manual_convert_exact_all><button class=g>🔁 Converti tutte le esatte di questo passaggio</button></form></p>';
    if ($A['drift']) echo '<div class="msg err">I blocchi generati nella bozza non coincidono con le impostazioni (modificati a mano?): la conversione li rigenera dalle impostazioni.</div>';
    if (!$ro && $A['total']) {
        echo '<form method=post>' . fh('p=manual') . '<input type=hidden name=action value=manual_convert>';
        echo '<p><button type=button class=s onclick="document.querySelectorAll(\'.mcb\').forEach(c=>c.checked=true)">Seleziona tutto</button> <button type=button class=s onclick="document.querySelectorAll(\'.mcb\').forEach(c=>c.checked=false)">Nessuna</button></p>';
        if ($A['opts'] || $rowsOpt) {
            echo '<h3>Sostituibili con opzioni già presenti</h3><table>';
            foreach ($A['opts'] as $o) echo '<tr><td><input type=checkbox class=mcb name="sel[]" value="' . h($o['id']) . '" checked></td><td><b>Opzione «' . h(implode(' · ', $o['titles'])) . '»</b> <small class=mut>(' . h($o['opt']) . ')</small><br><small class=mut>sostituisce ' . count($o['rows']) . ' regole: ' . h(implode(' ; ', array_slice($o['rows'], 0, 3))) . (count($o['rows']) > 3 ? ' …' : '') . '</small></td><td><span class="b b-ACCEPT">esatta</span></td></tr>';
            foreach ($rowsOpt as $r) echo '<tr><td><input type=checkbox class=mcb name="sel[]" value="' . h($r['key']) . '" checked></td><td><code>' . h($r['raw']) . '</code></td><td>' . h($r['why']) . ' <span class="b b-ACCEPT">esatta</span></td></tr>';
            echo '</table>';
        }
        if ($A['groups']) {
            echo '<h3>Da trasformare in nuove opzioni personalizzate</h3><p class=mut>Diventano opzioni con un nome, attivabili e disattivabili come le altre. Puoi rinominarle.</p>';
            foreach ($A['groups'] as $g) {
                echo '<div class=card data-iptm-layout="ui-735cd1f81a"><label><input type=checkbox class=mcb name="sel[]" value="' . h($g['id']) . '"' . ($g['exact'] ? ' checked' : '') . '> <b>Crea opzione</b></label> <input name="cname[' . h($g['id']) . ']" value="' . h($g['name']) . '" maxlength=60 data-iptm-layout="ui-45435946ea"> '
                    . ($g['exact'] ? '<span class="b b-ACCEPT">esatta</span>' : '<span class="b b-DROP">non equivalente</span> <small class=mut>l\'ordine di valutazione cambierebbe: selezionabile solo con «forza»</small>') . '<pre data-iptm-layout="ui-9724a43609">' . h(implode("\n", array_map(fn($r) => $r['t'] . ' ' . $r['raw'], $g['rows']))) . '</pre></div>';
            }
        }
        if ($clean) { echo '<h3>Da eliminare (nessun effetto)</h3><table>'; foreach ($clean as $r) echo '<tr><td><input type=checkbox class=mcb name="sel[]" value="' . h($r['key']) . '" checked></td><td><code>' . h($r['raw']) . '</code></td><td>' . h($r['why']) . '</td></tr>'; echo '</table>'; }
        if ($keep) { echo '<h3>Restano manuali</h3><table>'; foreach ($keep as $r) echo '<tr><td>🔒</td><td><code>' . h($r['raw']) . '</code></td><td>' . h($r['why']) . '</td></tr>'; echo '</table>'; }
        echo '<p><label><input type=checkbox name=force value=1> forza anche se il comportamento cambia (poi controlla le differenze in «Applica»)</label></p><p><button class=g>🔁 Converti le voci selezionate nella bozza</button></p></form>';
    }
    echo '</div>';
    if ($A['findings']) {
        echo '<div class=card><h3>Controlli di qualità sulle regole manuali</h3><table>'; $ic = ['bad' => '⛔', 'warn' => '⚠️', 'info' => 'ℹ️'];
        foreach ($A['findings'] as [$r, $lv, $tx]) echo '<tr><td>' . $ic[$lv] . '</td><td><code>' . h($r['t'] . ' ' . $r['raw']) . '</code></td><td>' . h($tx) . '</td></tr>';
        echo '</table></div>';
    }
    $co = $S['custom_opts'] ?? [];
    echo '<div class=card><h3>Opzioni personalizzate (' . count($co) . ')</h3>';
    if (!$co) echo '<p class=mut>Nessuna ancora. Si creano dall\'analisi qui sopra o inserendo direttamente le regole.</p>';
    else {
        echo '<table>';
        foreach ($co as $c) {
            $f = fn(string $act, string $lbl, string $cls = 's', string $cf = '') => '<form method=post style="display:inline">' . fh('p=manual') . '<input type=hidden name=action value=' . $act . '><input type=hidden name=id value="' . h($c['id']) . '"><button class="' . $cls . '"' . ($cf ? '' : '') . '>' . $lbl . '</button></form> ';
            echo '<tr><td>' . (!empty($c['on']) ? '<span class="b b-ACCEPT">attiva</span>' : '<span class="b b-jump">spenta</span>') . '</td><td><b>' . h($c['name']) . '</b><br><small class=mut>' . count($c['rules'] ?? []) . ' regole · posizione: ' . h(str_starts_with((string)$c['an'], 'rk:') ? 'dopo la regola precedente' : ['top' => 'in cima', 'est' => 'dopo le connessioni stabilite', 'end' => 'in fondo'][$c['an']] ?? $c['an']) . '</small><details><summary>regole</summary><pre data-iptm-layout="ui-092af903b2">' . h(implode("\n", array_map(fn($r) => $r['t'] . ' ' . $r['r'], $c['rules'] ?? []))) . '</pre></details></td><td>'
                . ($ro ? '' : $f('copt_toggle', !empty($c['on']) ? 'Spegni' : 'Attiva') . $f('copt_unmanage', 'Riporta a manuali', 's', 'Le regole tornano manuali e l\\\'opzione sparisce. Continuare?') . $f('copt_delete', 'Elimina', 'd', 'Eliminare l\\\'opzione e le sue regole dalla bozza?')) . '</td></tr>';
        }
        echo '</table>';
    }
    if (!$ro) echo '<details><summary>➕ Crea una nuova opzione inserendo le regole</summary><form method=post class=row>' . fh('p=manual') . '<input type=hidden name=action value=copt_add>'
        . '<label class=fl><span>Nome</span><input name=name required maxlength=60 placeholder="es. Accesso Plex dalla LAN"></label>'
        . '<label class=fl><span>Posizione</span><select name=an><option value=end>in fondo (prima della regola finale)</option><option value=est>dopo le connessioni stabilite</option><option value=top>in cima</option></select></label>'
        . '<label class=fl data-iptm-layout="ui-f11255a2fc"><span>Regole (una per riga: «-A INPUT …» oppure «nat -A PREROUTING …»)</span><textarea name=rules rows=5 required data-iptm-layout="ui-32ced6304d" placeholder="-A INPUT -s 192.168.1.0/24 -p tcp --dport 32400 -j ACCEPT"></textarea></label>'
        . '<button class=g>Crea opzione</button></form></details>';
    echo '</div>';
}

/** Offline, non-authoritative IP context: no DNS, whois or geolocation queries. */
function iptm_ip_context_label(string $ip, array $lanCidrs = [], array $known = []): string {
    $addr = explode('/', trim($ip), 2)[0];
    if (!filter_var($addr, FILTER_VALIDATE_IP)) return 'Indirizzo non valido';
    $v4 = filter_var($addr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
    $lan = false;
    foreach ($lanCidrs as $cidr) {
        if (!is_string($cidr) || !str_contains($cidr, '/')) continue;
        [$net, $mask] = explode('/', $cidr, 2);
        if (!ctype_digit($mask) || (int)$mask > ($v4 ? 32 : 128)) continue;
        $a = @inet_pton($addr); $n = @inet_pton($net);
        if ($a === false || $n === false || strlen($a) !== strlen($n)) continue;
        $bits = (int)$mask; $bytes = intdiv($bits, 8); $rest = $bits % 8;
        if (substr($a, 0, $bytes) === substr($n, 0, $bytes)
            && (!$rest || ((ord($a[$bytes]) ^ ord($n[$bytes])) & (255 << (8-$rest))) === 0)) { $lan = true; break; }
    }
    $row = $known[$addr] ?? null;
    if (is_array($row) && !empty($row['mac'])) $lan = true;
    if ($lan) {
        $vendor = trim((string)($row['vendor'] ?? ''));
        $vendor = ($vendor !== '' && strtolower($vendor) !== 'sconosciuto') ? $vendor : 'vendor non presente nel database';
        $name = trim((string)($row['name'] ?? ''));
        return 'LAN · '.(trim((string)($row['kind']??''))!==''?(['iot'=>'IoT','trusted'=>'Dispositivo fidato','guest'=>'Ospite','unknown'=>'Non classificato'][$row['kind']]??'Dispositivo').' · ':'').$vendor.($name !== '' ? ' · '.$name : '');
    }
    if ($v4) {
        // Compare packed prefixes: reliable on 32-bit DietPi/i386 too.
        $packed=inet_pton($addr);
        $matches=static function (string $network, int $bits) use ($packed): bool {
            $bytes=inet_pton($network); $whole=intdiv($bits,8); $rest=$bits%8;
            return $bytes!==false && substr($packed,0,$whole)===substr($bytes,0,$whole)
                && (!$rest || ((ord($packed[$whole])^ord($bytes[$whole])) & (255 << (8-$rest)))===0);
        };
        if ($matches('127.0.0.0',8)) return 'Loopback locale';
        if ($matches('169.254.0.0',16)) return 'Link-local IPv4';
        if ($matches('10.0.0.0',8) || $matches('172.16.0.0',12) || $matches('192.168.0.0',16)) return 'Rete privata · fuori dalle LAN configurate';
        if ($matches('100.64.0.0',10)) return 'Indirizzo CGNAT del provider';
        if ($matches('224.0.0.0',4)) return 'Indirizzo multicast/riservato';
        if ($matches('192.0.2.0',24) || $matches('198.51.100.0',24) || $matches('203.0.113.0',24)) return 'Indirizzo di documentazione';
        return 'Internet · vendor non identificabile da IP';
    }
    $bytes = inet_pton($addr);
    if ($addr === '::1') return 'Loopback locale IPv6';
    if ((ord($bytes[0]) & 0xfe) === 0xfc) return 'IPv6 privato ULA · fuori dalle LAN configurate';
    if (ord($bytes[0]) === 0xfe && (ord($bytes[1]) & 0xc0) === 0x80) return 'IPv6 link-local';
    if (ord($bytes[0]) === 0xff) return 'IPv6 multicast';
    return 'Internet IPv6 · vendor non identificabile da IP';
}
/** Resolve vendors only from local ARP/lease and the existing offline IEEE OUI DB. */
function iptm_ip_context_inventory(): array {
    static $cache=null;
    if ($cache !== null) return $cache;
    $cache=[];
    $classes=(array)(S_get()['iot_devices']??[]);
    $inventory=iptm_security_read('mac-inventory');
    $vendors=[];
    foreach ((array)($inventory['devices'] ?? []) as $d) {
        if (!is_array($d)) continue;
        $vendor=(string)($d['vendor'] ?? '');
        foreach ((array)($d['addresses'] ?? []) as $ip) {
            if (is_string($ip) && filter_var($ip, FILTER_VALIDATE_IP)) $cache[$ip]=['mac'=>(string)($d['mac']??''),'vendor'=>$vendor,'kind'=>$classes[strtolower((string)($d['mac']??''))]??'unknown'];
        }
        $mac=strtolower((string)($d['mac']??''));
        if (preg_match('/^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/', $mac)) $vendors[$mac]=$vendor;
    }
    foreach (devices() as $d) {
        $ip=(string)($d['ip']??''); $mac=strtolower((string)($d['mac']??''));
        if (!filter_var($ip, FILTER_VALIDATE_IP)) continue;
        $cache[$ip]=['mac'=>$mac,'vendor'=>$vendors[$mac]??($cache[$ip]['vendor']??''),'name'=>(string)($d['name']??''),'kind'=>$classes[$mac]??'unknown'];
    }
    return $cache;
}
function iptm_ip_html(string $ip, string $port=''): string {
    $ip=trim($ip);
    if ($ip==='') return '<span class=mut>non rilevato</span>';
    static $lan=null;
    if ($lan===null) {
        $setting=S_get(); $nets=$setting['lan_nets']??''; $lan=is_array($nets)?$nets:(preg_split('/[\s,;]+/',trim((string)$nets)) ?: []);
    }
    // Only private/local addresses need a MAC vendor lookup; public IP never goes online.
    $context=iptm_ip_context_label($ip,$lan,[]);
    if (!str_starts_with($context,'Internet') && !str_starts_with($context,'Indirizzo di documentazione')) {
        $context=iptm_ip_context_label($ip,$lan,iptm_ip_context_inventory());
    }
    return '<span class="iptm-ip-context"><code>'.h($ip.$port).'</code><small>'.h($context).'</small></span>';
}

function pg_conns() {
    [$c, $o, $e] = priv('conns'); echo '<div class=card><h2>Connessioni attive</h2>';
    if ($c) { echo '<p class=mut>Non leggibili (serve il modulo nf_conntrack): ' . h($e) . '</p></div>'; return; }
    $cn = conn_parse($o); $by = []; $src = []; foreach ($cn as $x) { $by[$x['proto'] . ($x['state'] ? '/' . $x['state'] : '')] = ($by[$x['proto'] . ($x['state'] ? '/' . $x['state'] : '')] ?? 0) + 1; $src[$x['src']] = ($src[$x['src']] ?? 0) + 1; } arsort($by); arsort($src); $tb = []; foreach ($cn as $x) $tb[$x['src']] = ($tb[$x['src']] ?? 0) + (int)$x['bytes']; arsort($tb);
    echo '<p class=mut>' . count($cn) . ' connessioni. ' . implode(' · ', array_map(fn($k, $v) => h($k) . ' <b>' . $v . '</b>', array_keys($by), $by)) . '</p><div class=iptm-stat-sources><div class=card><h3>Origini più attive</h3><table class=iptm-conns-summary><thead><tr><th scope=col>Dispositivo / origine</th><th scope=col>Conn.</th><th scope=col>Azioni</th></tr></thead><tbody>';
    foreach (array_slice($src, 0, 8, true) as $k => $v) echo '<tr><td>' . iptm_ip_html((string)$k) . '</td><td>' . $v . '</td><td>' . blk_btn($k, 'p=conns') . '</td></tr>'; echo '</tbody></table></div><div class=card><h3>Più traffico (origine)</h3><table class=iptm-conns-summary><thead><tr><th scope=col>Dispositivo / origine</th><th scope=col>Traffico</th></tr></thead><tbody>'; foreach (array_slice($tb, 0, 8, true) as $k => $v) echo '<tr><td>' . iptm_ip_html((string)$k) . '</td><td>' . hb((int)$v) . '</td></tr>'; echo '</tbody></table><p class=mut>Richiede la contabilità conntrack (Hardening kernel).</p></div></div>
<p><input id=tfilter data-table="#ctab" placeholder="Filtra (IP, porta, protocollo, stato)…"></p><div class="iptm-conns-scroll" data-iptm-layout="scroll" role="region" aria-label="Elenco connessioni" tabindex="0"><table id="ctab" class="iptm-conns-table"><colgroup><col class="ct-proto"><col class="ct-state"><col class="ct-source"><col class="ct-dest"><col class="ct-traffic"><col class="ct-ttl"><col class="ct-actions"></colgroup><thead><tr><th scope=col>Proto</th><th scope=col>Stato</th><th scope=col>Origine</th><th scope=col>Destinazione</th><th scope=col>Traffico</th><th scope=col>TTL</th><th scope=col>Azioni</th></tr></thead><tbody>';
    usort($cn, fn($a, $b) => $b['bytes'] <=> $a['bytes']);
    foreach (array_slice($cn, 0, 300) as $x) echo '<tr><td data-label="Proto" class="ct-proto">' . h($x['proto']) . '</td><td data-label="Stato" class="ct-state">' . h($x['state']) . '</td><td data-label="Origine" class="ct-source">' . iptm_ip_html((string)$x['src'], $x['sport'] !== '' ? ':'.$x['sport'] : '') . '</td><td data-label="Destinazione" class="ct-dest">' . iptm_ip_html((string)$x['dst'], $x['dport'] !== '' ? ':'.$x['dport'] : '') . '</td><td data-label="Traffico" class="ct-traffic">' . hb($x['bytes']) . '</td><td data-label="TTL" class="ct-ttl">' . h((string)$x['ttl']) . 's</td><td data-label="Azioni" class="ct-actions"><div class="ops iptm-conns-actions">
<form method=post>' . fh('p=conns') . '<input type=hidden name=action value=conn_kill>' . implode('', array_map(fn($k) => '<input type=hidden name=' . $k . ' value="' . h($x[$k]) . '">', ['proto', 'src', 'dst', 'sport', 'dport'])) . '<button class="s sm" title="Chiudi questa connessione" aria-label="Chiudi questa connessione">Chiudi</button></form>' . blk_btn($x['src'], 'p=conns') . '</div></td></tr>';
    echo '</tbody></table></div></div>';
}
/**
 * One logical device per MAC across IEEE/neighbor inventory and DHCP/ARP leases.
 * Never merge distinct MACs merely because a stale DHCP lease reuses an IP.
 * MAC-less records remain separate IP rows (no inferred vendor or classification).
 * Pure: suitable for regression tests without kernel/privileged commands.
 */
function iptm_devices_unified(array $inventory, array $network, array $classifications): array {
    $rows = [];
    $mac_key = static function ($raw): string {
        if (!is_string($raw)) return '';
        $mac = strtolower(str_replace('-', ':', trim($raw)));
        if (!preg_match('/^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/D', $mac)) return '';
        if ($mac === '00:00:00:00:00:00' || (hexdec(substr($mac, 0, 2)) & 1)) return '';
        return $mac;
    };
    $ensure = static function (string $key, string $mac) use (&$rows): void {
        if (!isset($rows[$key])) $rows[$key] = [
            'mac' => $mac, 'ips' => [], 'names' => [], 'interfaces' => [],
            'states' => [], 'vendor' => '', 'iot_vendor_hint' => false,
            'locally_administered' => false, 'has_inventory' => false,
        ];
    };
    $append = static function (array &$items, $value): void {
        if (!is_string($value)) return;
        $value = trim($value);
        if ($value !== '' && !in_array($value, $items, true)) $items[] = $value;
    };
    foreach ($inventory as $item) {
        if (!is_array($item)) continue;
        $mac = $mac_key($item['mac'] ?? null);
        if ($mac === '') continue;
        $key = 'mac:' . $mac;
        $ensure($key, $mac);
        $row = &$rows[$key];
        foreach ((array)($item['addresses'] ?? []) as $ip) $append($row['ips'], $ip);
        foreach ((array)($item['interfaces'] ?? []) as $interface) $append($row['interfaces'], $interface);
        $row['vendor'] = is_string($item['vendor'] ?? null) ? trim($item['vendor']) : '';
        $row['iot_vendor_hint'] = !empty($item['iot_vendor_hint']);
        $row['locally_administered'] = !empty($item['locally_administered']);
        $row['has_inventory'] = true;
        unset($row);
    }
    foreach ($network as $item) {
        if (!is_array($item)) continue;
        $ip = is_string($item['ip'] ?? null) ? trim($item['ip']) : '';
        $mac = $mac_key($item['mac'] ?? null);
        // Never invent a MAC; an unrecognized address gets its own record.
        if ($ip === '' && $mac === '') continue;
        $key = $mac !== '' ? 'mac:' . $mac : 'ip:' . $ip;
        $ensure($key, $mac);
        $row = &$rows[$key];
        $append($row['ips'], $ip);
        $append($row['names'], $item['name'] ?? '');
        $append($row['interfaces'], $item['if'] ?? '');
        $append($row['states'], $item['st'] ?? '');
        unset($row);
    }
    $classified = [];
    foreach ($classifications as $mac => $kind) {
        $key = $mac_key($mac);
        if ($key !== '' && in_array($kind, ['iot','trusted','guest','unknown'], true)) $classified[$key] = $kind;
    }
    foreach ($rows as &$row) {
        $row['kind'] = $row['mac'] !== '' ? ($classified[$row['mac']] ?? 'unknown') : 'unknown';
        // A complete MAC-only record is displayed even without DHCP/ARP data.
        sort($row['ips'], SORT_NATURAL);
    }
    unset($row);
    $rows = array_values($rows);
    usort($rows, static function (array $left, array $right): int {
        $la = $left['ips'][0] ?? ''; $ra = $right['ips'][0] ?? '';
        if ($la === '') return $ra === '' ? strcmp($left['mac'], $right['mac']) : 1;
        if ($ra === '') return -1;
        $li = filter_var($la, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ? ip2long($la) : false;
        $ri = filter_var($ra, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ? ip2long($ra) : false;
        if ($li !== false && $ri !== false) {
            $cmp = ($li & 0xffffffff) <=> ($ri & 0xffffffff);
            if ($cmp) return $cmp;
        }
        return strnatcasecmp($la, $ra) ?: strcmp($left['mac'], $right['mac']);
    });
    return $rows;
}
function pg_devices() {
    $inventory = iptm_security_read('mac-inventory');
    $state = S_get();
    $admin = (($_SESSION['role'] ?? 'viewer') === 'admin');
    $rows = iptm_devices_unified(
        !empty($inventory['ok']) ? (array)($inventory['devices'] ?? []) : [],
        devices(), (array)($state['iot_devices'] ?? [])
    );
    $classLabels = ['unknown' => 'Da riconoscere', 'iot' => 'IoT', 'trusted' => 'Fidato', 'guest' => 'Ospite'];
    $selectable = 0;
    echo '<div class=card><h2>Dispositivi · inventario unificato</h2>';
    echo '<p class=mut>Unica vista di cache ARP, lease DHCP e database vendor IEEE locale. La classificazione IoT è manuale; per generare policy usa <a href="?p=zones">Zone di rete</a>. Senza VLAN, il filtro protegge soltanto il traffico che attraversa DietPi.</p>';
    if (empty($inventory['ok'])) {
        echo '<div class="msg warn">Inventario MAC/vendor non disponibile: sono mostrati i dispositivi rilevati da ARP/DHCP. Il vendor non viene dedotto e le classificazioni salvate restano inalterate.</div>';
    }
    if ($admin) {
        echo '<form method=post data-iptm-layout="ui-536fa527eb">' . fh('p=devices') . '<input type=hidden name=action value=oui_update><button class=s>Aggiorna database IEEE</button><progress class=iptm-progress hidden></progress><span role=status class=mut></span></form>';
    }
    echo '<p><input id=tfilter type=search data-table="#dtab" placeholder="Filtra per IP, nome, MAC, vendor, classe o stato…" aria-label="Filtra dispositivi"></p>';
    if ($admin && array_filter($rows, static fn($x) => $x['mac'] !== '')) {
        echo '<form id=iotbulk method=post data-iptm-layout="ui-c45e284a36">' . fh('p=devices') . '<input type=hidden name=action value=iot_classify_many>';
        echo '<label>Classifica i selezionati: ' . sel('kind', $classLabels, 'unknown') . '</label> <button class=g>Salva selezione</button> '
            . '<button class=s type=button onclick="document.querySelectorAll(&quot;#dtab .iot-bulk-cb&quot;).forEach(x=>x.checked=true)">Seleziona tutti</button> '
            . '<button class=s type=button onclick="document.querySelectorAll(&quot;#dtab .iot-bulk-cb&quot;).forEach(x=>x.checked=false)">Nessuno</button>';
        echo '<progress class=iptm-progress hidden></progress><span role=status class=mut></span></form>';
    }
    echo '<p class=mut>' . count($rows) . ' dispositivi unificati · ' . count(array_filter($rows, static fn($x) => $x['kind'] === 'iot')) . ' classificati IoT. Se un dispositivo possiede più indirizzi, vengono mostrati nella stessa riga. I flag di filtro generano solo una bozza IPv4: verificare e applicare con rollback. I dispositivi sulla stessa rete L2 che non attraversano DietPi non vengono filtrati.</p>';
    echo '<div data-iptm-layout="scroll"><table id=dtab><tr><th>Seleziona</th><th>IP</th><th>Nome</th><th>MAC</th><th>Vendor</th><th>Classe IoT</th><th>Interfaccia</th><th>Stato</th><th>Azioni</th></tr>';
    foreach ($rows as $i => $row) {
        $mac = $row['mac']; $ips = $row['ips'];
        $canBulk = $admin && $mac !== '' && $selectable < 120;
        if ($canBulk) ++$selectable;
        $vendor = $row['vendor'] !== '' ? $row['vendor'] : '—';
        $vendorNote = $row['locally_administered'] ? ' <span class=mut title="MAC locale o randomizzato; il vendor potrebbe non essere attendibile">(MAC locale)</span>' : '';
        $hint = $row['iot_vendor_hint'] && !$row['locally_administered'] ? ' <span class="b b-jump" title="Suggerimento dal vendor: non modifica la classificazione">IoT possibile</span>' : '';
        $filterText = implode(' ', array_merge($ips, $row['names'], $row['interfaces'], $row['states'], [$mac, $vendor, $classLabels[$row['kind']] ?? $row['kind']]));
        echo '<tr data-filter="' . h($filterText) . '">';
        echo '<td>' . ($canBulk ? '<input type=checkbox class=iot-bulk-cb form=iotbulk name="macs[]" value="' . h($mac) . '" aria-label="Seleziona ' . h($mac) . '">' : '—') . '</td>';
        echo '<td>' . ($ips ? h(implode(', ', $ips)) : '—') . '</td>';
        echo '<td>' . ($row['names'] ? h(implode(', ', $row['names'])) : '—') . '</td>';
        echo '<td>' . ($mac !== '' ? '<code>' . h($mac) . '</code>' : '—') . '</td>';
        echo '<td>' . h($vendor) . $vendorNote . $hint . '</td>';
        echo '<td>';
        if ($admin && $mac !== '') {
            echo '<form method=post style="display:flex;gap:5px;align-items:center;flex-wrap:nowrap">' . fh('p=devices')
                . '<input type=hidden name=action value=iot_classify><input type=hidden name=mac value="' . h($mac) . '">'
                . sel('kind', $classLabels, $row['kind'], 'aria-label="Classe IoT di ' . h($mac) . '"')
                . '<button class="s sm">Salva</button><progress class=iptm-progress hidden></progress><span role=status class=mut></span></form>';
        } else echo $mac !== '' ? h($classLabels[$row['kind']] ?? $row['kind']) : '—';
        echo '</td>';
        echo '<td>' . ($row['interfaces'] ? h(implode(', ', $row['interfaces'])) : '—') . '</td>';
        echo '<td>' . ($row['states'] ? h(implode(', ', $row['states'])) : '—') . '</td>';
        echo '<td class=ops>';
        $target = $mac !== '' ? $mac : ($ips[0] ?? '');
        if ($target !== '') echo '<a href="?p=access&amp;add=' . h(rawurlencode($target)) . '" title="Crea restrizione di accesso" aria-label="Crea restrizione per ' . h($target) . '">🚫</a> ';
        if ($mac !== '' && $admin) echo '<form method=post style="display:inline">' . fh('p=devices')
            . '<input type=hidden name=action value=wol><input type=hidden name=mac value="' . h($mac) . '">'
            . '<button class="s sm" title="Wake-on-LAN" aria-label="Wake-on-LAN per ' . h($mac) . '">⏻</button></form>';
        echo '</td></tr>';
    }
    if (!$rows) echo '<tr><td colspan=9 class=mut>Nessun dispositivo rilevato.</td></tr>';
    echo '</table></div>';
    if ($admin && count(array_filter($rows, static fn($x) => $x['mac'] !== '')) > 120) {
        echo '<p class=mut>La modifica multipla è limitata a 120 MAC per operazione; per gli altri dispositivi usa il pulsante Salva della rispettiva riga.</p>';
    }
    echo '</div>';
}

function su_info(): array {
    return kc('suinfo', function () {
        [$c, $o] = priv('su-info');
        $r = ['installed' => false, 'version' => '', 'service' => '', 'enabled' => '', 'iface' => '', 'home_net' => '', 'rule_files' => '0', 'fast_log' => '', 'eve_log' => '', 'origin' => '', 'bin' => '', 'unit' => '', 'yaml' => '', 'log_dir' => '', 'rule_dir' => '', 'socket' => ''];
        if ($c !== 0) return $r;
        foreach (explode("\n", trim($o)) as $l) {
            $x = preg_split('/\s+/', trim($l), 2); if (count($x) < 2) continue;
            if ($x[0] === 'installed') $r['installed'] = $x[1] === 'yes';
            elseif (array_key_exists($x[0], $r)) $r[$x[0]] = $x[1];
        }
        return $r;
    });
}
function pg_ips() {
    $S = S_get(); $ro = ($_SESSION['role'] ?? 'viewer') === 'viewer'; $info = su_info();
    $tab = (string)($_GET['t'] ?? 'stato'); if (!in_array($tab, ['stato', 'avvisi', 'sorgenti', 'regole', 'stats', 'config', 'ecosistema'], true)) $tab = 'stato';
    [$eveRc,$eveOut] = priv('suricata-eve-summary');
    $eve = $eveRc === 0 ? json_decode($eveOut, true) : null;
    if (is_array($eve) && !empty($eve['available'])) {
        echo '<section class="card"><h3>Eventi EVE · riepilogo locale</h3>';
        echo '<p>Alert nell’ultima finestra letta: <b>'.(int)($eve['alerts']??0).'</b> (massimo 512 KiB, nessun indirizzo IP esposto).</p>';
        echo '<table><tr><th>SID</th><th>Severità</th><th>Occorrenze</th></tr>';
        foreach (($eve['top_signatures']??[]) as $entry) {
            if (!is_array($entry)) continue;
            echo '<tr><td>'.(int)($entry['sid']??0).'</td><td>'.(int)($entry['severity']??0).'</td><td>'.(int)($entry['count']??0).'</td></tr>';
        }
        echo '</table></section>';
    }
    if ($tab === 'stato' || $tab === 'avvisi') (function_exists('iptm_operator_insights') ? iptm_operator_insights('suricata') : null);
    echo '<div class=card><h2>Suricata (IDS/IPS)</h2><p class=mut>Gestione guidata di servizio, interfaccia di cattura, sorgenti regole (suricata-update), regole avanzate (HOME_NET, local.rules, suppress SID), avvisi e statistiche.</p>';
    if (!$info['installed']) {
        echo '<div class="msg err">Suricata non risulta installato. Vai in <a href="?p=progs">Strumenti → Programmi</a> e installa «Suricata (IDS)» scegliendo l\'interfaccia da monitorare (se l\'hai compilato da sorgenti, assicurati che <code>suricata</code> sia in <code>/usr/local/bin</code> e rilancia l\'installer).</div></div>';
        return;
    }
    $pill = function ($id, $label) use ($tab) {
        return '<a class="' . ($tab === $id ? 'on' : '') . '" href="?p=ips&t=' . $id . '">' . $label . '</a>';
    };
    echo '<div class=tabs>' . $pill('stato', 'Stato') . $pill('avvisi', 'Avvisi') . $pill('sorgenti', 'Sorgenti regole') . $pill('regole', 'Regole avanzate') . $pill('stats', 'Statistiche') . $pill('config', 'Configurazione') . $pill('ecosistema', 'Integrazioni') . '</div>';

    if ($tab === 'ecosistema') {
        if(!$ro){
            echo '<section class="card"><h3>Fonti Suricata · gestione transazionale</h3><p class="mut">Gestione operativa tramite suricata-update; dopo la modifica vengono ricostruite e testate le regole senza reload automatico in caso di errore.</p>';
            echo '<form method="post">'.fh('p=ips&t=ecosistema').'<input type="hidden" name="action" value="su_source_stage">';
            echo '<label>Nome fonte (es. et/open)<input required maxlength="96" name="source_name" pattern="[A-Za-z0-9_-]+/[A-Za-z0-9_.-]+" placeholder="et/open"></label>';
            echo '<label>Operazione<select name="source_mode"><option value="enable">Abilita</option><option value="disable">Disabilita</option></select></label><button class="s">Anteprima sorgente</button></form>';
            $source=$_SESSION['iptm_suricata_source']??null;
            if(is_array($source)&&time()-(int)($source['created']??0)<900){
                $hash=(string)($source['sha256']??'');
                echo '<form method="post">'.fh('p=ips&t=ecosistema').'<input type="hidden" name="action" value="su_source_apply"><input type="hidden" name="source_sha256" value="'.h($hash).'"><p>Fonte: '.h((string)$source['source']).' · SHA-256: <code>'.h($hash).'</code></p><button class="g">Applica modifica e verifica regole</button></form>';
            }
            echo '</section>';
        }

        [$bridgeRc, $bridgeOut] = priv('integration-status');
        $bridge = $bridgeRc === 0 ? json_decode($bridgeOut, true) : null;
        if (is_array($bridge)) {
            $si = $bridge['suricata'] ?? [];
            echo '<h3>Inventario Suricata verificato</h3>';
            echo '<p>suricata-update: <b>'.(!empty($si['suricata_update'])?'rilevato':'assente').'</b> · EVE JSON: <b>'.(!empty($si['eve_present'])?'presente':'assente').'</b> · file regole: <b>'.(!empty($si['rules_present'])?'presente':'assente').'</b></p>';
            if (!empty($si['enabled_sources']) && is_array($si['enabled_sources'])) {
                echo '<details><summary>Sorgenti di regole attive</summary><pre>'.h(implode("\n", $si['enabled_sources'])).'</pre></details>';
            }
        }
        echo '<h3>Estensioni Suricata</h3><p class="mut">Le applicazioni esterne analizzano EVE JSON o curano le regole; non si sostituiscono automaticamente al processo IDS/IPS IPTM.</p>';
        echo '<table><tr><th>Progetto</th><th>Ruolo</th></tr>';
        echo '<tr><td><a target="_blank" rel="noopener noreferrer" href="https://github.com/StamusNetworks/scirius">Scirius</a></td><td>Gestione dei set di regole</td></tr>';
        echo '<tr><td><a target="_blank" rel="noopener noreferrer" href="https://github.com/jasonish/evebox">EveBox</a></td><td>Consultazione e triage degli eventi EVE JSON</td></tr>';
        echo '<tr><td><a target="_blank" rel="noopener noreferrer" href="https://github.com/dzidulajubilee/Watcher">Watcher</a></td><td>Dashboard live, eventi e avvisi</td></tr></table>';
        echo '<p class="mut">Su hardware a risorse limitate: preferire un solo consumer EVE locale e disabilitare stack pesanti. Ogni modifica alle regole richiede suricata -T e rollback.</p>';
    }

    if ($tab === 'stato') {
        $badge = fn($s) => $s === 'active' ? '<span class="b b-ACCEPT">active</span>' : '<span class="b b-DROP">' . h($s ?: '?') . '</span>';
        echo '<table><tr><th>Voce</th><th>Valore</th></tr>';
        echo '<tr><td>Servizio</td><td>' . $badge($info['service']) . ' · enabled: ' . h($info['enabled']) . '</td></tr>';
        echo '<tr><td>Versione</td><td>' . h($info['version'] ?: '—') . ' · installazione: ' . h($info['origin'] ?: '?') . ' · unit systemd: ' . h($info['unit'] ?: '?') . '</td></tr>';
        echo '<tr><td>Percorsi rilevati</td><td><code>' . h($info['yaml'] ?: '—') . '</code><br><span class=mut>log: <code>' . h($info['log_dir'] ?: '—') . '</code> · regole: <code>' . h($info['rule_dir'] ?: '—') . '</code></span></td></tr>';
        echo '<tr><td>Interfaccia (af-packet)</td><td><code>' . h($info['iface'] ?: '—') . '</code></td></tr>';
        echo '<tr><td>HOME_NET</td><td><code>' . h($info['home_net'] ?: '—') . '</code></td></tr>';
        echo '<tr><td>File regole</td><td>' . h($info['rule_files']) . '</td></tr>';
        echo '<tr><td>Log</td><td>fast.log: ' . h($info['fast_log']) . ' · eve.json: ' . h($info['eve_log']) . '</td></tr></table>';
        if (!$ro) {
            echo '<form method=post class=ops data-iptm-layout="mt10">' . fh('p=ips&t=stato') . '<input type=hidden name=action value=su_svc>';
            echo sel('act', ['restart' => 'Riavvia', 'reload' => 'Ricarica', 'start' => 'Avvia', 'stop' => 'Ferma', 'status' => 'Stato'], 'restart');
            echo ' <button class=s>Esegui</button></form>';
            echo '<form method=post class=ops>' . fh('p=ips&t=stato') . '<input type=hidden name=action value=su_update><button class=g>Aggiorna regole (suricata-update)</button></form>';
            echo '<p class=mut>L\'aggiornamento scarica le regole dalle sorgenti abilitate e tenta il reload a caldo.</p>';
        }
    }

    if ($tab === 'avvisi') {
        [$c, $o] = priv('su-alerts', null, ['120']);
        $a = ips_parse($o);
        if ($a) {
            $sg = []; $sr = [];
            foreach ($a as $x) { $sg[$x['sig']] = ($sg[$x['sig']] ?? 0) + 1; $sr[$x['src']] = ($sr[$x['src']] ?? 0) + 1; }
            arsort($sg); arsort($sr);
            echo '<div class=row><div><h3>Firme più frequenti</h3><table>';
            foreach (array_slice($sg, 0, 10, true) as $k => $v) echo '<tr><td>' . iptm_ip_html((string)$k) . '</td><td>' . $v . '</td></tr>';
            echo '</table></div><div><h3>Origini più frequenti</h3><table>';
            foreach (array_slice($sr, 0, 10, true) as $k => $v) echo '<tr><td>' . iptm_ip_html((string)$k) . '</td><td>' . $v . '</td><td>' . (filter_var($k, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ? blk_btn($k, 'p=ips&t=avvisi') : '') . '</td></tr>';
            echo '</table></div></div>';
            echo '<h3>Ultimi avvisi</h3><div data-iptm-layout="scroll"><table><tr><th>Ora</th><th>Firma</th><th>Prio</th><th>Origine</th><th>Destinazione</th></tr>';
            foreach (array_slice($a, 0, 80) as $x) echo '<tr><td>' . h($x['t']) . '</td><td>' . h($x['sig']) . '</td><td>' . h($x['pri']) . '</td><td>' . h($x['src'] . ':' . $x['sport']) . '</td><td>' . h($x['dst'] . ':' . $x['dport']) . '</td></tr>';
            echo '</table></div>';
        } else {
            echo '<p class=mut>Nessun avviso nel log (fast.log / eve.json) oppure Suricata non sta generando alert.</p>';
            if (trim($o) !== '') echo '<pre data-iptm-layout="ui-63246f7e21">' . h($o) . '</pre>';
        }
    }

    if ($tab === 'sorgenti') {
        [$c, $o] = priv('su-sources');
        $parts = preg_split('/^### /m', trim($o));
        $en = $av = '';
        foreach ($parts as $part) {
            if (str_starts_with($part, 'enabled')) $en = trim(substr($part, strlen('enabled')));
            if (str_starts_with($part, 'available')) $av = trim(substr($part, strlen('available')));
        }
        echo '<p class=mut>Gestione sorgenti di <code>suricata-update</code>. Dopo enable/disable esegui «Aggiorna regole» nella scheda Stato.</p>';
        echo '<h3>Sorgenti abilitate</h3><pre>' . h($en !== '' ? $en : '(nessuna o comando non disponibile)') . '</pre>';
        if (!$ro) {
            echo '<form method=post class=ops>' . fh('p=ips&t=sorgenti') . '<input type=hidden name=action value=su_source_enable>';
            echo '<input name=name list=susrc placeholder="et/open oppure oisf/trafficid" required data-iptm-layout="ui-45435946ea"> <button class=g>Abilita sorgente</button></form>';
            echo '<form method=post class=ops>' . fh('p=ips&t=sorgenti') . '<input type=hidden name=action value=su_source_disable>';
            echo '<input name=name placeholder="nome sorgente da disabilitare" required data-iptm-layout="ui-45435946ea"> <button class=s>Disabilita sorgente</button></form>';
            $suggest = ['et/open', 'oisf/trafficid', 'sslbl/ssl-fp-blacklist', 'et/pro'];
            echo '<datalist id=susrc>'; foreach ($suggest as $s) echo '<option value="' . h($s) . '">'; echo '</datalist>';
            echo '<p class=mut>Esempi: ' . implode(', ', array_map(fn($s) => '<code>' . h($s) . '</code>', $suggest)) . '</p>';
        }
        echo '<h3>Sorgenti disponibili (anteprima)</h3><pre data-iptm-layout="ui-73faaab036">' . h($av !== '' ? $av : '—') . '</pre>';
    }

    if ($tab === 'regole') {
        // HOME_NET
        $hn = $info['home_net'] ?: '';
        $hn = trim($hn, '"');
        if (!$ro) {
            echo '<h3>HOME_NET</h3><p class=mut>Reti «di casa» usate dalle regole (variabile <code>$HOME_NET</code>). Esempi: <code>192.168.1.0/24</code> oppure <code>192.168.0.0/16,10.0.0.0/8</code>. Usa <code>any</code> solo se sai cosa fai.</p>';
            echo '<form method=post class=row>' . fh('p=ips&t=regole') . '<input type=hidden name=action value=su_homenet>';
            echo '<label class=fl data-iptm-layout="ui-83725d2c6e"><span>HOME_NET</span><input name=homenet value="' . h($hn !== '-' ? $hn : ($S['lan_nets'] ?? '192.168.0.0/16')) . '" placeholder="192.168.1.0/24,10.0.0.0/8"></label>';
            echo '<p class=sticky><button class=g>Salva HOME_NET e ricarica</button></p></form>';
        } else {
            echo '<p>HOME_NET: <code>' . h($hn ?: '—') . '</code></p>';
        }
        // Elenco file regole
        echo '<h3>File di regole caricati</h3>';
        [$c, $o] = priv('su-rules-list');
        $files = []; $localpath = '';
        foreach (explode("\n", trim($o)) as $l) {
            $x = preg_split('/\s+/', trim($l), 4);
            if (($x[0] ?? '') === 'file') $files[] = ['name' => $x[1] ?? '', 'lines' => (int)($x[2] ?? 0), 'active' => (int)($x[3] ?? 0)];
            if (($x[0] ?? '') === 'localpath') $localpath = $x[1] ?? '';
            if (($x[0] ?? '') === '###' && ($x[1] ?? '') === 'dir') echo '<p class=mut>Cartella: <code>' . h($x[2] ?? '') . '</code></p>';
        }
        if ($files) {
            echo '<div data-iptm-layout="scroll"><table><tr><th>File</th><th>Righe</th><th>Regole attive</th></tr>';
            foreach ($files as $f) echo '<tr><td><code>' . h($f['name']) . '</code></td><td>' . $f['lines'] . '</td><td>' . $f['active'] . '</td></tr>';
            echo '</table></div>';
        } else echo '<p class=mut>Nessun file regole trovato (esegui «Aggiorna regole» nella scheda Sorgenti).</p>';
        // local.rules
        echo '<h3>Regole locali (local.rules)</h3><p class=mut>Regole scritte da te (sintassi Suricata). Vengono testate con <code>suricata -T</code> prima del salvataggio; in caso di errore il file precedente viene ripristinato.</p>';
        [$c2, $loc] = priv('su-local-get');
        $locBody = $loc; $locFile = $localpath;
        if (preg_match('/^### path (.+)$/m', $loc, $m)) { $locFile = trim($m[1]); $locBody = preg_replace('/^### path .+\n?/', '', $loc); }
        if (!$ro) {
            echo '<form method=post>' . fh('p=ips&t=regole') . '<input type=hidden name=action value=su_local_save>';
            if ($locFile) echo '<p class=mut>File: <code>' . h($locFile) . '</code></p>';
            echo '<textarea name=local_rules rows=14 spellcheck=false placeholder="alert http $HOME_NET any -> $EXTERNAL_NET any (msg:\"esempio\"; sid:9000001; rev:1;)">' . h($locBody) . '</textarea>';
            echo '<p class=sticky><button class=g>Salva regole locali e ricarica</button></p></form>';
            echo '<details><summary>Esempi di regole</summary><pre>';
            echo h("alert http \$HOME_NET any -> \$EXTERNAL_NET any (msg:\"IPTM HTTP verso Internet\"; flow:established,to_server; sid:9000001; rev:1;)\n");
            echo h("alert dns \$HOME_NET any -> any any (msg:\"IPTM query DNS\"; dns.query; content:\".onion\"; sid:9000002; rev:1;)\n");
            echo h("drop tcp \$EXTERNAL_NET any -> \$HOME_NET 22 (msg:\"IPTM drop SSH dal WAN\"; flow:to_server; sid:9000003; rev:1;)\n");
            echo '</pre><p class=mut>SID locali: usa range 9000000–9999999 per non collidere con Emerging Threats.</p></details>';
        } else {
            echo '<pre data-iptm-layout="ui-56740a8d05">' . h($locBody) . '</pre>';
        }
        // Suppress SID
        if (!$ro) {
            echo '<h3>Sopprimi firma (SID)</h3><p class=mut>Disattiva un SID rumoroso senza toccare i file scaricati da suricata-update. Usa il numero SID dagli avvisi.</p>';
            echo '<form method=post class=row>' . fh('p=ips&t=regole') . '<input type=hidden name=action value=su_disable_sid>';
            echo '<label class=fl><span>SID</span><input name=sid pattern="[0-9]{1,10}" required placeholder="2100498" data-iptm-layout="mw140"></label>';
            echo '<p class=sticky><button class=s>Sopprimi SID</button></p></form>';
        }
        echo '<p class=mut>Dopo modifiche a HOME_NET o local.rules Suricata viene ricaricato automaticamente se è attivo. Controlla la scheda <b>Avvisi</b> e <b>Statistiche</b>.</p>';
    }

    if ($tab === 'stats') {
        [$c, $o] = priv('su-stats');
        echo '<p class=mut>Contatori via <code>suricatasc</code> (se disponibile) oppure coda di <code>stats.log</code>.</p>';
        echo '<pre data-iptm-layout="ui-1ebb464fcb">' . h(trim($o) !== '' ? $o : '—') . '</pre>';
    }

    if ($tab === 'config') {
        $ifaces = array_keys(sys_ifaces());
        if (!$ro) {
            echo '<h3>Interfaccia di cattura</h3>';
            echo '<form method=post class=ops>' . fh('p=ips&t=config') . '<input type=hidden name=action value=su_iface>';
            echo sel('iface', array_combine($ifaces, $ifaces), $info['iface'] !== '-' ? $info['iface'] : ($S['wan_if'] ?? ($ifaces[0] ?? '')));
            echo ' <button class=g>Imposta e riavvia</button></form>';
            echo '<form method=post class=ops>' . fh('p=ips&t=config') . '<input type=hidden name=action value=su_test><button class=s>Test configurazione (suricata -T)</button></form>';
        }
        [$c, $o] = priv('su-config');
        echo '<h3>Estratto suricata.yaml</h3><pre data-iptm-layout="ui-b679b81a1b">' . h(trim($o) !== '' ? $o : '—') . '</pre>';
        echo '<p class=mut>HOME_NET, regole locali e suppress SID si configurano nella scheda <a href="?p=ips&t=regole">Regole avanzate</a>. Qui interfaccia di cattura e test di validità.</p>';
    }
    echo '</div>';
}
function pg_history() {
    $ro = ($_SESSION['role'] ?? 'viewer') === 'viewer';
    // ---- rollback impostazioni ----
    $prev = DATA_DIR . '/settings.prev.json';
    $sBack = settings_backup_list(20);
    echo '<div class=card><h2>Rollback impostazioni</h2>';
    echo '<p class=mut>Prima di ogni modifica alle impostazioni viene salvata una copia. Puoi tornare all\'ultima versione o a un backup precedente. La bozza viene riallineata; le regole <b>live</b> del kernel cambiano solo dopo «Applica».</p>';
    if (is_file($prev) && !$ro) {
        $mt = date('Y-m-d H:i:s', (int)filemtime($prev));
        echo '<form method=post class=ops data-iptm-layout="ui-016af9a172">'
            . fh('p=history') . '<input type=hidden name=action value=settings_rollback><input type=hidden name=name value=prev>'
            . '<button class=g>↩ Ripristina ultime impostazioni</button>'
            . '<span class=mut>snapshot: ' . h($mt) . '</span></form>';
    } elseif (!is_file($prev)) {
        echo '<p class=mut>Nessuno snapshot «prev» ancora (verra creato al prossimo salvataggio impostazioni).</p>';
    }
    if ($sBack) {
        echo '<h3>Backup impostazioni</h3><table><tr><th>Quando</th><th>File</th><th></th></tr>';
        foreach ($sBack as $f) {
            $n = basename($f);
            $when = date('Y-m-d H:i:s', (int)filemtime($f));
            echo '<tr><td>' . h($when) . '</td><td><code>' . h($n) . '</code></td><td class=ops>';
            if (!$ro) {
                echo '<form method=post>'
                    . fh('p=history') . '<input type=hidden name=action value=settings_rollback><input type=hidden name=name value="' . h($n) . '">'
                    . '<button class="s sm">↩ ripristina</button></form>';
            }
            echo '</td></tr>';
        }
        echo '</table>';
    }
    echo '</div>';
    $bk = glob(DATA_DIR . '/backups/rules.v*.*') ?: []; usort($bk, fn($a, $b) => strcmp(substr(basename($b), 9), substr(basename($a), 9)));
    echo '<div class=card><h2>Storico regole (rules.v4 / v6)</h2><p class=mut>Ogni salvataggio su file crea una versione. Apri una versione per vedere cosa è cambiato rispetto alla precedente e ricaricarla nella bozza.</p>';
    foreach (array_slice($bk, 0, 25) as $i => $f) { $n = basename($f); $fam = $n[7]; $prev = null; foreach (array_slice($bk, $i + 1) as $g) if (basename($g)[7] === $fam) { $prev = $g; break; }
        $df = ''; if ($prev) { [, $df] = run(['/usr/bin/diff', '-u', '--label', basename($prev), '--label', $n, $prev, $f]); }
        echo '<details><summary>IPv' . h($fam) . ' · ' . h(substr($n, 9, 4) . '-' . substr($n, 13, 2) . '-' . substr($n, 15, 2) . ' ' . substr($n, 18, 2) . ':' . substr($n, 20, 2) . ':' . substr($n, 22, 2)) . ' <span class=mut>(' . count(file($f)) . ' righe' . ($prev ? ', ' . (substr_count($df, "\n+") + substr_count($df, "\n-") - 2) . ' modifiche' : '') . ')</span></summary>
<p class=ops><a href="?dl=' . h($n) . '">⬇ scarica</a><form method=post>' . fh('p=history') . '<input type=hidden name=action value=restore_backup><input type=hidden name=name value="' . h($n) . '"><button class="s sm">↩ carica in bozza</button></form></p><pre>' . h($df ?: ($prev ? 'nessuna differenza' : 'prima versione')) . '</pre></details>'; }
    echo $bk ? '' : '<p class=mut>Nessuna versione ancora.</p>'; echo '</div>';
    $f = DATA_DIR . '/audit.log'; $L = is_file($f) ? array_slice(array_reverse(file($f, FILE_IGNORE_NEW_LINES)), 0, 80) : [];
    echo '<div class=card><h3>Registro delle operazioni</h3><div data-iptm-layout="scroll"><table><tr><th>Quando</th><th>Utente</th><th>IP</th><th>Operazione</th></tr>'; foreach ($L as $l) echo '<tr><td>' . implode('</td><td>', array_map('h', array_pad(explode("\t", $l), 4, ''))) . '</td></tr>'; echo '</table></div></div>';
}

function impact_analyze(): array {
    global $draftTxt;
    $L = live_state();
    $out = [
        'ok' => $L['ok'],
        'pol' => $L['pol'] ?? [],
        'top_drop' => [], 'top_accept' => [], 'never' => [], 'hot' => [],
        'totals' => ['rules' => 0, 'hit' => 0, 'zero' => 0, 'drop_pkts' => 0, 'accept_pkts' => 0],
        'draft' => ['added' => 0, 'removed' => 0, 'same' => 0, 'by_chain' => []],
        'risks' => [],
    ];
    if ($L['ok']) {
        $rules = $L['rules'];
        $out['totals']['rules'] = count($rules);
        foreach ($rules as $x) {
            $out['totals']['hit'] += $x['p'] > 0 ? 1 : 0;
            $out['totals']['zero'] += $x['p'] === 0 ? 1 : 0;
            $j = 'OTHER';
            if (preg_match('/\s-j\s+(\S+)/', $x['r'], $m)) $j = $m[1];
            if (in_array($j, ['DROP', 'REJECT', 'TARPIT'], true)) $out['totals']['drop_pkts'] += $x['p'];
            if ($j === 'ACCEPT') $out['totals']['accept_pkts'] += $x['p'];
        }
        $sorted = $rules;
        usort($sorted, fn($a, $b) => $b['p'] <=> $a['p']);
        $out['hot'] = array_slice($sorted, 0, 15);
        $drops = array_values(array_filter($rules, function ($x) {
            return (bool)preg_match('/\s-j\s+(DROP|REJECT|TARPIT)\b/', $x['r']);
        }));
        usort($drops, fn($a, $b) => $b['p'] <=> $a['p']);
        $out['top_drop'] = array_slice($drops, 0, 12);
        $acc = array_values(array_filter($rules, fn($x) => (bool)preg_match('/\s-j\s+ACCEPT\b/', $x['r'])));
        usort($acc, fn($a, $b) => $b['p'] <=> $a['p']);
        $out['top_accept'] = array_slice($acc, 0, 10);
        $never = array_values(array_filter($rules, fn($x) => $x['p'] === 0 && preg_match('/\s-j\s+(DROP|REJECT|ACCEPT)\b/', $x['r'])));
        $out['never'] = array_slice($never, 0, 20);
        // risks from live
        foreach ($out['pol'] as $ch => $pol) {
            if ($pol === 'ACCEPT' && in_array($ch, ['INPUT', 'FORWARD'], true)) {
                $out['risks'][] = "Policy $ch = ACCEPT: senza una regola finale DROP tutto il resto passa.";
            }
        }
        $open = 0;
        foreach ($rules as $x) {
            if (preg_match('/-A INPUT\b/', $x['r']) && preg_match('/-j ACCEPT/', $x['r'])
                && !preg_match('/-s |--src | -i |--in-interface /', $x['r'])
                && !preg_match('/ctstate (ESTABLISHED|RELATED)/', $x['r'])) {
                $open++;
            }
        }
        if ($open >= 3) $out['risks'][] = "Ci sono $open regole ACCEPT in INPUT senza interfaccia/sorgente: ampliano la superficie di attacco.";
    }
    // draft vs live keys
    $liveKeys = [];
    if ($L['ok']) foreach ($L['rules'] as $x) $liveKeys[rkey($x['r'])] = true;
    $draftItems = parse_rules($draftTxt);
    $draftKeys = [];
    foreach ($draftItems as $it) {
        if (($it['t'] ?? '') !== 'rule' || empty($it['on'])) continue;
        $k = rkey($it['r']);
        $draftKeys[$k] = true;
        $ch = rchain($it['r']) ?: '?';
        $out['draft']['by_chain'][$ch] = ($out['draft']['by_chain'][$ch] ?? 0) + 1;
    }
    foreach ($draftKeys as $k => $_) {
        if (isset($liveKeys[$k])) $out['draft']['same']++;
        else $out['draft']['added']++;
    }
    foreach ($liveKeys as $k => $_) {
        if (!isset($draftKeys[$k])) $out['draft']['removed']++;
    }
    if ($out['draft']['added'] + $out['draft']['removed'] > 50) {
        $out['risks'][] = 'La bozza cambia molte regole (' . $out['draft']['added'] . ' nuove, ' . $out['draft']['removed'] . ' rimosse): usa Verifica completa e Applica con rollback.';
    }
    return $out;
}

/**
 * Centro operativo: policy iptables IPv4 effettivamente lette dal kernel.
 * Filtro di sola lettura. Non identifica l'uso applicativo e non resetta i contatori.
 * I contatori sono cumulativi dal reset/ricaricamento: zero hit != regola inutile.
 */
function iptm_ops_rule_filters(array $query): array {
    $pick = static function ($k, array $allowed, string $default) use ($query): string {
        $v = $query[$k] ?? $default;
        return is_string($v) && in_array($v, $allowed, true) ? $v : $default;
    };
    $search = $query['q'] ?? '';
    if (!is_string($search)) $search = '';
    $search = substr(trim(preg_replace('/[\x00-\x1F\x7F]/', ' ', $search) ?? ''), 0, 80);
    $chain = $query['chain'] ?? '';
    if (!is_string($chain) || !preg_match('/^[A-Za-z0-9_.:-]{0,28}$/D', $chain)) $chain = '';
    return ['q' => $search, 'chain' => $chain,
        'verdict' => $pick('verdict', ['all','accept','block','other'], 'all'),
        'hit' => $pick('hit', ['all','yes','no'], 'all'),
        'table' => $pick('table', ['all','filter','nat','mangle','raw','security'], 'all'),
        'page' => max(1, min(1000, filter_var($query['page'] ?? 1, FILTER_VALIDATE_INT) ?: 1))];
}
function iptm_ops_rule_verdict(string $rule): string {
    if (preg_match('/(?:^|\s)-j\s+(?:DROP|REJECT|TARPIT)(?:\s|$)/', $rule)) return 'block';
    if (preg_match('/(?:^|\s)-j\s+ACCEPT(?:\s|$)/', $rule)) return 'accept';
    return 'other';
}
function iptm_ops_rule_rows(array $rules, array $f, int $perPage = 80): array {
    $matches = [];
    $byVerdict = ['accept' => 0, 'block' => 0, 'other' => 0];
    $unrestricted = [];
    foreach ($rules as $r) {
        if (!is_array($r)) continue;
        $raw = (string)($r['r'] ?? '');
        $table = (string)($r['t'] ?? '');
        if (!preg_match('/^-A\s+([A-Za-z0-9_.:-]{1,28})(?:\s|$)/', $raw, $m)) continue;
        $chain = $m[1];
        $packets = max(0, (int)($r['p'] ?? 0));
        $bytes = max(0, (int)($r['b'] ?? 0));
        $v = iptm_ops_rule_verdict($raw);
        ++$byVerdict[$v];
        // Warning only: broad accepted INPUT traffic can be intentional (DNS/SSH/VPN).
        // Do not classify matches as active vulnerabilities or remove automatically.
        if ($table === 'filter' && $chain === 'INPUT' && $v === 'accept'
            && !preg_match('/(?:^|\s)(?:-s|--source|-i|--in-interface)(?:\s|$)/', $raw)
            && !preg_match('/--ctstate\s+[^\s]*(?:ESTABLISHED|RELATED)/', $raw)) {
            if (count($unrestricted) < 8) $unrestricted[] = $raw;
        }
        if ($f['chain'] !== '' && $f['chain'] !== $chain) continue;
        if ($f['table'] !== 'all' && $f['table'] !== $table) continue;
        if ($f['verdict'] !== 'all' && $f['verdict'] !== $v) continue;
        if ($f['hit'] === 'yes' && $packets === 0) continue;
        if ($f['hit'] === 'no' && $packets > 0) continue;
        if ($f['q'] !== '' && stripos($raw . ' ' . $table, $f['q']) === false) continue;
        $matches[] = ['chain'=>$chain, 'table'=>$table, 'verdict'=>$v,
            'packets'=>$packets, 'bytes'=>$bytes, 'rule'=>$raw];
    }
    usort($matches, static fn($a, $b) => ($b['packets'] <=> $a['packets']) ?: strcmp($a['rule'], $b['rule']));
    $total = count($matches);
    $perPage = max(10, min(100, $perPage));
    $pages = max(1, (int)ceil($total / $perPage));
    $page = max(1, min($pages, $f['page']));
    return ['total'=>$total, 'page'=>$page, 'pages'=>$pages,
        'rows'=>array_slice($matches, ($page-1)*$perPage, $perPage),
        'verdicts'=>$byVerdict, 'review'=> $unrestricted];
}
/** Compact kernel log parser, no command execution, credentials or packet payloads. */
function iptm_ops_events(string $journal, string $q = '', int $limit = 100): array {
    $out = [];
    $q = substr(trim($q), 0, 80);
    $lines = preg_split('/\r?\n/', $journal) ?: [];
    // Scan newest events first, stop after bounding the display.
    for ($i=count($lines)-1; $i>=0 && count($out)<max(1,min(200,$limit)); --$i) {
        $line = $lines[$i];
        if (strlen($line)>8192 || !preg_match('/\b(IPT[A-Za-z0-9_-]{0,40}):/', $line, $m)) continue;
        if ($q !== '' && stripos($line, $q) === false) continue;
        preg_match_all('/\b(IN|OUT|SRC|DST|PROTO|SPT|DPT)=([^\s]*)/', $line, $kv, PREG_SET_ORDER);
        $fields = []; foreach ($kv as $v) $fields[$v[1]] = substr($v[2],0,100);
        $out[] = ['timestamp'=>substr(trim(substr($line,0,(int)strpos($line,$m[0]))),0,100),'event'=>$m[1],
            'src'=>$fields['SRC']??'', 'dst'=>$fields['DST']??'',
            'proto'=>$fields['PROTO']??'', 'port'=>$fields['DPT']??'',
            'iface'=>$fields['IN']??''];
    }
    return $out;
}
/** Read-only firewall security operations; not the security commit or QoS console. */
function pg_security_operations(): void {
    $tab = (string)($_GET['t'] ?? 'summary');
    if (!in_array($tab, ['summary','policies','events'], true)) $tab = 'summary';
    echo '<div class="card"><h2>Centro operativo · Sicurezza</h2>';
    echo '<p class=mut>Analisi in sola lettura di regole iptables IPv4, eventi kernel e contatori. Nessuna applicazione, cattura o modifica della rete. I contatori possono azzerarsi dopo riavvii o ricaricamenti.</p>';
    echo '<div class=ops><a class="btn '.($tab==='summary'?'g':'s').'" href="?p=operations&amp;t=summary">Panoramica</a> '
        .'<a class="btn '.($tab==='policies'?'g':'s').'" href="?p=operations&amp;t=policies">Esplora policy</a> '
        .'<a class="btn '.($tab==='events'?'g':'s').'" href="?p=operations&amp;t=events">Eventi firewall</a></div></div>';
    if ($tab === 'events') {
        $q=$_GET['q']??''; if (!is_string($q)) $q=''; if (strlen($q)>80) $q=substr($q,0,80);
        echo '<div class=card><h3>Monitor eventi · Kernel</h3><form method=get class=ops><input type=hidden name=p value=operations><input type=hidden name=t value=events>'
            .'<input name=q type=search maxlength=80 placeholder="Filtra IP, porta, prefisso" value="'.h($q).'" data-iptm-layout="ui-3948c0f128"> <button class=s>Filtra</button> <a class="btn s" href="?p=operations&amp;t=events">Aggiorna</a></form>';
        [$c,$o,$err]=priv('journal');
        if ($c!==0) echo '<div class="msg warn">Log non disponibili: '.h(substr($err,0,180)).'. Non significa che non ci siano eventi.</div>';
        else {
            $events=iptm_ops_events($o,$q,100);
            echo '<p class=mut>'.count($events).' eventi mostrati (massimo 100, dal più recente). Il filtro opera sulle righe ricevute dal journal, non sull’intera cronologia.</p>';
            if (!$events) echo '<p>Nessun evento corrispondente nell’estratto disponibile.</p>';
            else {
                echo '<div data-iptm-layout="scroll"><table><tr><th>Ora / sorgente log</th><th>Tipo</th><th>IN</th><th>Origine</th><th>Destinazione</th><th>Proto</th><th>Porta</th></tr>';
                foreach ($events as $e) echo '<tr><td>'.h($e['timestamp']).'</td><td>'.h($e['event']).'</td><td>'.h($e['iface']).'</td><td>'.h($e['src']).'</td><td>'.h($e['dst']).'</td><td>'.h($e['proto']).'</td><td>'.h($e['port']).'</td></tr>';
                echo '</table></div>';
            }
        }
        echo '<p class=ops><a class="btn s" href="?p=monitor">CrowdSec / Monitoraggio</a> <a class="btn s" href="?p=ips&amp;t=avvisi">Alert Suricata</a> <a class="btn s" href="?p=log">Analisi log completa</a></p></div>';
        return;
    }
    $L=live_state();
    if (empty($L['ok'])) {
        echo '<div class="card msg warn">Stato delle policy non disponibile: lettura iptables-save/helper fallita. Non significa che il firewall sia disabilitato. <a href="?p=postcheck">Apri diagnosi</a>.</div>';
        return;
    }
    $rules=(array)($L['rules']??[]);
    $f=iptm_ops_rule_filters($_GET);
    $view=iptm_ops_rule_rows($rules,$f);
    $total=count($rules);
    $zero=0; $blocks=0;
    foreach($rules as $r) {if ((int)($r['p']??0)===0)++$zero; if (iptm_ops_rule_verdict((string)($r['r']??''))==='block')++$blocks;}
    echo '<div class=tiles>'.tile('Regole lette',number_format($total)).tile('Con 0 hit',number_format($zero)).tile('Azioni di blocco',number_format($blocks)).'</div>';
    if ($tab==='summary') {
        echo '<div class=card><h3>Stato delle policy</h3><p class=mut>Il contatore di una regola cresce quando un pacchetto la attraversa. Zero hit non dimostra che sia superflua. Le policy non vengono ottimizzate o rimosse automaticamente.</p>';
        $pol=(array)($L['pol']??[]);
        echo '<table><tr><th>Catena</th><th>Policy predefinita</th></tr>';
        foreach(['INPUT','FORWARD','OUTPUT'] as $chain) echo '<tr><td>'.h($chain).'</td><td>'.h($pol[$chain]??'non rilevata').'</td></tr>';
        echo '</table>';
        if ($view['review']) {
            echo '<details><summary>Regole INPUT permissive da riesaminare ('.count($view['review']).' esempi)</summary><p class=mut>Possibili eccezioni intenzionali: rilevamento indicativo, non vulnerabilità confermate.</p><ul>';
            foreach($view['review'] as $r) echo '<li><code>'.h($r).'</code></li>';
            echo '</ul></details>';
        }
        echo '<p class=ops><a class="btn s" href="?p=operations&amp;t=policies&amp;hit=no">Regole a 0 hit</a> <a class="btn s" href="?p=impact">Confronta bozza e live</a> <a class="btn s" href="?p=tracer">Simula bozza</a></p>';
        echo '<p class=mut>Il tracer usa la <b>bozza</b>, non il kernel: ipset, NAT, stato delle connessioni e regole esterne possono influire sul percorso reale.</p></div>';
        echo '<div class=card><h3>Indaga un problema</h3><div class=ops><a class="btn s" href="?p=health#health-policy">Salute e Preflight sicurezza</a> <a class="btn s" href="?p=zones">Zone e dispositivi</a> <a class="btn s" href="?p=dnsaudit">Percorso DNS</a> <a class="btn s" href="?p=operations&amp;t=events">Eventi</a> <a class="btn s" href="?p=history">Cronologia e backup</a></div></div>';
        return;
    }
    echo '<div class=card><h3>Esplora policy · iptables IPv4</h3><form method=get class=row><input type=hidden name=p value=operations><input type=hidden name=t value=policies>';
    echo '<label class=fl><span>Contiene</span><input type=search name=q maxlength=80 data-iptm-layout="ui-fa2d82fc85" value="'.h($f['q']).'" placeholder="IP, porta, commento, target"></label>';
    echo '<label class=fl><span>Catena</span><input name=chain maxlength=28 data-iptm-layout="mw140" value="'.h($f['chain']).'" placeholder="tutte"></label>';
    echo '<label class=fl><span>Tabella</span>'.sel('table',['all'=>'Tutte','filter'=>'filter','nat'=>'nat','mangle'=>'mangle','raw'=>'raw','security'=>'security'],$f['table']).'</label>';
    echo '<label class=fl><span>Verdetto</span>'.sel('verdict',['all'=>'Tutti','accept'=>'ACCEPT','block'=>'DROP/REJECT','other'=>'Altri/salti'],$f['verdict']).'</label>';
    echo '<label class=fl><span>Utilizzo</span>'.sel('hit',['all'=>'Tutte','yes'=>'Con hit','no'=>'0 hit'],$f['hit']).'</label>';
    echo '<div class=fl><span>&nbsp;</span><button class=g>Applica filtri</button></div></form>';
    echo '<p class=mut>Filtrate: '.number_format($view['total']).' · pagina '.(int)$view['page'].' di '.(int)$view['pages'].' · ordinate per pacchetti. Valori cumulativi; non sono velocità al secondo.</p>';
    echo '<div data-iptm-layout="scroll"><table><tr><th>Tabella / catena</th><th>Verdetto</th><th>Pacchetti</th><th>Byte</th><th>Regola attiva</th></tr>';
    foreach($view['rows'] as $r) echo '<tr><td>'.h($r['table']).' / '.h($r['chain']).'</td><td>'.h(strtoupper($r['verdict'])).'</td><td>'.number_format($r['packets']).'</td><td>'.hb($r['bytes']).'</td><td><code data-iptm-layout="ui-1dcaf1af29">'.h($r['rule']).'</code></td></tr>';
    echo '</table></div>';
    if (!$view['rows']) echo '<p class=mut>Nessuna regola corrispondente.</p>';
    if ($view['pages']>1) {
        echo '<div class=ops>';
        foreach ([max(1,$view['page']-1),min($view['pages'],$view['page']+1)] as $i=>$n) {
            if (($i===0 && $view['page']===1)||($i===1 && $view['page']===$view['pages'])) continue;
            $query=http_build_query(['p'=>'operations','t'=>'policies','q'=>$f['q'],'chain'=>$f['chain'],'table'=>$f['table'],'verdict'=>$f['verdict'],'hit'=>$f['hit'],'page'=>$n],'','&',PHP_QUERY_RFC3986);
            echo '<a class="btn s" href="?'.h($query).'">'.($i===0?'Precedente':'Successiva').'</a>';
        }
        echo '</div>';
    }
    echo '<p class=ops><a class="btn s" href="?p=rules">Modifica bozza regole</a> <a class="btn s" href="?p=apply">Verifica e applica con rollback</a></p></div>';
}

function pg_impact() {
    $A = impact_analyze();
    echo '<div class=card><h2>Analisi impatto regole</h2>';
    echo '<p class=mut>Panoramica su cosa stanno facendo le regole <b>attive nel kernel</b> (contatori) e su come la <b>bozza</b> cambierebbe la situazione se applicata.</p>';
    if (!$A['ok']) {
        echo '<div class="msg err">Impossibile leggere i contatori (helper/sudo). Controlla l\'installazione.</div></div>';
        return;
    }
    $t = $A['totals'];
    echo '<div class=row data-iptm-layout="ui-34311ab5e4">';
    $card = function ($label, $val, $hint = '') {
        echo '<div data-iptm-layout="ui-062af3e9ad"><div class=mut>' . h($label) . '</div><div data-iptm-layout="ui-aa698dcc74">' . h((string)$val) . '</div>' . ($hint ? '<div class=mut>' . h($hint) . '</div>' : '') . '</div>';
    };
    $card('Regole attive', number_format($t['rules']));
    $card('Con almeno 1 hit', number_format($t['hit']));
    $card('Mai usate (0 hit)', number_format($t['zero']));
    $card('Pkts DROP/REJECT', number_format($t['drop_pkts']));
    $card('Pkts ACCEPT', number_format($t['accept_pkts']));
    echo '</div>';

    if ($A['pol']) {
        echo '<h3>Policy catene filter</h3><table><tr><th>Catena</th><th>Policy</th></tr>';
        foreach ($A['pol'] as $ch => $pol) {
            $b = $pol === 'DROP' ? 'b-DROP' : ($pol === 'ACCEPT' ? 'b-ACCEPT' : 'b-jump');
            echo '<tr><td>' . h($ch) . '</td><td><span class="b ' . $b . '">' . h($pol) . '</span></td></tr>';
        }
        echo '</table>';
    }

    if ($A['risks']) {
        echo '<h3>Avvisi</h3><ul>';
        foreach ($A['risks'] as $r) echo '<li class=mut>' . h($r) . '</li>';
        echo '</ul>';
    }

    if (function_exists('chart_hbar_svg') && $A['top_drop']) {
        $hd = [];
        foreach (array_slice($A['top_drop'], 0, 10) as $x) {
            $lab = preg_replace('/^-A\s+\S+\s+/', '', $x['r'] ?? '');
            if (strlen($lab) > 42) $lab = substr($lab, 0, 40) . '…';
            $hd[] = ['label' => $lab ?: ($x['t'] ?? 'drop'), 'value' => (float)($x['p'] ?? 0)];
        }
        echo '<h3>Grafico blocchi (pacchetti)</h3>' . chart_hbar_svg($hd, ['color' => '#ef4444', 'label_w' => 180, 'max' => 10]);
    }
    echo '<h3>Blocchi più attivi (DROP / REJECT)</h3>';
    if (!$A['top_drop']) echo '<p class=mut>Nessuna regola di blocco con contatori.</p>';
    else {
        echo '<div data-iptm-layout="scroll"><table><tr><th>Pacchetti</th><th>Byte</th><th>Tab</th><th>Regola</th></tr>';
        foreach ($A['top_drop'] as $x) {
            echo '<tr><td>' . number_format($x['p']) . '</td><td>' . hb($x['b']) . '</td><td>' . h($x['t']) . '</td><td><code style="display:block;white-space:pre-wrap">' . h($x['r']) . '</code></td></tr>';
        }
        echo '</table></div>';
    }

    echo '<h3>Accept più usati</h3>';
    if (!$A['top_accept']) echo '<p class=mut>—</p>';
    else {
        echo '<div data-iptm-layout="scroll"><table><tr><th>Pacchetti</th><th>Byte</th><th>Regola</th></tr>';
        foreach ($A['top_accept'] as $x) {
            echo '<tr><td>' . number_format($x['p']) . '</td><td>' . hb($x['b']) . '</td><td><code style="display:block;white-space:pre-wrap">' . h($x['r']) . '</code></td></tr>';
        }
        echo '</table></div>';
    }

    echo '<h3>Regole mai usate (prime 20)</h3><p class=mut>Zero pacchetti dal boot o dall\'ultimo reset contatori. Possono essere redundant, troppo specifiche o semplicemente quiete.</p>';
    if (!$A['never']) echo '<p class=mut>Nessuna (o contatori non disponibili).</p>';
    else {
        echo '<div data-iptm-layout="scroll"><table><tr><th>Tab</th><th>Regola</th></tr>';
        foreach ($A['never'] as $x) {
            echo '<tr><td>' . h($x['t']) . '</td><td><code style="display:block;white-space:pre-wrap">' . h($x['r']) . '</code></td></tr>';
        }
        echo '</table></div>';
    }

    $d = $A['draft'];
    echo '<h3>Impatto della bozza (se applicata)</h3>';
    echo '<table><tr><th>Regole invariate</th><th>Nuove in bozza</th><th>Rimosse rispetto al live</th></tr>';
    echo '<tr><td>' . (int)$d['same'] . '</td><td>' . (int)$d['added'] . '</td><td>' . (int)$d['removed'] . '</td></tr></table>';
    if ($d['by_chain']) {
        arsort($d['by_chain']);
        echo '<p class=mut>Regole abilitate in bozza per catena:</p><table><tr><th>Catena</th><th>N.</th></tr>';
        foreach ($d['by_chain'] as $ch => $n) echo '<tr><td>' . h($ch) . '</td><td>' . $n . '</td></tr>';
        echo '</table>';
    }
    echo '<p class=ops data-iptm-layout="mt12"><a class="btn s" href="?p=apply">Vai ad Applica / Verifica</a> <a class="btn s" href="?p=tracer">Packet tracer</a> <a class="btn s" href="?p=rules">Elenco regole</a></p>';
    echo '</div>';
}

function pg_tracer() {
    global $M; $if = array_keys(sys_ifaces()); $g = fn($k, $d = '') => trim((string)($_GET[$k] ?? $d)); $loc = []; foreach (sys_ifaces() as $a) foreach ($a as $x) $loc[] = explode('/', $x)[0];
    echo '<div class=card><h2>Packet tracer</h2><p class=mut>Simula il percorso di un pacchetto nelle regole della <b>bozza</b> e mostra quale regola decide. Utile per capire «perché non passa» prima di applicare.</p><form method=get class=row><input type=hidden name=p value=tracer>
<label class=fl><span>Percorso</span>' . sel('flow', ['local' => 'Arriva a questo router (INPUT)', 'forward' => 'Attraversa il router (FORWARD)', 'out' => 'Generato dal router (OUTPUT)'], $g('flow', 'local')) . '</label>
<label class=fl><span>Interfaccia di ingresso</span>' . sel('in', array_merge(['' => '—'], array_combine($if, $if)), $g('in')) . '</label><label class=fl><span>Interfaccia di uscita</span>' . sel('out', array_merge(['' => '—'], array_combine($if, $if)), $g('out')) . '</label>
<label class=fl><span>IP origine</span><input name=src value="' . h($g('src')) . '" placeholder="192.168.1.50"></label><label class=fl><span>IP destinazione</span><input name=dst value="' . h($g('dst')) . '" placeholder="192.168.1.2 oppure 8.8.8.8"></label>
<label class=fl><span>Protocollo</span>' . sel('proto', ['tcp' => 'TCP', 'udp' => 'UDP', 'icmp' => 'ICMP'], $g('proto', 'tcp')) . '</label><label class=fl><span>Porta origine</span><input name=sport value="' . h($g('sport')) . '" placeholder="casuale"></label>
<label class=fl><span>Porta destinazione</span><input name=dport value="' . h($g('dport')) . '" placeholder="22"></label><label class=fl><span>Stato</span>' . sel('state', ['NEW' => 'Nuova connessione', 'ESTABLISHED' => 'Connessione già stabilita'], $g('state', 'NEW')) . '</label>
<div class=fl><span>&nbsp;</span><button>🔬 Traccia</button></div></form></div>';
    if ($g('src') !== '' && $g('dst') !== '') {
        if (!v_ok('ip', $g('src')) || !v_ok('ip', $g('dst'))) { echo '<div class="msg err">Indirizzi IP non validi.</div>'; return; }
        $r = trace_packet($M, ['flow' => $g('flow', 'local'), 'in' => $g('in'), 'out' => $g('out'), 'src' => $g('src'), 'dst' => $g('dst'), 'proto' => $g('proto', 'tcp'), 'sport' => $g('sport'), 'dport' => $g('dport'), 'state' => $g('state', 'NEW'), 'local_ips' => $loc, 'local_ip' => $loc[0] ?? '']);
        $ok = $r['verdict'] === 'ACCEPT'; echo '<div class=card><h3>Esito: <span class="b b-' . ($ok ? 'ACCEPT' : 'DROP') . '">' . ($ok ? 'PASSA' : ($r['verdict'] === 'REJECT' ? 'RIFIUTATO' : 'SCARTATO')) . '</span> ' . ($r['where'] ? '<small class=mut>dove: ' . h($r['where']) . '</small>' : '') . '</h3>';
        if (!empty($r['k']['dnat'])) echo '<p>🔀 Destinazione tradotta (DNAT) → <b>' . h($r['k']['d'] . ($r['k']['dport'] ? ':' . $r['k']['dport'] : '')) . '</b></p>'; if (!empty($r['k']['snat'])) echo '<p>🔀 Sorgente tradotta (NAT) → <b>' . h($r['k']['snat']) . '</b></p>';
        echo '<table><tr><th>Tabella / catena</th><th>#</th><th>Regola che corrisponde</th></tr>'; foreach ($r['steps'] as [$t, $c, $n, $raw]) echo '<tr><td>' . h("$t / $c") . '</td><td>' . ($n ?: '—') . '</td><td><code style="display:block">' . h($raw) . '</code></td></tr>';
        echo $r['steps'] ? '' : '<tr><td colspan=3 class=mut>Nessuna regola corrisponde: vale la policy.</td></tr>'; echo '</table>';
        foreach (array_unique($r['nt']) as $n) echo '<p class=mut>ℹ ' . h($n) . '</p>'; echo '<p class=mut>Ipotesi: limiti (hashlimit/recent/connlimit) non superati; set ipset e moduli di payload non valutabili.</p></div>';
    }
}
function pg_lists() {
    $S = S_get(); [, $st] = priv('lists-status');
    $arow = fn($i, $a) => '<tr><td><input name="al[' . $i . '][name]" value="' . h($a['name'] ?? '') . '" placeholder="NAS"></td><td><input name="al[' . $i . '][items]" value="' . h($a['items'] ?? '') . '" placeholder="192.168.1.10 192.168.1.11 oppure 80,443"></td><td><label><input type=checkbox name="al[' . $i . '][del]" value=1> elimina</label></td></tr>';
    $crow = fn($i, $b) => '<tr><td><input name="bc[' . $i . '][name]" value="' . h($b['name'] ?? '') . '" placeholder="Nome"></td><td><input name="bc[' . $i . '][url]" value="' . h($b['url'] ?? '') . '" placeholder="https://…/lista.txt"></td><td>' . iptm_direction_checkboxes('bc[' . $i . '][dir]', (string)($b['dir'] ?? 'in')) . '</td><td><label><input type=checkbox name="bc[' . $i . '][on]" value=1' . (!isset($b['on']) || $b['on'] ? ' checked' : '') . '> attiva</label> <label><input type=checkbox name="bc[' . $i . '][del]" value=1> elimina</label></td></tr>';
    $t = '<h3>Alias (gruppi con nome)</h3><p class=mut>Reti/IP (usabili come <code>@nome</code> in sorgente/destinazione) oppure porte (usabili come <code>@nome</code> nelle porte). Aggiornare un alias aggiorna tutte le regole che lo usano.</p><table id=altab><tr><th>Nome</th><th>Elementi</th><th></th></tr>';
    foreach ($S['aliases'] as $i => $a) $t .= $arow($i, $a); $t .= '</table><template id=altpl>' . $arow('__i__', []) . '</template><p><button type=button class=s data-tpl="#altpl" data-into="#altab">＋ Aggiungi alias</button></p>';
    $t .= '<h3>Liste di IP malevoli (aggiornate ogni giorno)</h3><p class=mut>Puoi scegliere ingresso e uscita insieme tramite due flag. Le reti private e le tue LAN sono sempre escluse dal blocco (le liste «bogon» come FireHOL Level 1 contengono 192.168.x e 10.x). Direzione predefinita: <b>solo ingresso</b>, come pfBlockerNG.</p><table><tr><th>Lista</th><th>Attiva</th><th>Direzione</th></tr>';
    $cur = []; foreach ($S['blocklists'] as $b) $cur[$b['id']] = $b;
    foreach (BL_PRESETS as $id => [$nm]) $t .= '<tr><td>' . h($nm) . '</td><td><input type=checkbox name="bp[' . $id . ']" value=1' . (!empty($cur[$id]['on']) ? ' checked' : '') . '></td><td>' . iptm_direction_checkboxes('bd[' . $id . ']', (string)($cur[$id]['dir'] ?? 'in')) . '</td></tr>';
    $t .= '</table><p class=mut>Liste personalizzate (URL http/https con un IP o CIDR per riga):</p><table id=bctab><tr><th>Nome</th><th>URL</th><th>Direzione</th><th></th></tr>'; $n = 0;
    foreach ($S['blocklists'] as $b) if (!isset(BL_PRESETS[$b['id']])) $t .= $crow($n++, $b); $t .= '</table><template id=bctpl>' . $crow('__i__', []) . '</template><p><button type=button class=s data-tpl="#bctpl" data-into="#bctab">＋ Lista personalizzata</button></p>';
    $t .= '<h3>Blocco per Paese (GeoIP)</h3>' . dd_radio($S, 'geo_on', 'Blocca i Paesi indicati', 'Liste da ipdeny.com, aggiornate ogni giorno.') . dd_in($S, 'geo_codes', 'Codici Paese', 'CN,RU', 'Codici ISO a 2 lettere separati da virgola.', '300px');
    $ch = ''; foreach (GEO_NAMES as $c => $nm) $ch .= '<a href="#" class=chip data-fill=geo_codes data-v="' . $c . '" data-add=1>' . $c . ' ' . h($nm) . '</a>';
    $t .= dd('Scelta rapida', $ch) . dd('Direzione', sel('geo_dir', ['both' => 'entrambe', 'in' => 'solo ingresso', 'out' => 'solo uscita'], $S['geo_dir']));
    $t .= '<h3>Regole per nome di dominio (FQDN)</h3><label class=fl><span>Una regola per riga: nome azione host…</span><textarea name=fqdn_rules rows=4 placeholder="social block facebook.com instagram.com&#10;aggiornamenti allow deb.debian.org">' . h($S['fqdn_rules'] ?? '') . '</textarea><small>Azione <b>block</b> (scarta il traffico in transito verso quegli host) o <b>allow</b> (consente prima delle liste). I nomi vengono risolti ogni 1 ora in indirizzi IPv4: i siti dietro CDN condivisi possono coinvolgere altri servizi. Nome: lettere/numeri, max 12.</small></label>';
    $t .= '<h3>Lista bianca</h3><label class=fl><span>IP/reti sempre consentiti</span><textarea name=manual_allow rows=2 placeholder="192.0.2.10 198.51.100.0/24">' . h($S['manual_allow'] ?? '') . '</textarea><small>Valutata prima di CrowdSec, liste e blocco manuale (INPUT e FORWARD): utile per non bloccare mai i tuoi IP di gestione.</small></label>';
    $t .= '<h3>Blocco manuale</h3><label class=fl><span>IP/reti sempre bloccati</span><textarea name=manual_block rows=3 placeholder="203.0.113.7 198.51.100.0/24">' . h($S['manual_block']) . '</textarea><small>Si alimenta anche dai pulsanti ⛔ nelle pagine Log, Connessioni e IPS.</small></label>';
    echo '<div class=card><h2>Alias · Liste · GeoIP</h2>' . '<form method=post class=acc>' . fh('p=lists') . '<input type=hidden name=action value=lists_apply>' . $t . '<p class=sticky><button>💾 Salva e aggiorna le liste</button> <span class=mut>Il download avviene in background.</span></p></form>
<h3>Stato delle liste</h3><pre>' . h(trim($st) ?: 'nessuna lista scaricata') . '</pre><form method=post>' . fh('p=lists') . '<input type=hidden name=action value=lists_refresh><button class=s>↻ Aggiorna ora</button></form></div>';
}
// IPTM 4: pg_sqm moved to modules/34_qos_pages.php (loaded before POST controller).
function pg_v6(bool $embedded = false) {
    $S = S_get(); $storedV6 = is_array($S['v6'] ?? null) ? $S['v6'] : []; $V = $storedV6 + v6_def();
    if (!array_key_exists('wg_port', $storedV6)) $V['wg_port'] = (int)($S['wg_port'] ?? 51820);
    if (!array_key_exists('wg_if', $storedV6)) $V['wg_if'] = (string)($S['wg_if'] ?? 'wg0');
    if (!preg_match('/^[A-Za-z0-9_.-]{1,15}$/', (string)$V['wg_if'])) $V['wg_if'] = 'wg0';
    $txt = v6_get(); $v6Rev = hash('sha256', $txt); $if = array_keys(sys_ifaces()); $wgi = wg_info();
    $v6KernelDisabled = trim((string)@file_get_contents('/proc/sys/net/ipv6/conf/all/disable_ipv6')) === '1';
    $V['wg_if'] = wg_preferred_iface($wgi['ifaces'] ?? [], (string)$V['wg_if']);
    $wgIfaces = array_values(array_unique(array_merge($wgi['ifaces'] ?? [], [$V['wg_if']])));
    $wgOpts = array_combine($wgIfaces ?: ['wg0'], $wgIfaces ?: ['wg0']);
    $ck = fn($k, $l) => '<label data-iptm-layout="ui-d26a99877d"><input type=checkbox name=' . $k . ' value=1' . (!empty($V[$k]) ? ' checked' : '') . '> ' . $l . '</label>';
    [$ctlRc, $ctlOut, $ctlErr] = priv('ipv6-control', null, ['status']);
    $ctl = [];
    if ($ctlRc === 0) foreach (preg_split('/\r?\n/', $ctlOut) as $line) {
        if (preg_match('/^(state|boot_disabled|all|default|interfaces|pending|pending_mode|seconds_left|persistent)=(.*)$/D', $line, $m))
            $ctl[$m[1]] = substr($m[2], 0, 1800);
    }
    $remote = preg_replace('/^::ffff:/i', '', (string)($_SERVER['REMOTE_ADDR'] ?? ''));
    $adminV4 = ($_SESSION['role'] ?? '') === 'admin' && (bool)filter_var($remote, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4);
    echo '<div class="card"><h2>Gestione IPv6 del kernel (tutte le interfacce)</h2>';
    if ($ctlRc !== 0) echo '<div class="msg warn">Stato kernel non disponibile: '. h(herr($ctlOut . $ctlErr)) .'</div>';
    else {
        $st6 = $ctl['state'] ?? 'unknown';
        echo '<p><b>Stato effettivo:</b> '.h($st6).' · <b>all:</b> '.h($ctl['all'] ?? '?')
           .' · <b>default (interfacce future):</b> '.h($ctl['default'] ?? '?')
           .' · <b>persistenza IPTM:</b> '.(!empty($ctl['persistent']) && $ctl['persistent']==='1'?'presente':'non configurata').'</p>';
        if (!empty($ctl['interfaces'])) echo '<p class="mut"><b>Interfacce attuali:</b> '.h($ctl['interfaces']).'</p>';
        if (($ctl['boot_disabled'] ?? '') === '1') echo '<div class="msg warn">IPv6 disabilitato dal boot del kernel: per riabilitarlo occorre correggere i parametri di avvio e riavviare; IPTM non li modifica automaticamente.</div>';
        if (($ctl['pending'] ?? '') === '1') {
            echo '<div class="msg warn"><b>Conferma richiesta:</b> '.h($ctl['pending_mode'] ?? '').' · circa '.(int)($ctl['seconds_left']??0).' secondi rimasti. Prova SSH, DNS e rete locale dalla connessione IPv4.</div>';
            if ($adminV4) echo '<div class="ops"><form method="post">'.fh($embedded?'p=apply':'p=v6').'<input type="hidden" name="action" value="ipv6_kernel_confirm"><button class="g">Conferma definitivamente</button></form><form method="post">'.fh($embedded?'p=apply':'p=v6').'<input type="hidden" name="action" value="ipv6_kernel_rollback"><button class="d">Ripristina subito IPv6 precedente</button></form></div>';
        } elseif ($adminV4) {
            echo '<p class="mut">Il controllo modifica i flag correnti <code>all</code>, <code>default</code> e ogni interfaccia; crea <code>/etc/sysctl.d/99-iptm-ipv6.conf</code> per applicarli ai riavvii e alle interfacce future. Watchdog di 120 secondi: senza conferma tenta il rollback automatico. Non cambia il backend firewall.</p>';
            echo '<form method="post">'.fh($embedded?'p=apply':'p=v6').'<input type="hidden" name="action" value="ipv6_kernel_apply"><label class="fl"><span>Operazione</span><select name="ipv6_mode"><option value="disable">Disabilita IPv6 su tutte le interfacce</option><option value="enable">Riabilita IPv6 su tutte le interfacce</option></select></label><button class="g">Applica con rollback</button></form>';
        } else echo '<p class="mut">Operazione disponibile soltanto a un amministratore collegato via IPv4 e senza transazioni pendenti.</p>';
    }
    echo '</div>';
    echo '<div class=card><h2>IPv6</h2><p class=mut>Firewall IPv6 semplice (file <code>/etc/iptables/rules.v6</code>): chiuso di default, ICMPv6 consentito, servizi solo dai prefissi indicati. Per regole avanzate modifica il testo qui sotto.</p>'
       . ($v6KernelDisabled ? '<div class="msg warn" role=status>IPv6 è disabilitato nel kernel. Puoi modificare la bozza, ma l’applicazione è bloccata perché non è possibile garantire il salvataggio dello stato IPv6 per il rollback. Non riabilitare IPv6 dalla dashboard senza verificare la connettività.</div>' : '')
       . '<form method=post class=acc>' . fh($embedded ? 'p=apply' : 'p=v6') . '<input type=hidden name=rev6 value=' . h($v6Rev) . '><input type=hidden name=action value=v6_save><h3>Opzioni</h3>' .
        dd('Modo', sel('mode', ['host' => 'Host (non inoltra)', 'router' => 'Router (inoltra LAN → WAN)'], $V['mode'])) . dd('Interfaccia LAN', sel('lan_if', array_merge(['' => '—'], array_combine($if, $if)), $V['lan_if'])) . dd('Interfaccia WAN', sel('wan_if', array_merge(['' => '—'], array_combine($if, $if)), $V['wan_if'])) .
        dd('Prefissi fidati', '<input name=lan_prefix value="' . h($V['lan_prefix']) . '" data-iptm-layout="mw420">', 'Separati da virgola (es. fe80::/10,2001:db8:1::/64). Da questi prefissi si accede ai servizi.') .
        dd('Servizi', $ck('icmp', 'ICMPv6 (necessario)') . $ck('dhcp6', 'DHCPv6 client') . $ck('ssh', 'SSH') . $ck('log', 'Log scarti') . $ck('crowdsec', 'CrowdSec IPv6') . $ck('bogon', 'Scarta ULA/documentazione dal WAN') . $ck('ssh_rl', 'Limite tentativi SSH')) . dd('WireGuard IPv6 / NAT66', $ck('wg_on', 'Consenti traffico WireGuard IPv6') . '<label class=fl><span>Interfaccia VPN</span>' . sel('wg_if', $wgOpts, (string)$V['wg_if']) . '</label><label class=fl><span>Porta UDP WireGuard</span><input name=wg_port value="' . h((string)$V['wg_port']) . '" data-iptm-layout="ui-ebb13c75de"></label>' . $ck('wg_input', 'I client raggiungono il router') . $ck('wg_lan', 'I client raggiungono LAN e Internet'), 'Attivala se il server DietPi-WireGuard usa IPv6/NAT66 e il firewall IPv6 IPTM è attivo. La porta deve coincidere con quella del server.') . dd('Set CrowdSec IPv6', '<input name=cs_sets value="' . h($V['cs_sets']) . '" data-iptm-layout="mw420">', 'Set del bouncer (crowdsec6-blacklists-0 … -3). Devono esistere al momento dell\'applicazione.') . dd('Porta SSH', '<input name=ssh_port value="' . h($V['ssh_port']) . '" data-iptm-layout="ui-ebb13c75de">') . dd('Altre porte TCP', '<input name=ports value="' . h($V['ports']) . '" placeholder="80,443" data-iptm-layout="mw240">') .
        '<p><button>💾 Genera la bozza IPv6</button></p></form><h3>Regole IPv6 (bozza)</h3><form method=post>' . fh($embedded ? 'p=apply' : 'p=v6') . '<input type=hidden name=rev6 value=' . h($v6Rev) . '><input type=hidden name=action value=v6_raw><textarea name=txt rows=18 spellcheck=false>' . h($txt) . '</textarea><p class=ops data-iptm-layout="ui-19678f38f5"><button class=s>Salva testo</button>
<button class=s name=action value=v6_test>🔎 Verifica sintassi</button><button class=g name=action value=v6_apply>🚀 Applica con rollback</button><button class=s name=action value=v6_write disabled title="Usa Applica con rollback e poi Conferma">Solo salva su file (bloccato)</button><button class=d name=action value=v6_reset>Scarta bozza</button></p></form></div>';
}
/** True if WAN and LAN share a NIC or WAN carries multiple IPv4 addresses. */
function iptm_shared_wan_lan(array $S): bool {
    $wan=(string)($S['wan_if'] ?? '');
    $wanAddrs=($wan!=='' && function_exists('sys_ifaces')) ? (sys_ifaces()[$wan] ?? []) : [];
    return !empty($S['single_nic']) || ($wan!=='' && $wan === (string)($S['lan_if'] ?? '')) || count($wanAddrs)>1;
}
/** Historical URL kept for bookmarks; the interactive workspace lives in Health. */
function pg_safeplan(): void {
    echo '<div class="hero"><h2>Preflight &amp; Commit</h2><p>La procedura interattiva è stata riunificata nella pagina Sistema → Salute DietPi.</p></div>';
    echo '<div class="card"><a class="btn g" href="?p=health#health-policy">Apri Preflight &amp; Commit in Salute</a><p class="mut">Il collegamento storico resta disponibile per non rompere segnalibri e aggiornamenti esistenti.</p></div>';
}

function pg_zero() {
    if (isset($_GET['check']) && is_string($_GET['check']) && preg_match('/^[a-zA-Z0-9_.-]{1,80}$/D', $_GET['check'])) {
        echo '<div class="card"><h3>Controllo da verificare: '.h($_GET['check']).'</h3><p>Il controllo non ha superato l’audit oppure è risultato non disponibile. Riesamina i valori nel wizard e ripeti il controllo da <a href="?p=health">Salute DietPi</a> prima di applicare modifiche.</p></div>';
    }
    $lg = DATA_DIR . '/last-good.json'; $src = ''; $SS = null;
    if (is_file($lg)) { $SS = json_decode((string)file_get_contents($lg), true); $src = 'ultima configurazione confermata (' . date('d/m/Y H:i', (int)@file_get_contents(DATA_DIR . '/last-good.time')) . ')'; }
    elseif (is_file(DATA_DIR . '/settings.json')) { $SS = S_get(); $src = 'impostazioni correnti (non ancora confermate)'; }
    $pre = $SS ? zero_prefill(array_merge(S_def(), $SS)) : [];
    $if = sys_ifaces(); $nets = []; foreach ($if as $n => $a) foreach ($a as $x) $nets[net_of($x)] = $n; $sv = []; foreach (ZSVC as $k => $v) $sv[$k] = $v[0];
    echo '<div class="card"><h2>Wizard dell’intero sistema — controlli preliminari</h2><p>Prima di generare una bozza controlla il gateway, i servizi e l’accesso di recupero. Le domande successive includono LAN, WAN, NAT, DNS, DHCP, WireGuard, Docker, CrowdSec, liste IP, log, IPv6 e porte amministrative. I valori non rilevabili vanno confermati manualmente.</p><div class="ops"><a class="btn s" href="?p=piholehealth">Pi-hole web e DNS</a><a class="btn s" href="?p=health">Audit DietPi e Lynis</a><a class="btn s" href="?p=crowdsec&t=logaudit">CrowdSec e log</a><a class="btn s" href="?p=health#health-policy">Preflight &amp; Commit · Salute</a></div><p class="mut">Il wizard prepara soltanto la bozza, senza riavviare servizi, installare software, toccare sysctl o applicare regole.</p></div>';
    echo '<div class="iptm-task-intro"><div><span class="iptm-eyebrow">CONFIGURAZIONE / SETUP</span><h2>Configurazione guidata completa</h2><p>Controlla rete, servizi, DNS, regole e protezioni prima di generare una bozza. La procedura non applica automaticamente regole al firewall.</p></div><a class="btn s" href="?p=apply">Stato applicazione</a></div><div class="iptm-safety-note" role="note"><strong>Prima di iniziare</strong><span>Verifica LAN, SSH e porte della console IPTM e di Pi-hole. Dopo la creazione della bozza controlla le differenze e applica solo con rollback e conferma.</span></div><div class="card iptm-wizard-surface" id=zero><div class=steps id=zprog aria-label="Avanzamento configurazione"></div><div id=zbody aria-live=polite></div></div><script>window.ZERO=' . json_encode(['ifaces' => array_map(fn($a) => implode(', ', $a), $if), 'nets' => $nets, 'svcs' => $sv, 'bl' => array_map(fn($b) => $b[0], BL_PRESETS), 'geo' => GEO_NAMES, 'fh' => fh('p=apply'), 'pre' => $pre, 'pre_src' => $src], JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP) . ';</script>';
}
function pg_admin() {
    $U = users_get(); $me = $U[me()] ?? ['role' => 'viewer', 'totp' => '']; $adm = ($me['role'] ?? 'viewer') === 'admin'; $N = notify_cfg(); [, $conf] = priv('conf'); [, $bk] = priv('backend'); $bk = trim($bk);
    echo '<div class=card><h2>Il mio account (' . h(me()) . ')</h2><form method=post class=row>' . fh('p=admin') . '<input type=hidden name=action value=chpw><label class=fl><span>Password attuale</span><input type=password name=old required></label><label class=fl><span>Nuova</span><input type=password name=pw required></label><label class=fl><span>Conferma</span><input type=password name=pw2 required></label><div class=fl><span>&nbsp;</span><button>Cambia password</button></div></form></div>';
    echo '<div class=card><h3>Autenticazione a due fattori (TOTP)</h3>';
    if (!empty($me['totp'])) echo '<p>✅ Attiva. <form method=post class=ops data-iptm-layout="ui-491198ddb7">' . fh('p=admin') . '<input type=hidden name=action value=totp_off><input type=password name=old placeholder="password per disattivare" required data-iptm-layout="mw240"><button class=d>Disattiva 2FA</button></form></p>';
    elseif (!empty($_SESSION['totp_pend'])) { $sec = $_SESSION['totp_pend']; $uri = 'otpauth://totp/iptables-manager:' . rawurlencode(me()) . '?secret=' . $sec . '&issuer=iptables-manager';
        echo '<p>Aggiungi in un\'app (Google Authenticator, Aegis, 2FAS…) con inserimento manuale:</p><p>Chiave: <code style="display:inline;font-size:15px">' . h(trim(chunk_split($sec, 4, ' '))) . '</code></p><p class=mut>Oppure apri: <a href="' . h($uri) . '">' . h($uri) . '</a></p><form method=post class=ops data-iptm-layout="ui-491198ddb7">' . fh('p=admin') . '<input type=hidden name=action value=totp_on><input name=code placeholder="codice a 6 cifre" required data-iptm-layout="mw200" inputmode=numeric><button class=g>Conferma e attiva</button></form>'; }
    else echo '<p class=mut>Non attiva.</p><form method=post>' . fh('p=admin') . '<input type=hidden name=action value=totp_start><button>Attiva 2FA</button></form>';
    echo '</div>';
    if ($adm) {
        echo '<div class=card><h3>Utenti</h3><table><tr><th>Utente</th><th>Ruolo</th><th>2FA</th><th></th></tr>';
        foreach ($U as $n => $u) echo '<tr><td>' . h($n) . '</td><td><form method=post class=ops>' . fh('p=admin') . '<input type=hidden name=action value=user_role><input type=hidden name=user value="' . h($n) . '">' . sel('role', ['admin' => 'amministratore', 'viewer' => 'sola lettura'], $u['role'] ?? 'viewer', 'data-iptm-layout="ui-75d5f75d1a"') . '<button class="s sm">Salva</button></form></td><td>' . (!empty($u['totp']) ? '✅' : '—') . '</td><td class=ops>
<form method=post>' . fh('p=admin') . '<input type=hidden name=action value=user_reset2fa><input type=hidden name=user value="' . h($n) . '"><button class="s sm">Reset 2FA</button></form><form method=post>' . fh('p=admin') . '<input type=hidden name=action value=user_del><input type=hidden name=user value="' . h($n) . '"><button class="d sm">Elimina</button></form></td></tr>';
        echo '</table><form method=post class=row data-iptm-layout="mt10">' . fh('p=admin') . '<input type=hidden name=action value=user_add><label class=fl><span>Nuovo utente</span><input name=user pattern="[a-z0-9_.-]{2,20}" required></label><label class=fl><span>Ruolo</span>' . sel('role', ['viewer' => 'sola lettura', 'admin' => 'amministratore']) . '</label><label class=fl><span>Password</span><input type=password name=pw required></label><div class=fl><span>&nbsp;</span><button>Aggiungi</button></div></form></div>';
        $evs = ['apply' => 'Applicazione in prova', 'confirm' => 'Conferma / salvataggio', 'revert' => 'Annullamento manuale', 'rollback' => 'Rollback automatico', 'login' => 'Accesso riuscito', 'loginfail' => 'Tentativi di accesso falliti', 'rulehit' => 'Hit su regole monitorate', 'ct_high' => 'Conntrack elevato (≥85%)'];
        echo '<div class=card><h3>Notifiche</h3><form method=post class=acc>' . fh('p=admin') . '<input type=hidden name=action value=notify_save>' . dd('Telegram: token del bot', '<input name=tg_token value="' . h($N['tg_token']) . '" placeholder="123456:ABC…" autocomplete=off>') . dd('Telegram: chat ID', '<input name=tg_chat value="' . h($N['tg_chat']) . '" data-iptm-layout="mw200">') .
            dd('Webhook (ntfy, Gotify…)', '<input name=webhook value="' . h($N['webhook']) . '" placeholder="https://ntfy.sh/mio-topic">') .
            dd('Alert su regole firewall', '<label><input type=checkbox name=rule_on value=1' . (!empty($N['rule_on']) ? ' checked' : '') . '> Abilita monitoraggio contatori</label><br><label class=mut>Soglia pacchetti (delta tra controlli) <input name=rule_min type=number min=1 max=1000000 value="' . h((string)($N['rule_min'] ?? 20)) . '" data-iptm-layout="ui-48a49aa0a8"></label><br><label class=mut>Pattern nelle regole (virgola) <input name=rule_patterns value="' . h($N['rule_patterns'] ?? 'DROP,REJECT,IPTM-DROP') . '" data-iptm-layout="mw420" placeholder="DROP,REJECT,IPTM-DROP,CROWDSEC"></label>', 'Il timer di monitoraggio confronta i contatori iptables: se una regola che contiene uno di questi testi guadagna almeno N pacchetti, invia un alert su Telegram/webhook. Richiede il timer watch attivo (installazione standard).') . dd('Eventi', implode('', array_map(fn($k, $l) => '<label style="display:block"><input type=checkbox name="ev[]" value=' . $k . (in_array($k, $N['ev'], true) ? ' checked' : '') . '> ' . $l . '</label>', array_keys($evs), $evs))) .
            '<p class=ops data-iptm-layout="ui-491198ddb7"><button>💾 Salva</button><button class=s name=action value=notify_test>Invia prova</button></p></form></div>';
        echo '<div class=card><h3>Backend iptables</h3><p>Attivo: <b>' . h($bk ?: 'n/d') . '</b> <span class=mut>(iptables-legacy è il backend prioritario)</span></p><p class=mut>Per evitare interruzioni della GUI, un cambio backend richiede una console con accesso indipendente e un piano di rollback; non è disponibile dal browser.</p></div>';
        echo '<div class=card><h3>API read-only</h3><p class=mut>Endpoint JSON per Home Assistant, script e Prometheus. Solo lettura; richiede token.</p>';
        $tok = function_exists('api_token_get') ? api_token_get() : '';
        echo '<form method=post class=acc>' . fh('p=admin') . '<input type=hidden name=action value=api_token_save>'
            . dd('Token', '<input name=api_token value="' . h($tok) . '" placeholder="vuoto = API disabilitata" autocomplete=off data-iptm-layout="mw420"> '
            . '<button class=s name=action value=api_token_gen type=submit>Genera nuovo</button>')
            . '<p class=mut>Esempi: <code>?api=status&amp;token=…</code>  · <code>?api=decisions</code> · <code>?api=metrics</code><br>Header: <code>Authorization: Bearer …</code></p>'
            . '<p class=ops><button>💾 Salva token</button></p></form></div>';

        $base = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' ? 'https' : 'http') . '://' . ($_SERVER['HTTP_HOST'] ?? 'ROUTER') . ($_SERVER['SCRIPT_NAME'] ?? '/iptables-manager.php');
        $tokHint = $tok !== '' ? '(token già impostato)' : 'TOKEN';
        echo '<details class=card data-iptm-layout="mt8"><summary><b>Snippet Home Assistant</b> (REST sensor)</summary>';
        echo '<p class=mut>Incolla in <code>configuration.yaml</code> (sostituisci host e token). Solo lettura.</p><pre data-iptm-layout="ui-5c26764056">';
        echo h("rest:\n"
            . "  - resource: {$base}?api=status&token=YOUR_TOKEN\n"
            . "    headers:\n"
            . "      Authorization: Bearer YOUR_TOKEN\n"
            . "    scan_interval: 60\n"
            . "    sensor:\n"
            . "      - name: IPTM version\n"
            . "        value_template: \"{{ value_json.app }}\"\n"
            . "      - name: IPTM WAN\n"
            . "        value_template: \"{{ value_json.wan_if }}\"\n"
            . "  - resource: {$base}?api=decisions&token=YOUR_TOKEN\n"
            . "    scan_interval: 120\n"
            . "    sensor:\n"
            . "      - name: IPTM CrowdSec decisions\n"
            . "        value_template: \"{{ value_json.count }}\"\n\n"
            . "# Prometheus scrape (opzionale):\n"
            . "#   - job_name: iptm\n"
            . "#     metrics_path: " . parse_url($base, PHP_URL_PATH) . "\n"
            . "#     params: { api: [metrics], token: [YOUR_TOKEN] }\n"
            . "#     static_configs: [{ targets: [\"HOST:80\"] }]");
        echo '</pre><p class=mut>wg-easy: apri <b>udp/51820</b> (tunnel) e, solo LAN, <b>tcp/51821</b> (UI) da Porte software o regole manuali. node_exporter tipicamente <b>tcp/9100</b> LAN.</p></details>';
        
        echo '<div class=card><h3>Servizi riavviati dopo l\'applicazione</h3><p class=mut>Configurazione di root in <code>/etc/iptables-manager.conf</code> (<code>POST_SERVICES</code>, <code>POST_SCRIPT</code>).</p><pre>' . h(trim($conf) ?: '(file vuoto o non presente)') . '</pre></div>
<div class=card><h3>Blocchi gestiti</h3><p class=mut>Rimuove dalla bozza i blocchi generati (le impostazioni restano salvate).</p><form method=post>' . fh('p=admin') . '<input type=hidden name=action value=strip_managed><button class=d>Rimuovi blocchi gestiti</button></form></div>';
    echo '<div class=card id=minimal><h3>Reset a profilo minimo (connessione funzionante)</h3><p class=mut>Ricostruisce impostazioni e bozza con il <b>minimo indispensabile</b> per restare online e gestire il firewall: SPI (connessioni stabilite + loopback), anti-spoof, scarto invalidi, drop finale, anti-lockout, SSH e HTTP/HTTPS dalla LAN. Conserva WAN/LAN/NAT/DNS/WireGuard se gia impostati. <b>Rimuove</b> portscan, stealth, liste, forward, opzioni personalizzate e profili aggressivi. Backup automatico in <code>data/backups/</code>.</p><form method=post class=ops data-iptm-layout="ui-19678f38f5">' . fh('p=admin') . '<input type=hidden name=action value=reset_minimal><button>Solo bozza (poi Applica)</button> <button class=g name=apply value=1>Salva e applica ora</button></form></div>';
        echo '<div class=card><h3>Reset da zero</h3>
<p class=mut>Azzera <b>impostazioni</b> e <b>bozza</b> (con backup timestamped). Non tocca le regole LIVE del kernel né <code>rules.v4</code> fino a un nuovo «Applica». Ideale dopo un aggiornamento software, per ripartire dal Wizard.</p>
<form method=post>' . fh('p=admin') . '<input type=hidden name=action value=factory_reset><button class=d>Reset da zero → Wizard</button></form></div>';
    }
}

function hit_cell(array $HL, string $t, string $c, string $r): string {
    $x = $HL[$t . '|' . $c . '|' . rkey($r)] ?? null; if (!$x) return ''; return $x['p'] ? '<small title="' . h(hb($x['b'])) . '"><b>' . number_format($x['p']) . '</b> pkt</small>' : '<small class=mut title="mai scattata dall\'ultimo caricamento">0</small>';
}
