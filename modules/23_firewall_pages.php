<?php
// ===================== PAGINE =====================
function chains_of(array $items): array { $o = []; foreach ($items as $it) if ($it['t'] === 'chain') $o[] = $it; return $o; }
function opts(array $l, string $sel = ''): string { $o = ''; foreach ($l as $v) $o .= '<option' . ($v === $sel ? ' selected' : '') . '>' . h($v) . '</option>'; return $o; }

function model_json(): string {
    global $M; $o = [];
    foreach ($M as $b) if ($b['k'] === 'table') {
        foreach (chains_of($b['items']) as $c) $o[$b['name']][$c['n']] = ['p' => $c['p'], 'r' => []];
        foreach (BUILTIN[$b['name']] ?? [] as $bc) $o[$b['name']][$bc] ??= ['p' => 'ACCEPT', 'r' => []];
        $cnt = [];
        foreach ($b['items'] as $it) if ($it['t'] === 'rule') {
            $f = rule_parse($it['r']); $ch = $f['chain']; $cnt[$ch] = ($cnt[$ch] ?? 0) + 1;
            $o[$b['name']][$ch]['p'] ??= '-'; $o[$b['name']][$ch]['r'][] = [$cnt[$ch], act_label($f['target'])[1] . ' ' . describe($f) . ($it['on'] ? '' : ' (disattivata)')];
        }
    }
    return json_encode($o, JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP);
}

function pg_rules() {
    global $M;
    $tn = is_string($_GET['t'] ?? null) ? $_GET['t'] : 'filter'; $ti = tb($M, $tn);
    if ($ti < 0) { foreach ($M as $k => $b) if ($b['k'] === 'table') { $ti = $k; break; } }
    if ($ti < 0) { echo '<section class="card"><h2>Nessuna tabella nella bozza</h2><p>Apri l’editor avanzato per crearne una.</p><a class="btn s" href="?p=raw">Editor avanzato</a></section>'; return; }
    $tn = $M[$ti]['name']; $items = $M[$ti]['items'];
    $chs = []; foreach (BUILTIN[$tn] ?? [] as $bc) $chs[$bc] = '-';
    foreach (chains_of($items) as $c) $chs[$c['n']] = $c['p'];
    foreach ($items as $it) if ($it['t'] === 'rule') $chs[rchain($it['r'])] ??= '-';
    if (!$chs) { iptm_view_error('Nessuna catena disponibile in questa tabella.'); return; }
    $ch = is_string($_GET['c'] ?? null) ? $_GET['c'] : array_key_first($chs); if (!isset($chs[$ch])) $ch = array_key_first($chs);
    $editable = ($_SESSION['role'] ?? 'viewer') === 'admin';
    $draftCount = count(chain_rules($items, $ch));
    echo iptm_policy_review_ui(ser($M), S_get());
    echo '<section class="iptm-rules-workbench" aria-label="Gestione delle regole firewall">';
    echo '<header class="iptm-workbench-heading"><div><span class="iptm-eyebrow">Firewall / editor regole</span><h2>Regole ' . h($tn) . ' · ' . h($ch) . '</h2><p class="mut">' . $draftCount . ' regole nella bozza · policy ' . h($chs[$ch]) . ' · ordine di valutazione dall’alto verso il basso</p></div>';
    echo '<div class="iptm-workbench-actions"><a class="btn s" href="?p=rulesaudit">Analizza rules.v4</a>' . ($editable ? '<a class="btn s" href="?p=wizard">Creazione guidata</a><a class="btn" href="?p=rule&amp;t=' . rawurlencode((string)$tn) . '&amp;c=' . rawurlencode((string)$ch) . '">Nuova regola</a>' : '<span class="mut">Sola lettura</span>') . '</div></header>';
    echo '<nav class="iptm-workbench-tabs" aria-label="Tabelle iptables">';
    foreach ($M as $b) if ($b['k'] === 'table') {
        $name = $b['name']; $current = $name === $tn;
        echo '<a class="' . ($current ? 'on' : '') . '" href="?p=rules&amp;t=' . rawurlencode((string)$name) . '"' . ($current ? ' aria-current="page"' : '') . '>' . h($name) . '</a>';
    }
    echo '</nav><nav class="iptm-workbench-chains" aria-label="Catene della tabella">';
    foreach ($chs as $c => $policy) {
        $current = $c === $ch;
        echo '<a class="' . ($current ? 'on' : '') . '" href="?p=rules&amp;t=' . rawurlencode((string)$tn) . '&amp;c=' . rawurlencode((string)$c) . '"' . ($current ? ' aria-current="page"' : '') . '><strong>' . h($c) . '</strong><small>' . h($policy) . ' · ' . count(chain_rules($items, $c)) . '</small></a>';
    }
    echo '</nav>';
    echo '<section class="card iptm-rule-list"><div class="iptm-rule-list-head"><div><h3>Elenco delle regole</h3><p class="mut">Modifiche salvate in bozza. Premi Applica per attivarle.</p></div><label class="iptm-rule-search" for="rsearch"><span>Cerca per IP, porta, target o testo</span><input type="search" id="rsearch" placeholder="Filtra le regole…" autocomplete="off"></label></div>';
    echo '<div class="iptm-rule-table-scroll" role="region" aria-label="Regole della catena" tabindex="0"><table id="rtab"><thead><tr><th scope="col">#</th><th scope="col">Regola e condizione</th><th scope="col">Traffico</th><th scope="col">Azioni</th></tr></thead><tbody>';
    $n = 0; $buf = []; $mg = ''; $HL = []; $LL = live_state();
    foreach ($LL['rules'] as $x) $HL[$x['t'] . '|' . rchain($x['r']) . '|' . rkey($x['r'])] = $x;
    foreach ($items as $i => $it) {
        if ($it['t'] === 'c') {
            if (preg_match('/^# >>> IPTM:(\S+)/', $it['x'], $mm)) { $mg = $mm[1]; continue; }
            if (str_starts_with($it['x'], '# <<< IPTM:')) { $mg = ''; continue; }
            if (trim($it['x']) !== '' && count($buf) < 6) $buf[] = $it['x'];
            continue;
        }
        if ($it['t'] !== 'rule') continue;
        if (rchain($it['r']) !== $ch) { $buf = []; continue; }
        foreach ($buf as $cm) echo '<tr class="cm"><td></td><td colspan="3">' . h(strlen($cm) > 220 ? substr($cm, 0, 220) . '…' : $cm) . '</td></tr>';
        $buf = [];
        $n++; $f = rule_parse($it['r']); [$cl, $lb] = act_label($f['target']);
        echo '<tr class="iptm-rule-row ' . ($it['on'] ? '' : 'off') . '"><td class="iptm-rule-number">' . $n . '</td><td><div class="iptm-rule-description"><span class="b b-' . h($cl) . '">' . h($lb) . '</span>' . ($mg ? '<span class="b b-jump" title="Generata dalle impostazioni">' . h($mg) . '</span>' : '') . h(describe($f)) . '</div><code>' . h($it['r']) . '</code></td><td>' . ($it['on'] ? hit_cell($HL, $tn, $ch, $it['r']) : '<span class="mut">Disattivata</span>') . '</td>';
        if (!$editable) { echo '<td><span class="mut">Sola lettura</span></td></tr>'; continue; }
        echo '<td><form method="post" class="ops iptm-rule-actions" aria-label="Operazioni sulla regola ' . $n . '">' . fh() . '<input type="hidden" name="action" value="rule_op"><input type="hidden" name="t" value="' . h($tn) . '"><input type="hidden" name="idx" value="' . $i . '">';
        echo '<button type="submit" name="op" value="up" aria-label="Sposta su la regola ' . $n . '" title="Sposta su">↑</button><button type="submit" name="op" value="down" aria-label="Sposta giù la regola ' . $n . '" title="Sposta giù">↓</button>';
        echo '<button type="submit" name="op" value="toggle" aria-label="' . ($it['on'] ? 'Disattiva' : 'Attiva') . ' la regola ' . $n . '" title="' . ($it['on'] ? 'Disattiva' : 'Attiva') . '">' . ($it['on'] ? '⏸' : '▶') . '</button>';
        echo '<a href="?p=rule&amp;t=' . rawurlencode((string)$tn) . '&amp;idx=' . $i . '" aria-label="Modifica regola ' . $n . '" title="Modifica">✎</a>';
        echo '<button type="submit" name="op" value="dup" aria-label="Duplica regola ' . $n . '" title="Duplica">⧉</button><button type="submit" name="op" value="del" aria-label="Elimina regola ' . $n . '" title="Elimina">🗑</button></form></td></tr>';
    }
    if (!$n) echo '<tr><td colspan="4" class="mut">Nessuna regola presente in questa catena.</td></tr>';
    echo '</tbody></table></div><p class="iptm-rule-footnote">Le regole vengono valutate in ordine. Questa pagina non modifica il firewall attivo.</p></section></section>';
}

function pg_rule() {
    global $M;
    $tn = is_string($_GET['t'] ?? null) ? $_GET['t'] : 'filter'; $ti = tb($M, $tn); if ($ti < 0) { echo '<div class=card>Tabella inesistente.</div>'; return; }
    $ix = isset($_GET['idx']) ? (int)$_GET['idx'] : -1; $edit = $ix >= 0 && ($M[$ti]['items'][$ix]['t'] ?? '') === 'rule';
    $it = $edit ? $M[$ti]['items'][$ix] : null; $f = $edit ? rule_parse($it['r']) : array_fill_keys(['chain', 'i', 'o', 's', 'd', 'p', 'sport', 'dport', 'sports', 'dports', 'ports', 'ctstate', 'extra', 'target', 'targs'], '');
    if (!$edit) { $f['chain'] = $_GET['c'] ?? 'INPUT'; $f['target'] = 'ACCEPT'; }
    $neg = str_starts_with($f['ctstate'], '!'); $cts = array_map('trim', explode(',', ltrim($f['ctstate'], '! ')));
    $in = fn($k, $l, $ph = '', $hp = '') => '<label class=fl><span>' . $l . '</span><input name=' . $k . ' value="' . h($f[$k]) . '" placeholder="' . h($ph) . '"><small>' . $hp . '</small></label>';
    echo '<div class=card><h2>' . ($edit ? 'Modifica regola' : 'Nuova regola avanzata') . '</h2><p class=mut>Compila solo i campi che ti servono: quelli vuoti non filtrano nulla. Anteponi <code>!</code> a un valore per negarlo (es. <code>! 192.168.1.5</code>).</p>
<form method=post>' . fh('p=rules&t=' . $tn) . '<input type=hidden name=action value=rule_save><input type=hidden name=ot value="' . h($tn) . '"><input type=hidden name=idx value="' . ($edit ? $ix : '') . '">
<h3>1 · Dove si applica</h3><div class=row><label class=fl><span>Tabella</span><select name=t id=f_t>';
    foreach ($M as $b) if ($b['k'] === 'table') echo '<option' . ($b['name'] === $tn ? ' selected' : '') . '>' . h($b['name']) . '</option>';
    echo '</select><small>filter = firewall, nat = traduzione indirizzi, mangle = modifica pacchetti, raw = prima del conntrack.</small></label>
<label class=fl><span>Catena</span><select name=chain id=f_c data-cur="' . h($f['chain']) . '"></select><small>INPUT: verso questo host · FORWARD: attraversa l\'host · OUTPUT: generato dall\'host.</small></label></div>
<h3>2 · Quali pacchetti (match)</h3><div class=row>' .
        $in('i', 'Interfaccia di ingresso (-i)', 'bond0, wg0, eth+', 'Il «+» è un jolly. Non valida in OUTPUT/POSTROUTING.') . $in('o', 'Interfaccia di uscita (-o)', 'bond0', 'Non valida in INPUT/PREROUTING.') .
        $in('s', 'Sorgente (-s)', '192.168.1.0/24', 'IP, rete CIDR o lista separata da virgole.') . $in('d', 'Destinazione (-d)', '192.168.1.165') . '</div><div class=row>
<label class=fl><span>Protocollo (-p)</span><select name=p id=f_p><option value="">qualsiasi</option>' . opts(['tcp', 'udp', 'icmp', 'igmp', 'gre', 'esp', 'ah', 'sctp', 'all'], ltrim($f['p'], '! ')) . '</select><small>Per usare le porte scegli tcp o udp.</small></label>' .
        $in('dport', 'Porta di destinazione (--dport)', '22 oppure 1000:2000') . $in('sport', 'Porta di origine (--sport)', '') . $in('dports', 'Più porte dest. (multiport)', '80,443,8080', 'Fino a 15 porte separate da virgola.') . $in('sports', 'Più porte origine', '') . '</div>
<fieldset data-iptm-layout="ui-a975e89274"><legend>Stato della connessione (conntrack)</legend>';
    foreach (['NEW' => 'NEW (primo pacchetto)', 'ESTABLISHED' => 'ESTABLISHED (già avviata)', 'RELATED' => 'RELATED (collegata)', 'INVALID' => 'INVALID', 'UNTRACKED' => 'UNTRACKED'] as $k => $l) echo '<label data-iptm-layout="ui-7f248c6d35"><input type=checkbox name="ct[]" value=' . $k . (in_array($k, $cts, true) ? ' checked' : '') . '> ' . $l . '</label>';
    echo '<label><input type=checkbox name=ctneg value=1' . ($neg ? ' checked' : '') . '> nega (tutti tranne i selezionati)</label></fieldset>
<label class=fl><span>Opzioni / moduli aggiuntivi (testo libero iptables)</span><textarea name=extra id=extra rows=2 placeholder="-m limit --limit 10/min">' . h($f['extra']) . '</textarea>
<small>Qui puoi usare QUALSIASI modulo di iptables. Inserisci un esempio: <select id=snip data-iptm-layout="ui-75d5f75d1a"><option value="">— scegli uno snippet —</option></select></small></label>
<h3>3 · Cosa fare (target)</h3><div class=row><label class=fl><span>Azione (-j)</span><select name=target id=tgt data-cur="' . h($f['target']) . '"></select><small id=thint></small></label>' .
        $in('targs', 'Parametri dell\'azione', '', '<a href="#" id=tuse>usa l\'esempio</a>') . '</div>
<h3>4 · Posizione e note</h3><div class=row><label class=fl><span>Posizione nella catena</span><select name=pos id=posSel data-edit="' . ($edit ? 1 : 0) . '"></select><small>L\'ordine conta! Un SCARTA sopra a un ACCETTA lo rende inutile.</small></label>' .
        ($edit ? '' : '<label class=fl><span>Commento sopra la regola (opz.)</span><input name=cmt placeholder="Spiega a cosa serve"></label>') . '</div>
<label><input type=checkbox name=off value=1' . ($edit && !$it['on'] ? ' checked' : '') . '> Salva come disattivata (commentata)</label><p><button>💾 Salva nella bozza</button> <a class="btn s" href="?p=rules&t=' . h($tn) . '">Annulla</a></p></form></div>';
}

function pg_wizard() {
    echo '<div class="iptm-task-intro"><div><span class="iptm-eyebrow">REGOLE / PROCEDURA GUIDATA</span><h2>Nuova regola firewall</h2><p>Definisci il traffico da gestire, controlla i parametri e salva la regola nella bozza. Il firewall attivo non cambia finché non applichi e confermi.</p></div><a class="btn s" href="?p=rules">Torna alle regole</a></div>';
    echo '<div class="iptm-safety-note" role="note"><strong>Applicazione sicura</strong><span>Verifica la bozza in Applica e backup. L’applicazione delle regole dispone di rollback; mantieni l’accesso SSH di emergenza.</span></div>';
    echo '<div class="card iptm-wizard-surface" id="wiz"><div class="steps" aria-label="Fasi della procedura"><span>1 · Obiettivo</span><span>2 · Dettagli</span><span>3 · Posizione</span><span>4 · Riepilogo</span></div><div id="wbody" aria-live="polite"></div></div>';
}

function pg_chains() {
    global $M;$admin=($_SESSION['role']??'viewer')==='admin';
    iptm_view_start('Struttura del firewall','La policy si applica ai pacchetti non gestiti da alcuna regola. DROP richiede autorizzazioni esplicite per i servizi necessari. Tutte le modifiche riguardano la bozza.');
    echo iptm_view_link('rules','Visualizza regole');iptm_view_end();
    foreach($M as $b){
        if(($b['k']??'')!=='table')continue;$tn=$b['name'];$all=[];
        foreach(BUILTIN[$tn]??[] as $c)$all[$c]=null;
        foreach(chains_of($b['items']) as $c)$all[$c['n']]=$c['p'];
        iptm_view_start('Tabella '.$tn);
        echo '<div class="iptm-table-scroll" role="region" aria-label="Catene" tabindex="0"><table><thead><tr><th scope="col">Catena</th><th scope="col">Tipo</th><th scope="col">Regole</th><th scope="col">Policy</th>'.($admin?'<th scope="col">Azioni</th>':'').'</tr></thead><tbody>';
        foreach($all as $c=>$policy){
            $built=in_array($c,BUILTIN[$tn]??[],true);
            echo '<tr><th scope="row">'.iptm_view_text($c).'</th><td>'.($built?'Predefinita':'Personalizzata').'</td><td>'.count(chain_rules($b['items'],$c)).'</td><td>'.iptm_view_text($policy).'</td>';
            if($admin){
                echo '<td>';iptm_view_form('chains','chain_op',['t'=>$tn,'chain'=>$c,'op'=>$built?'policy':'del']);
                if($built){$id='policy-'.hash('sha256',$tn.'|'.$c);echo '<label for="'.$id.'">Nuova policy</label><select name="policy" id="'.$id.'"><option value="ACCEPT"'.($policy==='ACCEPT'?' selected':'').'>ACCEPT</option><option value="DROP"'.($policy==='DROP'?' selected':'').'>DROP</option></select>';iptm_view_submit('Imposta','s');}
                else{echo '<label><input type="checkbox" name="withrules" value="1"> Elimina anche le regole</label>';iptm_view_submit('Elimina catena','d');}
                echo '</td>';
            }echo '</tr>';
        }
        echo '</tbody></table></div>';
        if($admin){iptm_view_form('chains','chain_op',['t'=>$tn,'op'=>'add']);$id='new-chain-'.hash('sha256',$tn);echo '<label for="'.$id.'">Nome nuova catena</label><input id="'.$id.'" name="chain" placeholder="WEB-ALLOW" pattern="[A-Za-z0-9_.:-]{1,28}" maxlength="28" required>';iptm_view_submit('Crea catena');}
        iptm_view_end();
    }
}

function pg_raw() {
    global $draftTxt;
    iptm_view_start('Editor della bozza completa','Modificare il testo non cambia il firewall attivo. Conserva le regole SSH, DNS e web; verifica la sintassi e le differenze prima di applicare.');
    echo '<div class="iptm-workspace-actions">'.iptm_view_link('rules','Editor visuale').iptm_view_link('apply','Controlla e applica').'</div>';
    if(($_SESSION['role']??'viewer')==='admin')iptm_view_form('raw','raw_save');
    echo '<label for="iptm-raw-editor">Testo iptables-restore</label><textarea id="iptm-raw-editor" name="txt" rows="32" spellcheck="false"'.(($_SESSION['role']??'viewer')==='admin'?'':' readonly').'>'.htmlspecialchars((string)$draftTxt,ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8').'</textarea>';
    if(($_SESSION['role']??'viewer')==='admin')iptm_view_submit('Salva nella bozza');
    else echo '<p>Modifica riservata agli amministratori.</p>';
    iptm_view_end();
}

function pg_apply() {
    global $draftTxt, $rev;
    $fileTxt = rules_live();
    $mod = $draftTxt !== $fileTxt;
    $u = function_exists('posix_getpwuid') ? posix_getpwuid(posix_geteuid())['name'] : 'www-data';
    echo '<div class=card><h2>Bozza ' . ($mod ? '<span class="b b-jump">modificata rispetto al file</span>' : '<span class="b b-ACCEPT">identica al file rules.v4</span>') . '</h2>';
    if ($mod) {
        // Do not reuse shared names (_live.tmp/_draft.tmp): concurrent admins
        // could overwrite each other's diff, or expose stale network policy.
        $a = @tempnam(DATA_DIR, '.iptm-live-');
        $b = @tempnam(DATA_DIR, '.iptm-draft-');
        $o = '';
        try {
            if (!is_string($a) || !is_string($b) ||
                @file_put_contents($a, $fileTxt, LOCK_EX) !== strlen($fileTxt) ||
                @file_put_contents($b, $draftTxt, LOCK_EX) !== strlen($draftTxt)) {
                $o = 'Diff non disponibile: impossibile creare snapshot temporanei';
            } else {
                @chmod($a,0600); @chmod($b,0600);
                [$c,$out,$e] = run(['/usr/bin/diff', '-u', '--label', 'rules.v4 su disco',
                   '--label', 'bozza', $a, $b],null,12.0,150000);
                $o = in_array($c,[0,1],true) ? $out : 'Diff non disponibile: esito '.$c;
            }
        } finally {
            if(is_string($a))@unlink($a);
            if(is_string($b))@unlink($b);
        }
        echo '<details><summary>Differenze bozza rispetto a rules.v4</summary><pre>'.h($o!==''?$o:'Nessuna differenza').'</pre></details>';
    }
    $vr = $_SESSION['rules_verify'] ?? null; unset($_SESSION['rules_verify']);
    if ($vr) {
        echo '<h3>Report verifica</h3><table><tr><th>Controllo</th><th>Esito</th><th>Dettaglio</th></tr>';
        foreach ($vr['report'] as $row) {
            [$name, $st, $det] = $row;
            $b = $st === 'ok' ? 'b-ACCEPT' : ($st === 'warn' ? 'b-jump' : 'b-DROP');
            echo '<tr><td>' . h($name) . '</td><td><span class="b ' . $b . '">' . h($st) . '</span></td><td class=mut>' . h($det) . '</td></tr>';
        }
        echo '</table>';
        if (!empty($vr['raw'])) echo '<details><summary>Dettaglio rules-check</summary><pre data-iptm-layout="ui-1934322bc0">' . h($vr['raw']) . '</pre></details>';
    }
    
    try {$dnsGuardRemoved=iptm_dns_guard_losses($fileTxt,$draftTxt);}
    catch(RuntimeException $ex){$dnsGuardRemoved=[];echo '<p class="msg err">Controllo DNS/DoT non riuscito: '.h($ex->getMessage()).'</p>';}
    if($dnsGuardRemoved)echo '<div class="msg err" role="alert"><strong>La bozza rimuoverebbe protezioni DNS presenti su disco:</strong> '.h(implode(', ',$dnsGuardRemoved)).'. <a href="?p=setup">Ripristina i blocchi nella pagina Setup</a>, oppure conferma espressamente la cancellazione sotto.</div>';
    echo '<section class="card iptm-apply-primary"><h2>Applica la bozza</h2><p class=mut>Un clic per applicare: IPTM esegue i controlli prima della modifica e attiva il rollback automatico. L’applicazione definitiva delle regole richiede che il canale di gestione rimanga raggiungibile.</p>';

    echo '<div class=ops data-iptm-layout="ui-08ace85272">';
    echo '<form method=post>'.fh('p=apply').'<input type=hidden name=action value=rules_verify><button class=s>Test facoltativo</button></form>';
    if ($dnsGuardRemoved) echo '<p class="msg warn">La bozza non include alcune protezioni DNS/DoT presenti su disco: verranno rimosse all’applicazione.</p>';
    echo '<form method=post>'.fh('p=apply').'<input type=hidden name=action value=apply>'.iptm_trial_timeout_field('4').'<button class=g>Applica ora</button></form>';
    echo '</div><p class=mut>Le regole vengono applicate in prova: verifica SSH, DNS e LAN, poi premi Conferma e salva. Senza conferma si attiva il ripristino automatico. Il caricamento può ricreare le catene runtime di Docker, CrowdSec e fail2ban.</p></section>';
    echo '<details class="card iptm-apply-advanced"><summary><b>Strumenti avanzati</b> · sintassi, pulizia, regole manuali e operazioni sul file</summary><div class=ops data-iptm-layout="ui-0e001e227c">';
    echo '<form method=post>'.fh('p=apply').'<input type=hidden name=action value=test><button class=s>Test solo sintassi</button></form>';
    echo '<form method=post>'.fh('p=apply').'<input type=hidden name=action value=policy_export><button class=s>Esporta policy YAML</button></form>';
    echo '<form method=post>'.fh('p=apply').'<input type=hidden name=action value=save_file><button class=s>Salva soltanto su disco</button></form>';
    echo '<form method=post>'.fh('p=apply').'<input type=hidden name=action value=draft_reset><button class=d>Scarta bozza</button></form></div>';

        // --- Pulizia regole obsolete / inutili ---
    $cl = $_SESSION['rules_cleanup'] ?? null;
    echo '<div class=card data-iptm-layout="ui-0e001e227c"><h3>Pulizia regole</h3>';
    echo '<p class=mut>Trova e rimuove dalla <b>bozza</b> regole duplicate, irraggiungibili, target incompatibili/obsoleti (es. PORTSCAN), salti a catene mancanti, regole disattivate e catene orfane. Non applica al kernel finché non fai «Applica».</p>';
    echo '<div class="card"><h4>Pulizia delle regole nel kernel (non nella bozza)</h4>';
    echo '<p class="mut">Rimuove esclusivamente duplicati <b>consecutivi identici</b> nelle catene IPTM_*, lasciando intatti CrowdSec, Suricata, Docker, INPUT/FORWARD e catene di terzi. La conferma richiede una nuova verifica dello snapshot e salva il backup root-only.</p>';
    echo '<form method="post">'.fh('p=apply').'<input type="hidden" name="action" value="live_rules_scan"><button class="s">Analizza regole runtime IPv4/IPv6</button></form>';
    $live=$_SESSION['iptm_live_cleanup']??null;
    if(is_array($live)&&time()-(int)($live['created']??0)<180){
        echo '<p><b>'.(int)$live['count'].'</b> duplicati runtime candidati.</p>';
        if(!empty($live['count'])){
            echo '<table><thead><tr><th>IP</th><th>Tabella</th><th>Catena</th><th>Posizione</th></tr></thead><tbody>';
            foreach($live['findings'] as $r)echo '<tr><td>'.h($r['family']??'').'</td><td>'.h($r['table']??'').'</td><td>'.h($r['chain']??'').'</td><td>'.(int)($r['number']??0).'</td></tr>';
            echo '</tbody></table><form method="post">'.fh('p=apply').'<input type="hidden" name="action" value="live_rules_apply"><input type="hidden" name="plan_sha256" value="'.h($live['sha256']).'"><button class="d">Esegui pulizia runtime</button></form>';
        }
    }
    echo '</div>';
    echo '<form method=post class=ops>' . fh('p=apply') . '<input type=hidden name=action value=rules_cleanup_scan><button class=s>🧹 Analizza bozza</button></form>';
    if (($_SESSION['role'] ?? 'viewer') !== 'viewer') echo '<form method=post class=ops data-iptm-layout="mt8">' . fh('p=apply') . '<input type=hidden name=action value=rules_compact_safe><button class=g>Compatta: rimuovi solo duplicati esatti</button></form>';
    if ($cl && is_array($cl)) {
        $labels = [
            'duplicate' => 'Duplicate esatte',
            'unreachable' => 'Irraggiungibili (dopo catch-all)',
            'bad_target' => 'Target obsoleti (PORTSCAN…)',
            'incompatible' => 'Target non disponibili nel kernel',
            'missing_chain' => 'Salto a catena inesistente',
            'disabled' => 'Regole disattivate',
            'noisy' => 'LOG senza limit',
            'orphan_chain' => 'Catene orfane vuote',
        ];
        if (empty($cl['total'])) {
            echo '<p class="msg ok">Nessuna regola candidata alla pulizia.</p>';
        } else {
            if (!empty($cl['incompatible_n'])) {
                echo '<div class="msg err"><b>Regole incompatibili: ' . (int)$cl['incompatible_n'] . '</b>';
                if (!empty($cl['modules_missing'])) echo ' · moduli/target assenti: <code>' . h(implode(', ', $cl['modules_missing'])) . '</code>';
                echo '<ul data-iptm-layout="ui-4087b25a64">';
                $n = 0;
                foreach ($cl['incompatible'] as $f) {
                    if ($n++ >= 12) { echo '<li class=mut>…</li>'; break; }
                    echo '<li><code>' . h(($f['t'] ?? '') . '/' . ($f['c'] ?? '')) . '</code> — ' . h($f['why'] ?? '') . '</li>';
                }
                echo '</ul></div>';
            }
            echo '<p><b>' . (int)$cl['total'] . '</b> voci trovate · per categoria: ';
            $bits = [];
            foreach ($cl['by_cat'] as $k => $n) $bits[] = h($labels[$k] ?? $k) . ': ' . (int)$n;
            echo implode(' · ', $bits) . '</p>';
            echo '<form method=post>' . fh('p=apply') . '<input type=hidden name=action value=rules_cleanup_apply>';
            echo '<p>';
            foreach ($labels as $k => $lab) {
                if (empty($cl['by_cat'][$k])) continue;
                $chk = in_array($k, ['duplicate','unreachable','bad_target','incompatible','missing_chain'], true) ? ' checked' : '';
                echo '<label data-iptm-layout="ui-2d0d1ae7bd"><input type=checkbox name=cats[] value="' . h($k) . '"' . $chk . '> ' . h($lab) . ' (' . (int)$cl['by_cat'][$k] . ')</label> ';
            }
            echo '</p>';
            echo '<p><label><input type=checkbox name=include_managed value=1> Includi anche regole dentro blocchi gestiti IPTM (di solito no: verranno rigenerate)</label></p>';
            echo '<p class=ops><button class=d>Rimuovi selezionate dalla bozza</button></p></form>';
            echo '<details><summary>Dettaglio (prime 40)</summary><table><tr><th>Cat</th><th>Sev</th><th>Tabella/catena</th><th>Motivo</th><th>Regola</th></tr>';
            $n = 0;
            foreach ($cl['findings'] as $f) {
                if ($n++ >= 40) break;
                $b = ($f['sev'] ?? '') === 'err' ? 'b-DROP' : (($f['sev'] ?? '') === 'warn' ? 'b-jump' : 'b-ACCEPT');
                echo '<tr><td>' . h($f['cat']) . '</td><td><span class="b ' . $b . '">' . h($f['sev']) . '</span></td>';
                echo '<td class=mut>' . h(($f['t'] ?? '') . '/' . ($f['c'] ?? '')) . (!empty($f['managed']) ? ' · gestita' : '') . '</td>';
                echo '<td>' . h($f['why'] ?? '') . '</td><td><code data-iptm-layout="ui-a49cca52be">' . h(strlen($f['raw'] ?? '') > 100 ? substr($f['raw'], 0, 100) . '…' : ($f['raw'] ?? '')) . '</code></td></tr>';
            }
            echo '</table></details>';
        }
    }
    echo '</div>';


    // --- Regole personalizzate: elenco, integrazione, pulizia ---
    $crp = $_SESSION['custom_rules_plan'] ?? null;
    echo '<div class=card data-iptm-layout="ui-0e001e227c"><h3>Regole personalizzate</h3><p><a class=btn href="?p=manual">🔎 Analisi avanzata: conversione verificata in opzioni →</a></p>';
    echo '<p class=mut>Regole <b>fuori</b> dai blocchi gestiti IPTM. Dove possibile: estrazione nelle impostazioni (servizi, port forward, allow/block) e rigenerazione dei blocchi.</p>';
    echo '<form method=post class=ops>' . fh('p=apply') . '<input type=hidden name=action value=custom_rules_scan><button class=s>📋 Analizza personalizzate</button></form>';
    if ($crp && is_array($crp)) {
        echo '<p><b>' . (int)$crp['total_custom'] . '</b> personalizzate · <span class="b b-ACCEPT">' . (int)$crp['n_can'] . ' integrabili</span> · <span class="b b-jump">' . (int)$crp['n_left'] . ' manuali</span></p>';
        if (!empty($crp['can'])) {
            echo '<h4>Integrabili nelle regole generate</h4><table><tr><th>Dove</th><th>Integrazione</th><th>Regola</th></tr>';
            foreach (array_slice($crp['can'], 0, 30) as $r) {
                echo '<tr><td class=mut>' . h(($r['t'] ?? '') . '/' . ($r['c'] ?? '')) . '</td><td>' . h($r['how'] ?? '') . '</td><td><code data-iptm-layout="ui-a49cca52be">' . h(strlen($r['raw'] ?? '') > 90 ? substr($r['raw'], 0, 90) . '…' : ($r['raw'] ?? '')) . '</code></td></tr>';
            }
            echo '</table>';
            echo '<form method=post class=ops data-iptm-layout="mt8">' . fh('p=apply') . '<input type=hidden name=action value=custom_rules_integrate>';
            echo '<button class=g>✨ Integra nelle generate</button></form>';
        }
        if (!empty($crp['left'])) {
            echo '<h4>Restano personalizzate</h4><form method=post>' . fh('p=apply') . '<input type=hidden name=action value=custom_rules_delete>';
            echo '<table><tr><th></th><th>Catena</th><th>Motivo</th><th>Regola</th></tr>';
            foreach (array_slice($crp['left'], 0, 40) as $r) {
                $key = (int)$r['ti'] . ':' . (int)$r['i'];
                echo '<tr><td><input type=checkbox name=cr[] value="' . h($key) . '"></td>';
                echo '<td class=mut>' . h(($r['t'] ?? '') . '/' . ($r['c'] ?? '')) . '</td>';
                echo '<td>' . h($r['why'] ?? '') . '</td>';
                echo '<td><code data-iptm-layout="ui-a49cca52be">' . h(strlen($r['raw'] ?? '') > 90 ? substr($r['raw'], 0, 90) . '…' : ($r['raw'] ?? '')) . '</code></td></tr>';
            }
            echo '</table>';
            echo '<p class=ops><button class=d>Elimina selezionate</button></p></form>';
        }
        if (empty($crp['total_custom'])) echo '<p class="msg ok">Nessuna regola personalizzata fuori dai blocchi IPTM.</p>';
    }
    echo '</div>';

    pg_apply_extra();
    echo '</details>';
    // diagnostica
    [$c1, , $e1] = priv('ping'); $ok = fn($v) => $v ? '✅' : '❌';
    echo '<div class=card><h3>Diagnostica</h3><p>' . $ok(rules_live() !== '') . ' lettura ' . h(RULES_FILE) . ' &nbsp; ' . $ok($c1 === 0) . ' helper root (' . h(HELPER) . ') &nbsp; <small>(utente web: ' . h($u) . ')</small></p>';
    if ($c1) echo '<p>Helper non raggiungibile: esegui <code>install-dietpi.sh</code> come root (vedi Guida). Dettaglio: ' . h(trim($e1)) . '</p>';
    echo '</div>';
    $bk = glob(DATA_DIR . '/backups/rules.v*.*') ?: []; rsort($bk);
    echo '<div class=card><h3>Checklist post-apply</h3><p class=mut><a href="?p=postcheck">Apri checklist servizi / script / catene runtime →</a></p></div>';
    echo '<div class=card><h3>Backup con etichetta</h3><form method=post class=row>' . fh('p=apply') . '<input type=hidden name=action value=backup_named>'
        . '<label class=fl data-iptm-layout="ui-83725d2c6e"><span>Etichetta</span><input name=label placeholder="prima-di-audit" maxlength=40></label>'
        . '<p><button class=s>💾 Crea backup etichettato</button></p></form></div>';
    echo '<div class=card><h3>Backup automatici — ultimi 10 per tipologia (più backup manuali)</h3><table>';
    foreach (array_slice($bk, 0, 30) as $f) { $n = basename($f);
        echo '<tr><td>' . h($n) . '</td><td>' . number_format(filesize($f)) . ' B</td><td class=ops><a href="?dl=' . h($n) . '">⬇ scarica</a><form method=post>' . fh('p=apply') . '<input type=hidden name=rev6 value="' . h($backupRev6 ??= hash('sha256',v6_get())) . '"><input type=hidden name=action value=restore_backup><input type=hidden name=name value="' . h($n) . '"><button>↩ carica in bozza</button></form></td></tr>'; }
    echo $bk ? '' : '<tr><td class=mut>Nessun backup ancora.</td></tr>'; echo '</table></div>';
    if (($_SESSION['role']??'')==='admin') {
        $eligible=array_values(array_filter($bk, static function($f) { return is_file($f) && !is_link($f) && preg_match('/^rules\.v[46]\.\d{8}-\d{6}$/D',basename($f)) && filemtime($f)<time()-7*86400; }));
        usort($eligible, static fn($x,$y) => strcmp(basename($y),basename($x)));
        $eligible=array_slice($eligible,10);
        echo '<div class=card><h3>Pulizia backup automatici</h3><p class=mut>Elimina solo le copie selezionate. I backup recenti e di emergenza sono protetti.</p>';
        if ($eligible) {
            echo '<form method=post>'.fh('p=apply').'<input type=hidden name=action value=backup_prune><div data-iptm-layout="ui-9e2a89054c">';
            foreach(array_slice($eligible,0,100) as $f) echo '<label style="display:block;padding:5px"><input type=checkbox name="backup_files[]" value="'.h(basename($f)).'"> '.h(basename($f)).'</label>';
            echo '</div><p><button class=d>Elimina i backup selezionati</button></p></form>';
        } else echo '<p>Non ci sono backup automatici idonei alla pulizia.</p>';
        echo '</div>';
    }

    echo '<div class="card"><h2>IPv6 nella stessa pagina</h2><p class=mut>Editor e anteprima IPv6 sotto la bozza IPv4. La disattivazione dello stack IPv6 richiede accesso console e non viene eseguita automaticamente dalla UI.</p></div>';
    pg_v6(true);
}

function pg_guide() {
    iptm_view_start('Come usare IPTM','Le configurazioni vengono preparate nella bozza. L’attivazione del firewall è separata e deve essere confermata dopo la prova.');
    $sections=[
        ['1. Rileva il sistema','Controlla interfacce, gateway, servizi e accesso amministrativo. Non scegliere una WAN diversa da quella effettivamente utilizzata.','system','Rilevamento sistema'],
        ['2. Conserva una copia','Esporta il profilo e conserva un backup DietPi. L’export portabile non include tutte le credenziali.','config','Backup e configurazioni'],
        ['3. Prepara la bozza','Usa il wizard o importa le regole correnti. Controlla sempre LAN, VPN, DNS e le catene di Docker/CrowdSec.','zero','Wizard completo'],
        ['4. Analizza le modifiche','Verifica le differenze e simula il traffico. La simulazione non riproduce tutti i moduli o lo stato del kernel.','tracer','Simulazione pacchetto'],
        ['5. Prova e conferma','Mantieni una console locale disponibile. Verifica SSH, navigazione e DNS da un secondo dispositivo durante la prova. Se un controllo fallisce, non confermare.','apply','Applica e backup'],
        ['6. Controlla prestazioni e servizi','Configura QoS dopo avere verificato WAN e proprietà delle qdisc. Le modifiche DNS, sysctl, reti e servizi hanno procedure dedicate.','health','Salute DietPi']
    ];foreach($sections as [$title,$desc,$route,$label])echo '<article class="iptm-guide-step"><h3>'.iptm_view_text($title).'</h3><p>'.iptm_view_text($desc).'</p>'.iptm_view_link($route,$label).'</article>';
    iptm_view_end();
    iptm_view_start('Aggiornamenti e recupero','Da una 5.30.29 funzionante usa il pacchetto Native Update, non l’archivio FULL. Conserva il digest da una fonte attendibile. HTTP resta supportato; non esporre IPTM sulla WAN.');
    echo '<p>La distribuzione FULL contiene installatore, recovery, guida e test. Segui il README incluso, non i vecchi script install-dietpi.sh o update-dietpi.sh.</p>'.iptm_view_link('update','Aggiornamenti'). ' '.iptm_view_link('history','Storico e ripristino');iptm_view_end();
    iptm_view_start('Limiti della simulazione','IPv4 e IPv6 hanno bozze distinte. Le policy MAC richiedono controllo della topologia. I set IP, il routing, i moduli dinamici e i servizi esterni possono modificare il risultato osservato.');
    echo '<p>Un test positivo non garantisce la raggiungibilità da tutte le reti. Mantieni sempre un percorso di recupero indipendente.</p>';iptm_view_end();
}



/** IPTM 5.30.9: one-click offline rules.v4 audit and in-memory hardening. */
function pg_rulesaudit() {
    $admin = (($_SESSION['role'] ?? 'viewer') === 'admin');
    echo '<div class="iptm-task-intro"><div><h2>Analizza e correggi rules.v4</h2>'
        . '<p>Individua aperture e conflitti. Crea solo una bozza, senza modificare il firewall attivo.</p>'
        . '</div><a class="btn s" href="?p=rules">Regole</a></div>';
    if ($admin) {
        echo '<section class="card"><h3>Nuova bozza sicura</h3><form method="post" enctype="multipart/form-data">'
            . fh('p=rulesaudit') . '<input type="hidden" name="action" value="rules_audit_import">'
            . '<label class="fl" for="iptm_rules_audit_file"><span>File rules.v4 (opzionale)</span>'
            . '<input id="iptm_rules_audit_file" type="file" name="rules_file" accept=".v4,.txt,text/plain" />'
            . '<small>Se non scegli un file, analizza la bozza corrente. Limite 2 MB.</small></label>'
            . '<div class="ops"><button class="btn s" type="submit" name="audit_mode" value="audit">Controlla soltanto</button>'
            . '<button class="g" type="submit" name="audit_mode" value="harden">Crea bozza corretta</button></div></form></section>';
    }
    // Quick, read-only cross-check of the CURRENT selected settings. This is
    // deliberately lightweight even on an Atom N450; the 500k matrix is an
    // OFFLINE release test, never performed inside a web request.
    echo '<p class="mut"><strong>Continuità rete:</strong> ' . (!empty(S_get()['continuity_priority'])
         ? 'attiva' : 'disattivata') . ' · <a href="?p=security">Modifica in Protezione</a></p>';
    $currentWarnings = [];
    try {
        [, $currentWarnings] = gen_sections(S_get());
    } catch (Throwable $e) {
        $currentWarnings = ['Controllo delle opzioni temporaneamente non disponibile.'];
    }
    $messages = array_values(array_unique(array_filter(array_map('strval', (array)$currentWarnings))));
    $nb = count($messages);
    echo '<details class="card"><summary>Controllo opzioni attive (' . $nb . ' avvisi)</summary>';
    if ($nb === 0) echo '<p>Nessun avviso dai controlli di generazione.</p>';
    else {
        echo '<ul>';
        foreach (array_slice($messages, 0, 20) as $message) echo '<li>' . h($message) . '</li>';
        if ($nb > 20) echo '<li>Altri ' . ($nb - 20) . ' avvisi: verifica le impostazioni di rete.</li>';
        echo '</ul>';
    }
    echo '<p class="mut">Test di release: 2.097.152 combinazioni offline. La verifica non applica regole e non sostituisce il test con rollback sul sistema.</p></details>';
    $report = $_SESSION['iptm_rules_audit'] ?? null;
    if (!is_array($report)) return;
    $findings = (array)($report['findings'] ?? []);
    $changes = (array)($report['changes'] ?? []);
    $count = ['critical'=>0,'high'=>0,'medium'=>0,'low'=>0,'info'=>0];
    foreach ($findings as $item) {
        $level = (string)($item['severity'] ?? 'info');
        $count[$level] = ($count[$level] ?? 0) + 1;
    }
    $auditOnly = (($report['mode'] ?? 'harden') === 'audit');
    echo '<section class="card"><h3>' . ($auditOnly ? 'Controllo della bozza' : 'Bozza corretta') . '</h3><p>' . (int)($report['before']??0)
         . ' regole originali · ' . (int)($report['after']??0) . ' nella nuova bozza · <b>'
         . count($changes) . ' modifiche</b></p>';
    echo '<p class="ops"><span class="b b-jump">Critiche: ' . $count['critical'] . '</span>'
         . '<span class="b b-jump">Alte: ' . $count['high'] . '</span>'
         . '<span>Da verificare: ' . ($count['medium'] + $count['low'] + $count['info']) . '</span></p>';
    echo '<p class="ops">';
    if (!$auditOnly) echo '<a class="btn" href="?p=apply">Verifica e applica con rollback</a>';
    echo '<a class="btn s" href="?p=raw">Apri bozza</a></p></section>';
    echo '<section class="card"><h3>Problemi e correzioni</h3><div class="iptm-rule-table-scroll" role="region" tabindex="0" aria-label="Analisi rules.v4"><table>'
         . '<thead><tr><th>Rischio</th><th>Problema</th><th>Esito</th></tr></thead><tbody>';
    foreach ($findings as $item) {
        if (!is_array($item)) continue;
        $sev = (string)($item['severity'] ?? 'info');
        $label = ['critical'=>'Critico','high'=>'Alto','medium'=>'Medio','low'=>'Basso','info'=>'Info'][$sev] ?? 'Info';
        $resolution = (!$auditOnly && ($item['resolution'] ?? '') === 'automatic') ? 'Corretto' : 'Da verificare';
        $ln = implode(', ', array_map('intval', (array)($item['lines']??[])));
        echo '<tr><td>' . h($label) . '</td><td><strong>' . h((string)($item['message']??'')) . '</strong>'
           . ($ln !== '' ? '<small>Righe: ' . h($ln) . '</small>' : '');
        $details = (array)($item['details']??[]);
        if (!empty($details['mac']) && is_array($details['mac']))
            echo '<small>MAC: ' . h(implode(', ',array_slice($details['mac'],0,16))) . '</small>';
        echo '</td><td>' . h($resolution) . '</td></tr>';
    }
    echo '</tbody></table></div></section>';
    if ($changes) {
        echo '<details class="card"><summary>Dettaglio modifiche (' . count($changes) . ')</summary><ul>';
        foreach ($changes as $item) if (is_array($item))
            echo '<li>Riga ' . (int)($item['line']??0) . ': ' . h((string)($item['reason']??'')) . '</li>';
        echo '</ul></details>';
    }
    echo '<p class="mut">Regole non applicate. Controlla servizi, MAC, VPN e IPv6 prima del test con rollback.</p>';
}
