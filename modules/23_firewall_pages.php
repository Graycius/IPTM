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
    $tn = $_GET['t'] ?? 'filter'; $ti = tb($M, $tn);
    if ($ti < 0) { foreach ($M as $k => $b) if ($b['k'] === 'table') { $ti = $k; break; } }
    if ($ti < 0) { echo '<section class="card"><h2>Nessuna tabella nella bozza</h2><p>Apri l’editor avanzato per crearne una.</p><a class="btn s" href="?p=raw">Editor avanzato</a></section>'; return; }
    $tn = $M[$ti]['name']; $items = $M[$ti]['items'];
    $chs = []; foreach (BUILTIN[$tn] ?? [] as $bc) $chs[$bc] = '-';
    foreach (chains_of($items) as $c) $chs[$c['n']] = $c['p'];
    foreach ($items as $it) if ($it['t'] === 'rule') $chs[rchain($it['r'])] ??= '-';
    $ch = $_GET['c'] ?? array_key_first($chs); if (!isset($chs[$ch])) $ch = array_key_first($chs);
    $draftCount = count(chain_rules($items, $ch));
    echo iptm_policy_review_ui(ser($M), S_get());
    echo '<section class="iptm-rules-workbench" aria-label="Gestione delle regole firewall">';
    echo '<header class="iptm-workbench-heading"><div><span class="iptm-eyebrow">Firewall / editor regole</span><h2>Regole ' . h($tn) . ' · ' . h($ch) . '</h2><p class="mut">' . $draftCount . ' regole nella bozza · policy ' . h($chs[$ch]) . ' · ordine di valutazione dall’alto verso il basso</p></div>';
    echo '<div class="iptm-workbench-actions"><a class="btn s" href="?p=rulesaudit">Analizza rules.v4</a><a class="btn s" href="?p=wizard">Creazione guidata</a><a class="btn" href="?p=rule&amp;t=' . rawurlencode((string)$tn) . '&amp;c=' . rawurlencode((string)$ch) . '">Nuova regola</a></div></header>';
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
    $tn = $_GET['t'] ?? 'filter'; $ti = tb($M, $tn); if ($ti < 0) { echo '<div class=card>Tabella inesistente.</div>'; return; }
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
    echo '<div class="iptm-task-intro"><div><span class="iptm-eyebrow">FIREWALL / STRUTTURA</span><h2>Catene e tabelle</h2><p>Organizza le catene iptables per tabella. Modifiche e riordinamenti interessano la bozza, non il firewall attivo.</p></div><a class="btn s" href="?p=rules">Visualizza regole</a></div>';
    global $M;
    foreach ($M as $b) if ($b['k'] === 'table') {
        $tn = $b['name']; echo '<div class=card><h2>Tabella ' . h($tn) . '</h2><table>';
        $all = []; foreach (BUILTIN[$tn] ?? [] as $bc) $all[$bc] = null; foreach (chains_of($b['items']) as $c) $all[$c['n']] = $c['p'];
        foreach ($all as $c => $p) {
            $bi = in_array($c, BUILTIN[$tn] ?? [], true); $nr = count(chain_rules($b['items'], $c));
            echo '<tr><td><b>' . h($c) . '</b> <small>' . ($bi ? 'predefinita' : 'personalizzata') . ' · ' . $nr . ' regole</small></td><td><form method=post class=ops data-iptm-layout="ui-3f0497fe70">' . fh('p=chains') . '<input type=hidden name=action value=chain_op><input type=hidden name=t value="' . h($tn) . '"><input type=hidden name=chain value="' . h($c) . '">';
            if ($bi) echo '<span>policy</span><select name=policy data-iptm-layout="ui-75d5f75d1a"><option' . ($p === 'ACCEPT' ? ' selected' : '') . '>ACCEPT</option><option' . ($p === 'DROP' ? ' selected' : '') . '>DROP</option></select><button name=op value=policy>Imposta</button>';
            else echo '<label><input type=checkbox name=withrules value=1> elimina anche le regole</label><button class=d name=op value=del>Elimina</button>';
            echo '</form></td></tr>';
        }
        echo '</table><form method=post class=ops data-iptm-layout="ui-0521fd815d">' . fh('p=chains') . '<input type=hidden name=action value=chain_op><input type=hidden name=op value=add><input type=hidden name=t value="' . h($tn) . '"><input name=chain placeholder="nuova catena (es. WEB-ALLOW)" data-iptm-layout="ui-ad426e4154" pattern="[A-Za-z0-9_.:-]{1,28}" required><button>＋ Crea catena</button></form></div>';
    }
    echo '<p class=mut>La <b>policy</b> è l\'azione per i pacchetti che nessuna regola ha gestito. Con policy DROP + regole di ACCEPT esplicite hai un firewall «chiuso di default».</p>';
}

function pg_raw() {
    echo '<div class="iptm-task-intro"><div><span class="iptm-eyebrow">FIREWALL / AVANZATE</span><h2>Editor testuale delle regole</h2><p>Per utenti esperti. Rivedi differenze e sintassi della bozza prima dell’applicazione.</p></div><a class="btn s" href="?p=rules">Editor visuale</a></div><div class="iptm-safety-note" role="note"><strong>Attenzione alla connettività</strong><span>Le regole per SSH, DNS e interfaccia web devono rimanere raggiungibili. Usa sempre la procedura di applicazione con rollback.</span></div>';
    global $draftTxt;
    echo '<div class=card><h2>Editor testo (bozza completa)</h2><p class=mut>Modifica diretta del file per gli utenti esperti. Commenti e ordine sono mantenuti esattamente come li scrivi.</p><form method=post>' . fh('p=raw') . '<input type=hidden name=action value=raw_save>
<textarea name=txt rows=32 spellcheck=false>' . h($draftTxt) . '</textarea><p><button>💾 Salva nella bozza</button></p></form></div>';
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
    echo '<section class="card iptm-apply-primary"><h2>Applica la bozza</h2><p class=mut>IPTM verifica le regole e le applica temporaneamente con rollback automatico. L’applicazione definitiva delle regole richiede che il canale di gestione rimanga raggiungibile.</p>';

    echo '<div class=ops data-iptm-layout="ui-08ace85272">';
    echo '<form method=post>'.fh('p=apply').'<input type=hidden name=action value=rules_verify><button class=s>Test facoltativo</button></form>';
    echo '<form method=post>'.fh('p=apply').'<input type=hidden name=action value=apply><input type=hidden name=secs value="'.(int)ROLLBACK_SECS.'">';
    if ($dnsGuardRemoved) echo '<label><input type=checkbox name=confirm_dns_guard_removal value=1 required> Autorizzo esplicitamente la rimozione delle protezioni DNS/DoT indicate (operazione in prova con rollback)</label>';
    echo '<button class=g>Applica in prova con rollback</button></form>';
    echo '</div><p class=mut><b>Non viene confermato automaticamente.</b> Dopo il caricamento verifica da un secondo client SSH, la LAN, DNS e VPN: premi «Conferma e salva» nel pannello transazione pendente prima della scadenza. Senza conferma il watchdog ripristina le regole precedenti. Le modifiche non vengono scritte su rules.v4 finché non confermate.</p></section>';
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
        echo '<tr><td>' . h($n) . '</td><td>' . number_format(filesize($f)) . ' B</td><td class=ops><a href="?dl=' . h($n) . '">⬇ scarica</a><form method=post>' . fh('p=apply') . '<input type=hidden name=action value=restore_backup><input type=hidden name=name value="' . h($n) . '"><button>↩ carica in bozza</button></form></td></tr>'; }
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
    echo <<<'HTML'
<div class=card><h2>📘 Guida</h2>
<details open><summary>Come funziona (stile DD-WRT)</summary>
<p>Le pagine <b>Setup, Sicurezza, NAT/Forward, Restrizioni</b> si comportano come il firmware DD-WRT: imposti opzioni (Abilita/Disabilita) e lo script <b>genera le regole iptables</b> per te, scrivendole in blocchi delimitati da <code># &gt;&gt;&gt; IPTM:…</code> / <code># &lt;&lt;&lt; IPTM:…</code> dentro <code>rules.v4</code>. Le tue regole scritte a mano restano dove sono; i blocchi gestiti si rigenerano a ogni «Salva» (non modificarli a mano: usa «Regole avanzate»).</p>
<table><tr><th>DD-WRT</th><th>Qui</th></tr>
<tr><td>Firewall SPI, Block WAN requests, Filter IDENT/Multicast, Limit SSH/Telnet, Impede DoS, Log management</td><td>Sicurezza → Firewall</td></tr>
<tr><td>Port Range Forward, DMZ, NAT loopback</td><td>NAT / Forward</td></tr>
<tr><td>Access Restrictions (policy per client, giorni, orari, servizi, parole chiave)</td><td>Restrizioni accesso</td></tr>
<tr><td>WAN/LAN, NAT, DNS redirect, IP forwarding</td><td>Setup</td></tr>
<tr><td>Commands → Firewall script</td><td>Avanzate → Editor testo / Regole / Wizard</td></tr>
<tr><td>QoS</td><td>Rete → QoS (SQM/CAKE)</td></tr><tr><td>Port triggering, UPnP, filtri Java/ActiveX/Cookie</td><td>non supportati (moduli assenti nel kernel Debian o obsoleti)</td></tr></table></details>
<details open><summary>CrowdSec, Docker e i tuoi script: come convivono con il firewall</summary><p><b>CrowdSec</b>: gli agganci li crea e li reinserisce il bouncer stesso (catena <code>CROWDSEC_CHAIN</code>); l'app non scrive regole sui suoi set, perché il bouncer li crea solo per le origini che hanno decisioni (<code>crowdsec-blacklists-0</code>, <code>-1</code>… oppure un solo <code>crowdsec-blacklists</code> nelle versioni Debian) e deve poterli ricreare. L'app gli indica solo le catene da proteggere (INPUT, FORWARD se router, DOCKER-USER) e lo riavvia dopo ogni «Applica», perché il caricamento delle regole svuota la sua catena. Se usi il bouncer in modo nftables non serve nulla: lavora in una tabella propria.</p><p>Apri <b>Strumenti → Rilevamento sistema</b> per vedere ipset e catene del kernel con il loro gestore. Prima di applicare, lo script dichiara in automatico le catene create a runtime (CrowdSec, fail2ban, Docker) e toglie i riferimenti a set CrowdSec che non esistono; se una catena non esiste affatto, blocca l'applicazione invece di lasciare il firewall a metà.</p></details>
<details open><summary>Perché i client possono perdere la connessione (e cosa fa ora lo script)</summary><ul>
<li><b>Liste IP «bogon»</b> (es. FireHOL Level 1) contengono 10.x, 172.16.x e 192.168.x: usate come blocco globale spegnerebbero la LAN. Ora le reti private e le tue LAN sono <b>sempre escluse</b> (catena <code>IPTM-BL</code>) e l'helper le toglie anche dalle liste scaricate. Il GeoIP blocca di default solo il traffico in <b>ingresso</b>.</li>
<li><b>Caricare un file azzera tutto</b>: Docker, CrowdSec, fail2ban e i tuoi script ricreano le loro catene a runtime. In «Applica &amp; Backup» vedi cosa andrebbe perso e imposti i servizi/lo script da rilanciare dopo ogni applicazione (con esito per ogni passo e test di connettività).</li>
<li><b>«Salva» senza modifiche non ricarica più il firewall</b>: se la bozza è equivalente al file attivo (stesso comportamento, ignorando commenti, duplicati e ordine tra regole con lo stesso verdetto) non cambia nulla.</li>
<li><b>Protezioni contro la perdita di regole</b>: prima di applicare simulo la tua connessione alla pagina e blocco se ti chiuderesti fuori; se bozza e impostazioni non coincidono, il salvataggio viene rifiutato; le regole generate non sono modificabili a mano; ogni salvataggio mostra «+N / −M regole».</li></ul></details>
<details><summary>Importazione pulita e ottimizzata</summary><p>L'importazione riconosce le opzioni e rimuove le regole <b>duplicate</b> e quelle <b>irraggiungibili</b> (dopo una regola che chiude la catena); le righe adiacenti che differiscono solo per porte o reti vengono <b>unite</b> (es. <code>-s a,b</code>, <code>--dports 80,443</code>) e prendono un nome parlante (SSH, DNS, WireGuard…). Il risultato è verificato come semanticamente equivalente all'originale.</p></details>
<details><summary>Protezioni aggiuntive (Sicurezza e Hardening kernel)</summary><ul>
<li><b>Anti-lockout</b> (come pfSense), scarto dei <b>frammenti</b> IP, <b>rilevamento port scan</b> configurabile (hitcount / finestra / ban), filtro <b>bogon dal WAN</b>, limite di <b>nuove connessioni per client</b>, blocco <b>SMTP in uscita</b>, <b>modalità stealth</b>, <b>SYNPROXY</b>, <b>TARPIT</b> e protezione <b>DNS rebinding</b> di base.</li>
<li><b>Hardening del kernel</b> (CIS e progetti noti): SYN cookies, niente source routing né redirect ICMP, ignora ping broadcast, rp_filter <i>loose</i> (adatto a router e VPN).</li></ul></details>
<details><summary>Wizard da zero: suggerimenti</summary><p>Il wizard precompila i campi dall'<b>ultima configurazione confermata</b> (quella che hai premuto «Conferma» dopo un test riuscito), oppure dalle impostazioni correnti.</p></details>
<details open><summary>Importazione delle tue regole</summary><p>Al primo accesso la pagina <b>Importa regole</b> analizza il file e trasforma le regole scritte a mano in <b>opzioni già selezionate</b> (Setup, Sicurezza, Accesso router). Le regole generate sono identiche e nello stesso ordine; quelle non riconoscibili restano in Avanzate → Regole. L'originale viene salvato nei backup e puoi tornare indietro con «Azzera impostazioni».</p></details>
<details open><summary>Configurazione guidata da zero</summary><p>La pagina <b>Wizard da zero</b> ti pone una domanda alla volta (ruolo del dispositivo, interfacce e reti, NAT, DNS locale, livello di sicurezza, VPN, SSH, servizi, Docker/CrowdSec, port forwarding, liste IP/GeoIP, log, IPv6) e crea tutta la configurazione nella <b>bozza</b>. Poi controlli le differenze e applichi con rollback automatico.</p></details>
<details><summary>Strumenti: cosa fanno</summary><ul>
<li><b>Packet tracer</b>: simula un pacchetto nelle regole della bozza e mostra quale regola decide (ipotesi: limiti non superati; ipset e payload non valutabili).</li>
<li><b>Connessioni</b>: tabella di conntrack con filtri, «chiudi connessione» e «blocca IP». <b>Dispositivi</b>: ARP + lease DHCP, Wake-on-LAN, scorciatoia per creare una restrizione. <b>IPS</b>: avvisi di Suricata.</li>
<li><b>Alias · Liste · GeoIP</b>: gruppi con nome (<code>@nome</code> nelle tabelle), liste di IP malevoli scaricate ogni giorno (timer systemd), blocco per Paese, blocco manuale. Usano ipset: vengono ripristinati al boot dal servizio <code>iptm-ipset</code> prima del caricamento delle regole.</li>
<li><b>Port knocking</b> (Sicurezza), <b>QoS/SQM</b> con CAKE (Rete), <b>IPv6</b> semplice (Rete), <b>Storico</b> con differenze e registro delle operazioni.</li>
<li><b>Account</b>: più utenti (amministratore o sola lettura), autenticazione a due fattori TOTP, notifiche Telegram/webhook.</li></ul></details>
<details><summary>Aggiornare a una nuova versione</summary><p>Copia sul DietPi i file nuovi (<code>iptables-manager.php</code>, <code>iptm-helper</code>, <code>install-dietpi.sh</code>, <code>update-dietpi.sh</code>) e, come root: <pre>bash update-dietpi.sh</pre>Mantiene impostazioni, utenti, backup e regole; controlla la sintassi prima di sostituire i file e conserva la versione precedente in <code>/var/lib/iptables-manager/</code>.</p></details>
<details open><summary>Flusso sicuro</summary><ol><li>Modifica → «Salva (bozza)»: il firewall attivo non cambia.</li><li>«Applica ora»: carica nel kernel e salva subito su <code>/etc/iptables/rules.v4</code> (con backup datato).</li></ol></details>
<details><summary>Installazione su DietPi (Debian 13 Trixie)</summary>
<ol><li>Da <code>dietpi-software</code> installa un web server con PHP (es. Lighttpd/Nginx/Apache + PHP-FPM).</li>
<li>Copia sul DietPi <code>iptables-manager.php</code> e <code>install-dietpi.sh</code>, poi come root: <pre>bash install-dietpi.sh ./iptables-manager.php /var/www</pre></li>
<li>L'installer: installa <code>iptables-persistent</code>, crea l'helper <code>/usr/local/sbin/iptm-helper</code> con la riga sudoers (solo quell'helper), la cartella dati e il file di configurazione <code>/etc/iptables-manager.conf</code> (servizi da riavviare dopo l'applicazione, es. docker/crowdsec).</li>
<li>Apri <code>http://IP/iptables-manager.php</code>: il codice di setup è in <code>/var/lib/iptables-manager/setup-token.txt</code>.</li></ol>
<p><b>Backend iptables</b>: l'installer imposta <b>iptables-legacy</b> (predefinito). nftables (<code>iptables-nft</code>) è l'alternativa: installa con <code>--nft</code> oppure cambia da Amministrazione → Gestione (carica le regole nel nuovo backend, svuota il vecchio e riavvia i servizi).</p><p><b>Protezione IoT</b>: seleziona i dispositivi dall’inventario OUI locale e genera bozze MAC. Non vengono installati script esterni o cron; eventuali automazioni precedenti richiedono migrazione verificata.</p>
<p>Se PHP-FPM ha <code>NoNewPrivileges=yes</code>, sudo non funziona: l'installer lo segnala e dà il comando per correggerlo.</p></details>
<details><summary>Note importanti</summary><ul>
<li><b>Interfaccia unica</b>: se WAN e LAN condividono la scheda (come bond0), attiva «WAN e LAN sulla stessa interfaccia» in Setup e indica le reti LAN: il lato WAN è «tutto ciò che non è LAN».</li>
<li><b>Orari</b> delle restrizioni: convertiti in UTC (il modulo time lavora in UTC) usando il fuso di PHP; dopo un cambio ora legale premi di nuovo «Salva».</li>
<li><b>Ordine</b>: i blocchi «top» vanno prima di tutto, quelli «est» subito dopo la regola RELATED,ESTABLISHED, quelli «end» prima della regola finale catch-all.</li>
<li>Applicare ricarica <b>tutte</b> le tabelle: Docker, CrowdSec, script IoT vanno riavviati (configurali in <code>/etc/iptables-manager.conf</code>).</li>
<li><b>Sicurezza</b>: chi accede controlla il firewall. Accesso limitato a reti private (<code>ALLOWED_NETS</code>); usa HTTPS o VPN e non esporre su Internet.</li><li>Solo IPv4.</li></ul></details></div>
HTML;
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
