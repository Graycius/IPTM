<?php
/* IPTM action domain: firewall. Inherits the authenticated controller scope. */
switch ($a) {
case 'rule_op': {
            $ti = tb($M, (string)($_POST['t'] ?? '')); $ix = (int)($_POST['idx'] ?? -1); $op = (string)($_POST['op'] ?? '');
            if ($ti < 0 || !isset($M[$ti]['items'][$ix])) { flash('Regola non trovata.', 'err'); break; }
            $items = &$M[$ti]['items']; $it = $items[$ix];
            if ($it['t'] === 'rule' && $op !== 'dup' && in_region($items, $ix)) { unset($items); flash('Questa regola è generata dalle impostazioni e verrebbe rigenerata al prossimo salvataggio: modificala da Setup/Sicurezza (o disattiva l\'opzione).', 'err'); break; }
            if ($op === 'toggle' && $it['t'] === 'rule') $items[$ix]['on'] = !$it['on'];
            elseif ($op === 'del' && $it['t'] !== 'chain') array_splice($items, $ix, 1);
            elseif ($op === 'dup' && $it['t'] === 'rule') array_splice($items, $ix + 1, 0, [['t' => 'rule', 'r' => $it['r'], 'on' => true]]);
            elseif (($op === 'up' || $op === 'down') && $it['t'] === 'rule') {
                $l = chain_rules($items, rchain($it['r'])); $p = array_search($ix, $l, true); $q = $op === 'up' ? $p - 1 : $p + 1;
                if (isset($l[$q])) { $tmp = $items[$ix]; $items[$ix] = $items[$l[$q]]; $items[$l[$q]] = $tmp; }
            }
            unset($items); save_model(); break;
        }
        case 'rule_save': {
            $tn = (string)($_POST['t'] ?? ''); $ti = tb($M, $tn);
            if ($ti < 0) { flash('Tabella inesistente.', 'err'); break; }
            $f = []; foreach (['chain', 'i', 'o', 's', 'd', 'p', 'sport', 'dport', 'sports', 'dports', 'ports', 'extra', 'target', 'targs'] as $k) $f[$k] = trim((string)($_POST[$k] ?? ''));
            $ct = array_intersect((array)($_POST['ct'] ?? []), ['NEW', 'ESTABLISHED', 'RELATED', 'INVALID', 'UNTRACKED', 'SNAT', 'DNAT']);
            $f['ctstate'] = ($ct ? (!empty($_POST['ctneg']) ? '! ' : '') . implode(',', $ct) : '');
            $bad = !preg_match('/^[A-Za-z0-9_.:-]{1,28}$/', $f['chain']) || !preg_match('/^[A-Za-z0-9_.:-]*$/', $f['target']);
            foreach (['i', 'o', 's', 'd', 'p', 'sport', 'dport', 'sports', 'dports', 'ports'] as $k) if (!preg_match('/^(!\s*)?[^\s\x00-\x1f]*$/', $f[$k])) $bad = true;
            if (preg_match('/[\x00-\x1f]/', $f['extra'] . $f['targs'])) $bad = true;
            if ($bad) { flash('Valori non validi (spazi o caratteri di controllo nei campi semplici).', 'err'); break; }
            if (!chain_ok($tn, $M[$ti]['items'], $f['chain'])) { flash('La catena «' . $f['chain'] . '» non esiste in ' . $tn . ': creala prima nella scheda Catene.', 'err'); break; }
            $raw = rule_build($f); $on = !isset($_POST['off']); $pos = preg_match('/^(keep|start|last|smart|\d+)$/', (string)($_POST['pos'] ?? '')) ? $_POST['pos'] : 'smart';
            $ot = (string)($_POST['ot'] ?? ''); $ix = ($_POST['idx'] ?? '') === '' ? -1 : (int)$_POST['idx']; $oti = tb($M, $ot);
            if ($ix >= 0 && $oti >= 0 && isset($M[$oti]['items'][$ix]) && in_region($M[$oti]['items'], $ix)) { flash('Questa regola è generata dalle impostazioni: modificala da Setup/Sicurezza.', 'err'); break; }
            $same = $ix >= 0 && $oti === $ti && isset($M[$ti]['items'][$ix]) && rchain($M[$ti]['items'][$ix]['r'] ?? '') === $f['chain'];
            if ($same && $pos === 'keep') { $M[$ti]['items'][$ix] = ['t' => 'rule', 'r' => $raw, 'on' => $on]; }
            else {
                if ($ix >= 0 && $oti >= 0 && isset($M[$oti]['items'][$ix]) && $M[$oti]['items'][$ix]['t'] === 'rule') array_splice($M[$oti]['items'], $ix, 1);
                $new = []; $c = trim((string)($_POST['cmt'] ?? '')); if ($c !== '' && !preg_match('/[\x00-\x1f]/', $c)) $new[] = ['t' => 'c', 'x' => '# ' . $c];
                $new[] = ['t' => 'rule', 'r' => $raw, 'on' => $on];
                array_splice($M[$ti]['items'], ins_index($M[$ti]['items'], $f['chain'], $pos === 'keep' ? 'smart' : $pos), 0, $new);
            }
            save_model(); flash('Regola salvata nella bozza.'); $back = 'p=rules&t=' . $tn . '&c=' . $f['chain']; break;
        }
        case 'wizard_add': {
            $rs = json_decode((string)($_POST['rules'] ?? ''), true); $pos = preg_match('/^(start|last|smart|\d+)$/', (string)($_POST['pos'] ?? '')) ? $_POST['pos'] : 'smart';
            if (!is_array($rs) || !$rs) { flash('Nessuna regola da aggiungere.', 'err'); break; }
            $groups = [];
            foreach ($rs as $x) {
                $tn = (string)($x['t'] ?? ''); $r = (string)($x['r'] ?? ''); $ti = tb($M, $tn);
                if ($ti < 0 || !lint_rule($r) || !chain_ok($tn, $M[$ti]['items'], rchain($r))) { flash('Regola non valida o catena inesistente: ' . $r, 'err'); go($back); }
                $groups[$tn . '|' . rchain($r)][] = ['t' => 'rule', 'r' => $r, 'on' => true];
            }
            $first = true; $c = trim((string)($_POST['cmt'] ?? '')); $c = preg_replace('/[\x00-\x1f]/', ' ', $c);
            foreach ($groups as $key => $its) {
                [$tn, $ch] = explode('|', $key, 2); $ti = tb($M, $tn);
                if ($first && $c !== '') array_unshift($its, ['t' => 'c', 'x' => '# [Wizard] ' . $c]);
                array_splice($M[$ti]['items'], ins_index($M[$ti]['items'], $ch, $first ? $pos : 'smart'), 0, $its);
                if ($first) $back = 'p=rules&t=' . $tn . '&c=' . $ch; $first = false;
            }
            save_model(); flash('Regole aggiunte alla bozza. Ora usa «Applica & Backup» per provarle.'); break;
        }
        case 'chain_op': {
            $tn = (string)($_POST['t'] ?? ''); $ti = tb($M, $tn); $ch = (string)($_POST['chain'] ?? ''); $op = (string)($_POST['op'] ?? '');
            if ($ti < 0 || !preg_match('/^[A-Za-z0-9_.:-]{1,28}$/', $ch)) { flash('Parametri non validi.', 'err'); break; }
            $items = &$M[$ti]['items'];
            $ci = null; foreach ($items as $i => $it) if ($it['t'] === 'chain' && $it['n'] === $ch) $ci = $i;
            if ($op === 'add') {
                if ($ci !== null || in_array($ch, BUILTIN[$tn] ?? [], true)) flash('La catena esiste già.', 'err');
                else { $last = 0; foreach ($items as $i => $it) if ($it['t'] === 'chain') $last = $i + 1; array_splice($items, $last, 0, [['t' => 'chain', 'n' => $ch, 'p' => '-']]); flash('Catena creata.'); }
            } elseif ($op === 'policy' && $ci !== null && in_array($items[$ci]['n'], BUILTIN[$tn] ?? [], true) && in_array($_POST['policy'] ?? '', ['ACCEPT', 'DROP'], true)) {
                $items[$ci]['p'] = $_POST['policy']; flash('Policy di ' . $ch . ' → ' . $_POST['policy'] . ' (nella bozza).');
            } elseif ($op === 'del' && $ci !== null && !in_array($ch, BUILTIN[$tn] ?? [], true)) {
                $rl = chain_rules($items, $ch);
                if ($rl && empty($_POST['withrules'])) flash('La catena contiene ' . count($rl) . ' regole: spunta «elimina anche le regole».', 'err');
                else { $items = array_values(array_filter($items, fn($it, $i) => $i !== $ci && !($it['t'] === 'rule' && rchain($it['r']) === $ch), ARRAY_FILTER_USE_BOTH)); flash('Catena eliminata. Verifica che nessuna regola faccia più «-j ' . $ch . '» (il Test lo segnala).'); }
            } else flash('Operazione non consentita.', 'err');
            unset($items); save_model(); break;
        }
        case 'import_apply': {
            if (is_file(DATA_DIR . '/settings.json')) { flash('Importazione già eseguita.', 'err'); break; }
            $pl = import_plan_safe($M); $orig = ser($M);
            @mkdir(DATA_DIR . '/backups', 0700, true); file_put_contents(DATA_DIR . '/pre-import.rules', $orig); file_put_contents(DATA_DIR . '/backups/rules.v4.' . date('Ymd-His'), $orig);
            import_apply_model($M, $pl, false);
            $warn = regen($M, $pl['S']);
            $cleaned = iptm_import_without_legacy_comments(ser($M));
            $M = parse_rules($cleaned['draft']);
            S_put($pl['S']); save_model();
            flash('Importate ' . count($pl['absorbed']) . ' regole come opzioni (' . count($pl['on']) . ' opzioni attive); rimossi ' . $cleaned['removed'] . ' commenti e regole disattivate della vecchia bozza. Nessuna regola live modificata. Controlla le differenze prima di applicare.'); foreach ($warn as $w) flash('⚠ ' . $w, 'err');
            $back = 'p=apply'; break;
        }
        case 'import_skip': S_put(S_def()); flash('Importazione saltata: impostazioni vuote.'); $back = 'p=setup'; break;
        case 'custom_rules_scan': {
            $plan = custom_rules_integrate_plan($M, S_get());
            $_SESSION['custom_rules_plan'] = $plan;
            flash('Regole personalizzate: ' . (int)$plan['total_custom'] . ' totali, ' . (int)$plan['n_can'] . ' integrabili, ' . (int)$plan['n_left'] . ' da lasciare manuali.');
            $back = 'p=apply'; break;
        }
        case 'custom_rules_integrate': {
            $plan = $_SESSION['custom_rules_plan'] ?? null;
            if (!$plan || empty($plan['can'])) {
                $plan = custom_rules_integrate_plan($M, S_get());
            }
            if (empty($plan['can'])) { flash('Nessuna regola personalizzata integrabile automaticamente.', 'err'); $back = 'p=apply'; break; }
            $res = custom_rules_integrate_apply($M, S_get(), $plan);
            save_model();
            unset($_SESSION['custom_rules_plan']);
            audit('custom_rules_integrate n=' . count($plan['can']));
            flash($res['msg'] . (!empty($res['warn']) ? ' Avvisi: ' . implode('; ', $res['warn']) : ''));
            $back = 'p=apply'; break;
        }
        case 'custom_rules_delete': {
            // elimina solo regole personalizzate selezionate (ti:i)
            $sel = (array)($_POST['cr'] ?? []);
            $n = 0;
            $del = [];
            foreach ($sel as $key) {
                if (!preg_match('/^(\d+):(\d+)$/', (string)$key, $m)) continue;
                $del[(int)$m[1]][] = (int)$m[2];
            }
            foreach ($del as $ti => $idxs) {
                rsort($idxs, SORT_NUMERIC);
                foreach ($idxs as $i) {
                    if (!isset($M[$ti]['items'][$i])) continue;
                    // solo se ancora non gestita
                    if (in_region($M[$ti]['items'], $i)) continue;
                    if (($M[$ti]['items'][$i]['t'] ?? '') !== 'rule') continue;
                    array_splice($M[$ti]['items'], $i, 1);
                    $n++;
                }
            }
            save_model();
            audit("custom_rules_delete n=$n");
            flash("Eliminate $n regole personalizzate dalla bozza.");
            $back = 'p=apply'; break;
        }
        case 'live_rules_scan': {
            $back='p=apply';
            [$c,$o,$e]=priv('live-rule-cleanup',null,['scan']);
            $j=json_decode($o,true);
            if ($c!==0 || empty($j['ok']) || !preg_match('/^[a-f0-9]{64}$/D',(string)($j['plan_sha256']??''))) {
                unset($_SESSION['iptm_live_cleanup']);flash('Analisi runtime non riuscita: '.herr((string)($j['error']??$e??$o)),'err');break;
            }
            $_SESSION['iptm_live_cleanup']=['sha256'=>$j['plan_sha256'],'created'=>time(),'findings'=>array_slice($j['findings']??[],0,50),'count'=>count($j['findings']??[])];
            flash('Analisi kernel: '.count($j['findings']??[]).' duplicati consecutivi in catene IPTM. Nessuna modifica effettuata.');
            break;
        }
        case 'live_rules_apply': {
            $back='p=apply';$saved=$_SESSION['iptm_live_cleanup']??null;
            $sha=(string)($_POST['plan_sha256']??'');
            if (!is_array($saved)||time()-(int)($saved['created']??0)>180||!preg_match('/^[a-f0-9]{64}$/D',$sha)||
                !hash_equals((string)$saved['sha256'],$sha)) {
                flash('Conferma non valida o anteprima scaduta. Nessuna modifica.','err');break;
            }
            [$c,$o,$e]=priv('live-rule-cleanup',null,['apply',$sha]);$j=json_decode($o,true);
            unset($_SESSION['iptm_live_cleanup']);
            if($c!==0||empty($j['ok'])) {flash('Pulizia runtime respinta: '.herr((string)($j['error']??$e??$o)),'err');break;}
            audit('live_rules_cleanup n='.(int)($j['removed']??0));
            flash('Pulizia runtime: eliminati '.(int)($j['removed']??0).' duplicati consecutivi. Snapshot salvato in /var/lib/iptm-live-rule-cleanup.','ok');
            break;
        }
        case 'rules_cleanup_scan': {
            $sc = rules_cleanup_scan($M);
            $_SESSION['rules_cleanup'] = $sc;
            flash('Analisi pulizia: ' . (int)$sc['total'] . ' voci trovate. Rivedi e applica le categorie scelte.');
            $back = 'p=apply'; break;
        }
        case 'rules_cleanup_apply': {
            $cats = (array)($_POST['cats'] ?? []);
            $allowed = ['duplicate','unreachable','bad_target','incompatible','missing_chain','disabled','noisy','orphan_chain'];
            $cats = array_values(array_intersect($cats, $allowed));
            if (!$cats) { flash('Seleziona almeno una categoria da rimuovere.', 'err'); $back = 'p=apply'; break; }
            $inc = !empty($_POST['include_managed']);
            $res = rules_cleanup_apply($M, $cats, $inc);
            save_model();
            unset($_SESSION['rules_cleanup']);
            audit('rules_cleanup ' . implode(',', $cats) . ' n=' . $res['removed']);
            flash('Pulizia bozza: rimosse ' . (int)$res['removed'] . ' voci (' . implode(', ', $cats) . '). Verifica e applica quando pronto.');
            $back = 'p=apply'; break;
        }
        case 'ipv6_kernel_apply': {
            $back = 'p=v6';
            $mode = (string)($_POST['ipv6_mode'] ?? '');
            $expected = $mode === 'disable' ? 'DISABILITA' : ($mode === 'enable' ? 'RIABILITA' : '');
            $remote = preg_replace('/^::ffff:/i', '', (string)($_SERVER['REMOTE_ADDR'] ?? ''));
            if ($expected === '') { flash('Modalità IPv6 non valida.','err'); break; }
            if (!filter_var($remote, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                flash('Usa una sessione amministrativa IPv4 per cambiare IPv6, altrimenti potresti perdere la connessione.', 'err'); break;
            }
            if (is_file(DATA_DIR . '/pending.json')) { flash('Conferma o annulla prima il rollback firewall in sospeso.', 'err'); break; }
            [$rc,$out,$err] = priv('ipv6-control', null, ['apply', $mode, $remote]);
            audit('ipv6 kernel apply ' . $mode . ' rc=' . $rc);
            flash($rc === 0 ? 'Modifica IPv6 avviata. Verifica la connettività da IPv4 e conferma entro 120 secondi o verrà ripristinato lo stato precedente.' : 'Modifica IPv6 non eseguita: ' . herr($out . $err), $rc === 0 ? 'ok' : 'err');
            break;
        }
        case 'ipv6_kernel_confirm':
        case 'ipv6_kernel_rollback': {
            $back = 'p=v6';
            $remote = preg_replace('/^::ffff:/i', '', (string)($_SERVER['REMOTE_ADDR'] ?? ''));
            if (!filter_var($remote, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) { flash('Conferma/ripristino consentiti da sessione IPv4.', 'err'); break; }
            $isRollback = $a === 'ipv6_kernel_rollback';
            [$rc,$out,$err] = priv('ipv6-control', null, $isRollback ? ['rollback'] : ['confirm', $remote]);
            audit('ipv6 kernel ' . ($isRollback ? 'rollback' : 'confirm') . ' rc=' . $rc);
            flash($rc === 0 ? ($isRollback ? 'Ripristino IPv6 richiesto: ' : 'Modifica IPv6 confermata: ') . trim($out) : 'Operazione IPv6 non riuscita: ' . herr($out . $err), $rc === 0 ? 'ok' : 'err');
            break;
        }
        case 'v6_save': {
            $S = S_get(); $V = v6_def(); $err = false;
            foreach (['mode' => ['host', 'router']] as $k => $l) $V[$k] = in_array($_POST[$k] ?? '', $l, true) ? $_POST[$k] : 'host';
            foreach (['lan_if', 'wan_if'] as $k) { $V[$k] = trim((string)($_POST[$k] ?? '')); if (!v_ok('if', $V[$k])) $err = true; }
            $V['lan_prefix'] = preg_replace('/\s+/', '', (string)($_POST['lan_prefix'] ?? '')); if (!v6_prefixes_ok($V['lan_prefix'])) $err = true;
            $V['ssh_port'] = trim((string)($_POST['ssh_port'] ?? '22')); if (!v_ok('port', $V['ssh_port']) || $V['ssh_port'] === '') $err = true; $V['ports'] = trim((string)($_POST['ports'] ?? '')); if (!v_ok('ports', $V['ports'])) $err = true;
            foreach (['icmp', 'dhcp6', 'ssh', 'log', 'crowdsec', 'bogon', 'ssh_rl', 'wg_on', 'wg_input', 'wg_lan'] as $k) $V[$k] = empty($_POST[$k]) ? 0 : 1; $V['on'] = 1;
            $V['wg_if'] = trim((string)($_POST['wg_if'] ?? 'wg0')); if (!v_ok('if', $V['wg_if'])) $err = true;
            $V['wg_port'] = trim((string)($_POST['wg_port'] ?? '51820')); if (!v_ok('port', $V['wg_port']) || $V['wg_port'] === '') $err = true;
            $V['cs_sets'] = preg_replace('/\s+/', '', (string)($_POST['cs_sets'] ?? '')); if (!v_ok('setlist', $V['cs_sets'])) $err = true;
            if ($err) { flash('Valori IPv6 non validi.', 'err'); break; } $S['v6'] = $V;
            $oldV6 = v6_get();
            if (!v6_put(v6_gen($V))) { flash('Impossibile salvare bozza IPv6.', 'err'); break; }
            try { S_put($S); }
            catch (Throwable $ex) {
                // Rollback compensativo della bozza, con CAS per non cancellare
                // un eventuale salvataggio intervenuto fra le due operazioni.
                $revWasPresent = array_key_exists('rev6', $_POST);
                $oldRev = $_POST['rev6'] ?? null; unset($_POST['rev6']);
                try {
                    $restored = v6_put($oldV6);
                    flash('Impostazioni IPv6 non salvate: ' . $ex->getMessage() . ($restored ? ' Bozza ripristinata.' : ' ATTENZIONE: ripristino bozza fallito.'), 'err');
                } catch (Throwable $recoverErr) {
                    flash('Impostazioni IPv6 non salvate e bozza non ripristinata: ' . $recoverErr->getMessage(), 'err');
                } finally { if ($revWasPresent) $_POST['rev6'] = $oldRev; }
                break;
            }
            flash('Bozza IPv6 generata.'); break;
        }
        case 'v6_raw': if (!v6_put(str_replace("\r\n", "\n", (string)($_POST['txt'] ?? '')))) { flash('Salvataggio IPv6 fallito.', 'err'); break; } flash('Testo IPv6 salvato nella bozza.'); break;
        case 'v6_test': { if (!v6_put(str_replace("\r\n", "\n", (string)($_POST['txt'] ?? '')))) { flash('Bozza IPv6 non salvata.', 'err'); break; } [$c, $o, $e] = priv('test6', v6_get()); flash($c === 0 ? '✔ Sintassi IPv6 valida.' : '✖ Errore: ' . trim($o . $e), $c === 0 ? 'ok' : 'err'); break; }
        case 'v6_apply': { if (!v6_put(str_replace("\r\n", "\n", (string)($_POST['txt'] ?? '')))) { flash('Bozza IPv6 non salvata.', 'err'); break; } if (apply_result(do_apply(ROLLBACK_SECS, '6'))) flash('Regole IPv6 applicate: conferma entro ' . ROLLBACK_SECS . ' s.'); break; }
        case 'v6_write': {
            // Salvare per il boot SENZA il test rollback può tagliare fuori
            // l'IPv6 al prossimo riavvio. Usare Applica IPv6 + conferma.
            flash('Scrittura diretta di rules.v6 bloccata per sicurezza. Usa «Applica con rollback» e poi «Conferma».', 'err');
            break;
        }
        case 'v6_reset': if (!v6_reset_draft()) { flash('Impossibile scartare bozza IPv6.', 'err'); break; } flash('Bozza IPv6 scartata.'); break;
        case 'rules_compact_safe': {
            $res = rules_cleanup_apply($M, ['duplicate'], false); save_model(); audit('rules_compact_safe n=' . $res['removed']);
            flash('Compattazione sicura della bozza: rimossi ' . (int)$res['removed'] . ' duplicati esatti fuori dai blocchi gestiti. Nessuna regola con semantica diversa è stata accorpata.'); $back = 'p=apply'; break;
        }
        case 'confirm': { if (iptm_health_policy_marker_read() !== null) { flash('Conferma della policy in prova solo da Sistema → Salute DietPi.', 'err'); $back='p=health'; break; } $e = confirm_pending(); flash($e ?: 'Confermato e salvato su file.', $e ? 'err' : 'ok'); break; }
        case 'revert': { if (iptm_health_policy_marker_read() !== null) { flash('Ripristino della policy in prova dalla pagina Salute DietPi.', 'err'); $back='p=health'; break; } $e = revert_pending(); flash($e ?: 'Ripristinato lo stato precedente.', $e ? 'err' : 'ok'); break; }
        case 'raw_save': {
            $tx = str_replace("\r\n", "\n", (string)($_POST['txt'] ?? ''));
            if (!put_draft($tx)) throw new RuntimeException('Impossibile salvare il testo della bozza.');
            flash('Testo salvato nella bozza.');
            if (is_file(DATA_DIR . '/settings.json') && str_contains($tx, '# >>> IPTM:')) { $M3 = parse_rules($tx); regen($M3, S_get()); if (!rules_equiv(ser($M3), $tx)) flash('⚠ Hai modificato blocchi generati dalle impostazioni: al prossimo «Salva» delle pagine di impostazioni verranno rigenerati e le tue modifiche andranno perse. Per regole tue usa righe fuori dai blocchi «# >>> IPTM».', 'err'); }
            break;
        }
        case 'draft_reset': @unlink(DATA_DIR . '/draft.rules'); flash('Bozza scartata: ricaricato il file attuale.'); break;
        case 'fw_restore_saved': {
            [$c, $o, $e] = priv('fw-heal', null, ['force']); audit('fw_restore_saved rc=' . $c);
            flash($c === 0 ? 'Firewall ripristinato dalle regole salvate. ' . trim($o) : 'Ripristino non riuscito: ' . trim($o . $e), $c === 0 ? 'ok' : 'err'); $back = 'p=status'; break;
        }
        case 'manual_convert_exact_all': {
            global $M, $draftTxt;
            $S = S_get();
            $A = manual_analyze($M, $S);
            $sel = [];
            $names = [];
            foreach ($A['rules'] as $k => $r) {
                if (($r['cat'] ?? '') === 'option' && !empty($r['exact'])) $sel[] = $k;
                if (($r['cat'] ?? '') === 'clean') $sel[] = $k;
            }
            foreach ($A['opts'] ?? [] as $k => $o) $sel[] = $k;
            foreach ($A['groups'] ?? [] as $k => $g) {
                if (!empty($g['exact'])) { $sel[] = $k; $names[$k] = $g['name'] ?? $k; }
            }
            $sel = array_values(array_unique($sel));
            if (!$sel) { flash('Nessuna voce esatta convertibile in questo passaggio', 'err'); $back = 'p=manual'; break; }
            $rep = manual_apply($M, $S, $A, $sel, $names, false);
            if (empty($rep['ok'])) {
                flash($rep['msg'] ?? 'Conversione fallita', 'err');
                $back = 'p=manual'; break;
            }
            S_put($S);
            put_draft(ser($M));
            $draftTxt = ser($M);
            flash($rep['msg'] . ' Ricarica per analizzare il resto.');
            $back = 'p=manual'; break;
        }
case 'manual_convert': {
            $S = S_get(); $A = manual_analyze($M, $S);
            $r = manual_apply($M, $S, $A, array_map('strval', (array)($_POST['sel'] ?? [])), array_map('strval', (array)($_POST['cname'] ?? [])), !empty($_POST['force']));
            if ($r['ok']) audit('regole manuali convertite: ' . $r['msg']);
            flash($r['msg'], $r['ok'] && $r['same'] ? 'ok' : 'err'); $back = 'p=manual'; break;
        }
        case 'copt_toggle': case 'copt_delete': case 'copt_unmanage': {
            $S = S_get(); $id = (string)($_POST['id'] ?? ''); $k = null; $back = 'p=manual';
            foreach ($S['custom_opts'] ?? [] as $n => $c) if (($c['id'] ?? '') === $id) $k = $n;
            if ($k === null) { flash('Opzione non trovata.', 'err'); break; }
            $co = $S['custom_opts'][$k];
            if ($a === 'copt_toggle') $S['custom_opts'][$k]['on'] = empty($co['on']) ? 1 : 0; else unset($S['custom_opts'][$k]);
            $S['custom_opts'] = array_values($S['custom_opts']); $w = regen($M, $S);
            if ($a === 'copt_unmanage') {   // le regole tornano manuali, nella posizione che l'opzione aveva
                $by = []; foreach ($co['rules'] ?? [] as $cr) if (isset(BUILTIN[$cr['t'] ?? '']) && lint_rule((string)$cr['r'])) $by[$cr['t'] . '|' . rchain($cr['r'])][] = ['t' => 'rule', 'r' => $cr['r'], 'on' => true];
                foreach ($by as $kk => $blk) { [$t, $c] = explode('|', $kk, 2); ensure_table($M, $t); ensure_chain($M, $t, $c); $ti = tb($M, $t); $at = out_of_region($M[$ti]['items'], anchor_index($M[$ti]['items'], $c, (string)($co['an'] ?? 'end'))); array_splice($M[$ti]['items'], $at, 0, $blk); }
            }
            S_put($S); save_model(); audit($a . ' ' . ($co['name'] ?? $id));
            flash(['copt_toggle' => 'Opzione «' . ($co['name'] ?? '') . '» ' . (empty($co['on']) ? 'attivata' : 'disattivata') . ' nella bozza.', 'copt_delete' => 'Opzione eliminata (le sue regole non sono più nella bozza).', 'copt_unmanage' => 'Opzione sciolta: le regole sono tornate manuali.'][$a] . ($w ? ' Avvisi: ' . implode('; ', $w) : '')); break;
        }
        case 'copt_add': {
            $S = S_get(); $back = 'p=manual'; $rules = []; $bad = [];
            foreach (preg_split('/\R/', trim((string)($_POST['rules'] ?? ''))) as $ln) {
                $ln = trim($ln); if ($ln === '' || $ln[0] === '#') continue;
                if (preg_match('/^(filter|nat|mangle|raw|security)\s+(-A .*)$/', $ln, $m)) { $t = $m[1]; $r = $m[2]; } elseif (str_starts_with($ln, '-A ')) { $t = 'filter'; $r = $ln; } else { $bad[] = $ln; continue; }
                if (lint_rule($r) && !preg_match('/[;`$|&<>\\\\]/', $r)) $rules[] = ['t' => $t, 'r' => $r]; else $bad[] = $ln;
            }
            if (!$rules || count($rules) > 200) { flash('Inserisci da 1 a 200 regole, una per riga, nel formato «-A INPUT ...» oppure «nat -A PREROUTING ...».' . ($bad ? ' Non valide: ' . implode(' | ', array_slice($bad, 0, 3)) : ''), 'err'); break; }
            if ($bad) { flash('Righe non valide: ' . implode(' | ', array_slice($bad, 0, 3)) . '. Nulla è stato creato.', 'err'); break; }
            $S = copt_add($S, (string)($_POST['name'] ?? ''), (string)($_POST['an'] ?? 'end'), $rules, (string)($_POST['desc'] ?? ''));
            $w = regen($M, $S); S_put($S); save_model(); audit('copt_add ' . end($S['custom_opts'])['name']);
            flash('Opzione personalizzata creata (' . count($rules) . ' regole). Applica la bozza per attivarla nel firewall.' . ($w ? ' Avvisi: ' . implode('; ', $w) : '')); break;
        }
        case 'rules_verify': {
            $report = [];
            ipsets_prepare();
            [$c, $o, $e] = priv('test', $draftTxt);
            $report[] = ['Sintassi bozza', $c === 0 ? 'ok' : 'err', $c === 0 ? 'iptables-restore --test OK' : trim($o . $e)];
            [$c2, $chk] = priv('rules-check');
            $liveN = $fileN = '?';
            foreach (explode("\n", trim($chk)) as $l) {
                if (str_starts_with($l, 'live_rules ')) $liveN = substr($l, 11);
                if (str_starts_with($l, 'file_rules ')) $fileN = substr($l, 11);
            }
            $report[] = ['Regole nel kernel', 'ok', $liveN . ' regole attive'];
            $report[] = ['File rules.v4', 'ok', $fileN . ' regole'];
            $undef = []; $tmiss = []; $ipv6dis = false;
            foreach (explode("
", $chk) as $l) {
                if (str_starts_with($l, 'undefined_chain ')) $undef[] = substr($l, 16);
                elseif (str_starts_with($l, 'undefined ')) $undef[] = substr($l, 10);
                elseif (str_starts_with($l, 'target_ext ') && str_ends_with($l, ' missing')) $tmiss[] = (explode(' ', $l)[1] ?? '');
                elseif (str_starts_with($l, 'ipv6 disabled')) $ipv6dis = true;
            }
            $builtinTg = ['NOTRACK','SYNPROXY','TARPIT','ACCEPT','DROP','REJECT','RETURN','LOG','DNAT','SNAT','MASQUERADE','REDIRECT','CT','TCPMSS','MARK','SET','NFQUEUE'];
            $undef = array_values(array_filter($undef, fn($x) => $x !== '' && !in_array(strtoupper($x), $builtinTg, true)));
            $report[] = ['Catene riferite', $undef ? 'err' : 'ok', $undef ? ('non definite: ' . implode(', ', array_slice($undef, 0, 8))) : 'tutte definite'];
            if ($tmiss) {
                $hint = [];
                if (in_array('TARPIT', $tmiss, true)) $hint[] = 'TARPIT: installa xtables-addons';
                if (in_array('SYNPROXY', $tmiss, true)) $hint[] = 'SYNPROXY: modulo xt_SYNPROXY';
                if (in_array('NOTRACK', $tmiss, true)) $hint[] = 'NOTRACK: tabella raw/xt_CT';
                $report[] = ['Target estensione', 'warn', implode(', ', $tmiss) . ($hint ? ' — ' . implode('; ', $hint) : '')];
            }
            [, $st] = priv('selftest');
            $fails = array_values(array_filter(explode("\n", trim($st)), fn($l) => str_starts_with($l, 'FAIL')));
            $report[] = ['Connettivita', $fails ? 'err' : 'ok', $fails ? implode('; ', $fails) : 'gateway/DNS/TCP OK'];
            preg_match_all('/\s-m\s+([A-Za-z0-9_]+)/', $draftTxt, $mm);
            $mods = array_values(array_unique($mm[1] ?? []));
            $args = array_map(fn($x) => 'm:' . $x, array_slice($mods, 0, 30));
            [, $co] = priv('compat', null, $args);
            $miss = []; $info = [];
            foreach (explode("
", $co) as $l) {
                $l = trim($l);
                if (!str_contains($l, ' missing')) continue;
                if (str_starts_with($l, 'table6 ')) {
                    $info[] = !empty($ipv6dis) ? 'IPv6 disabilitato sul sistema' : ($l . ' (solo se usi regole IPv6)');
                } else $miss[] = $l;
            }
            $report[] = ['Moduli kernel', $miss ? 'warn' : 'ok', $miss ? implode('; ', array_slice($miss, 0, 6)) : ('match usati disponibili' . ($info ? ' · ' . implode('; ', $info) : ''))];
            $_SESSION['rules_verify'] = ['report' => $report, 'raw' => $chk, 'self' => $st];
            $bad = count(array_filter($report, fn($r) => $r[1] === 'err'));
            flash($bad ? "Verifica completata con $bad errori: vedi il report sotto." : 'Verifica completata: nessun errore critico.', $bad ? 'err' : 'ok');
            $back = 'p=apply'; break;
        }
        case 'save_file':
            // Never allow a permanent boot write to interleave a firewall apply
            // or a concurrent draft edit. Order locks: apply -> draft.
            $al=@fopen(DATA_DIR.'/apply.lock','c');
            if (!$al || !@flock($al,LOCK_EX|LOCK_NB)) {
                if (is_resource($al)) @fclose($al);
                flash('Altra applicazione in corso: salvataggio annullato.','err');break;
            }
            $dl=@fopen(DATA_DIR.'/draft.lock','c');
            if (!$dl || !@flock($dl,LOCK_EX|LOCK_NB)) {
                if (is_resource($dl)) @fclose($dl);
                @flock($al,LOCK_UN);@fclose($al);
                flash('Bozza occupata: salvataggio annullato.','err');break;
            }
            try {
                if (is_file(DATA_DIR.'/pending.json')) {
                    flash('Rollback in sospeso: non salvare nuove regole permanenti.','err');break;
                }
                if (($ipv6Risk = iptm_mac_ipv6_guard()) !== '') {flash($ipv6Risk, 'err');break;}
                $onDiskDraft=get_draft();
                if (!hash_equals(hash('sha256',$draftTxt),hash('sha256',$onDiskDraft))) {
                    flash('Bozza modificata: salvataggio annullato. Ricarica.','err');break;
                }
                ipsets_prepare(); [$c,$o,$e]=priv('test',$draftTxt);
                if ($c) {flash('Non salvo: bozza non valida. '.herr($o.$e),'err');break;}
                // draft.lock serializes all ordinary draft writes through commit.
                [$c,$e]=write_live($draftTxt);
                if ($c) flash('Scrittura fallita: '.herr($e),'err');
                else {
                    if (is_file(DATA_DIR.'/draft.rules') && !@unlink(DATA_DIR.'/draft.rules'))
                        flash('Regole permanenti salvate, ma bozza non eliminata: controlla lo stato.','err');
                    else flash('Salvato in '.RULES_FILE.' (backup creato). NON è stato applicato al firewall in esecuzione.');
                }
            } finally {
                @flock($dl,LOCK_UN);@fclose($dl);
                @flock($al,LOCK_UN);@fclose($al);
            }
            break;
        case 'apply':
            if (apply_result(do_apply((int)($_POST['secs'] ?? ROLLBACK_SECS), '4', !empty($_POST['force'])))) flash('Regole applicate. Premi «Conferma» entro il tempo indicato: altrimenti torna tutto com\'era.');
            $back = 'p=apply'; break;
    
}
