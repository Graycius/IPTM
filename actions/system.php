<?php
/* IPTM action domain: system. Inherits the authenticated controller scope. */
switch ($a) {

case 'feature_migration_preview': {
    $known=array_keys(iptm_migration_catalog());
    $requested=$_POST['features']??[];
    if (!is_array($requested) || count($requested)>count($known)) {flash('Selezione non valida.','err');break;}
    $selected=[];
    foreach ($requested as $entry) {
       if (!is_string($entry) || !in_array($entry,$known,true)) {flash('Opzione sconosciuta: nessuna anteprima.','err');$back='p=upgrade-wizard';break 2;}
       if (!in_array($entry,$selected,true)) $selected[]=$entry;
    }
    $_SESSION['iptm_feature_migration_preview']=['selected'=>$selected,'nonce'=>bin2hex(random_bytes(12))];
    flash('Anteprima disponibile. Nessuna modifica di sistema.');$back='p=upgrade-wizard';break;
}
case 'feature_migration_save': {
    $preview=$_SESSION['iptm_feature_migration_preview']??null;
    if (!is_array($preview) || !isset($preview['nonce']) || !is_array($preview['selected']??null)) {flash('Genera una nuova anteprima.','err');$back='p=upgrade-wizard';break;}
    $path=DATA_DIR.'/feature-migration-plan.json';
    if (is_link($path)) {flash('Percorso piano non sicuro.','err');$back='p=upgrade-wizard';break;}
    $record=['schema'=>1,'source_version'=>APP_VERSION,'created'=>gmdate('c'),'selected'=>array_values($preview['selected']),'applied'=>false,'notes'=>'Piano non applicato: ogni funzione richiede configurazione e test autonomi.'];
    $tmp=tempnam(DATA_DIR,'.iptm-migrate-');
    if ($tmp===false) {flash('Non posso creare la bozza.','err');$back='p=upgrade-wizard';break;}
    try {
      chmod($tmp,0600);
      $data=json_encode($record,JSON_THROW_ON_ERROR|JSON_UNESCAPED_UNICODE);
      if (file_put_contents($tmp,$data,LOCK_EX)!==strlen($data) || !rename($tmp,$path)) throw new RuntimeException('Scrittura atomica fallita');
      unset($_SESSION['iptm_feature_migration_preview']);
      audit('Piano migrazione nuove funzioni salvato (non applicato)');flash('Piano salvato: nessuna policy attivata.');
    } catch (Throwable $e) { @unlink($tmp);flash('Salvataggio piano non riuscito: '.$e->getMessage(),'err'); }
    $back='p=upgrade-wizard';break;
}

case 'sec_preset': {
            if (($_POST['level'] ?? '') !== 'standard') {
                flash('I profili Rigoroso e Paranoico sono stati ritirati: potevano interrompere la rete su bond0.', 'err');
                $back = 'p=security'; break;
            }
            $S = S_get();
            foreach (['spi', 'antispoof', 'invalid', 'final_drop', 'dhcp_accept'] as $key) $S[$key] = 1;
            $S = iptm_safe_settings($S);
            $before = ser($M);
            $warn = regen($M,$S);
            S_put($S);
            save_model();
            flash('Profilo di base salvato nella bozza; nessun sysctl applicato. ' . delta_msg($before, ser($M)));
            foreach ($warn as $w) flash('⚠ ' . $w, 'err');
            $back = 'p=security'; break;
        }
        case 'dns_guard_restore_disk': {
            $back='p=setup';
            // Strict validation ensures that we restore only the original
            // expected LAN DNS rules, never broad or foreign NAT/ACCEPT rules.
            try {
                [$s2,$recovered]=iptm_dns_guard_restore_plan(S_get(),rules_live());
                $m2=$M;$warnings=regen($m2,$s2);
                S_put($s2);$M=$m2;save_model();
                audit('dns_guard_restore_disk '.implode(',',$recovered));
                flash('Protezione '.implode(', ',$recovered).' ripristinata nelle impostazioni e nella bozza. Nessuna regola live modificata. Verifica il diff e applica soltanto con rollback.','ok');
                foreach($warnings as $warning)flash('⚠ '.$warning,'err');
            }catch(RuntimeException $ex){flash('Recupero DNS/DoT bloccato: '.$ex->getMessage(),'err');}
            break;
        }
        case 'settings_save': {
            $sec = (string)($_POST['sec'] ?? ''); if (!isset(SEC_FIELDS[$sec])) { flash('Sezione sconosciuta.', 'err'); break; }
            $S = S_get(); $err = []; $partial = !empty($_POST['_partial']);
            // Form parziali (es. CrowdSec → Firewall): aggiorna solo i campi presenti nel POST.
            // Checkbox ('b'): in form completo assenti → 0; in form parziale assenti → lasciati invariati.
            foreach (SEC_FIELDS[$sec] as $k => $t) {
                if ($t === 'b') {
                    if ($partial && !array_key_exists($k, $_POST)) continue;
                    $S[$k] = empty($_POST[$k]) ? 0 : 1; continue;
                }
                if (!array_key_exists($k, $_POST)) continue;
                $v = $t === 'prefix' ? (string)$_POST[$k] : trim((string)$_POST[$k]);
                if ($t === 'macs') $v = strtolower(preg_replace('/[\s;]+/', ',', $v));
                if (str_starts_with($t, 'n:')) { [, $lo, $hi] = explode(':', $t); if ($v === '' || !ctype_digit($v) || (int)$v < (int)$lo || (int)$v > (int)$hi) $err[] = $k; else $S[$k] = (int)$v; continue; }
                if (!v_ok($t, $v) || ($t === 'port' && $v === '')) $err[] = $k; else $S[$k] = $v;
            }
            if ($sec === 'setup') {
                // Never persist a claimed trusted ingress that points at the
                // upstream/untrusted NIC; a wrong -i could lock out SSH/DNS.
                $maps=iptm_lan_ingress_pairs((string)($S['lan_ingress_map']??''));
                $external=array_filter(explode(',',(string)($S['external_ifs']??'')));
                foreach($maps as $cidr=>$iface) {
                    if(!iptm_scope_within_lan($cidr,(string)($S['lan_nets']??'')))
                        $err[]='lan_ingress_map (subnet non presente nelle LAN: '.$cidr.')';
                    if($iface===(string)($S['wan_if']??'') || in_array($iface,$external,true))
                        $err[]='lan_ingress_map (interfaccia WAN/esterna non attendibile: '.$iface.')';
                    if(!array_key_exists($iface,(array)sys_ifaces()))
                        $err[]='lan_ingress_map (interfaccia non rilevata: '.$iface.')';
                }
                $trusted=iptm_trusted_ingress_interfaces($S);
                foreach($external as $iface) if(isset($trusted[$iface]))
                    $err[]='external_ifs (interfaccia LAN/VPN fidata: '.$iface.')';
                if(!empty($S['single_nic']) && ($maps || $external))
                    $err[]='single_nic (configura ingressi separati solo quando WAN e LAN non sono condivise)';
            }
            if (!empty($S['mac_only']) && trim((string)$S['lan_nets']) === '') { $err[] = 'LAN solo per dispositivi autorizzati: indica prima le reti LAN in Base · NAT · DNS (la regola si applica a quelle reti).'; }
            if (!empty($S['mac_only']) && trim((string)$S['mac_allow']) === '') $err[] = 'mac_allow (vuoto: tutta la LAN verrebbe bloccata)';
            if (($S['ui_nets'] ?? '') !== '' && !ip_in_nets(preg_replace('/^::ffff:/', '', $_SERVER['REMOTE_ADDR'] ?? ''), $S['ui_nets'])) $err[] = 'ui_nets (non includerebbe il tuo indirizzo: resteresti fuori)';
            if ($sec === 'fwdtable' || $sec === 'forward') {
                $rows = [];
                foreach ((array)($_POST['f'] ?? []) as $r) {
                    if (!is_array($r) || !empty($r['del'])) continue;
                    $x = ['on' => empty($r['on']) ? 0 : 1, 'name' => trim((string)($r['name'] ?? '')), 'proto' => in_array($r['proto'] ?? '', ['tcp', 'udp', 'both'], true) ? $r['proto'] : 'both',
                        'src' => trim((string)($r['src'] ?? '')), 'eport' => trim((string)($r['eport'] ?? '')), 'ip' => trim((string)($r['ip'] ?? '')), 'tport' => trim((string)($r['tport'] ?? ''))];
                    if ($x['eport'] === '' && $x['ip'] === '') continue;
                    if (!v_ok('name', $x['name']) || !v_ok('nets', $x['src']) || strpos($x['src'], ',') !== false || $x['eport'] === '' || !v_ok('ports', $x['eport']) || strpos($x['eport'], ',') !== false || $x['ip'] === '' || !v_ok('ip', $x['ip']) || !v_ok('port', $x['tport'])) { $err[] = 'riga «' . $x['name'] . '»'; continue; }
                    $rows[] = $x;
                }
                if ($sec === 'forward') $S['fwd'] = $rows;
            }
            if ($sec === 'router') {
                foreach ([['svc_in', 's_in', false], ['svc_fwd', 's_fw', true]] as [$key, $pk, $fwd]) {
                    $rows = [];
                    foreach ((array)($_POST[$pk] ?? []) as $r) {
                        if (!is_array($r) || !empty($r['del'])) continue;
                        $x = ['on' => empty($r['on']) ? 0 : 1, 'name' => trim((string)($r['name'] ?? '')), 'iif' => trim((string)($r['iif'] ?? '')), 'src' => trim((string)($r['src'] ?? '')), 'dst' => trim((string)($r['dst'] ?? '')),
                            'proto' => in_array($r['proto'] ?? '', ['', 'tcp', 'udp', 'icmp', 'igmp'], true) ? $r['proto'] : '', 'ports' => trim((string)($r['ports'] ?? '')), 'ct' => strtoupper(trim((string)($r['ct'] ?? ''))), 'act' => 'ACCEPT'];
                        if ($fwd) $x['oif'] = trim((string)($r['oif'] ?? '')); else $x['after'] = empty($r['after']) ? 0 : 1;
                        if ($x['iif'] . $x['src'] . $x['dst'] . $x['proto'] . $x['ports'] . $x['ct'] . ($x['oif'] ?? '') === '') continue;
                        if (!v_ok('name', $x['name']) || !v_ok('if', $x['iif']) || !v_ok('if', $x['oif'] ?? '') || !v_netal($x['src'], $S) || !v_netal($x['dst'], $S) || !(v_ok('ports', $x['ports']) || preg_match('/^@[A-Za-z][A-Za-z0-9_-]{1,24}$/', $x['ports'])) || !v_ok('ct', $x['ct']) || ($x['ports'] !== '' && !in_array($x['proto'], ['tcp', 'udp'], true))) { $err[] = 'riga «' . $x['name'] . '» (' . $pk . ')'; continue; }
                        $rows[] = $x;
                    }
                    $S[$key] = $rows;
                }
            }
            if ($sec === 'access') {
                $rows = [];
                foreach ((array)($_POST['a'] ?? []) as $r) {
                    if (!is_array($r) || !empty($r['del'])) continue;
                    $x = ['on' => empty($r['on']) ? 0 : 1, 'name' => trim((string)($r['name'] ?? '')), 'clients' => trim((string)($r['clients'] ?? '')), 'days' => array_values(array_intersect(array_keys(DAYS), (array)($r['days'] ?? []))),
                        'from' => trim((string)($r['from'] ?? '00:00')), 'to' => trim((string)($r['to'] ?? '24:00')), 'svc' => array_values(array_intersect(array_keys(SVC), (array)($r['svc'] ?? []))),
                        'custom' => trim((string)($r['custom'] ?? '')), 'urls' => trim((string)($r['urls'] ?? ''))];
                    if ($x['name'] === '' && $x['clients'] === '' && !$x['svc'] && $x['custom'] === '' && $x['urls'] === '') continue;   // riga vuota del form: non è un criterio
                    [, $bad] = acl_clients($x['clients']);
                    if (!v_ok('name', $x['name']) || !v_ok('time', $x['from']) || !v_ok('time', $x['to']) || $bad) { $err[] = 'criterio «' . $x['name'] . '»' . ($bad ? ' (client non valido: ' . $bad[0] . ')' : ''); continue; }
                    $rows[] = $x;
                }
                $S['acl'] = $rows;
            }
            if ($err) { flash('Valori non validi, nulla salvato: ' . implode(', ', $err), 'err'); break; }
            // Sincronizza opzioni sicurezza → harden kernel (ARP / TCP Fast Open)
            if ($sec === 'security') {
                $S['harden'] = $S['harden'] ?? [];
                $S['harden']['arp_protect'] = !empty($S['arp_protect']) ? 1 : 0;
                $S['harden']['tcp_fastopen_off'] = !empty($S['tcp_fastopen_off']) ? 1 : 0;
            }
            $S = iptm_safe_settings($S);
            $cross = iptm_settings_cross_validate($S);
            if ($cross) { flash('Impostazioni incomplete o incoerenti: ' . implode('; ', $cross), 'err'); break; }
            $old = S_get(); $before = ser($M); $M2 = $M; $warn = regen($M2, $S, $sec === 'setup' && !empty($_POST['confirm_dns_guard_removal']));
            // Blocca solo se la rigenerazione TOGLIE/cambia regole senza modifiche tue; le sole aggiunte (nuove regole generate da un aggiornamento) passano e sono mostrate nel riepilogo.
            if ($S == $old && !rules_equiv(ser($M2), $before) && model_delta($before, ser($M2))[1] > 0) { flash('Annullato per proteggere le tue regole: le impostazioni salvate non corrispondono alla bozza (rigenerandola cambierebbero regole pur senza modifiche tue). Nulla è stato toccato. Riallinea da «Importa regole» (dopo «Azzera impostazioni») oppure da un backup in Storico.', 'err'); break; }
            if (function_exists('settings_snapshot')) settings_snapshot('pre-save-' . $sec);
            S_put($S); $M = $M2; save_model();
            $nSec = count(gen_sections($S)[0]);
            $summary = function_exists('iptm_settings_section_summary') ? iptm_settings_section_summary($sec, $S) : $sec;
            flash(delta_msg($before, ser($M)));
            flash('Impostazioni «' . $sec . '» salvate nella bozza (' . $nSec . ' sezioni). ' . $summary);
            foreach ($warn as $w) flash('⚠ ' . $w, 'err');
            if ($sec === 'security') {
                $miss = []; $stt = tools_status();
                if ($GLOBALS['_iptm_tools_status_error'] ?? '') {
                    flash('Rilevamento programmi non disponibile: non è possibile stabilire quali dipendenze manchino. Controlla Strumenti → Programmi.', 'err');
                } else {
                    foreach (required_tools($S) as $tk => $why) if (empty(($stt[$tk] ?? [])['inst'])) $miss[] = (tool_defs()[$tk][0] ?? $tk) . ' (' . $why . ')';
                    if ($miss) flash('Programmi consigliati non ancora installati: ' . implode('; ', $miss) . '. Vai in Strumenti → Programmi per installarli in coda.', 'err');
                }
            }
            // Changing a UI form does not apply kernel sysctl. Use Hardening → preview/apply explicitly.
            if (!empty($_POST['apply'])) { if (apply_result(do_apply(ROLLBACK_SECS, '4'))) flash('Impostazioni applicate in prova: verifica SSH/LAN, poi conferma.'); $back = 'p=apply'; }
            break;
        }
        case 'settings_reset': {
            $f = DATA_DIR . '/pre-import.rules'; if (is_file($f)) put_draft((string)file_get_contents($f)); else { strip_regions($M); save_model(); }
            $GLOBALS['_Sc'] = null; @unlink(DATA_DIR . '/settings.json'); flash('Impostazioni azzerate' . (is_file($f) ? ' e bozza ripristinata a prima dell\'importazione.' : '.')); $back = 'p=import'; break;
        }
        case 'backend_set': {
            // Cambiare backend dalla stessa sessione web è irreversibile se le
            // catene legacy/nft contengono regole diverse e può tagliare la GUI.
            // Soltanto da console locale/OOB con snapshot e verifica netfilter.
            flash('Cambio backend non consentito dalla UI remota: eseguirlo da console con snapshot di entrambi i backend e accesso di recupero.', 'err');
            break;
        }
        case 'strip_managed': strip_regions($M); save_model(); flash('Rimossi tutti i blocchi gestiti dalla bozza (le impostazioni restano salvate).'); break;
        case 'forward_sysctl': {
            if (empty($_POST['v'])) {
                flash('Per evitare l’isolamento di LAN/VPN, la disattivazione del forwarding è consentita solo da console locale con accesso di recupero.', 'err');
                break;
            }
            [$c, , $e] = priv('forward', null, ['1']);
            flash($c === 0 ? 'IP forwarding attivato (persistente in /etc/sysctl.d).' : 'Errore: ' . $e, $c === 0 ? 'ok' : 'err'); break;
        }
        case 'lists_apply': {
            $S = S_get(); $err = []; $al = []; $seen = [];
            foreach ((array)($_POST['al'] ?? []) as $r) {
                if (!is_array($r) || !empty($r['del'])) continue; $n = trim((string)($r['name'] ?? '')); $it = trim((string)($r['items'] ?? '')); if ($n === '' && $it === '') continue;
                $tk = preg_split('/[\s,;]+/', $it, -1, PREG_SPLIT_NO_EMPTY); $isP = $tk && !array_filter($tk, fn($x) => !preg_match('/^\d{1,5}(:\d{1,5})?$/', $x));
                if (!preg_match('/^[A-Za-z][A-Za-z0-9_-]{1,24}$/', $n) || isset($seen[$n])) { $err[] = 'alias «' . $n . '»'; continue; } $seen[$n] = 1;
                if (!$isP) foreach ($tk as $x) if (!v_ok('nets', $x) || str_contains($x, ',')) $err[] = 'alias ' . $n . ': ' . $x;
                $al[] = ['name' => $n, 'items' => implode(' ', $tk)];
            }
            $bl = []; foreach (BL_PRESETS as $id => [$nm, $url]) { $d = iptm_list_direction($_POST['bd'][$id] ?? 'in'); $bl[] = ['on' => empty($_POST['bp'][$id]) ? 0 : 1, 'id' => $id, 'name' => $nm, 'url' => $url, 'dir' => in_array($d, ['in', 'out', 'both'], true) ? $d : 'in']; }
            $k = 0; foreach ((array)($_POST['bc'] ?? []) as $r) {
                if (!is_array($r) || !empty($r['del'])) continue; $url = trim((string)($r['url'] ?? '')); $nm = trim((string)($r['name'] ?? '')); if ($url === '' && $nm === '') continue;
                if (!preg_match('~^https?://[A-Za-z0-9._:/?#@&()*+,;=%\~-]{4,300}$~', $url) || !v_ok('name', $nm)) { $err[] = 'lista «' . $nm . '»'; continue; }
                $d = iptm_list_direction($r['dir'] ?? 'in'); $bl[] = ['on' => empty($r['on']) ? 0 : 1, 'id' => 'c' . (++$k), 'name' => $nm ?: 'lista ' . $k, 'url' => $url, 'dir' => in_array($d, ['in', 'out', 'both'], true) ? $d : 'in'];
            }
            $man = preg_split('/[\s,;]+/', trim((string)($_POST['manual_block'] ?? '')), -1, PREG_SPLIT_NO_EMPTY); foreach ($man as $x) if (!v_ok('nets', $x) || str_contains($x, ',')) $err[] = 'blocco manuale: ' . $x;
            $alw = preg_split('/[\s,;]+/', trim((string)($_POST['manual_allow'] ?? '')), -1, PREG_SPLIT_NO_EMPTY); foreach ($alw as $x) if (!v_ok('nets', $x) || str_contains($x, ',')) $err[] = 'lista bianca: ' . $x;
            $fq = trim((string)($_POST['fqdn_rules'] ?? '')); $fqn = count(array_filter(preg_split('/\R/', $fq), fn($l) => trim($l) !== '')); if ($fq !== '' && count(fq_parse($fq)) !== $fqn) $err[] = 'regole FQDN (nome azione host: nome unico, block|allow)';
            $cc = strtoupper(preg_replace('/\s+/', '', (string)($_POST['geo_codes'] ?? ''))); if (!v_ok('cc', $cc)) $err[] = 'codici Paese'; $gd = in_array($_POST['geo_dir'] ?? '', ['in', 'out', 'both'], true) ? $_POST['geo_dir'] : 'both';
            if ($err) { flash('Valori non validi, nulla salvato: ' . implode(', ', $err), 'err'); break; }
            $S['aliases'] = $al; $S['blocklists'] = $bl; $S['manual_block'] = implode(' ', $man); $S['manual_allow'] = implode(' ', $alw); $S['fqdn_rules'] = $fq; $S['geo_on'] = empty($_POST['geo_on']) ? 0 : 1; $S['geo_codes'] = $cc; $S['geo_dir'] = $gd;
            $before = ser($M); S_put($S); ipsets_prepare(); $warn = regen($M, $S); save_model(); priv('lists-sync', lists_conf($S)); priv('fqdn-sync', implode("\n", array_map(fn($id, $q) => "fq_$id " . implode(' ', $q['hosts']), array_keys(fq_parse($fq)), fq_parse($fq))) . "\n"); flash(delta_msg($before, ser($M)));
            flash('Salvato nella bozza. Download delle liste avviato in background; poi applica le regole.'); foreach ($warn as $w) flash('⚠ ' . $w, 'err'); break;
        }
        case 'lists_refresh': priv('lists-update'); flash('Aggiornamento delle liste avviato in background.'); break;
        case 'block_ip': {
            $ip = trim((string)($_POST['ip'] ?? '')); if ($ip === '' || !v_ok('ip', $ip)) { flash('IP non valido.', 'err'); break; }
            $S = S_get(); $cur = preg_split('/[\s,;]+/', trim($S['manual_block']), -1, PREG_SPLIT_NO_EMPTY); if (!in_array($ip, $cur, true)) $cur[] = $ip; $S['manual_block'] = implode(' ', $cur);
            S_put($S); ipsets_prepare(); regen($M, $S); save_model(); flash("$ip aggiunto ai blocchi manuali (bozza). Applica per attivare la regola."); break;
        }
        case 'conn_kill': {
            $p = (string)($_POST['proto'] ?? ''); $x = array_map(fn($k) => (string)($_POST[$k] ?? ''), ['src', 'dst', 'sport', 'dport']);
            if (!in_array($p, ['tcp', 'udp'], true) || !v_ok('ip', $x[0]) || !v_ok('ip', $x[1]) || !v_ok('port', $x[2]) || !v_ok('port', $x[3])) { flash('Connessione non valida.', 'err'); break; }
            [$c, $o, $e] = priv('conn-kill', null, array_merge([$p], $x)); flash($c === 0 ? 'Connessione chiusa.' : herr($o . $e), $c === 0 ? 'ok' : 'err'); break;
        }
        case 'wol': { $m = (string)($_POST['mac'] ?? ''); if (!preg_match('/^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/', $m)) { flash('MAC non valido.', 'err'); break; } [$c, $o, $e] = priv('wol', null, [$m]); flash($c === 0 ? "Pacchetto Wake-on-LAN inviato a $m." : 'Errore (serve il pacchetto wakeonlan): ' . trim($o . $e), $c === 0 ? 'ok' : 'err'); break; }
        case 'zero_apply': {
            $A = json_decode((string)($_POST['answers'] ?? ''), true); if (!is_array($A)) { flash('Risposte non valide.', 'err'); break; }
            [$S2, $w, $v6] = zero_build($A); $S2 = iptm_safe_settings($S2, $w); $S2['notify'] = S_get()['notify']; if (($A['base'] ?? 'zero') === 'keep') $S2['custom_opts'] = S_get()['custom_opts'] ?? [];   // «mantieni le regole»: le opzioni personalizzate restano @mkdir(DATA_DIR . '/backups', 0700, true);
            $o = ser($M); file_put_contents(DATA_DIR . '/pre-zero.rules', $o); file_put_contents(DATA_DIR . '/backups/rules.v4.' . date('Ymd-His'), $o);
            if (($A['base'] ?? 'zero') !== 'keep') $M = parse_rules(zero_skeleton());
            S_put($S2); $warn = regen($M, $S2); save_model(); /* Procedura guidata: niente sysctl, ipset o liste live; applicazione separata con rollback. */ if ($v6 && !v6_put(v6_gen($v6))) throw new RuntimeException('Bozza IPv6 non salvata: verifica spazio e permessi');
            flash('Configurazione creata nella bozza (' . count(gen_sections($S2)[0]) . ' blocchi di regole).'); foreach (array_merge($w, $warn) as $x) flash('⚠ ' . $x, 'err');
            if (!empty($_POST['apply_now'])) {
                if (apply_result(do_apply(ROLLBACK_SECS, '4'))) flash('Configurazione applicata in prova: conferma entro il tempo di rollback.');
            }
            $back = 'p=apply'; break;
        }
        case 'regen_now': { $before = ser($M); $S = S_get(); $warn = regen($M, $S); save_model(); flash('Bozza rigenerata dalle impostazioni salvate. ' . delta_msg($before, ser($M))); foreach ($warn as $w) flash('⚠ ' . $w, 'err'); $back = 'p=apply'; break; }
        case 'post_scan': {
            $R = dyn_report($M); $names = $R['ok'] ? array_slice(array_keys($R['chains']), 0, 12) : []; [, $sg] = priv('post-suggest', null, $names); $sv = []; $sc = [];
            foreach (explode("\n", trim($sg)) as $l) { if (str_starts_with($l, 'service ')) $sv[] = substr($l, 8); elseif (str_starts_with($l, 'script ')) $sc[] = substr($l, 7); }
            file_put_contents(DATA_DIR . '/suggest.json', json_encode(['t' => time(), 'services' => array_values(array_unique($sv)), 'scripts' => array_values(array_unique($sc))])); flash('Ricerca completata: ' . count($sv) . ' servizi e ' . count($sc) . ' script suggeriti.'); $back = 'p=apply'; break;
        }
        case 'post_set': {
            [$c, $o, $e] = priv('post-set', null, [trim((string)($_POST['services'] ?? '')), trim((string)($_POST['script'] ?? ''))]);
            flash($c === 0 ? 'Configurazione post-applicazione salvata.' : 'Non salvato: ' . trim($o . $e), $c === 0 ? 'ok' : 'err'); break;
        }
        case 'post_test': { [, $o] = priv('post'); flash("Esecuzione post-applicazione:\n" . (trim($o) ?: '(nessun servizio/script configurato)'), str_contains($o, 'FAIL') ? 'err' : 'ok'); break; }
        case 'sysctl_dedupe':
        case 'sysctl_consolidate':
        case 'sysctl_consolidate_rollback': {
            flash('Funzione sysctl legacy ritirata. Usa soltanto Hardening del kernel e Manutenzione controllata.', 'err');
            $back = 'p=harden';
            break;
        }
        case 'harden_apply': {
            $S = S_get(); $H = []; foreach (HARDEN as $id => $_) $H[$id] = empty($_POST['h'][$id]) ? 0 : 1; $H['rpf'] = in_array($_POST['rpf'] ?? '', ['0', '1', '2'], true) ? $_POST['rpf'] : '2';
            $conflicts = harden_conflicts($H);
            if ($conflicts) { flash(implode(' ', $conflicts), 'err'); break; }
            [$c, $o, $e] = sysctl_maintenance_apply_text(harden_lines($H)); if ($c === 0) { $S['harden'] = $H; S_put($S); flash('Hardening del kernel applicato.'); } else flash(herr($o . $e), 'err'); break;
        }
        case 'profile_home': case 'profile_office': case 'profile_hard': {
            $S = S_get();
            // baseline comune (SPI, anti-spoof leggero)
            $S['spi'] = 1; $S['antispoof'] = 1; $S['icmp_limit'] = 1; $S['invalid'] = 1;
            if ($a === 'profile_home') {
                $S['dos'] = 1; $S['portscan'] = 0; $S['bogon_wan'] = 0; $S['stealth'] = 0; $S['final_drop'] = 1;
                $S['ssh_limit'] = 1; $S['crowdsec'] = $S['crowdsec'] ?? 0; $S['guest_on'] = 0;
                $msg = 'Profilo Casa applicato alle impostazioni (bozza da rigenerare/salvare).';
            } elseif ($a === 'profile_office') {
                $S['dos'] = 1; $S['portscan'] = 1; $S['bogon_wan'] = 1; $S['stealth'] = 0; $S['final_drop'] = 1;
                $S['ssh_limit'] = 1; $S['web_rl'] = 1; $S['amp_block'] = 1; $S['lockout_on'] = 1;
                $msg = 'Profilo Ufficio applicato (portscan, bogon, rate-limit web).';
            } else {
                $S['dos'] = 1; $S['portscan'] = 1; $S['bogon_wan'] = 1; $S['stealth'] = 1; $S['final_drop'] = 1;
                $S['ssh_limit'] = 1; $S['web_rl'] = 1; $S['amp_block'] = 1; $S['lockout_on'] = 1;
                // Old dangerous profile fields intentionally retired in 3.9.98.
                $msg = 'Profilo avanzato convertito a policy protetta; filtri WAN e opzioni pericolose esclusi.';
            }
            $S = iptm_safe_settings($S);
            S_put($S);
            // regen draft blocks from settings
            global $M; $M = parse_rules(get_draft());
            if (function_exists('regen')) { regen($M, $S); save_model(); }
            audit('security profile ' . $a);
            flash($msg . ' Vai su Applica per renderlo attivo.');
            $back = 'p=security'; break;
        }
        case 'apps_save': {
            $S = S_get();
            $cat = app_catalog();
            $sel = [];
            foreach ((array)($_POST['apps'] ?? []) as $id) {
                $id = preg_replace('/[^a-z0-9_]/', '', (string)$id);
                if ($id !== '' && isset($cat[$id])) $sel[] = $id;
            }
            $S['apps'] = array_values(array_unique($sel));
            S_put($S);
            global $M; $M = parse_rules(get_draft());
            if (function_exists('regen')) { regen($M, $S); save_model(); }
            audit('apps_save n=' . count($S['apps']));
            $msg = 'Porte software aggiornate: ' . count($S['apps']) . ' abilitati (bozza rigenerata).';
            if (!empty($_POST['apply'])) {
                if (apply_result(do_apply(ROLLBACK_SECS))) flash($msg . ' Applicato: conferma entro ' . ROLLBACK_SECS . ' s.');
                else flash($msg);
                $back = 'p=apply';
            } else {
                flash($msg . ' Vai su Applica per attivare.');
                $back = 'p=apps';
            }
            break;
        }
        case 'factory_reset': {
            if (is_file(DATA_DIR . '/pending.json')) {
                flash('Rollback firewall pendente: reset bloccato. Conferma o ripristina prima di modificare impostazioni e bozze.', 'err');
                break;
            }
            $ts = date('Ymd-His');
            iptm_backup_reset_files(['settings.json' => "settings.reset-$ts.json", 'draft.rules' => "draft.reset-$ts.rules", 'settings-v6.json' => "settings-v6.reset-$ts.json", 'draft6.rules' => "draft6.reset-$ts.rules"]);
            @unlink(DATA_DIR . '/settings.json'); @unlink(DATA_DIR . '/draft.rules');
            @unlink(DATA_DIR . '/settings-v6.json'); @unlink(DATA_DIR . '/draft6.rules');
            $GLOBALS['_Sc'] = null;
            @file_put_contents(DATA_DIR . '/post-update-reset.flag', 'reset=' . $ts . ' version=' . APP_VERSION . "\n");
            foreach (['settings','draft','settings-v6','draft6'] as $family) iptm_rotate_backups($family);
            audit('factory_reset (settings+bozza)');
            flash('Reset da zero completato: impostazioni e bozza azzerate (backup in data/backups/). Le regole LIVE non sono state toccate. Usa il Wizard da zero per ricostruire.');
            $back = 'p=zero'; break;
        }
        case 'reset_minimal': {
            if (is_file(DATA_DIR . '/pending.json')) {
                flash('Rollback firewall pendente: reset bloccato. Conferma o ripristina prima di modificare impostazioni e bozze.', 'err');
                break;
            }
            // Reset a profilo minimo funzionante: SPI + anti-spoof + invalid + drop finale + anti-lockout + SSH/HTTP dalla LAN.
            // Conserva WAN/LAN/NAT/DNS/WG. Backup automatico. Opzionale: applica subito con rollback.
            $ts = date('Ymd-His');
            $oldS = S_get();
            iptm_backup_reset_files(['settings.json' => "settings.minimal-$ts.json", 'draft.rules' => "draft.minimal-$ts.rules"]);
            $liveSnap = '';
            [$sc, $liveOut] = priv('save');
            if ($sc === 0 && trim((string)$liveOut) !== '') {
                $liveSnap = DATA_DIR . '/backups/live.minimal-' . $ts . '.rules';
                if (!atomic_data_write($liveSnap, (string)$liveOut, 0600))
                    throw new RuntimeException('Snapshot regole live non riuscito: reset minimo annullato.');
            }
            $S = minimal_settings($oldS);
            // preserva anche notify e ruolo operativo non-firewall
            if (isset($oldS['notify'])) $S['notify'] = $oldS['notify'];
            S_put($S); $GLOBALS['_Sc'] = null;
            global $M;
            $M = parse_rules(zero_skeleton());
            $w = regen($M, $S);
            save_model();
            foreach (['settings','draft','live'] as $family) iptm_rotate_backups($family);
            audit('reset_minimal lan=' . ($S['lan_nets'] ?? '') . ' wan=' . ($S['wan_if'] ?? ''));
            $apply = !empty($_POST['apply']);
            if ($apply) {
                if (apply_result(do_apply(ROLLBACK_SECS))) {
                    flash('Profilo minimo applicato in prova: conferma entro ' . ROLLBACK_SECS . ' s. SPI, anti-lockout, SSH/HTTP dalla LAN. Backup in data/backups/.');
                } else {
                    // apply_result ha già fatto flash su errore/@skip; messaggio contestuale
                    flash('Profilo minimo salvato in bozza. Se l\'applicazione non e\' partita, usa Applica.');
                }
                $back = 'p=apply';
            } else {
                $msg = 'Profilo minimo pronto in bozza (SPI, invalid, anti-spoof, drop finale, anti-lockout, SSH/HTTP dalla LAN).';
                if ($w) $msg .= ' Avvisi: ' . implode('; ', $w);
                $msg .= ' Vai su «Applica» per attivarlo (le regole LIVE non sono ancora cambiate).';
                flash($msg);
                $back = 'p=apply';
            }
            break;
        }
        case 'advise_apply': {
            $S = S_get();
            $sel = array_map('strval', (array)($_POST['sel'] ?? []));
            if (!$sel) { flash('Nessuna proposta selezionata.', 'err'); $back = 'p=advise'; break; }
            [$S2, $nKeys, $nApps] = sys_propose_apply($S, $sel);
            S_put($S2);
            global $M; $M = parse_rules(get_draft());
            $w = function_exists('regen') ? regen($M, $S2) : [];
            if (function_exists('save_model')) save_model();
            audit('advise_apply n=' . count($sel) . ' keys~' . $nKeys . ' apps=' . $nApps);
            $msg = 'Analisi applicata: ' . count($sel) . ' proposte, impostazioni aggiornate, bozza rigenerata.';
            if ($w) $msg .= ' Avvisi: ' . implode('; ', $w);
            if (!empty($_POST['apply'])) {
                if (apply_result(do_apply(ROLLBACK_SECS))) flash($msg . ' Applicato: conferma entro ' . ROLLBACK_SECS . ' s.');
                else flash($msg);
                $back = 'p=apply';
            } else {
                flash($msg . ' Vai su Applica per attivare sul kernel.');
                $back = 'p=advise';
            }
            break;
        }
        case 'settings_rollback': {
            $name = trim((string)($_POST['name'] ?? 'prev'));
            $r = settings_restore_from($name === '' ? 'prev' : $name);
            flash($r['msg'], $r['ok'] ? 'ok' : 'err');
            $back = !empty($_POST['back']) ? (string)$_POST['back'] : 'p=history';
            break;
        }
        case 'test':
            ipsets_prepare(); [$c, $o, $e] = priv('test', $draftTxt);
            flash($c === 0 ? '✔ La bozza è sintatticamente valida (iptables-restore --test).' : '✖ Errore: ' . trim($o . $e) . (($c === 127 || stripos($e, 'sudo') !== false || stripos($e, 'password') !== false) ? "\nHelper/sudo non configurato: esegui install-dietpi.sh (vedi Guida)." : ''), $c === 0 ? 'ok' : 'err'); break;
        
}
