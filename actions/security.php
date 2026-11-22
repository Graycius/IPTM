<?php
/* IPTM action domain: security. Inherits the authenticated controller scope. */
switch ($a) {
case 'cs_feed_stage': {
    $back='p=crowdsec&t=ecosistema';
    if(($_SESSION['role']??'viewer')!=='admin'){flash('Solo amministratore.','err');break;}
    $urls=preg_split('/\r?\n/',trim((string)($_POST['feed_urls']??'')));
    $urls=array_values(array_unique(array_filter(array_map('trim',$urls),'strlen')));
    if(count($urls)<1||count($urls)>8||array_filter($urls,fn($u)=>strlen($u)>250)){
        flash('Selezionare 1-8 URL HTTPS di feed IP, massimo 250 caratteri.','err');break;
    }
    $obj=['urls'=>$urls,'local_files'=>[],'duration'=>(string)($_POST['feed_duration']??'4h'),'reason'=>'iptm-feed'];
    [$c,$out,$err]=priv('security-stack',json_encode($obj,JSON_THROW_ON_ERROR),['crowdsec-stage']);
    $v=json_decode($out,true);
    if($c!==0||!is_array($v)||empty($v['ok'])||!preg_match('/^[a-f0-9]{64}$/D',(string)($v['sha256']??''))){
        unset($_SESSION['iptm_feed_plan']);flash('Feed non importati: '.herr((string)($v['error']??$err??$out)),'err');break;
    }
    $_SESSION['iptm_feed_plan']=['sha256'=>$v['sha256'],'created'=>time(),'total'=>(int)($v['total']??0)];
    flash('Feed scaricati e deduplicati: '.(int)($v['total']??0).' voci, '.(int)($v['excluded']??0).' escluse. Nessun ban applicato.','ok');break;
}
case 'cs_feed_apply': {
    $back='p=crowdsec&t=ecosistema';$j=$_SESSION['iptm_feed_plan']??null;
    $hash=(string)($_POST['feed_hash']??'');
    if(($_SESSION['role']??'viewer')!=='admin'||!is_array($j)||time()-(int)($j['created']??0)>900||
       !preg_match('/^[a-f0-9]{64}$/D',$hash)||!hash_equals((string)($j['sha256']??''),$hash)){
        flash('Piano feed scaduto o hash diverso.','err');break;
    }
    [$c,$o,$e]=priv('security-stack',null,['crowdsec-apply',$hash]);$res=json_decode($o,true);
    if($c===0&&!empty($res['ok']))unset($_SESSION['iptm_feed_plan']);
    flash($c===0&&!empty($res['ok'])?'Decisioni CrowdSec importate tramite cscli, durata limitata.':
        'Importazione CrowdSec fallita: '.herr((string)($res['error']??$e??$o)),$c===0?'ok':'err');break;
}
case 'su_source_stage': {
    $back='p=ips&t=ecosistema';
    if(($_SESSION['role']??'viewer')!=='admin'){flash('Solo amministratore.','err');break;}
    $obj=['source'=>(string)($_POST['source_name']??''),'enabled'=>(string)($_POST['source_mode']??'')==='enable'];
    [$c,$o,$e]=priv('security-stack',json_encode($obj,JSON_THROW_ON_ERROR),['suricata-stage']);$res=json_decode($o,true);
    if($c!==0||empty($res['ok'])||!preg_match('/^[a-f0-9]{64}$/D',(string)($res['sha256']??''))){
        unset($_SESSION['iptm_suricata_source']);flash('Anteprima sorgente rifiutata: '.herr((string)($res['error']??$e??$o)),'err');break;
    }
    $_SESSION['iptm_suricata_source']=['sha256'=>$res['sha256'],'created'=>time(),'source'=>$obj['source']];
    flash('Anteprima sorgente preparata, nessuna modifica alle regole.','ok');break;
}
case 'su_source_apply': {
    $back='p=ips&t=ecosistema';$j=$_SESSION['iptm_suricata_source']??null;$hash=(string)($_POST['source_sha256']??'');
    if(($_SESSION['role']??'viewer')!=='admin'||!is_array($j)||time()-(int)($j['created']??0)>900||
       !preg_match('/^[a-f0-9]{64}$/D',$hash)||!hash_equals((string)($j['sha256']??''),$hash)){
        flash('Conferma sorgente non valida.','err');break;
    }
    [$c,$o,$e]=priv('security-stack',null,['suricata-apply',$hash]);$res=json_decode($o,true);
    if($c===0&&!empty($res['ok']))unset($_SESSION['iptm_suricata_source']);
    flash($c===0&&!empty($res['ok'])?'Sorgenti aggiornate e regole verificate con suricata -T. Reload resta manuale.':
        'Aggiornamento bloccato o fallito: '.herr((string)($res['error']??$e??$o)),$c===0?'ok':'err');break;
}
case 'cs_autodetect': {
            $d = cs_detect(); if ($d['chain'] === '') { flash('Nessuna catena CrowdSec rilevata: il bouncer è avviato? (in modo nftables non serve nulla: usa una tabella propria)', 'err'); break; }
            $S = S_get(); $S['crowdsec'] = 1; $S['cs_set'] = ''; S_put($S); [$c, $o] = priv('cs-chains', null, cs_chains_for($S, '')); priv('cs-svc', null, ['restart', 'bouncer']);
            flash('CrowdSec collegato: ' . trim($o) . ' Set rilevati: ' . (implode(', ', $d['sets']) ?: 'nessuno ancora (compaiono con le prime decisioni)') . '. Il bouncer è stato riavviato; le regole del firewall non cambiano.'); $back = 'p=system'; break;
        }
        case 'tool_install': {
            $tk = (string)($_POST['tool'] ?? ''); $arg = trim((string)($_POST['arg'] ?? '')); $def = tool_defs()[$tk] ?? null;
            if (!$def) { flash('Programma sconosciuto.', 'err'); break; }
            if ($def[2] === 'iface' && $arg !== '' && !isset(sys_ifaces()[$arg])) { flash('Interfaccia non valida.', 'err'); break; }
            if ($def[2] === 'iface' && $arg === '') $arg = (string)(S_get()['wan_if'] ?? array_key_first(sys_ifaces()) ?? '');
            if ($def[2] === 'nets') { $arg = preg_replace('/\s+/', '', $arg); if ($arg !== '' && !v_ok('nets', $arg)) { flash('Reti non valide.', 'err'); break; } if ($arg === '') $arg = (string)(S_get()['lan_nets'] ?? ''); }
            [$c, $o, $e] = priv('tool-install', null, [$tk, $arg]); audit("programma $tk: installazione/configurazione");
            flash($c === 0 ? 'Operazione avviata in background: segui il registro in questa pagina.' : 'Non avviata: ' . trim($o . $e), $c === 0 ? 'ok' : 'err'); break;
        }
        case 'tool_queue': {
            $tools = array_values(array_filter((array)($_POST['tools'] ?? []), fn($t) => isset(tool_defs()[$t])));
            if (!$tools) { flash('Nessun programma selezionato.', 'err'); break; }
            $S = S_get(); $started = []; $skip = [];
            foreach ($tools as $tk) {
                $def = tool_defs()[$tk]; $arg = '';
                if ($def[2] === 'iface') $arg = (string)($S['wan_if'] ?? array_key_first(sys_ifaces()) ?? '');
                if ($def[2] === 'nets') $arg = (string)($S['lan_nets'] ?? '');
                [$c, $o, $e] = priv('tool-install', null, [$tk, $arg]);
                if ($c === 0) { $started[] = $tk; audit("programma $tk: coda installazione"); }
                else $skip[] = $tk . ' (' . trim($o . $e) . ')';
                // piccola pausa tra avvii per evitare race su apt lock (il secondo aspetterà se il primo è ancora in corso)
                if (count($started) > 1) usleep(300000);
            }
            if ($started) flash('Coda avviata: ' . implode(', ', array_map(fn($t) => tool_defs()[$t][0] ?? $t, $started)) . '. Segui i registri in questa pagina (aggiornamento automatico).');
            if ($skip) flash('Non avviati: ' . implode('; ', $skip), 'err');
            break;
        }
        case 'tool_svc': {
            $tk = (string)($_POST['tool'] ?? ''); $act = (string)($_POST['act'] ?? ''); if (!isset(tool_defs()[$tk]) || !in_array($act, ['start', 'stop', 'restart'], true)) { flash('Richiesta non valida.', 'err'); break; }
            [$c, $o, $e] = priv('tool-svc', null, [$tk, $act]); audit("programma $tk: $act"); flash($c === 0 ? "Servizio $tk: $act eseguito." . (trim($o) !== '' ? "\n" . trim($o) : '') : herr($o . $e), $c === 0 ? 'ok' : 'err'); break;
        }
        case 'f2b_unban': { [$c, $o, $e] = priv('f2b-unban', null, [(string)($_POST['jail'] ?? ''), (string)($_POST['ip'] ?? '')]); audit('fail2ban sban ' . ($_POST['ip'] ?? '')); flash($c === 0 ? 'Indirizzo sbannato.' : herr($o . $e), $c === 0 ? 'ok' : 'err'); break; }
        case 'cs_ban': { $d = (string)($_POST['dur'] ?? '4h'); [$c, $o, $e] = priv('cs-ban', null, [trim((string)($_POST['ip'] ?? '')), $d]); audit('crowdsec ban ' . ($_POST['ip'] ?? '') . " $d"); flash($c === 0 ? 'Decisione aggiunta (il bouncer la applica entro pochi secondi).' : herr($o . $e), $c === 0 ? 'ok' : 'err'); $back = !empty($_POST['from_cs']) ? 'p=crowdsec' : 'p=monitor'; break; }
        case 'cs_unban': { [$c, $o, $e] = priv('cs-unban', null, [trim((string)($_POST['ip'] ?? ''))]); audit('crowdsec unban ' . ($_POST['ip'] ?? '')); flash($c === 0 ? 'Decisione rimossa.' : herr($o . $e), $c === 0 ? 'ok' : 'err'); $back = !empty($_POST['from_cs']) ? 'p=crowdsec' : 'p=monitor'; break; }
        case 'cs_allow_add': { $d = (string)($_POST['dur'] ?? '8760h'); [$c, $o, $e] = priv('cs-allow-add', null, [trim((string)($_POST['ip'] ?? '')), $d]); audit('crowdsec allow ' . ($_POST['ip'] ?? '')); flash($c === 0 ? 'IP aggiunto in allowlist.' : herr($o . $e), $c === 0 ? 'ok' : 'err'); $back = 'p=crowdsec'; break; }
        case 'cs_allow_del': { [$c, $o, $e] = priv('cs-allow-del', null, [trim((string)($_POST['ip'] ?? ''))]); audit('crowdsec allow-del ' . ($_POST['ip'] ?? '')); flash($c === 0 ? 'Allow rimosso.' : herr($o . $e), $c === 0 ? 'ok' : 'err'); $back = 'p=crowdsec'; break; }
        case 'cs_collection_install': { $n = trim((string)($_POST['name'] ?? '')); [$c, $o, $e] = priv('cs-collection-install', null, [$n]); audit("crowdsec collection install $n"); flash($c === 0 ? "Collezione installata:\n" . trim($o) : herr($o . $e), $c === 0 ? 'ok' : 'err'); $back = 'p=crowdsec'; break; }
        case 'cs_collection_remove': { $n = trim((string)($_POST['name'] ?? '')); [$c, $o, $e] = priv('cs-collection-remove', null, [$n]); audit("crowdsec collection remove $n"); flash($c === 0 ? "Collezione rimossa:\n" . trim($o) : herr($o . $e), $c === 0 ? 'ok' : 'err'); $back = 'p=crowdsec'; break; }
        case 'cs_hub_update': { [$c, $o, $e] = priv('cs-hub-update'); audit('crowdsec hub update'); flash($c === 0 ? "Hub aggiornato:\n" . trim($o) : herr($o . $e), $c === 0 ? 'ok' : 'err'); $back = 'p=crowdsec'; break; }
        case 'cs_svc': { $act = (string)($_POST['act'] ?? 'restart'); $tgt = (string)($_POST['tgt'] ?? 'both'); [$c, $o, $e] = priv('cs-svc', null, [$act, $tgt]); audit("crowdsec svc $act $tgt"); flash($c === 0 ? "Servizio: $act ($tgt)\n" . trim($o) : herr($o . $e), $c === 0 ? 'ok' : 'err'); $back = 'p=crowdsec'; break; }
        case 'su_svc': { $act = (string)($_POST['act'] ?? 'restart'); [$c, $o, $e] = priv('su-svc', null, [$act]); audit("suricata svc $act"); flash($c === 0 ? "Suricata: $act\n" . trim($o) : herr($o . $e), $c === 0 ? 'ok' : 'err'); $back = 'p=ips'; break; }
        case 'su_update': { [$c, $o, $e] = priv('su-update'); audit('suricata-update'); flash($c === 0 ? "Regole aggiornate:\n" . trim($o) : herr($o . $e), $c === 0 ? 'ok' : 'err'); $back = 'p=ips'; break; }
        case 'su_source_enable': { $n = trim((string)($_POST['name'] ?? '')); [$c, $o, $e] = priv('su-source-enable', null, [$n]); audit("suricata enable-source $n"); flash($c === 0 ? trim($o) : herr($o . $e), $c === 0 ? 'ok' : 'err'); $back = 'p=ips&t=sorgenti'; break; }
        case 'su_source_disable': { $n = trim((string)($_POST['name'] ?? '')); [$c, $o, $e] = priv('su-source-disable', null, [$n]); audit("suricata disable-source $n"); flash($c === 0 ? trim($o) : herr($o . $e), $c === 0 ? 'ok' : 'err'); $back = 'p=ips&t=sorgenti'; break; }
        case 'su_iface': { $if = trim((string)($_POST['iface'] ?? '')); [$c, $o, $e] = priv('su-iface', null, [$if]); audit("suricata iface $if"); flash($c === 0 ? trim($o) : herr($o . $e), $c === 0 ? 'ok' : 'err'); $back = 'p=ips&t=config'; break; }
        case 'su_test': { [$c, $o, $e] = priv('su-test'); flash(($c === 0 ? "Test OK\n" : "Test fallito\n") . trim($o . $e), $c === 0 ? 'ok' : 'err'); $back = 'p=ips&t=config'; break; }
        case 'su_homenet': {
            $hn = trim((string)($_POST['homenet'] ?? ''));
            if ($hn === '' || !preg_match('/^[A-Za-z0-9.\/,\[\]_\s-]{1,200}$/', $hn)) { flash('HOME_NET non valido (usa CIDR separati da virgola, es. 192.168.1.0/24,10.0.0.0/8).', 'err'); break; }
            [$c, $o, $e] = priv('su-homenet', null, [$hn]); audit("suricata HOME_NET $hn");
            flash($c === 0 ? trim($o) : herr($o . $e), $c === 0 ? 'ok' : 'err'); $back = 'p=ips&t=regole'; break;
        }
        case 'su_local_save': {
            $txt = (string)($_POST['local_rules'] ?? '');
            if (strlen($txt) > 200000) { flash('Regole locali troppo lunghe (max 200 KB).', 'err'); break; }
            [$c, $o, $e] = priv('su-local-set', $txt); audit('suricata local.rules save');
            flash($c === 0 ? trim($o) : herr($o . $e), $c === 0 ? 'ok' : 'err'); $back = 'p=ips&t=regole'; break;
        }
        case 'su_disable_sid': {
            $sid = trim((string)($_POST['sid'] ?? ''));
            if (!preg_match('/^\d{1,10}$/', $sid)) { flash('SID non valido (solo numeri).', 'err'); break; }
            [$c, $o, $e] = priv('su-disable-sid', null, [$sid]); audit("suricata suppress sid $sid");
            flash($c === 0 ? trim($o) : herr($o . $e), $c === 0 ? 'ok' : 'err'); $back = 'p=ips&t=regole'; break;
        }

        case 'cs_scenario_enable': {
            $n = trim((string)($_POST['name'] ?? ''));
            [$c, $o, $e] = priv('cs-scenario-enable', null, [$n]); audit("crowdsec scenario enable $n");
            flash($c === 0 ? trim($o) : herr($o . $e), $c === 0 ? 'ok' : 'err'); $back = 'p=crowdsec&t=avanzate'; break;
        }
        case 'cs_scenario_disable': {
            $n = trim((string)($_POST['name'] ?? ''));
            [$c, $o, $e] = priv('cs-scenario-disable', null, [$n]); audit("crowdsec scenario disable $n");
            flash($c === 0 ? trim($o) : herr($o . $e), $c === 0 ? 'ok' : 'err'); $back = 'p=crowdsec&t=avanzate'; break;
        }
        case 'cs_bouncer_set': {
            $key = (string)($_POST['key'] ?? ''); $val = (string)($_POST['val'] ?? '');
            if (!in_array($key, ['mode', 'deny_action', 'deny_log', 'update_frequency'], true)) { flash('Chiave non consentita.', 'err'); break; }
            [$c, $o, $e] = priv('cs-bouncer-set', null, [$key, $val]); audit("crowdsec bouncer $key=$val");
            flash($c === 0 ? trim($o) : herr($o . $e), $c === 0 ? 'ok' : 'err'); $back = 'p=crowdsec&t=avanzate'; break;
        }
        case 'cs_simulation': {
            $act = (string)($_POST['sim'] ?? 'status');
            if (!in_array($act, ['on', 'off', 'status'], true)) { flash('Azione non valida.', 'err'); break; }
            [$c, $o, $e] = priv('cs-simulation', null, [$act]); audit("crowdsec simulation $act");
            flash($c === 0 ? trim($o) : herr($o . $e), $c === 0 ? 'ok' : 'err'); $back = 'p=crowdsec&t=avanzate'; break;
        }
        case 'cs_hub_upgrade': {
            [$c, $o, $e] = priv('cs-hub-upgrade'); audit('crowdsec hub upgrade');
            flash($c === 0 ? "Hub aggiornato e scenari aggiornati:\n" . trim($o) : herr($o . $e), $c === 0 ? 'ok' : 'err'); $back = 'p=crowdsec&t=avanzate'; break;
        }
        case 'cs_bouncer_setup': {
            $chains = [];
            foreach (['INPUT', 'FORWARD', 'DOCKER-USER'] as $c) if (!empty($_POST['ch_' . str_replace('-', '_', $c)])) $chains[] = $c;
            if (!$chains) $chains = ['INPUT'];
            $deny = (string)($_POST['deny'] ?? 'DROP');
            if (!in_array($deny, ['DROP', 'REJECT', 'TARPIT'], true)) $deny = 'DROP';
            $args = array_merge($chains, [$deny]);
            [$c, $o, $e] = priv('cs-bouncer-setup', null, $args);
            audit('crowdsec bouncer setup iptables ' . implode(',', $chains));
            // abilita integrazione in settings
            if ($c === 0) {
                $S = S_get(); $S['crowdsec'] = 1;
                $S['cs_docker'] = in_array('DOCKER-USER', $chains, true) ? 1 : ($S['cs_docker'] ?? 0);
                S_put($S);
            }
            flash($c === 0 ? "Bouncer iptables configurato:\n" . trim($o) : herr($o . $e), $c === 0 ? 'ok' : 'err');
            $back = 'p=crowdsec&t=firewall'; break;
        }
        case 'cs_bouncer_mode': {
            [$c, $o, $e] = priv('cs-bouncer-set', null, ['mode', 'iptables']);
            audit('crowdsec bouncer mode iptables');
            flash($c === 0 ? trim($o) : herr($o . $e), $c === 0 ? 'ok' : 'err'); $back = 'p=crowdsec&t=firewall'; break;
        }
        case 'health_policy_preview': {
            $back='p=health#health-policy';
            if (pending() || iptm_health_policy_marker_read() !== null) { flash('Concludi la transazione in corso prima di preparare una nuova policy.','err'); break; }
            $S=S_get();
            $preset=(string)($_POST['preset']??'');
            if ($preset==='restrictive')
                $selected=array_keys(array_filter(iptm_health_policy_catalog(),fn($r)=>!empty($r[3])));
            elseif ($preset==='current')
                $selected=array_keys(array_filter(iptm_health_policy_catalog(),fn($r,$k)=>!empty($S[$k]),ARRAY_FILTER_USE_BOTH));
            elseif ($preset==='') $selected=iptm_health_policy_selected($_POST['sec_flags']??[]);
            else throw new RuntimeException('Profilo preflight non riconosciuto.');
            $draft=get_draft(); $pf=iptm_health_policy_preview($S,$selected,$draft);
            $_SESSION['health_policy_preview']=[
                'selected'=>$selected,'settings_hash'=>hash('sha256',serialize($S)),
                'draft_hash'=>hash('sha256',$draft),'errors'=>$pf['errors'],
                'warnings'=>array_slice($pf['warnings'],0,25),'changed'=>$pf['changed'],'ts'=>time()];
            flash(empty($pf['errors'])?'Preflight sicurezza superato: proposta pronta per una prova temporanea.':'Preflight bloccato: nessuna modifica al sistema.',empty($pf['errors'])?'ok':'err');
            break;
        }
        case 'health_policy_trial': {
            $back='p=health#health-policy';
            $plan=$_SESSION['health_policy_preview']??null;
            $secs=filter_var($_POST['secs']??'',FILTER_VALIDATE_INT);
            if (!is_array($plan) || !empty($plan['errors']) || time()-(int)($plan['ts']??0)>1200 || $secs===false || $secs<30 || $secs>600)
                throw new RuntimeException('Anteprima scaduta o timeout non valido: ripeti il preflight.');
            if (pending() || iptm_health_policy_marker_read()!==null) throw new RuntimeException('Transazione firewall già attiva.');
            $S=S_get(); $draft=get_draft();
            if (!hash_equals((string)$plan['settings_hash'],hash('sha256',serialize($S))) ||
                !hash_equals((string)$plan['draft_hash'],hash('sha256',$draft)))
                throw new RuntimeException('Impostazioni o bozza modificate dopo il preflight; ripeti la verifica.');
            $result=iptm_health_policy_preview($S,$plan['selected'],$draft);
            if (!empty($result['errors'])) throw new RuntimeException('Preflight non più valido: '.implode(' ',$result['errors']));
            if (!put_draft($result['txt'])) throw new RuntimeException('Impossibile preparare la bozza per la prova.');
            // Marker blocks legacy one-click confirmation while settings are not yet committed.
            $guard=bin2hex(random_bytes(16));
            if (!atomic_data_write(iptm_health_policy_marker(),json_encode(['token'=>$guard,'status'=>'starting']),0600)) {
                put_draft($draft); throw new RuntimeException('Impossibile proteggere la conferma: bozza ripristinata.');
            }
            $out=do_apply($secs);
            $pd=pending();
            if ($out==='@skip') {
                @unlink(iptm_health_policy_marker());
                S_put($result['candidate']);
                if (get_draft() === $result['txt']) @unlink(DATA_DIR.'/draft.rules');
                unset($_SESSION['health_policy_preview']);
                flash('Policy già identica a quella confermata nel kernel: aggiornate soltanto le impostazioni, senza ricaricare iptables.');
                break;
            }
            if ($out!=='' || !$pd || empty($pd['txid']) || ($pd['fam']??'')!=='4') {
                if (!$pd) {
                    @unlink(iptm_health_policy_marker());
                    if (get_draft()===$result['txt']) put_draft($draft);
                }
                throw new RuntimeException($out!==''?$out:'Prova non registrata correttamente: il watchdog resta da verificare.');
            }
            $markerData=json_encode(['token'=>(string)$pd['txid'],'status'=>'pending']);
            if (!atomic_data_write(iptm_health_policy_marker(),(string)$markerData,0600)) {
                $revert=revert_pending();
                if ($revert==='') { @unlink(iptm_health_policy_marker()); if (get_draft()===$result['txt']) put_draft($draft); }
                throw new RuntimeException('Impossibile registrare la conferma. '.($revert===''?'Rollback eseguito.':'Rollback NON verificato: '.$revert));
            }
            foreach ($GLOBALS['apply_notes'] ?? [] as [$level,$message]) flash($message,(string)$level);
            $_SESSION['health_policy_active']=['txid'=>(string)$pd['txid'], 'settings_hash'=>(string)$plan['settings_hash'],
                'selected'=>$plan['selected'], 'original_draft'=>$draft, 'trial_hash'=>hash('sha256',get_draft())];
            unset($_SESSION['health_policy_preview']);
            flash('Policy temporaneamente attiva. Verifica SSH, Pi-hole e LAN; poi conferma da questa pagina entro '.$secs.' secondi.');
            break;
        }
        case 'health_policy_confirm': {
            $back='p=health#health-policy';
            $tx=$_SESSION['health_policy_active']??null; $marker=iptm_health_policy_marker_read();$pd=pending();
            if (!is_array($tx)||!is_array($marker)||!is_array($pd)||!empty($pd['invalid'])||
                time()>=(int)($pd['until']??0)||!isset($tx['txid'],$marker['token'],$pd['txid'])||
                !hash_equals((string)$tx['txid'],(string)$pd['txid'])||
                !hash_equals((string)$tx['txid'],(string)$marker['token']))
                throw new RuntimeException('Conferma non autorizzata o scaduta. Il watchdog resta operativo.');
            $old=S_get();
            if (!hash_equals((string)$tx['settings_hash'],hash('sha256',serialize($old))))
                throw new RuntimeException('Impostazioni modificate durante la prova: conferma bloccata, usa Ripristina.');
            [$candidate,$notes,$blocked]=iptm_health_policy_candidate($old,$tx['selected']);
            if ($blocked) throw new RuntimeException('Opzioni ora non consentite: usa Ripristina.');
            S_put($candidate); // If write fails, independent watchdog stays armed.
            $err=confirm_pending();
            if ($err!=='') {
                try { S_put($old); $err.=' Impostazioni precedenti ripristinate.'; }
                catch(Throwable $rollbackErr) { $err.=' ERRORE: ripristino impostazioni non riuscito: '.$rollbackErr->getMessage(); }
                throw new RuntimeException($err.' Verifica il watchdog prima di ritentare.');
            }
            @unlink(iptm_health_policy_marker());unset($_SESSION['health_policy_active']);
            flash('Preflight & Commit confermato: regole e impostazioni sincronizzate.');
            break;
        }
        case 'health_recovery_retry': {
            $back='p=health#health-policy';
            if (($_SESSION['role']??'') !== 'admin')
                throw new RuntimeException('Recupero riservato ad amministratore.');
            $pd=pending();
            $txid=(string)($_POST['recovery_txid']??'');
            if (!is_array($pd) || !empty($pd['invalid']) ||
                ($pd['status']??'') !== 'recovery_required' ||
                !preg_match('/^[a-f0-9]{32}$/D',(string)($pd['txid']??'')) ||
                !hash_equals((string)$pd['txid'],$txid))
                throw new RuntimeException('Recupero assistito non autorizzato: conferma, scadenza o ID transazione non validi.');
            $err=revert_pending(); // Stesso lock e watchdog; preflight snapshot obbligatorio.
            if ($err!=='') throw new RuntimeException('Recupero non eseguito/verificato: '.$err);
            $marker=iptm_health_policy_marker_read();
            if (is_array($marker) && !empty($marker['token']) &&
                hash_equals((string)$marker['token'],$txid)) {
                @unlink(iptm_health_policy_marker());
                $tx=$_SESSION['health_policy_active']??null;
                if (is_array($tx) && ($tx['txid']??'')===$txid) iptm_health_policy_restore_draft($tx);
                unset($_SESSION['health_policy_active'],$_SESSION['health_policy_preview']);
            }
            flash('Recupero assistito completato: verifica comunque accesso SSH, DNS e client LAN prima di nuovi Apply.');
            break;
        }
        case 'health_policy_revert': {
            $back='p=health#health-policy';
            $marker=iptm_health_policy_marker_read(); $pd=pending();
            if ($marker===null) { flash('Nessuna prova guidata attiva.','err'); break; }
            if (!$pd) {
                $tx=$_SESSION['health_policy_active']??null;
                $draftRestored=is_array($tx) ? iptm_health_policy_restore_draft($tx) : false;
                @unlink(iptm_health_policy_marker());
                unset($_SESSION['health_policy_active'],$_SESSION['health_policy_preview']);
                flash('Transazione non più pendente. '.($draftRestored?'Bozza di partenza ripristinata.':'Verifica bozza e stato del kernel; il recupero non è stato verificato da IPTM.'),'err');
                break;
            }
            if (empty($marker['token']) || empty($pd['txid']) ||
                !hash_equals((string)$marker['token'],(string)$pd['txid']))
                throw new RuntimeException('ID transazione non corrispondente: nessuna modifica effettuata; verificare da console.');
            $err=revert_pending();
            if ($err!=='') throw new RuntimeException('Rollback non verificato: '.$err);
            @unlink(iptm_health_policy_marker());
            $tx=$_SESSION['health_policy_active']??null;
            $draftRestored=is_array($tx) ? iptm_health_policy_restore_draft($tx) : false;
            unset($_SESSION['health_policy_active'],$_SESSION['health_policy_preview']);
            flash('Regole firewall precedenti ripristinate.'.($draftRestored?' Anche la bozza precedente è stata ripristinata.':' Controlla manualmente la bozza: non è stato possibile ripristinarla in sicurezza.'));
            break;
        }
        case 'ti_vt_test': {
            $S = S_get();
            $key = trim((string)($_POST['virustotal'] ?? ($S['ti']['virustotal'] ?? '')));
            if ($key === '' || !preg_match('/^[A-Za-z0-9_\-]{32,128}$/', $key)) { flash('Inserisci una chiave VirusTotal valida prima del test.', 'err'); $back = 'p=attacks'; break; }
            // salva se fornita nel form
            if (trim((string)($_POST['virustotal'] ?? '')) !== '') {
                $S['ti'] = array_merge(ti_cfg(), (array)($S['ti'] ?? []), ['virustotal' => $key]);
                S_put($S);
            }
            $ip = '8.8.8.8'; // probe noto
            $body = ti_curl('https://www.virustotal.com/api/v3/ip_addresses/' . $ip, ['x-apikey: ' . $key, 'Accept: application/json'], 8);
            if ($body === null || $body === '') { flash('VirusTotal: nessuna risposta (rete, DNS o firewall in uscita verso www.virustotal.com).', 'err'); $back = 'p=attacks'; break; }
            $j = json_decode($body, true);
            if (!is_array($j)) { flash('VirusTotal: risposta non JSON.', 'err'); $back = 'p=attacks'; break; }
            if (isset($j['error'])) {
                $msg = (string)($j['error']['message'] ?? json_encode($j['error']));
                flash('VirusTotal errore: ' . $msg, 'err');
            } elseif (isset($j['data']['attributes']['last_analysis_stats'])) {
                $st = $j['data']['attributes']['last_analysis_stats'];
                flash('VirusTotal OK (test su 8.8.8.8): malicious=' . (int)($st['malicious'] ?? 0) . ' suspicious=' . (int)($st['suspicious'] ?? 0) . ' harmless=' . (int)($st['harmless'] ?? 0) . '. Chiave funzionante.');
            } else {
                flash('VirusTotal: risposta inattesa (chiave forse valida ma formato diverso).', 'err');
            }
            $back = 'p=attacks'; break;
        }
        case 'ti_save': {
            $S = S_get();
            $ti = [
                'abuseipdb' => trim((string)($_POST['abuseipdb'] ?? '')),
                'greynoise' => trim((string)($_POST['greynoise'] ?? '')),
                'otx' => trim((string)($_POST['otx'] ?? '')),
                'virustotal' => trim((string)($_POST['virustotal'] ?? '')),
                'urlscan' => trim((string)($_POST['urlscan'] ?? '')),
                'ipapi' => 0, // legacy HTTP-only service: deliberately disabled for privacy
                'threatfox' => !empty($_POST['threatfox']) ? 1 : 0,
                'urlhaus' => !empty($_POST['urlhaus']) ? 1 : 0,
                'cache_hours' => max(1, min(168, (int)($_POST['cache_hours'] ?? 24))),
            ];
            if ($ti['abuseipdb'] !== '' && !preg_match('/^[A-Za-z0-9]{20,80}$/', $ti['abuseipdb'])) { flash('Chiave AbuseIPDB non valida.', 'err'); break; }
            if ($ti['greynoise'] !== '' && !preg_match('/^[A-Za-z0-9_.-]{16,120}$/', $ti['greynoise'])) { flash('Chiave GreyNoise non valida.', 'err'); break; }
            if ($ti['otx'] !== '' && !preg_match('/^[A-Za-z0-9]{16,120}$/', $ti['otx'])) { flash('Chiave OTX non valida.', 'err'); break; }
            if ($ti['virustotal'] !== '' && !preg_match('/^[A-Za-z0-9_\-]{32,128}$/', $ti['virustotal'])) { flash('Chiave VirusTotal non valida (32–128 caratteri).', 'err'); break; }
            if ($ti['urlscan'] !== '' && !preg_match('/^[A-Za-z0-9\-]{8,64}$/', $ti['urlscan'])) { flash('Chiave urlscan.io non valida.', 'err'); break; }
            $S['ti'] = $ti; S_put($S);
            // svuota cache se richiesto
            if (!empty($_POST['clear_cache'])) @unlink(DATA_DIR . '/ti-cache.json');
            flash('Threat intel API salvate' . (!empty($_POST['clear_cache']) ? ' (cache svuotata)' : '') . '.');
            $back = 'p=attacks'; break;
        }
        case 'av_save_key': {
            $S = S_get();
            $key = trim((string)($_POST['virustotal'] ?? ''));
            if ($key !== '' && !preg_match('/^[A-Za-z0-9_\-]{32,128}$/', $key)) { flash('Chiave VirusTotal non valida (32–128 caratteri).', 'err'); $back = 'p=avscan'; break; }
            $S['ti'] = array_merge(ti_cfg(), (array)($S['ti'] ?? []), ['virustotal' => $key]);
            S_put($S);
            flash($key === '' ? 'Chiave VirusTotal rimossa.' : 'Chiave VirusTotal salvata.');
            $back = 'p=avscan'; break;
        }
        case 'av_hash': {
            $r = vt_file_report((string)($_POST['hash'] ?? ''));
            $_SESSION['av_result'] = $r;
            if (empty($r['ok'])) flash($r['err'] ?? 'Errore scan hash', 'err');
            elseif (empty($r['found'])) flash($r['msg'] ?? 'Hash sconosciuto', 'err');
            else {
                $v = $r['verdict'] ?? '';
                flash('Hash: ' . ($r['malicious'] ?? 0) . ' malicious / ' . ($r['suspicious'] ?? 0) . ' suspicious — verdetto ' . $v, $v === 'malicious' ? 'err' : ($v === 'suspicious' ? 'err' : 'ok'));
            }
            $back = 'p=avscan'; break;
        }
        case 'av_url': {
            $r = vt_url_scan((string)($_POST['url'] ?? ''));
            $_SESSION['av_result'] = $r;
            if (empty($r['ok'])) flash($r['err'] ?? 'Errore scan URL', 'err');
            else {
                $v = $r['verdict'] ?? 'unknown';
                flash('URL: ' . ($r['malicious'] ?? 0) . ' malicious / ' . ($r['suspicious'] ?? 0) . ' suspicious — verdetto ' . $v . (!empty($r['queued']) ? ' (analisi appena avviata)' : ''), $v === 'malicious' ? 'err' : 'ok');
            }
            $back = 'p=avscan'; break;
        }
        case 'av_file': {
            if (empty($_FILES['sample']) || (int)($_FILES['sample']['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
                flash('Seleziona un file da caricare.', 'err'); $back = 'p=avscan'; break;
            }
            $tmp = (string)$_FILES['sample']['tmp_name'];
            $name = basename((string)$_FILES['sample']['name']);
            $mode = (string)($_POST['av_mode'] ?? 'hash');
            if (!in_array($mode, ['local', 'hash', 'upload'], true)) { flash('Modalità antivirus non valida.', 'err'); break; }
            $clamRes = null;
            if ($mode === 'local' || !empty($_POST['also_clam'])) $clamRes = clam_scan_file($tmp);
            if ($mode === 'local') {
                $r = !empty($clamRes['ok']) ? ['ok'=>true,'found'=>false,'hash'=>hash_file('sha256',$tmp),
                      'msg'=>'Scansione solo locale completata; nessun byte o hash inviato al cloud.'] :
                      ['ok'=>false,'err'=>'ClamAV locale non disponibile: installalo prima di selezionare questo metodo.'];
            } elseif (!empty($clamRes['infected'])) {
                // Never send a file identified as infected to a cloud service automatically.
                $r = ['ok'=>true,'found'=>false,'hash'=>hash_file('sha256',$tmp),
                      'msg'=>'ClamAV ha rilevato malware: nessuna trasmissione al cloud eseguita.'];
            } elseif ($mode === 'hash') {
                $r = vt_file_report(hash_file('sha256',$tmp));
            } else {
                $r = vt_file_upload($tmp, $name);
            }
            if ($clamRes !== null) $r['clam'] = $clamRes;
            $_SESSION['av_result'] = $r;
            if (empty($r['ok'])) flash($r['err'] ?? 'Errore upload', 'err');
            elseif (!empty($clamRes['ok']) && !empty($clamRes['infected'])) flash('ClamAV: file INFETTO in locale. ' . ($clamRes['detail'] ?? ''), 'err');
            elseif (empty($r['found'])) flash($r['msg'] ?? 'Report non ancora pronto', 'err');
            else {
                $v = $r['verdict'] ?? '';
                flash('File: ' . ($r['malicious'] ?? 0) . ' malicious — verdetto ' . $v, $v === 'malicious' ? 'err' : 'ok');
            }
            $back = 'p=avscan'; break;
        }
        case 'cs_bouncer_set_only': {
            [$rc, $msg] = cs_bouncer_set_only();
            flash($msg, $rc === 0 ? 'ok' : 'err');
            break;
        }
        case 'cs_bouncer_setup_rec': {
            [$rc, $msg] = cs_bouncer_setup_recommended();
            flash($rc === 0 ? ('Bouncer configurato:\n' . $msg) : ('Setup bouncer fallito:\n' . $msg), $rc === 0 ? 'ok' : 'err');
            $back = 'p=crowdsec&t=stato'; break;
        }
        case 'lynis_update': {
            $back='p=health';
            [$rc,$o,$e]=priv('security',null,['lynis-update']);$j=json_decode($o,true);
            flash($rc===0?'Lynis aggiornato o già alla versione disponibile.':'Impossibile aggiornare Lynis: '.($j['error']??$j['summary']??trim($o.$e)),$rc===0?'ok':'err');
            if ($rc===0) audit('Lynis package upgrade requested');
            break;
        }
        case 'lynis_run': {
            $back='p=health';[$rc,$o,$e]=priv('security',null,['lynis-start']);$j=json_decode($o,true);
            flash($rc===0?'Audit Lynis avviato in background; aggiorna la pagina per consultare lo stato.':'Lynis: '.($j['error']??$j['summary']??trim($o.$e)),$rc===0?'ok':'err'); break;
        }
        case 'lynis_mark': {
            $back='p=health';
            $job=(string)($_POST['lynis_job']??'');
            $finding=(string)($_POST['finding']??'');
            $review=(string)($_POST['review']??'');
            if (!preg_match('/^[0-9a-f]{16}$/D',$job) || !preg_match('/^(warning|suggestion):[A-Z]{2,6}-[0-9]{4,5}:[a-f0-9]{8}$/D',$finding)
                || !in_array($review,['open','planned','reviewed'],true)) {
                flash('Raccomandazione o revisione non valida.','err'); break;
            }
            $input=json_encode(['audit_id'=>$job,'finding'=>$finding,'review'=>$review],JSON_THROW_ON_ERROR);
            [$rc,$out,$err]=priv('security',$input,['lynis-review']);
            $reply=json_decode($out,true);
            flash($rc===0?'Stato della raccomandazione salvato (nessuna modifica al sistema).':'Revisione non salvata: '.h($reply['error']??$err),$rc===0?'ok':'err');
            if ($rc===0) audit('lynis reviewed finding '. $finding);
            break;
        }
        case 'lynis_safe_apply': {
            $back='p=health';
            $allow=['aslr'=>'kernel.randomize_va_space = 2','suid'=>'fs.suid_dumpable = 0'];
            $selected=array_values(array_unique(array_filter((array)($_POST['fix']??[]),fn($x)=>is_string($x)&&isset($allow[$x]))));
            if (!$selected) { flash('Seleziona almeno una correzione.','err'); break; }
            $body=implode("\n",array_map(fn($k)=>$allow[$k],$selected))."\n";
            $args=['sysctl-apply','--file','-'];
            if (!empty($_POST['apply_fix'])) $args[]='--apply';
            [$rc,$o,$e]=priv('maintenance',$body,$args);
            flash(($rc===0?'Sysctl verificato: ':'Errore sysctl: ').trim($o.$e),$rc===0?'ok':'err');
            if ($rc===0&&!empty($_POST['apply_fix'])) audit('lynis sysctl allowlist: '.implode(',',$selected));
            break;
        }
        
}
