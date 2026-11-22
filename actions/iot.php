<?php
/* IPTM action domain: iot. Inherits the authenticated controller scope. */
switch ($a) {
case 'warden_retire': {
            $back='p=zones';
            if (($_SESSION['role']??'')!=='admin') { flash('Solo amministratore.','err'); break; }
            $want=(string)($_POST['fingerprint']??'');
            if (!preg_match('/^[a-f0-9]{64}$/D',$want)) { flash('Anteprima non valida.','err'); break; }
            [$rc,$o,$e]=priv('iot-warden',null,['retire',$want]);
            $result=json_decode($o,true);
            if ($rc!==0 || !is_array($result) || empty($result['ok'])) {
                flash('Gestione IoT precedente non archiviata: '.substr((string)($result['error']??$o.$e),0,260),'err'); break;
            }
            $S=S_get();$S['iot_strategy']='none';
            try { S_put($S); } catch (Throwable $setError) {
                audit('WARNING IoT Warden retired, settings update failed: '.$setError->getMessage());
                flash('Warden disattivato ma salvataggio preferenza fallito: controllare impostazioni e backup.','err');
            }
            audit('iot-warden retired (backup created; live firewall unmodified)');
            flash('Automazioni precedenti archiviate con backup. Nessuna catena live rimossa. Backup: '.(string)($result['backup']??'n/d').'. Ora prepara la pulizia della bozza e applicala con rollback.');
            break;
        }
        case 'warden_script_switch': {
            $back='p=zones';
            if (($_SESSION['role']??'')!=='admin') { flash('Solo amministratore.','err'); break; }
            $target=(string)($_POST['target']??''); $fingerprint=(string)($_POST['fingerprint']??'');
            if (!in_array($target,['enable','disable'],true) || !preg_match('/^[a-f0-9]{64}$/D',$fingerprint)) {
                flash('Dati Warden non validi: aggiorna inventario.','err'); break;
            }
            [$rc,$out,$err]=priv('iot-warden',null,['switch',$target,$fingerprint]);
            $res=json_decode($out,true);
            if ($rc!==0 || empty($res['ok'])) { flash('Script Warden non modificato: '.substr((string)($res['error']??$out.$err),0,250),'err'); break; }
            audit('IoT Warden script switch: '.$target);
            flash('Script Warden: '.($target==='enable'?'pianificazione precedente ripristinata':'attivatori riconosciuti disattivati').'. Regole live immutate.');
            break;
        }
        case 'warden_scrub_draft': {
            $back='p=zones';
            if (($_SESSION['role']??'')!=='admin') { flash('Solo amministratore.','err'); break; }
            if (($_POST['rev']??'')!==$rev) { flash('La bozza è cambiata: ricarica prima della pulizia.','err'); break; }
            $wi=iptm_warden_state();
            if (empty($wi['ok']) || !empty($wi['active']) || !empty($wi['detected']) || !empty($wi['blockers']) || empty($wi['retired'])) {
                flash('Non è sicuro eliminare le catene: IoT Warden ancora attivo, non verificabile o con attivatori ignoti.','err'); break;
            }
            $S=S_get();
            foreach ((array)($S['custom_opts']??[]) as $custom) {
                foreach ((array)($custom['rules']??[]) as $rule) {
                    if (preg_match('/\bIOT_(?:FW|DNS)\b/',(string)($rule['r']??''))) {
                        flash('Una opzione personalizzata contiene ancora IOT_FW/IOT_DNS: disattivala manualmente prima della pulizia.','err'); break 3;
                    }
                }
            }
            try { [$clean,$removed]=iptm_warden_scrub_model(parse_rules(get_draft())); }
            catch (Throwable $ex) { flash('Rimozione rifiutata: '.$ex->getMessage(),'err'); break; }
            if (!$removed) { flash('La bozza IPv4 non contiene catene o salti IOT_WARDEN da eliminare. Le eventuali catene live richiedono ancora un Applica controllato.'); break; }
            $draft=ser($clean);
            [$tc,$to,$te]=priv('test',$draft);
            if ($tc!==0) { flash('iptables-restore --test rifiuta la bozza ripulita: '.herr($to.$te),'err'); break; }
            settings_snapshot('iot-warden-clean');
            if (!put_draft($draft)) { flash('Impossibile salvare la bozza ripulita.','err'); break; }
            audit('iot-warden draft rules removed='.$removed);
            flash('Eliminate '.$removed.' righe Warden dalla bozza IPv4. Regole LIVE immutate: verifica e usa Applica con watchdog. Controlla a parte IPv6 e cron non riconosciuti.');
            $back='p=apply'; break;
        }
        case 'zone_vlan_remove': {
            $back='p=zones';
            if (($_SESSION['role']??'')!=='admin') { flash('Solo amministratore.','err'); break; }
            $req=['mode'=>'delete','confirm'=>'RIMUOVI VLAN IOT',
                  'admin_ip'=>(string)($_SERVER['REMOTE_ADDR']??'')];
            [$rc,$o,$e]=priv('security',json_encode($req,JSON_UNESCAPED_UNICODE),['vlan-manage']);
            $j=json_decode($o,true);
            if ($rc!==0 || !is_array($j) || empty($j['ok'])) {
                flash('VLAN non rimossa: '.(is_array($j)?(string)($j['error']??'controllo VLAN fallito'):herr($o.$e)),'err'); break;
            }
            audit('IoT managed VLAN removed '.$j['iface']);
            flash('VLAN IoT rimossa dal runtime; le regole non sono state cambiate.');
            break;
        }
        case 'zone_vlan_create': {
            $back='p=zones';
            if (($_SESSION['role']??'')!=='admin') { flash('Solo amministratore.','err'); break; }
            $warden=iptm_warden_state();
            if (empty($warden['ok']) || !empty($warden['active']) || !empty($warden['blockers']) || !empty($warden['detected'])) {
                flash('Disattiva IoT Warden prima di creare una VLAN IPTM: motori concorrenti non consentiti.','err'); break;
            }
            $req=['mode'=>'create','parent'=>(string)($_POST['vlan_parent']??''),
                  'vlan_id'=>(string)($_POST['vlan_id']??''),'network'=>(string)($_POST['vlan_network']??''),
                  'gateway'=>(string)($_POST['vlan_gateway']??''),
                  'admin_ip'=>(string)($_SERVER['REMOTE_ADDR']??''),
                  'confirm'=>'CREA VLAN IOT'];
            [$rc,$o,$e]=priv('security',json_encode($req,JSON_UNESCAPED_UNICODE),['vlan-manage']);
            $j=json_decode($o,true);
            if ($rc!==0 || !is_array($j) || empty($j['ok'])) {
                flash('VLAN non creata: '.(is_array($j)?(string)($j['error']??'errore VLAN'):herr($o.$e)),'err');break;
            }
            audit('IoT managed VLAN created '.$j['iface']);
            flash('Interfaccia VLAN '.$j['iface'].' creata sul kernel. La VLAN fisica deve essere configurata su switch/AP. Ora genera la policy IoT: le regole non sono ancora attive.');
            break;
        }
        case 'zone_plan': {
            $back='p=zones';
            $warden=iptm_warden_state();
            if (empty($warden['ok']) || !empty($warden['active']) || !empty($warden['blockers']) || !empty($warden['detected'])) { flash('Prima di creare una VLAN IPTM disattiva IoT Warden e risolvi eventuali attivatori sconosciuti.','err'); break; }
            $S=S_get();
            $req=['iface'=>(string)($_POST['iface']??''),'network'=>(string)($_POST['network']??''),
                 'trusted_nets'=>(string)($S['lan_nets']??''),'wan_if'=>(string)($S['wan_if']??''),
                 'dns_ip'=>(string)($_POST['dns_ip']??($S['dns_ip']??'')),
                 'admin_ip'=>(string)($_SERVER['REMOTE_ADDR']??''),'block_quic'=>!empty($_POST['block_quic']),
                 'ipv6_mode'=>(string)($_POST['ipv6_mode']??'block'), 'network6'=>(string)($_POST['network6']??''),
                 'trusted_nets6'=>(string)($_POST['trusted_nets6']??''), 'dns_ip6'=>(string)($_POST['dns_ip6']??''),
                 'strict_egress'=>!empty($_POST['strict_egress']),
                 'block_common_resolvers'=>!empty($_POST['block_common_resolvers']),
                 'blocked_resolvers4'=>(string)($_POST['blocked_resolvers4']??''),
                 'blocked_resolvers6'=>(string)($_POST['blocked_resolvers6']??'')];
            [$rc,$o,$e]=priv('security',json_encode($req),['zone-plan']);
            $j=json_decode($o,true);
            if ($rc!==0 || empty($j['ok'])) { flash('Piano zona rifiutato: '.h((string)($j['error']??$o.$e)),'err'); unset($_SESSION['zone_plan']); break; }
            $_SESSION['zone_plan']=['data'=>$j,'rev'=>$rev,'s_sha'=>hash('sha256',json_encode($S)),'time'=>time()];
            flash('Anteprima pronta: rivedi le regole. Non sono state salvate o applicate.');
            break;
        }
        case 'zone_stage': {
            $back='p=zones'; $warden=iptm_warden_state();
            if (empty($warden['ok']) || !empty($warden['active']) || !empty($warden['blockers']) || !empty($warden['detected'])) { flash('IoT Warden deve essere disattivato prima di attivare la zona IPTM.','err'); break; }
            $plan=$_SESSION['zone_plan']??null;
            if (!is_array($plan) || time()-($plan['time']??0)>600 || ($plan['rev']??'')!==$rev ||
                !hash_equals((string)($plan['s_sha']??''),hash('sha256',json_encode(S_get())))) {
                flash('Anteprima scaduta o stato modificato: rigenera il piano prima di procedere.','err'); break;
            }
            if (empty($plan['data']['ready_to_apply'])) { flash('Prerequisiti VLAN/DNS/forwarding non soddisfatti: prima rendi operativa la rete IoT, poi rigenera l’anteprima.','err'); break; }
            $rules=$plan['data']['rules']??[];
            if (!is_array($rules) || count($rules)>80 || !$rules) { flash('Piano non valido.','err'); break; }
            $ipv6Rules=$plan['data']['ipv6_rules']??[];
            if (!is_array($ipv6Rules) || count($ipv6Rules)>110 || !$ipv6Rules) { flash('Piano IPv6 mancante.','err'); break; }
            try { $newV6=iptm_zone_v6_merge(v6_get(),(string)$plan['data']['interface'],$ipv6Rules); }
            catch (Throwable $e) { flash('IPv6: '.$e->getMessage(),'err'); break; }
            [$vc,$vo,$ve]=priv('test6',$newV6);
            if ($vc!==0) { flash('ip6tables-restore --test ha rifiutato la bozza IPv6: '.herr($vo.$ve),'err'); break; }
            $before=S_get(); $previousDraft=get_draft(); $previousV6=v6_get();
            $zoneLock=@fopen(DATA_DIR.'/zone-stage.lock','c');
            if (!$zoneLock || !flock($zoneLock,LOCK_EX|LOCK_NB)) { if (is_resource($zoneLock)) fclose($zoneLock); flash('Altra modifica delle zone in corso.','err'); break; }
            $S=$before; $S['custom_opts']=array_values(array_filter($S['custom_opts']??[],fn($v)=>empty($v['iptm_zone_v1'])));
            $S=copt_add($S,'Zona IoT '.$plan['data']['network'],'top',$rules,'Policy rete instradata: verificare VLAN, DNS e IPv6');
            $last=array_key_last($S['custom_opts']);$S['custom_opts'][$last]['iptm_zone_v1']=true;
            // Place isolation before generic SPI ESTABLISHED, broad allows and ACLs.
            $S['custom_opts'][$last]['pr']=-1000;
            $S['iot_strategy']='iptm_zone';
            $M2=parse_rules(get_draft());$warnings=regen($M2,$S);$proposed=ser($M2);
            [$tc,$to,$te]=priv('test',$proposed);
            if ($tc!==0) { flash('iptables-restore --test fallito: bozza non modificata. '.herr($to.$te),'err'); break; }
            settings_snapshot('zone-stage');
            $stageOk=false;
            try {
                S_put($S);
                if (!put_draft($proposed)) throw new RuntimeException('scrittura della bozza IPv4 fallita');
                if (!v6_put($newV6)) throw new RuntimeException('scrittura della bozza IPv6 fallita');
                $stageOk=true;
            } catch (Throwable $e) {
                // Best-effort restoration of all three files; never apply partial drafts.
                $restored4=put_draft($previousDraft); $restored6=v6_put($previousV6);
                $GLOBALS['_Sc']=null;
                try { S_put($before); $restoredS=true; } catch (Throwable $re) { $restoredS=false; audit('zone-stage settings rollback failed '.$re->getMessage()); }
                audit('zone-stage interrupted '.$e->getMessage());
                flash('Zona non salvata: '.$e->getMessage().'. Ripristino IPv4='.(int)$restored4.' IPv6='.(int)$restored6.' settings='.(int)$restoredS.'. Nessuna regola live modificata.','err');
            }
            flock($zoneLock,LOCK_UN); fclose($zoneLock);
            if (!$stageOk) break;
            unset($_SESSION['zone_plan']); audit('zona IoT staged only');
            flash('Zone IPv4 e IPv6 salvate nelle rispettive bozze. NON attive: applica e conferma entrambe dalla pagina Applica/IPv6 con rollback separato. '.implode('; ',array_slice($warnings,0,3)));
            $back='p=apply'; break;
        }
        case 'mac_plan': {
            $back='p=zones';
            $GLOBALS['_iptm_mac_stage']='authorization';
            if (($_SESSION['role']??'')!=='admin') { flash('Solo amministratore.','err'); break; }
            $GLOBALS['_iptm_mac_stage']='warden_inventory';
            $legacy=iptm_warden_state();
            if (empty($legacy['ok']) || !empty($legacy['active']) || !empty($legacy['blockers']) || !empty($legacy['live_chains'])) {
                flash('Prima disattiva la gestione IoT precedente e completa la pulizia controllata delle sue regole.', 'err'); break;
            }
            $GLOBALS['_iptm_mac_stage']='form_validation';
            $postMacs=$_POST['macs']??[];
            if (!is_array($postMacs) || count($postMacs)<1 || count($postMacs)>32) {
                flash('Seleziona fino a 32 dispositivi dall’inventario MAC.', 'err');break;
            }
            // A malformed or duplicated checkbox list must produce a readable
            // validation error, never an ambiguous helper request.
            $macs=[];
            foreach ($postMacs as $raw) {
                if (!is_string($raw) || !preg_match('/^(?:[a-f0-9]{2}:){5}[a-f0-9]{2}$/iD',$raw)) {
                    flash('MAC non valido nella selezione.', 'err');break 2;
                }
                $mac=strtolower($raw);
                if (in_array($mac,$macs,true)) {
                    flash('Un MAC è stato selezionato più volte: aggiorna l’inventario e riprova.','err');break 2;
                }
                $macs[]=$mac;
            }
            foreach (['lan_if','wan_if','dns_ip'] as $field) {
                if (!is_string($_POST[$field]??null)) {
                    flash('Campo rete non valido: '. $field .'. Ricarica Zone di rete.','err');break 2;
                }
            }
            if (!preg_match('/^[A-Za-z0-9_.:-]{1,15}$/D',$_POST['lan_if']) ||
                !preg_match('/^[A-Za-z0-9_.:-]{1,15}$/D',$_POST['wan_if']) ||
                filter_var($_POST['dns_ip'],FILTER_VALIDATE_IP,FILTER_FLAG_IPV4)===false) {
                flash('Interfaccia LAN/WAN o DNS IPv4 non valido: correggi i campi e riprova.','err');break;
            }
            $GLOBALS['_iptm_mac_stage']='settings';
            $S=S_get();
            $customOpts=$S['custom_opts']??[];
            if (!is_array($customOpts)) {
                flash('Impostazioni zone non valide: esporta la configurazione ed esegui una verifica, senza applicare regole.', 'err');break;
            }
            if (array_filter($customOpts,static fn($co)=>is_array($co) && !empty($co['iptm_zone_v1']))) {
                flash('È già configurata una zona VLAN: rimuovila e applica il rollback prima di cambiare modalità.', 'err');break;
            }
            $req=['macs'=>$macs,'lan_if'=>(string)($_POST['lan_if']??''),
                'wan_if'=>(string)($_POST['wan_if']??''),'dns_ip'=>(string)($_POST['dns_ip']??''),
                'block_quic'=>!empty($_POST['block_quic']),
                'strict_egress'=>!empty($_POST['strict_egress']),
                'admin_ip'=>(string)($_SERVER['REMOTE_ADDR']??'')];
            $GLOBALS['_iptm_mac_stage']='helper_mac_plan';
            $requestJson=json_encode($req,JSON_THROW_ON_ERROR);
            [$rc,$out,$err]=priv('security',$requestJson,['mac-plan']);
            $j=json_decode($out,true);
            if ($rc!==0 || !is_array($j) || empty($j['ok'])) {
                $detail=is_array($j)?(string)($j['error']??'Nessuna risposta valida'):'Nessuna risposta JSON dal generatore';
                flash('Anteprima MAC non generata: '.substr($detail,0,280).
                    '. Se l’errore persiste, verifica l’helper e l’inventario MAC via SSH.','err');
                unset($_SESSION['mac_plan']);break;
            }
            if (!is_array($j['rules']??null) || !is_array($j['ipv6_rules']??null) ||
                !is_array($j['readiness']??null) || !is_array($j['source_ips']??null)) {
                unset($_SESSION['mac_plan']);
                flash('L’helper ha restituito un piano MAC incompleto: verifica le versioni dei moduli.','err');break;
            }
            $GLOBALS['_iptm_mac_stage']='session_plan';
            $settingsJson=json_encode($S,JSON_THROW_ON_ERROR);
            $_SESSION['mac_plan']=['data'=>$j,'request'=>$req,'rev'=>$rev,'s_sha'=>hash('sha256',$settingsJson),'time'=>time()];
            flash('Anteprima MAC preparata: nessuna regola è stata applicata al kernel.');
            unset($GLOBALS['_iptm_mac_stage']);
            break;
        }
        case 'mac_pending_clear': {
            $back='p=zones';
            if (($_SESSION['role']??'')!=='admin') { flash('Solo amministratore.','err');break; }
            if (is_file(iptm_mac_pending_file()) && !@unlink(iptm_mac_pending_file())) {
                flash('Impossibile eliminare il piano sospeso.','err');break;
            }
            flash('Piano MAC sospeso eliminato. Nessuna modifica a bozze o firewall attivo.');
            break;
        }
        case 'mac_stage': {
            $back='p=zones';
            if (($_SESSION['role']??'')!=='admin') { flash('Solo amministratore.','err');break; }
            $legacy=iptm_warden_state();
            if (empty($legacy['ok']) || !empty($legacy['active']) || !empty($legacy['blockers']) || !empty($legacy['live_chains'])) {
                flash('Policy non salvata: gestione IoT precedente ancora presente o non verificabile.','err');break;
            }
            $plan=$_SESSION['mac_plan']??null;$before=S_get();
            if (!is_array($plan) || time()-(int)($plan['time']??0)>600 || ($plan['rev']??'')!==$rev ||
                !hash_equals((string)($plan['s_sha']??''),hash('sha256',json_encode($before)))) {
                flash('Anteprima scaduta o impostazioni modificate: rigenera il piano.','err');break;
            }
            if (empty($plan['data']['ready_to_stage'])) {flash('Prerequisiti non soddisfatti: verifica routing e DNS locale sul DietPi.','err');break;}
            // Re-read the network neighbor table on commit; an IP/MAC binding may
            // change between preview and staging (DHCP, MAC randomization, spoofing).
            $request=$plan['request']??null;
            if (!is_array($request)) {flash('Anteprima precedente non riutilizzabile: rigenerala.','err');break;}
            [$checkRc,$checkOut,$checkErr]=priv('security',json_encode($request),['mac-plan']);
            $fresh=json_decode($checkOut,true);
            if ($checkRc!==0 || empty($fresh['ok']) ||
                !hash_equals(hash('sha256',json_encode($fresh['rules']??[])),hash('sha256',json_encode($plan['data']['rules']??[]))) ||
                !hash_equals(hash('sha256',json_encode($fresh['source_ips']??[])),hash('sha256',json_encode($plan['data']['source_ips']??[]))) ||
                !hash_equals(hash('sha256',json_encode($fresh['ipv6_rules']??[])),hash('sha256',json_encode($plan['data']['ipv6_rules']??[])))) {
                flash('Inventario MAC/IP modificato o non disponibile: rigenera la policy per evitare dispositivi errati.','err');break;
            }

            $rules=$plan['data']['rules']??[];$v6=$plan['data']['ipv6_rules']??[];
            if (!is_array($rules)||count($rules)>450||!$rules||!is_array($v6)||count($v6)>256||!$v6) {
                flash('Piano MAC non valido.','err');break;
            }
            if (array_filter($before['custom_opts']??[],fn($co)=>!empty($co['iptm_zone_v1']))) {
                flash('Modalità VLAN già attiva: non sovrapporre due policy IoT.','err');break;
            }
            // Fully disabled gateway IPv6 has no restorable ip6tables table.
            // Allow saving the IPv4 draft *only* when root verifies that IPv6
            // is disabled globally and on every non-loopback interface.
            // Active or unverifiable IPv6 must still pass the IPv6 test.
            $ipv6Skipped=iptm_gateway_ipv6_disabled();
            $newV6=null;
            if (!$ipv6Skipped) {
                try {$newV6=iptm_mac_v6_merge(v6_get(),$v6);}catch(Throwable $ex) {
                    flash('IPv6: '.$ex->getMessage(),'err');break;
                }
                [$vc,$vo,$ve]=priv('test6',$newV6);
                if ($vc!==0) {
                    $diag=iptm_v6_diagnostic();
                    $state=(string)($diag['state']??'unknown');
                    $filter=(string)($diag['filter']??'unknown');
                    $detail='IPv6='.$state.', filter='.$filter.', backend='.($diag['backend']??'sconosciuto').
                        ', all.disable_ipv6='.($diag['all']??'?').', default.disable_ipv6='.($diag['default']??'?');
                    if ($filter==='unavailable' && $state!=='disabled') {
                        // Data-only fallback: do NOT persist settings.json, draft.rules,
                        // draft6.rules, active firewall rules, or a "ready to apply" marker.
                        $pending=['schema'=>1,'time'=>time(),'state'=>'SUSPENDED_V6_BACKEND',
                            'macs'=>array_values((array)($request['macs']??[])),
                            'request'=>$request,'rules'=>$rules,'ipv6_rules'=>$v6,
                            'settings_sha'=>hash('sha256',json_encode($before)),
                            'diagnostic'=>$detail];
                        $blob=json_encode($pending,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);
                        if (is_string($blob) && strlen($blob)<=262144 && atomic_data_write(iptm_mac_pending_file(),$blob,0600)) {
                            flash('Piano MAC conservato come SOSPESO ('.count($pending['macs']).' dispositivi). Il kernel non espone la tabella IPv6 filter: '.$detail.
                                '. Nessuna bozza firewall e nessuna regola LIVE modificata. Non è applicabile: ripara il backend IPv6 oppure disabilita IPv6 completamente, poi rigenera anteprima e salva.','err');
                        } else {
                            flash('Test IPv6 fallito e piano sospeso non scrivibile: '.herr($vo.$ve).'. '.$detail.'. Nessuna regola salvata.','err');
                        }
                    } else {
                        flash('Test IPv6 rifiutato: '.herr($vo.$ve).' ('.$detail.'). Nessuna bozza salvata. Se IPv6 è attivo, NON ignorare il test.','err');
                    }
                    break;
                }
            }
            $previousDraft=get_draft();$previousV6=$ipv6Skipped ? null : v6_get();
            $fp=@fopen(DATA_DIR.'/zone-stage.lock','c');
            if (!$fp || !flock($fp,LOCK_EX|LOCK_NB)) {
                if (is_resource($fp)) fclose($fp);flash('Un’altra modifica delle zone è in corso.','err');break;
            }
            $S=$before;
            $S['custom_opts']=array_values(array_filter($S['custom_opts']??[],fn($co)=>empty($co['iptm_mac_v1'])));
            $S=copt_add($S,'Protezione IoT MAC senza VLAN','top',$rules,'Solo traffico instradato attraverso DietPi');
            $idx=array_key_last($S['custom_opts']);$S['custom_opts'][$idx]['iptm_mac_v1']=true;
            $S['custom_opts'][$idx]['pr']=-1000;$S['iot_strategy']='iptm_mac';
            $S['iot_ipv6_status']=$ipv6Skipped ? 'gateway-disabled' : 'draft-staged';
            try {
                $M2=parse_rules($previousDraft);$warnings=regen($M2,$S);$proposed=ser($M2);
                $iotSyntax=iptm_iot_rules_diagnose($proposed);
                if($iotSyntax)throw new RuntimeException('Bozza IoT non valida: '.implode('; ',$iotSyntax));
                [$tc,$to,$te]=priv('test',$proposed);
                if ($tc!==0) throw new RuntimeException('IPv4 test: '.herr($to.$te));
                settings_snapshot('mac-stage');
                S_put($S);
                if (!put_draft($proposed)) throw new RuntimeException('Salvataggio bozza IPv4 non riuscito');
                if (!$ipv6Skipped && !v6_put($newV6)) throw new RuntimeException('Salvataggio bozza IPv6 non riuscito');
                unset($_SESSION['mac_plan']);
                @unlink(iptm_mac_pending_file());
                if ($ipv6Skipped)
                    flash('Policy MAC salvata SOLO nella bozza IPv4: IPv6 interamente disabilitato sul gateway, nessuna bozza IPv6 modificata. LIVE INVARIATO. Se IPv6 torna attivo, IPTM blocca l’applicazione IPv4 finché non rigeneri la policy. Il traffico locale L2 resta fuori dal controllo di DietPi.','ok');
                else
                    flash('Policy MAC salvata nelle bozze IPv4/IPv6. LIVE INVARIATO: verifica e applica con rollback separato per famiglia.');
                $back='p=apply';
            } catch(Throwable $ex) {
                $r4=false;$r6=$ipv6Skipped;
                try {$r4=put_draft($previousDraft);}catch(Throwable $rollbackEx){audit('MAC rollback IPv4 failed '.$rollbackEx->getMessage());}
                if (!$ipv6Skipped) {
                    try {$r6=v6_put($previousV6);}catch(Throwable $rollbackEx){audit('MAC rollback IPv6 failed '.$rollbackEx->getMessage());}
                }
                $GLOBALS['_Sc']=null;
                try {S_put($before);$rs=true;}catch(Throwable $inner){$rs=false;audit('MAC stage restore failed '.$inner->getMessage());}
                flash('Policy MAC non salvata: '.$ex->getMessage().' (ripristino bozze IPv4='.(int)$r4.', IPv6='.(int)$r6.', settings='.(int)$rs.').','err');
            } finally {flock($fp,LOCK_UN);fclose($fp);}
            break;
        }
        case 'iot_bulk_save': {
            $back=(($_POST['return_to_topology']??'')==='1')?'p=topology':'p=zones';
            $included=$_POST['included']??[];
            $kindInput=$_POST['kinds']??[];
            $policyInput=$_POST['policies']??[];
            $selectedInput=$_POST['selected_macs']??[];
            if (!is_array($included) || count($included)>200 || !$included ||
                !is_array($kindInput) || !is_array($policyInput) || !is_array($selectedInput) ||
                count($selectedInput)>200 || count($policyInput)>200) {
                flash('Formato delle selezioni IoT non valido.','err'); break;
            }
            $validMac=static fn($mac)=>is_string($mac) && (bool)preg_match('/^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/D',$mac);
            $rows=[];
            foreach ($included as $mac) {
                if (!$validMac($mac) || isset($rows[$mac])) {flash('MAC duplicato o malformato: nessun salvataggio.','err');break 2;}
                $rows[$mac]=true;
            }
            $allowed=iptm_iot_policy_options();$newKinds=[];$newPolicies=[];
            foreach ($rows as $mac=>$_) {
                $kind=$kindInput[$mac]??'unknown';
                if (!is_string($kind) || !in_array($kind,['iot','trusted','guest','unknown'],true)) {
                    flash('Classe IoT non valida.','err');break 2;
                }
                $newKinds[$mac]=$kind;
                $flags=$policyInput[$mac]??[];
                if (!is_array($flags) || count($flags)>count($allowed)) {flash('Flag IoT non validi.','err');break 2;}
                $unique=[];
                foreach($flags as $flag) {
                    if(!is_string($flag) || !isset($allowed[$flag])) {flash('Flag IoT sconosciuto.','err');break 3;}
                    $unique[$flag]=$flag;
                }
                if (isset($unique['forward']) && count($unique)>1) {flash('Blocco totale non combinabile con altri filtri.','err');break 2;}
                if ($unique)$newPolicies[$mac]=array_values($unique);
            }
            foreach(array_keys($kindInput) as $mac) if(!isset($rows[$mac])) {flash('Classe fuori inventario.','err');break 2;}
            foreach(array_keys($policyInput) as $mac) if(!isset($rows[$mac])) {flash('Policy fuori inventario.','err');break 2;}
            $selected=[];
            foreach($selectedInput as $mac) {
                if (!$validMac($mac) || !isset($rows[$mac])) {flash('Selezione MAC fuori inventario.','err');break 2;}
                $selected[$mac]=true;
            }
            if(count($selected)>32) {flash('Massimo 32 MAC per anteprima.','err');break;}
            $lock=@fopen(DATA_DIR.'/apply.lock','c');
            if (!$lock || !@flock($lock,LOCK_EX|LOCK_NB)) {
                if(is_resource($lock))@fclose($lock);
                flash('Firewall occupato: riprovare senza applicare regole.','err');break;
            }
            try {
                $beforeS=S_get();$beforeDraft=get_draft();$S=$beforeS;
                $S['iot_devices']=array_replace((array)($S['iot_devices']??[]),$newKinds);
                $S['iot_policies']=(array)($S['iot_policies']??[]);
                foreach($rows as $mac=>$_) {
                    if(isset($newPolicies[$mac]))$S['iot_policies'][$mac]=$newPolicies[$mac];
                    else unset($S['iot_policies'][$mac]);
                }
                if(count($S['iot_policies'])>128)throw new RuntimeException('Massimo 128 policy IoT');
                $S['iot_selected_macs']=array_keys($selected);
                $model=parse_rules($beforeDraft);$warnings=regen($model,$S);$proposal=ser($model);
                $iotSyntax=iptm_iot_rules_diagnose($proposal);
                if($iotSyntax)throw new RuntimeException('Bozza IoT non valida: '.implode('; ',$iotSyntax));
                [$rc,$out,$err]=priv('test',$proposal);
                if($rc!==0)throw new RuntimeException('Bozza non valida: '.herr($out.$err));
                settings_snapshot('iot-bulk');
                S_put($S);
                if(!put_draft($proposal))throw new RuntimeException('Scrittura della bozza fallita');
                $M=$model;$rev=hash('sha256',$proposal);
                flash('Salvate in un unico passaggio '.count($rows).' righe IoT, '.count($newPolicies).' filtri e '.count($selected).' MAC selezionati. LIVE INVARIATO.');
                foreach($warnings as $warning)flash($warning,'err');
            } catch(Throwable $ex) {
                try {
                    // Restoration is deliberately best-effort: concurrent writes must not be overwritten silently.
                    if(isset($beforeS)) S_put($beforeS);
                    if(isset($beforeDraft))put_draft($beforeDraft);
                } catch(Throwable $restore) {audit('iot_bulk_restore_failed '.get_class($restore));}
                flash('Salvataggio IoT annullato: '.$ex->getMessage(),'err');
            } finally {@flock($lock,LOCK_UN);@fclose($lock);}
            break;
        }
        case 'iot_policy_save': {
            $back='p=zones';
            if (($_SESSION['role']??'')!=='admin') {flash('Solo amministratore.','err');break;}
            $mac=strtolower(trim((string)($_POST['mac']??'')));
            $raw=$_POST['flags']??[];
            if(!preg_match('/^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/D',$mac) || !is_array($raw) || count($raw)>7) {
                flash('MAC o selezione non valida.','err');break;
            }
            $allowed=iptm_iot_policy_options();$flags=[];
            foreach($raw as $flag) {
                if (!is_string($flag) || !isset($allowed[$flag])) {flash('Flag IoT non previsto.','err');break 2;}
                $flags[$flag]=$flag;
            }
            if(isset($flags['forward']) && count($flags)>1) {flash('Blocco completo non combinabile con filtri selettivi.','err');break;}
            $beforeS=S_get();$beforeDraft=ser($M);$S=$beforeS;
            if(!isset($S['iot_policies']) || !is_array($S['iot_policies'])) $S['iot_policies']=[];
            if(!$flags)unset($S['iot_policies'][$mac]);else $S['iot_policies'][$mac]=array_values($flags);
            if(count($S['iot_policies'])>128) {flash('Massimo 128 policy IoT.','err');break;}
            try {
                $model=parse_rules($beforeDraft);$warnings=regen($model,$S);$proposal=ser($model);
                $iotSyntax=iptm_iot_rules_diagnose($proposal);
                if($iotSyntax)throw new RuntimeException('Bozza IoT non valida: '.implode('; ',$iotSyntax));
                [$rc,$o,$e]=priv('test',$proposal);
                if($rc!==0)throw new RuntimeException('Verifica rules.v4 non superata: '.herr($o.$e));
                settings_snapshot('iot-policy');
                S_put($S);
                if(!put_draft($proposal))throw new RuntimeException('Salvataggio bozza fallito');
                $M=$model;
                flash('Filtri IoT salvati in bozza; il kernel non è stato modificato. Apri Applica e usa il rollback.');
                foreach($warnings as $w)flash($w,'err');
            }catch(Throwable $ex){
                try{S_put($beforeS);put_draft($beforeDraft);}catch(Throwable $restore){audit('iot policy restore failed '.$restore->getMessage());}
                flash('Policy IoT non applicata: '.$ex->getMessage(),'err');
            }
            break;
        }
        case 'ipv4_convert_preview': {
            $back='p=v6convert';
            try {$_SESSION['v6_convert']=iptm_v4_to_v6_preview((string)($_POST['source_v4']??''),(string)($_POST['address_map']??''));
                flash('Anteprima generata: nessuna regola IPv6 applicata.');}
            catch(Throwable $ex) {flash('Conversione rifiutata: '.$ex->getMessage(),'err');}
            break;
        }
        case 'iot_classify_many': {
            $back='p=devices';
            $kind=(string)($_POST['kind']??'unknown'); $input=$_POST['macs']??[];
            if (!is_array($input) || count($input)>120 || !in_array($kind,['iot','trusted','guest','unknown'],true)) {
                flash('Selezione multipla non valida.','err'); break;
            }
            $macs=[];
            foreach ($input as $raw) {
                if (!is_string($raw) || !preg_match('/^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/D',$raw)) {
                    flash('MAC non valido nella selezione: nessuna modifica.','err'); break 2;
                }
                $macs[$raw]=true;
            }
            if (!$macs) { flash('Seleziona almeno un dispositivo.','err'); break; }
            $S=S_get();$S['iot_devices']=(array)($S['iot_devices']??[]);
            foreach ($macs as $mac=>$_) $S['iot_devices'][$mac]=$kind;
            S_put($S);
            flash(count($macs).' dispositivi classificati. La modalità MAC senza VLAN è disponibile in Zone di rete; i filtri operano soltanto sul traffico che attraversa DietPi.'); break;
        }
        case 'iot_classify': {
            $back='p=devices';$mac=strtolower(trim((string)($_POST['mac']??'')));
            $kind=(string)($_POST['kind']??'unknown');
            if (!preg_match('/^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/D',$mac) || !in_array($kind,['iot','trusted','guest','unknown'],true)) { flash('MAC o classe non valida.','err'); break; }
            $S=S_get();$S['iot_devices']=(array)($S['iot_devices']??[]);$S['iot_devices'][$mac]=$kind;
            S_put($S);
            flash('Dispositivo classificato. La classificazione NON sposta un client di VLAN: configura la VLAN sullo switch/AP.'); break;
        }
        case 'oui_update': {
            $back='p=devices';
            [$rc,$o,$e]=priv('security',null,['oui-update']);$j=json_decode($o,true);
            flash($rc===0?'Database MAC aggiornato ('.(int)($j['updated']??0).' vendor).':'Aggiornamento OUI non riuscito: '.($j['error']??trim($o.$e)),$rc===0?'ok':'err');break;
        }
        
}
