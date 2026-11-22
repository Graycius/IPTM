<?php
/* IPTM action domain: network. Inherits the authenticated controller scope. */
switch ($a) {
        case 'nm_editor_stage': {
            $back='p=multinic';
            if(($_SESSION['role']??'viewer')!=='admin'){flash('Solo amministratore.','err');break;}
            $uuid=(string)($_POST['nm_uuid']??'');$props=(string)($_POST['nm_properties']??'');
            if(!preg_match('/^[a-fA-F0-9-]{36}$/D',$uuid)||strlen($props)>8192){flash('UUID o JSON troppo grande.','err');break;}
            try{$values=json_decode($props,true,32,JSON_THROW_ON_ERROR);}
            catch(Throwable $e){flash('Proprietà JSON non valide.','err');break;}
            if(!is_array($values)||array_is_list($values)||count($values)>48){flash('Atteso oggetto JSON di proprietà nmcli.','err');break;}
            [$c,$o,$e]=priv('nm-editor',json_encode(['uuid'=>$uuid,'properties'=>$values],JSON_THROW_ON_ERROR),['stage']);
            $j=json_decode($o,true);
            if($c!==0||empty($j['ok'])||!preg_match('/^[a-f0-9]{64}$/D',(string)($j['sha256']??''))){
                unset($_SESSION['iptm_nm_editor']);flash('Anteprima NM rifiutata: '.herr((string)($j['error']??$e??$o)),'err');break;
            }
            $_SESSION['iptm_nm_editor']=['hash'=>$j['sha256'],'created'=>time()];
            flash('Profilo verificato. Il profilo originale resta invariato; verrà creato un clone inattivo.','ok');break;
        }
        case 'nm_editor_apply': {
            $back='p=multinic';$pending=$_SESSION['iptm_nm_editor']??null;$hash=(string)($_POST['nm_sha256']??'');
            if(($_SESSION['role']??'viewer')!=='admin'||!is_array($pending)||time()-(int)($pending['created']??0)>900||
               !preg_match('/^[a-f0-9]{64}$/D',$hash)||!hash_equals((string)($pending['hash']??''),$hash)){
                flash('Conferma NetworkManager non valida.','err');break;
            }
            [$c,$o,$e]=priv('nm-editor',null,['apply',$hash]);$j=json_decode($o,true);
            if($c===0&&!empty($j['ok'])){unset($_SESSION['iptm_nm_editor']);$_SESSION['iptm_nm_clone']=(string)($j['clone_uuid']??'');}
            flash($c===0&&!empty($j['ok'])?'Clone NM creato inattivo: '.herr((string)($j['clone_uuid']??'')):
                'Operazione NM respinta: '.herr((string)($j['error']??$e??$o)),$c===0?'ok':'err');break;
        }
        case 'nm_activate_trial': {
            $back='p=multinic';$clone=(string)($_SESSION['iptm_nm_clone']??'');$uuid=(string)($_POST['clone_uuid']??'');$iface=(string)($_POST['trial_iface']??'');
            if(($_SESSION['role']??'viewer')!=='admin'||!preg_match('/^[a-fA-F0-9-]{36}$/D',$uuid)||
                !hash_equals($clone,$uuid)||!preg_match('/^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$/D',$iface)){
                flash('Clone o interfaccia non verificabili.','err');break;
            }
            [$c,$o,$e]=priv('nm-editor',null,['activate-trial',$uuid,$iface]);$j=json_decode($o,true);
            if($c!==0||empty($j['ok'])||!preg_match('/^[a-f0-9]{24}$/D',(string)($j['token']??''))){
                flash('Checkpoint NetworkManager rifiutato: '.herr((string)($j['error']??$e??$o)),'err');break;
            }
            $_SESSION['iptm_nm_trial']=['token'=>$j['token'],'created'=>time()];
            flash('Connessione di prova attiva con checkpoint NetworkManager: conferma entro 180 secondi oppure rollback automatico.','ok');break;
        }
        case 'nm_trial_confirm':case 'nm_trial_revert': {
            $back='p=multinic';$pending=$_SESSION['iptm_nm_trial']??null;$token=(string)($_POST['trial_token']??'');
            if(($_SESSION['role']??'viewer')!=='admin'||!is_array($pending)||!preg_match('/^[a-f0-9]{24}$/D',$token)||
                !hash_equals((string)($pending['token']??''),$token)){
                flash('Token della prova NetworkManager non valido.','err');break;
            }
            $op=$a==='nm_trial_confirm'?'confirm-trial':'revert-trial';
            [$c,$o,$e]=priv('nm-editor',null,[$op,$token]);$j=json_decode($o,true);
            if($c===0&&!empty($j['ok']))unset($_SESSION['iptm_nm_trial']);
            flash($c===0&&!empty($j['ok'])?'Transazione NetworkManager '.($op==='confirm-trial'?'confermata':'ripristinata').'.':
                'Checkpoint non finalizzato: '.herr((string)($j['error']??$e??$o)),$c===0?'ok':'err');break;
        }
        case 'nm_profile_save': case 'nm_bond_port': {
            $back='p=multinic';
            $client=(string)($_SERVER['REMOTE_ADDR']??'');
            $iface=(string)($_POST['nm_device']??'');
            if(!preg_match('/^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$/D',$iface) ||
                !filter_var($client,FILTER_VALIDATE_IP,FILTER_FLAG_IPV4) ||
                in_array($client,['127.0.0.1','0.0.0.0'],true)){
                flash('Interfaccia o sessione non verificabile.','err');break;
            }
            if($a==='nm_profile_save'){
                $ipRaw=(string)($_POST['nm_ips']??'');
                $items=array_values(array_filter(array_map('trim',preg_split('/[\s,;]+/',$ipRaw)),'strlen'));
                if(strlen($ipRaw)>320 || count($items)<1 || count($items)>8 ||
                  !ctype_digit((string)($_POST['nm_mtu']??'')) ||
                  !ctype_digit((string)($_POST['nm_metric']??''))){
                    flash('Indirizzi IPv4 o opzioni NM non validi.','err');break;
                }
                $payload=['ipv4'=>$items,'mtu'=>(int)$_POST['nm_mtu'],'metric'=>(int)$_POST['nm_metric']];
                $operation='profile-save';
            } else {
                $bond=(string)($_POST['nm_bond']??'');
                $operation=(string)($_POST['nm_bond_action']??'');
                if(!in_array($operation,['bond-add','bond-remove'],true) ||
                   !preg_match('/^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$/D',$bond)){
                    flash('Bond o operazione non validi.','err');break;
                }
                $payload=['bond'=>$bond];
            }
            [$rc,$out,$err]=priv('nm-config',json_encode($payload,JSON_THROW_ON_ERROR),[$operation,$iface,$client]);
            $result=json_decode($out,true);
            $ok=$rc===0&&is_array($result)&&!empty($result['ok']);
            audit('NetworkManager '.$operation.' '.$iface.' result='.$rc);
            flash($ok?(string)($result['message']??'Profilo NM salvato. Nessuna attivazione automatica.'):
                 herr(substr((string)($result['error']??$err??$out),0,350)),$ok?'ok':'err');
            break;
        }
        case 'nm_profile_prepare': {
            $back='p=multinic';
            $iface=(string)($_POST['nm_device']??'');
            $ip=(string)($_POST['nm_profile_ip']??'');
            $client=(string)($_SERVER['REMOTE_ADDR']??'');
            if(!preg_match('/^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$/D',$iface) ||
               !preg_match('~^(?:[0-9]{1,3}\.){3}[0-9]{1,3}/(?:[89]|[12][0-9]|30)$~D',$ip) ||
               !filter_var($client,FILTER_VALIDATE_IP,FILTER_FLAG_IPV4) ||
               in_array($client,['127.0.0.1','0.0.0.0'],true)){
                flash('Profilo IP o client non validi.','err');break;
            }
            [$rc,$out,$err]=priv('nm-profile',null,[$iface,$client,$ip]);
            $res=json_decode($out,true);$ok=$rc===0&&is_array($res)&&!empty($res['ok']);
            audit('NetworkManager: profilo offline '.$iface.' status='.$rc);
            flash($ok?'Profilo statico creato per '.$iface.' senza attivazione; DHCP invariato.':
                herr(substr((string)($res['error']??$err??$out),0,340)),$ok?'ok':'err');
            break;
        }
        case 'nm_device_control': {
            $back='p=multinic';
            $iface=(string)($_POST['nm_device']??'');
            $verb=(string)($_POST['nm_verb']??'');
            $client=(string)($_SERVER['REMOTE_ADDR']??'');
            if(!preg_match('/^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$/D',$iface) ||
               !in_array($verb,['up','down'],true) ||
               !filter_var($client,FILTER_VALIDATE_IP,FILTER_FLAG_IPV4) ||
               in_array($client,['127.0.0.1','0.0.0.0'],true)){
                 flash('Azione NetworkManager non sicura o client non verificabile.','err');break;
            }
            [$rc,$out,$err]=priv('nm-safe',null,[$verb,$iface,$client]);
            $result=json_decode($out,true);
            $ok=$rc===0&&is_array($result)&&!empty($result['ok'])&&!empty($result['applied']);
            audit('NetworkManager: richiesta '.$verb.' '.$iface.' status='.$rc);
            flash($ok?'Interfaccia '.$iface.': '.($verb==='up'?'attivazione richiesta':'disattivazione del profilo IPTM richiesta').'. Verifica lo stato aggiornato.':
                herr(substr((string)($result['error']??$err??$out),0,340)),$ok?'ok':'err');
            break;
        }
        case 'network_guard_preflight': {
            $back='p=multinic';
            if(($_SESSION['role']??'viewer')!=='admin'){
                flash('Preflight di rete consentito solo all’amministratore.','err');break;
            }
            [$rc,$out,$err]=priv('network-guard',null,['preflight']);
            $result=json_decode($out,true);
            if($rc!==0||!is_array($result)||empty($result['ok'])){
                unset($_SESSION['iptm_network_guard_preflight']);
                flash('Preflight non riuscito: '.herr(substr((string)($result['error']??$err??$out),0,350)),'err');break;
            }
            $_SESSION['iptm_network_guard_preflight']=[
                'version'=>(string)($result['version']??''),
                'physical_nics'=>(int)($result['physical_nics']??0),
                'blockers'=>array_slice((array)($result['blockers']??[]),0,30),
                'warnings'=>array_slice((array)($result['warnings']??[]),0,30),
                'can_apply_live'=>false];
            audit('network-guard: preflight read-only');
            flash('Analisi di sicurezza rete completata: nessuna configurazione modificata.');
            break;
        }
        case 'dhcp_reservations_apply':
        case 'dhcp_reservations_check': {
            $back = 'p=multinic';
            $address = trim((string)($_POST['dhcp_res_address'] ?? ''));
            $start = trim((string)($_POST['dhcp_res_start'] ?? ''));
            $end = trim((string)($_POST['dhcp_res_end'] ?? ''));
            $gateway = trim((string)($_POST['dhcp_res_gateway'] ?? ''));
            $raw = (string)($_POST['dhcp_reservations'] ?? '');
            if (strlen($raw) > 60000) { flash('Lista reservation troppo grande.', 'err'); break; }
            $entries = [];
            // Accept JSON array or lines: mac,ip[,hostname]
            $trim = trim($raw);
            if ($trim !== '' && ($trim[0] === '[' || $trim[0] === '{')) {
                $decoded = json_decode($trim, true);
                if (!is_array($decoded)) { flash('JSON reservation non valido.', 'err'); break; }
                $entries = isset($decoded['reservations']) && is_array($decoded['reservations'])
                    ? $decoded['reservations']
                    : (array_is_list($decoded) ? $decoded : []);
            } else {
                foreach (preg_split('/\R/', $raw) ?: [] as $line) {
                    $line = trim($line);
                    if ($line === '' || str_starts_with($line, '#')) continue;
                    $parts = preg_split('/[\s,;]+/', $line);
                    if (!$parts || count($parts) < 2) {
                        flash('Riga reservation non valida: ' . $line, 'err');
                        break 2;
                    }
                    $row = ['mac' => $parts[0], 'ip' => $parts[1]];
                    if (!empty($parts[2])) $row['hostname'] = $parts[2];
                    $entries[] = $row;
                }
            }
            $mode = ($a === 'dhcp_reservations_apply') ? 'apply' : 'check';
            $payload = [
                'address' => $address,
                'start' => $start,
                'end' => $end,
                'gateway' => $gateway,
                'allow_in_pool' => !empty($_POST['allow_in_pool']),
                'reservations' => $entries,
                'mode' => $mode,
            ];
            $json = json_encode($payload, JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE);
            [$rc, $out, $err] = priv('net-audit', $json, ['dhcp-reservations']);
            $result = json_decode($out, true);
            if (!is_array($result)) {
                flash('Reservation DHCP: operazione non disponibile: ' . herr(substr($err ?: $out, 0, 300)), 'err');
                break;
            }
            $_SESSION['iptm_dhcp_reservations_check'] = $result;
            if (empty($result['ok'])) {
                $msgs = [];
                foreach ((array)($result['errors'] ?? []) as $e) {
                    if (is_array($e)) {
                        $msgs[] = (($e['code'] ?? '') !== '' ? '[' . $e['code'] . '] ' : '')
                            . (string)($e['message'] ?? 'errore')
                            . (isset($e['index']) ? ' (riga ' . ((int)$e['index'] + 1) . ')' : '');
                    }
                }
                if (!$msgs && !empty($result['error'])) $msgs[] = (string)$result['error'];
                flash('Reservation DHCP non valide: ' . implode(' · ', array_slice($msgs, 0, 12)), 'err');
            } elseif ($mode === 'apply') {
                if (empty($result['applied'])) {
                    flash('Validazione ok ma applicazione non confermata: ' . herr((string)($result['error'] ?? 'esito sconosciuto')), 'err');
                } else {
                    audit('dhcp-reservations applied n=' . (int)($result['hosts_written'] ?? $result['count'] ?? 0));
                    flash('Reservation applicate su Pi-hole: ' . (int)($result['hosts_written'] ?? $result['count'] ?? 0) . ' host (dhcp.hosts).');
                }
            } else {
                $warnN = count((array)($result['warnings'] ?? []));
                flash('Reservation DHCP valide: ' . (int)($result['count'] ?? 0) . ' host'
                    . ($warnN ? (' · avvisi: ' . $warnN) : '')
                    . '. Usa «Applica su Pi-hole» per scriverle.');
            }
            break;
        }
        case 'dhcp_dual_preview': {
            $back='p=multinic';
            $primary=[];$secondary=[];
            foreach(['interface','address','start','end','gateway'] as $field){
                $value=$_POST['dhcp_primary_'.$field]??'';
                if(!is_string($value)||strlen($value)>80){flash('DHCP primario: campo non valido.','err');break 2;}
                $primary[$field]=trim($value);
            }
            foreach(['interface','address','start','end','gateway','dns'] as $field){
                $value=$_POST['dhcp_secondary_'.$field]??'';
                if(!is_string($value)||strlen($value)>80){flash('DHCP secondario: campo non valido.','err');break 2;}
                $secondary[$field]=trim($value);
            }
            $json=json_encode(['primary'=>$primary,'secondary'=>$secondary],JSON_THROW_ON_ERROR);
            [$rc,$out,$err]=priv('net-audit',$json,['dhcp-preview']);
            $result=json_decode($out,true);
            if($rc!==0||!is_array($result)||empty($result['ok'])){
                unset($_SESSION['iptm_dual_dhcp_preview']);
                flash('Piano doppio DHCP non valido: '.herr(substr((string)($result['error']??$err??$out),0,350)),'err');
                break;
            }
            $_SESSION['iptm_dual_dhcp_preview']=$result['plan'];
            $_SESSION['iptm_dhcp_secondary_selected']=$secondary['interface'];
            audit('dual-dhcp: anteprima senza applicazione');
            flash('Piano doppio DHCP verificato; nessun server riconfigurato.');
            break;
        }
        case 'multinic_preview': {
            $back='p=multinic';
            $profile=iptm_multinic_input();
            $json=json_encode($profile,JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR);
            if(strlen($json)>65536){flash('Piano troppo grande.','err');break;}
            [$rc,$out,$err]=priv('multi-nic',$json,['preview']);
            $result=json_decode($out,true);
            if($rc!==0||!is_array($result)||empty($result['ok'])){
                unset($_SESSION['iptm_multinic_preview']);
                flash('Anteprima multi-NIC respinta: '.herr(substr((string)($result['error']??$err??$out),0,350)),'err');
                break;
            }
            $_SESSION['iptm_multinic_preview']=$result;
            flash('Profilo validato. Non è stata modificata alcuna connessione.');
            break;
        }
        case 'multinic_save': {
            $back='p=multinic';
            $plan=$_SESSION['iptm_multinic_preview']??null;
            $hash=is_array($plan)&&isset($plan['profile'])
                ? hash('sha256',json_encode($plan['profile'],JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE)) : '';
            if(!$plan||!hash_equals($hash,(string)($_POST['plan_hash']??''))){
                flash('Anteprima scaduta o consenso non valido: rigenera il piano.','err');break;
            }
            $json=json_encode($plan['profile'],JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR);
            [$rc,$out,$err]=priv('multi-nic',$json,['save']);
            $result=json_decode($out,true);
            if($rc!==0||!is_array($result)||empty($result['ok'])){
                flash('Salvataggio multi-NIC non riuscito: '.herr(substr((string)($result['error']??$err??$out),0,350)),'err');
            } else {
                unset($_SESSION['iptm_multinic_preview']);
                audit('multi-nic: salvata bozza senza modifica live');
                flash('Bozza multi-NIC salvata. Nessuna interfaccia, route o servizio modificato.');
            }
            break;
        }
        case 'multinic_clear': {
            $back='p=multinic';
            [$rc,$out,$err]=priv('multi-nic',null,['clear']);
            if($rc===0){unset($_SESSION['iptm_multinic_preview']);audit('multi-nic: bozza eliminata');}
            flash($rc===0?'Bozza multi-NIC eliminata; configurazione attiva invariata.':herr(substr($err?:$out,0,350)),$rc===0?'ok':'err');
            break;
        }

case 'wg_init': {
            $pt = trim((string)($_POST['port'] ?? '')); $net = trim((string)($_POST['net'] ?? '')); $ep = trim((string)($_POST['ep'] ?? '')); $dns = trim((string)($_POST['dns'] ?? ''));
            if (!v_ok('port', $pt) || $pt === '' || !preg_match('~^(\d{1,3}\.){3}0/24$~', $net) || !preg_match('/^[A-Za-z0-9][A-Za-z0-9.-]{0,98}$/', $ep) || ($dns !== '' && !v_ok('ip', $dns))) { flash('Parametri non validi (rete /24 del tipo 10.8.0.0/24).', 'err'); break; }
            [$c, $o, $e] = priv('wg-init', null, [$pt, $net, $ep, $dns]); audit('wireguard: creazione server');
            if ($c === 0) { $S = S_get(); $S['wg_port'] = (int)$pt; $S['wg_net'] = $net; S_put($S); }
            flash($c === 0 ? 'Server WireGuard creato. Attiva le regole firewall qui sotto e applica.' : herr($o . $e), $c === 0 ? 'ok' : 'err'); break;
        }
        case 'wg_add': {
            $n = trim((string)($_POST['name'] ?? '')); $mode = ($_POST['mode'] ?? '') === 'lan' ? 'lan' : 'full'; $lan = preg_replace('/\s+/', '', (string)($_POST['lan'] ?? ''));
            if (!preg_match('/^[a-z0-9_-]{1,20}$/', $n) || ($mode === 'lan' && !v_ok('nets', $lan))) { flash('Nome o reti non validi.', 'err'); break; }
            [$c, $o, $e] = priv('wg-peer-add', null, array_merge([$n, $mode], $mode === 'lan' ? [$lan] : [])); audit("wireguard: nuovo client $n");
            flash($c === 0 ? trim($o) . ' — apri «Configurazione / QR» per consegnarlo.' : herr($o . $e), $c === 0 ? 'ok' : 'err'); break;
        }
        case 'wg_del': { $n = trim((string)($_POST['name'] ?? '')); if (!preg_match('/^[a-z0-9_-]{1,20}$/', $n)) { flash('Nome non valido.', 'err'); break; } [$c, $o, $e] = priv('wg-peer-del', null, [$n]); audit("wireguard: client $n eliminato"); flash($c === 0 ? trim($o) : herr($o . $e), $c === 0 ? 'ok' : 'err'); break; }
        case 'wg_svc': { $act = (string)($_POST['act'] ?? ''); $iface = (string)($_POST['iface'] ?? 'wg0'); if (!in_array($act, ['start', 'stop', 'restart'], true) || !preg_match('/^[A-Za-z0-9_.-]{1,15}$/', $iface)) { flash('Richiesta non valida.', 'err'); break; } [$c, $o, $e] = priv('wg-svc', null, [$act, $iface]); audit("wireguard: $act $iface"); flash($c === 0 ? "WireGuard $iface: $act eseguito." : herr($o . $e), $c === 0 ? 'ok' : 'err'); break; }
        case 'wg_mgmt_nets': {
            $S = S_get();
            $S['ui_nets'] = wg_mgmt_nets_suggest($S);
            S_put($S);
            flash('Accesso gestione limitato a: ' . $S['ui_nets']);
            $back = 'p=security'; break;
        }
        case 'traffic_policy_save': {
            $back='p=traffic';
            if(($_SESSION['role']??'viewer')!=='admin'){flash('Solo amministratore.','err');break;}
            $ips=$_POST['mitm_clients']??[]; $ports=$_POST['mitm_ports']??[];
            if(!is_array($ips)||!is_array($ports)||count($ips)>32){flash('Client o porte non validi.','err');break;}
            $hosts=preg_split('/\R/',trim((string)($_POST['mitm_hosts']??'')));
            if(!is_array($hosts)||count($hosts)>32){flash('Domini eccessivi.','err');break;}
            $json=json_encode(['clients'=>array_values(array_unique($ips)),'ports'=>array_map('intval',$ports),
                'hosts'=>array_values(array_filter(array_map('trim',$hosts),'strlen'))]);
            if($json===false||strlen($json)>8192){flash('Dati non validi.','err');break;}
            [$rc,$o,$e]=priv('traffic-policy',$json,['apply']);$res=json_decode($o,true);
            $ok=$rc===0&&is_array($res)&&!empty($res['ok']);
            flash($ok?'Policy proxy salvata. I client devono configurare esplicitamente il proxy e autorizzare la CA.':herr((string)($res['error']??$e)), $ok?'ok':'err');
            break;
        }
        case 'traffic_start': case 'traffic_stop': {
            $back = 'p=traffic';
            [$c, $o, $e] = priv($a === 'traffic_start' ? 'traffic-start' : 'traffic-stop');
            audit('traffic ' . $a . ' status=' . $c);
            flash($c === 0 ? ($a === 'traffic_start' ? 'Proxy attivato.' : 'Proxy fermato.') : herr($o . $e), $c === 0 ? 'ok' : 'err');
            break;
        }
        
}
