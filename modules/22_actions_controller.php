<?php
// Registro unico delle azioni autenticate; gli handler conservano lo scope di richiesta.
function iptm_action_registry(): array {
    return array (
  'rule_op' => 'firewall',
  'rule_save' => 'firewall',
  'wizard_add' => 'firewall',
  'chain_op' => 'firewall',
  'sec_preset' => 'system',
  'settings_save' => 'system',
  'dns_guard_restore_disk' => 'system',
  'feature_migration_preview' => 'system',
  'feature_migration_save' => 'system',
  'import_apply' => 'firewall',
  'import_skip' => 'firewall',
  'settings_reset' => 'system',
  'backend_set' => 'system',
  'custom_rules_scan' => 'firewall',
  'custom_rules_integrate' => 'firewall',
  'custom_rules_delete' => 'firewall',
  'live_rules_scan' => 'firewall',
  'live_rules_apply' => 'firewall',
  'rules_cleanup_scan' => 'firewall',
  'rules_cleanup_apply' => 'firewall',
  'strip_managed' => 'system',
  'forward_sysctl' => 'system',
  'lists_apply' => 'system',
  'lists_refresh' => 'system',
  'block_ip' => 'system',
  'conn_kill' => 'system',
  'wol' => 'system',
  'ssh_continuity_recover' => 'security',
  'qos_guard_install' => 'qos',
  'qos_adaptive_enable' => 'qos',
  'qos_adaptive_disable' => 'qos',
  'qos_postinstall_ensure' => 'qos',
  'qos_policy_stage' => 'qos',
  'qos_policy_apply' => 'qos',
  'qos_policy_disable' => 'qos',
  'qos_calibrate_start' => 'qos',
  'qos_auto_enable' => 'qos',
  'qos_auto_disable' => 'qos',
  'upgrade_cleanup_scan' => 'qos',
  'upgrade_cleanup_retire' => 'qos',
  'upgrade_cleanup_run' => 'update_backup',
  'release_cleanup_run' => 'update_backup',
  'qos_stage' => 'qos',
  'qos_apply' => 'qos',
  'qos_commit' => 'qos',
  'qos_revert' => 'qos',
  'qos_disable' => 'qos',
  'cs_feed_stage' => 'security',
  'cs_feed_apply' => 'security',
  'su_source_stage' => 'security',
  'su_source_apply' => 'security',
  'nm_editor_stage' => 'network',
  'nm_editor_apply' => 'network',
  'nm_activate_trial' => 'network',
  'nm_trial_confirm' => 'network',
  'nm_trial_revert' => 'network',
  'ipv6_kernel_apply' => 'firewall',
  'ipv6_kernel_confirm' => 'firewall',
  'ipv6_kernel_rollback' => 'firewall',
  'v6_save' => 'firewall',
  'v6_raw' => 'firewall',
  'v6_test' => 'firewall',
  'v6_apply' => 'firewall',
  'v6_write' => 'firewall',
  'v6_reset' => 'firewall',
  'zero_apply' => 'system',
  'regen_now' => 'system',
  'post_scan' => 'system',
  'cs_autodetect' => 'security',
  'tool_install' => 'security',
  'tool_queue' => 'security',
  'tool_svc' => 'security',
  'f2b_unban' => 'security',
  'cs_ban' => 'security',
  'cs_unban' => 'security',
  'cs_allow_add' => 'security',
  'cs_allow_del' => 'security',
  'cs_collection_install' => 'security',
  'cs_collection_remove' => 'security',
  'cs_hub_update' => 'security',
  'cs_svc' => 'security',
  'su_svc' => 'security',
  'su_update' => 'security',
  'su_source_enable' => 'security',
  'su_source_disable' => 'security',
  'su_iface' => 'security',
  'su_test' => 'security',
  'su_homenet' => 'security',
  'su_local_save' => 'security',
  'su_disable_sid' => 'security',
  'cs_scenario_enable' => 'security',
  'cs_scenario_disable' => 'security',
  'cs_bouncer_set' => 'security',
  'cs_simulation' => 'security',
  'cs_hub_upgrade' => 'security',
  'cs_bouncer_setup' => 'security',
  'cs_bouncer_mode' => 'security',
  'wg_init' => 'network',
  'wg_add' => 'network',
  'wg_del' => 'network',
  'wg_svc' => 'network',
  'multinic_preview' => 'network',
  'multinic_save' => 'network',
  'multinic_clear' => 'network',
  'nm_device_control' => 'network',
  'nm_profile_prepare' => 'network',
  'nm_profile_save' => 'network',
  'nm_bond_port' => 'network',
  'network_guard_preflight' => 'network',
  'dhcp_dual_preview' => 'network',
  'dhcp_reservations_check' => 'network',
  'dhcp_reservations_apply' => 'network',
  'post_set' => 'system',
  'post_test' => 'system',
  'sysctl_dedupe' => 'system',
  'sysctl_consolidate' => 'system',
  'sysctl_consolidate_rollback' => 'system',
  'rules_compact_safe' => 'firewall',
  'rules_audit_import' => 'firewall',
  'dns_wizard_plan' => 'dns',
  'antidpi_live' => 'dns',
  'antidpi_sources' => 'dns',
  'dns_sni_activate' => 'dns',
  'dns_sni_disable' => 'dns',
  'dnscrypt_compat_repair' => 'dns',
  'dns_guard_preview' => 'dns',
  'dns_guard_apply' => 'dns',
  'dns_guard_confirm' => 'dns',
  'dns_guard_revert' => 'dns',
  'dns_unbound_harden' => 'dns',
  'dns_unbound_profile' => 'dns',
  'dns_service' => 'dns',
  'dnscrypt_config' => 'dns',
  'dns_stack' => 'dns',
  'dns_test' => 'dns',
  'sysctl_maintenance_apply' => 'dns',
  'dns_rethink_refresh' => 'dns',
  'pihole_credentials' => 'dns',
  'zapret_manage' => 'dns',
  'diag_manage' => 'diagnostics',
  'dns_pihole_export' => 'dns',
  'dns_pihole_import' => 'dns',
  'harden_apply' => 'system',
  'health_policy_preview' => 'security',
  'health_policy_trial' => 'security',
  'health_policy_confirm' => 'security',
  'health_policy_revert' => 'security',
  'health_recovery_retry' => 'security',
  'profile_home' => 'system',
  'profile_office' => 'system',
  'profile_hard' => 'system',
  'ti_vt_test' => 'security',
  'ti_save' => 'security',
  'av_save_key' => 'security',
  'av_hash' => 'security',
  'av_url' => 'security',
  'av_file' => 'security',
  'notify_save' => 'identity',
  'notify_test' => 'identity',
  'user_add' => 'identity',
  'user_del' => 'identity',
  'user_role' => 'identity',
  'user_reset2fa' => 'identity',
  'totp_start' => 'identity',
  'totp_on' => 'identity',
  'totp_off' => 'identity',
  'chpw' => 'identity',
  'confirm' => 'firewall',
  'revert' => 'firewall',
  'raw_save' => 'firewall',
  'apps_save' => 'system',
  'draft_reset' => 'firewall',
  'factory_reset' => 'system',
  'reset_minimal' => 'system',
  'fw_restore_saved' => 'firewall',
  'api_token_save' => 'identity',
  'api_token_gen' => 'identity',
  'policy_export' => 'update_backup',
  'cs_bouncer_set_only' => 'security',
  'cs_bouncer_setup_rec' => 'security',
  'wg_mgmt_nets' => 'network',
  'retention_save' => 'update_backup',
  'retention_run' => 'update_backup',
  'backup_named' => 'update_backup',
  'whatsnew_ack' => 'update_backup',
  'postcheck_restart' => 'update_backup',
  'postcheck_script' => 'update_backup',
  'postcheck_all' => 'update_backup',
  'manual_convert_exact_all' => 'firewall',
  'manual_convert' => 'firewall',
  'copt_toggle' => 'firewall',
  'copt_delete' => 'firewall',
  'copt_unmanage' => 'firewall',
  'copt_add' => 'firewall',
  'traffic_policy_save' => 'network',
  'traffic_start' => 'network',
  'traffic_stop' => 'network',
  'dns_bundle_export' => 'dns',
  'dns_bundle_import' => 'dns',
  'config_bundle_import' => 'update_backup',
  'warden_retire' => 'iot',
  'warden_script_switch' => 'iot',
  'warden_scrub_draft' => 'iot',
  'zone_vlan_remove' => 'iot',
  'zone_vlan_create' => 'iot',
  'zone_plan' => 'iot',
  'zone_stage' => 'iot',
  'mac_plan' => 'iot',
  'mac_pending_clear' => 'iot',
  'mac_pending_resume' => 'iot',
  'mac_stage' => 'iot',
  'iot_bulk_save' => 'iot',
  'iot_policy_save' => 'iot',
  'ipv4_convert_preview' => 'iot',
  'iot_classify_many' => 'iot',
  'iot_classify' => 'iot',
  'oui_update' => 'iot',
  'lynis_update' => 'security',
  'lynis_run' => 'security',
  'lynis_mark' => 'security',
  'lynis_safe_apply' => 'security',
  'ui_update_apply' => 'update_backup',
  'update_apply' => 'update_backup',
  'update_url_apply' => 'update_backup',
  'dismiss_reset_flag' => 'update_backup',
  'advise_apply' => 'system',
  'settings_rollback' => 'system',
  'backup_prune' => 'update_backup',
  'restore_backup' => 'update_backup',
  'release_rollback' => 'update_backup',
  'rules_verify' => 'firewall',
  'test' => 'system',
  'save_file' => 'firewall',
  'apply' => 'firewall',
);
}
/** Validate the complete security decision before invoking a privileged driver. */
function iptm_security_decision_request(string $action,array $post): array {
    $ip=$post['ip']??null;
    if(!is_string($ip)||strlen($ip)>80)throw new InvalidArgumentException('Indirizzo non valido.');
    $ip=trim($ip);$parts=explode('/',$ip);
    if(count($parts)>2||!filter_var($parts[0],FILTER_VALIDATE_IP))throw new InvalidArgumentException('Indirizzo IP non valido.');
    if(count($parts)===2) {
        $max=str_contains($parts[0],':')?128:32;
        if($action==='f2b_unban'||!preg_match('/^[0-9]{1,3}$/D',$parts[1])||(int)$parts[1]>$max)throw new InvalidArgumentException('Prefisso CIDR non valido.');
    }
    if($action==='f2b_unban') {
        $jail=$post['jail']??null;
        if(!is_string($jail)||!preg_match('/^[A-Za-z0-9_.-]{1,40}$/D',$jail))throw new InvalidArgumentException('Jail non valida.');
        return ['command'=>'f2b-unban','args'=>[$jail,$ip],'success'=>'Indirizzo sbannato.'];
    }
    if($action==='cs_ban') {
        $duration=$post['dur']??'4h';
        if(!is_string($duration)||!preg_match('/^[0-9]{1,5}[smhd]$/D',$duration)||(int)$duration===0)throw new InvalidArgumentException('Durata non valida.');
        return ['command'=>'cs-ban','args'=>[$ip,$duration],'success'=>'Decisione aggiunta; il bouncer la applica secondo la propria configurazione.'];
    }
    if($action==='cs_unban')return ['command'=>'cs-unban','args'=>[$ip],'success'=>'Decisione rimossa.'];
    throw new InvalidArgumentException('Azione non valida.');
}
/** Require a complete IPv4 connection tuple before deletion. */
function iptm_connection_request(array $post): array {
    $fields=[];foreach(['proto','src','dst','sport','dport'] as $key){$v=$post[$key]??null;if(!is_string($v)||$v==='')throw new InvalidArgumentException('Connessione incompleta.');$fields[]=$v;}
    [$proto,$src,$dst,$sport,$dport]=$fields;
    if(!in_array($proto,['tcp','udp'],true))throw new InvalidArgumentException('Protocollo non valido.');
    foreach([$src,$dst] as $ip)if(!filter_var($ip,FILTER_VALIDATE_IP,FILTER_FLAG_IPV4))throw new InvalidArgumentException('Indirizzo IPv4 non valido.');
    foreach([$sport,$dport] as $port)if(!preg_match('/^[1-9][0-9]{0,4}$/D',$port)||(int)$port>65535)throw new InvalidArgumentException('Porta non valida.');
    return $fields;
}
/** Typed diagnostic request; an unexpected checkbox value cannot enable network probes. */
function iptm_diagnostic_request(array $post): array {
    $op=$post['diag_op']??null;
    if(!is_string($op)||!in_array($op,['start','clear'],true))throw new InvalidArgumentException('Operazione diagnostica non valida.');
    if($op==='clear')return ['op'=>$op,'payload'=>null];
    $level=$post['diag_level']??'preflight';$network=$post['diag_network']??'0';
    if(!is_string($level)||!in_array($level,['schema','preflight','isolated'],true)||!is_string($network)||!in_array($network,['0','1'],true))throw new InvalidArgumentException('Parametri diagnostici non validi.');
    return ['op'=>$op,'payload'=>json_encode(['include_network'=>$network==='1','level'=>$level],JSON_THROW_ON_ERROR)];
}
function iptm_action_authorized(string $action, string $role): bool {
    return $role==='admin' || ($role==='viewer' && in_array($action,['chpw','totp_start','totp_on','totp_off'],true));
}
/** Nonblocking request coordinator. The lock belongs to the web data owner, not root.
 * Never hold it across requests or take it from recovery watchdogs.
 */
function iptm_request_gate_required(string $action): bool {
    return !in_array($action,['confirm','revert','qos_commit','qos_revert','nm_trial_confirm','nm_trial_revert','ipv6_kernel_confirm','ipv6_kernel_rollback','dns_guard_confirm','dns_guard_revert','health_policy_confirm','health_policy_revert','health_recovery_retry','ssh_continuity_recover','fw_restore_saved','sysctl_consolidate_rollback','release_rollback','dns_guard_restore_disk'],true);
}
function iptm_request_gate(string $directory) {
    clearstatcache(true,$directory);
    $dir=@lstat($directory);
    if (!is_array($dir) || ($dir['mode'] & 0170000)!==0040000 || ($dir['mode'] & 0022)!==0) return false;
    $path=$directory.'/request-transaction.lock';
    clearstatcache(true,$path);
    $st=@lstat($path);
    if ($st===false) {
        $fp=@fopen($path,'x+b');
        if ($fp!==false) { if (!@chmod($path,0600)) {fclose($fp);return false;} }
        else {clearstatcache(true,$path);$st=@lstat($path);}
    }
    if (!isset($fp) || $fp===false) {
        if (!is_array($st) || ($st['mode'] & 0170000)!==0100000 || $st['uid']!==$dir['uid'] || $st['nlink']!==1 || ($st['mode'] & 0077)!==0) return false;
        $fp=@fopen($path,'r+b');
    }
    if (!is_resource($fp)) return false;
    if (!@flock($fp,LOCK_EX|LOCK_NB)) {fclose($fp);return false;}
    clearstatcache(true,$path);$st=@lstat($path);$opened=@fstat($fp);
    if (!is_array($st)||!is_array($opened)||($opened['mode'] & 0170000)!==0100000||$opened['uid']!==$dir['uid']||$opened['nlink']!==1||($opened['mode'] & 0077)!==0||$st['dev']!==$opened['dev']||$st['ino']!==$opened['ino']) {fclose($fp);return false;}
    return $fp;
}
// ===================== AZIONI POST =====================
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!iptm_action_authorized($a, $_SESSION['role'] ?? 'viewer')) {
        if ($a==='antidpi_sources' && ($_POST['source_async']??'')==='1') {
            header('Content-Type: application/json; charset=utf-8');
            http_response_code(403);
            echo json_encode(['ok'=>false,'error'=>'Account IPTM in sola lettura.']);
            exit;
        }
        flash('Account in sola lettura.', 'err'); go($back);
    }
    $MUT = ['rule_save', 'rule_op', 'wizard_add', 'chain_op', 'raw_save', 'settings_save', 'strip_managed', 'import_apply', 'rules_cleanup_apply', 'custom_rules_integrate', 'custom_rules_delete', 'apply', 'save_file', 'iot_bulk_save', 'sec_preset', 'regen_now', 'rules_compact_safe', 'rules_audit_import', 'dns_guard_restore_disk', 'restore_backup', 'settings_rollback', 'config_bundle_import', 'advise_apply'];
    if (in_array($a, $MUT, true) && ($_POST['rev'] ?? '') !== $rev) { flash('La bozza è cambiata in un\'altra scheda: operazione annullata, ricarica e riprova.', 'err'); go($back); }
    try {
    $iptm_handlers=iptm_action_registry();
    if ($a!=='modules_repair' && !isset($iptm_handlers[$a])) {
        flash('Azione non riconosciuta: nessuna modifica applicata.', 'err'); go($back);
    }
    if (iptm_request_gate_required($a)) {
        $iptmRequestLock=iptm_request_gate(DATA_DIR);
        if ($iptmRequestLock===false) {
            if ($a==='antidpi_sources' && ($_POST['source_async']??'')==='1') {
                http_response_code(409);header('Content-Type: application/json; charset=utf-8');
                echo json_encode(['ok'=>false,'error'=>'Transazione IPTM occupata o lock non verificabile.']);exit;
            }
            flash('Altra operazione IPTM in corso o lock non verificabile. Riprova dopo il completamento.', 'err');go($back);
        }
        // The first revision check ran before admission; repeat with the
        // current snapshot while serialized, before any handler mutates state.
        if (in_array($a, $MUT, true) && !hash_equals($rev, hash('sha256',get_draft()))) {
            fclose($iptmRequestLock);
            flash('La bozza è cambiata durante l’accesso: ricarica e riprova.', 'err'); go($back);
        }
        // Keep the descriptor alive through handler exits and post_hooks.
        register_shutdown_function(static function() use ($iptmRequestLock) {if (is_resource($iptmRequestLock)) fclose($iptmRequestLock);});
    }
    if ($a==='modules_repair') {
        // Safe remediation of a partially-installed bridge. Does not mutate
        // firewall, DNS settings, or the current firewall draft.
        $GLOBALS['_iptm_post_stage']='modules:deploy';
        [$rc,$o,$e]=priv('modules-deploy');
        if($rc===0) {
            $missing=[];
            foreach(array_unique(array_values($iptm_handlers)) as $domain) {
                if(!is_file(IPTM_RELEASE_DIR.'/actions/'.$domain.'.php') ||
                   !is_readable(IPTM_RELEASE_DIR.'/actions/'.$domain.'.php')) $missing[]=$domain;
            }
            if($missing)flash('Release incompleta: mancano handler '.implode(', ',$missing).'. Reinstalla il pacchetto aggiornamento in sicurezza.','err');
            else flash('Verifica moduli riuscita. Ora riprova l’operazione. Nessuna regola firewall applicata.');
        } else flash('Verifica/riparazione moduli non riuscita (exit '.$rc.'): controlla sudoers, helper e log PHP/IPTM. Nessuna regola applicata.','err');
        unset($GLOBALS['_iptm_post_stage']);
        go($back);
    }
    $iptmSourceAjax=($a==='antidpi_sources' && ($_POST['source_async']??'')==='1');
    if (isset($iptm_handlers[$a])) {
        $iptm_handler=IPTM_RELEASE_DIR.'/actions/'.$iptm_handlers[$a].'.php';
        // Runtime components may be only partially deployed after a legacy
        // upgrade. Return an actionable, phase-specific message rather than a
        // generic caught "Operazione non riuscita" exception for every POST.
        if (!is_file($iptm_handler) || !is_readable($iptm_handler)) {
            error_log('IPTM handler_missing action='.preg_replace('/[^a-z0-9_]/','',$a)
                .' handler='.basename($iptm_handler));
            if ($iptmSourceAjax) {
                http_response_code(503);
                header('Content-Type: application/json; charset=utf-8');
                header('Cache-Control: no-store, private');
                echo json_encode(['ok'=>false,'error'=>'Modulo Anti-DPI non installato. Verifica il deploy della release.'],JSON_UNESCAPED_UNICODE);
                exit;
            }
            flash('Modulo azione non installato: '.basename($iptm_handler).
                '. Verifica il deploy della release e usa sudo iptm-helper modules-deploy. Nessuna modifica applicata.', 'err');
            go($back);
        }
        $GLOBALS['_iptm_post_stage']='handler:'.$iptm_handlers[$a];
        require $iptm_handler;
        unset($GLOBALS['_iptm_post_stage']);
    }

    } catch (\Throwable $exc) {
        // Exception boundaries must include TypeError and JSON exceptions. In
        // particular, a failed MAC preview must never become HTTP 500 without
        // usable diagnostics or retry instructions; do not log POST secrets.
        $incident=iptm_request_id();
        $macStage=($a==='mac_plan') ? preg_replace('/[^a-z_]/','',(string)($GLOBALS['_iptm_mac_stage']??'unknown')) : '';
        $postStage=preg_replace('/[^a-z0-9_:]/','',(string)($GLOBALS['_iptm_post_stage']??'controller'));
        $exceptionKind=get_class($exc); // diagnostica tipizzata, senza valore dei parametri POST
        $incidentHelp=($exc instanceof \Error && str_contains($exc->getMessage(),'undefined function'))
            ? 'Dipendenza PHP mancante: verifica deploy e ordine dei moduli.'
            : 'Consulta il log PHP con il riferimento.';
        // Never write exception messages from POST actions: they may contain
        // network identifiers, paths, credentials or unexpected helper data.
        error_log('IPTM POST '.$incident.' action='.preg_replace('/[^a-z0-9_]/','',(string)$a).
            ($macStage!=='' ? ' stage='.$macStage : '').
            ' stage='.$postStage.' exception='.get_class($exc).' at='.basename($exc->getFile()).':'.$exc->getLine());
        unset($GLOBALS['_iptm_mac_stage']);
        if ($a==='antidpi_sources' && ($_POST['source_async']??'')==='1') {
            http_response_code(500);
            header('Content-Type: application/json; charset=utf-8');
            header('Cache-Control: no-store, private');
            echo json_encode(['ok'=>false,'error'=>'Errore interno importazione Anti-DPI (rif. '.$incident.'). Controlla i log PHP/IPTM.'],JSON_UNESCAPED_UNICODE);
            exit;
        }
        if ($a==='mac_plan') {
            unset($_SESSION['mac_plan']);
            flash('Anteprima MAC annullata per errore interno (rif. '.$incident.'). ' .
                'Nessuna regola applicata. Fase: '.$macStage.'. Cerca il riferimento nel log PHP/IPTM.', 'err');
        } else {
            flash('Operazione annullata (rif. '.$incident.'; azione '.$a.'; fase '.$postStage.'). Nessuna conferma automatica. Controlla il log PHP; verifica lo stato prima di riprovare.', 'err');
        }
        go($back);
    }
    post_hooks($a);
    go($back);
}

