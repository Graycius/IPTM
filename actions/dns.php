<?php
/* IPTM action domain: dns. Inherits the authenticated controller scope. */
switch ($a) {
        case 'dns_wizard_plan': {
            $back='p=dnsguard#dns-tls-wizard';
            try {
                $plan=iptm_dns_wizard_normalize($_POST);
                unset($_SESSION['iptm_dns_wizard_retry']);
                $cap=iptm_dns_wizard_capabilities();
                $warnings=iptm_dns_wizard_summary($plan,$cap);
                $hash=hash('sha256',json_encode($plan,JSON_THROW_ON_ERROR));
                $_SESSION['iptm_dns_wizard_plan']=['plan'=>$plan,'warnings'=>$warnings,
                    'hash'=>$hash,'until'=>time()+600,'draft_rev'=>$rev];
                flash('Anteprima DNS/TLS validata, senza modifiche live. Controlla le avvertenze; l’Anti-DPI si configura nel pannello dedicato.');
            } catch (InvalidArgumentException $ex) {
                unset($_SESSION['iptm_dns_wizard_plan']);
                $_SESSION['iptm_dns_wizard_retry']=iptm_dns_wizard_retry_capture($_POST,$ex->getMessage());
                flash($ex->getMessage(),'err');
            }
            break;
        }
        case 'zapret_manage': {
            $back='p=dnsguard';
            $engine=(string)($_POST['zapret_engine']??'zapret2');
            if(in_array($engine,['zapret2','classic'],true))$back='p=dnsguard&zapret_engine='.$engine.'#dns-zapret-manager';
            if (!in_array($engine,['zapret2','classic'],true)) {flash('Motore Zapret non valido.','err');break;}
            $cmd=$engine==='zapret2'?'zapret2':'zapret';
            $op=(string)($_POST['zapret_op']??'');
            $allowed=$engine==='zapret2'?['status','latest','preview','install-latest','configure']:
                ['status','latest','preview','install','install-latest','configure'];
            if(!in_array($op,$allowed,true)) {flash('Operazione non autorizzata per '.$engine,'err');break;}
            $body=null;
            $sessionKey='iptm_zapret_latest_'.$engine;
            if($op==='install-latest') {
                $candidate=$_SESSION[$sessionKey]??null;
                if(!is_array($candidate) || (int)($candidate['at']??0)<time()-600 ||
                    !hash_equals((string)($candidate['tag']??''),(string)($_POST['zapret_tag']??''))) {
                    flash('Versione Zapret non confermata o scaduta: ripeti la ricerca.','err');break;
                }
                unset($_SESSION[$sessionKey]);$body=['tag'=>$candidate['tag']];
            } elseif($op==='install' && $engine==='classic') {
                $body=['url'=>(string)($_POST['zapret_url']??''),'sha256'=>(string)($_POST['zapret_sha256']??'')];
            } elseif($op==='configure') {
                $clients=preg_split('/\R+/',trim((string)($_POST['zapret_clients']??'')));
                $domainText=(string)($_POST['zapret_domains']??'');
                if(strlen($domainText)>16*1024*1024){flash('Elenco domini oltre 16 MiB: riduci la dimensione del testo, non il numero di voci.','err');break;}
                $domains=preg_split('/\R+/',trim($domainText));
                $body=['wan_if'=>(string)($_POST['zapret_wan']??''),'clients'=>$clients,'domains'=>$domains,
                       'queue'=>(int)($_POST['zapret_queue']??200),'strategy'=>(string)($_POST['zapret_strategy']??'multisplit')];
            }
            $json=$body===null?null:json_encode($body,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);
            if($body!==null&&!is_string($json)) {flash('Dati Zapret non validi.','err');break;}
            [$rc,$out,$err]=run([BIN_SUDO,'-n',HELPER,$cmd,$op],$json,in_array($op,['install','install-latest'],true)?180.0:25.0,65536);
            $j=json_decode($out,true);
            if ($rc!==0 || !is_array($j) || empty($j['ok']))
                flash('Errore '.$engine.': '.h((string)($j['error']??herr($out.$err))),'err');
            elseif($op==='preview') {$_SESSION['zapret_preview_'.$engine]=$j;flash('Anteprima '.$engine.' generata; NFQUEUE non modificata.');}
            elseif($op==='latest') {
                $_SESSION[$sessionKey]=['tag'=>(string)$j['tag'],'url'=>(string)$j['url'],
                    'sha256'=>(string)($j['sha256']??''),'at'=>time()];
                flash('Versione ufficiale '.$engine.' individuata: '.$j['tag'].'.');
            } else flash($engine.': operazione '.$op.' completata; nessuna modifica live a servizi o NFQUEUE.');
            break;
        }
case 'antidpi_sources': {
    $engine=(string)($_POST['zapret_engine']??'zapret2');
    $op=(string)($_POST['source_op']??'');
    $back='p=dnsguard&zapret_engine='.$engine.'#dns-zapret-manager';
    $async=($op==='start' && (string)($_POST['source_async']??'')==='1');
    $respond=static function(bool $ok,string $message,array $result=[])use($async):void {
        if($async){
            header('Content-Type: application/json; charset=utf-8');
            header('Cache-Control: no-store, private');
            http_response_code($ok?200:422);
            echo json_encode((['ok'=>$ok,'error'=>$ok?'':$message,'message'=>$message]+$result),JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR);
            exit;
        }
        flash($message,$ok?'ok':'err');
    };
    if(!in_array($engine,['zapret2','classic'],true)||!in_array($op,['start','preview','apply'],true)){
        $respond(false,'Importazione Anti-DPI non valida');break;
    }
    if($op==='start'){
        $ids=$_POST['source_ids']??[];
        if(!is_array($ids)||count($ids)>9||array_filter($ids,static fn($x)=>!is_string($x)||!preg_match('/^(?:it|global|fr|de|es|gb|nl|be|agcom_archive)$/D',$x))){
            $respond(false,'Raccolte selezionate non valide');break;
        }
        $mode=(string)($_POST['source_mode']??'merge');
        if(!in_array($mode,['merge','replace'],true)){$respond(false,'Modalità non valida');break;}
        $local=(string)($_POST['source_local']??'');
        if(strlen($local)>16*1024*1024){$respond(false,'Testo importazione oltre 16 MiB');break;}
        if(!$ids && trim($local)===''){$respond(false,'Seleziona una raccolta, un servizio o un file TXT');break;}
        $draftRaw=(string)($_POST['source_draft']??'');
        if(strlen($draftRaw)>16*1024*1024+4096){$respond(false,'Profilo oltre il limite tecnico');break;}
        $draft=json_decode($draftRaw,true);
        if(!is_array($draft)||count($draft)!==5||array_diff(['wan_if','clients','domains','queue','strategy'],array_keys($draft))){
            $respond(false,'Completa interfaccia WAN, reti client e strategia nel profilo');break;
        }
        $payload=json_encode(['engine'=>$engine,'sources'=>array_values($ids),'mode'=>$mode,'local'=>$local,'draft'=>$draft],JSON_THROW_ON_ERROR);
        if($async && session_status()===PHP_SESSION_ACTIVE)session_write_close();
        [$rc,$out,$stderr]=run([BIN_SUDO,'-n',HELPER,'anti-dpi-sources','start'],$payload,25.0,4096);
        $j=json_decode($out,true);
        if($rc!==0||!is_array($j)||($j['ok']??false)!==true||!is_string($j['token']??null)||!preg_match('/^[a-f0-9]{24}$/D',$j['token']))$respond(false,'Download Anti-DPI: '.herr((string)($j['error']??$out.$stderr)));
        else $respond(true,'Job avviato; i domini saranno inseriti nella casella dopo la conclusione dei download.',
            ['token'=>(string)($j['token']??''),'state'=>(string)($j['state']??'queued')]);
    }else{
        $token=(string)($_POST['source_token']??'');
        if(!preg_match('/^[a-f0-9]{24}$/D',$token)){$respond(false,'Identificatore download non valido');break;}
        [$rc,$out,$stderr]=run([BIN_SUDO,'-n',HELPER,'anti-dpi-sources',$op,$token,$engine],null,35.0,4096);
        $j=json_decode($out,true);
        if($rc!==0||!is_array($j)||empty($j['ok']))$respond(false,'Liste Anti-DPI: '.herr((string)($j['error']??$out.$stderr)));
        else{
            if($op==='apply')audit('Anti-DPI multi-source import engine='.$engine.' count='.intval($j['total']??0));
            $respond(true,$op==='apply'?'Hostlist salvata; NFQUEUE resta inattivo.':'Anteprima pronta; nessuna regola applicata.');
        }
    }
    break;
}
case 'antidpi_live': {
            $back='p=dnsguard';
            $op=(string)($_POST['antidpi_op']??'');
            $engine=(string)($_POST['zapret_engine']??'zapret2');
            if(in_array($engine,['zapret2','classic'],true))$back='p=dnsguard&zapret_engine='.$engine.'#dns-zapret-manager';
            if(!in_array($op,['preflight','start','confirm','stop','persist-enable','persist-disable'],true) || !in_array($engine,['zapret2','classic'],true)) {
                flash('Operazione Anti-DPI non valida.','err');break;
            }
            $args=[$op];if(in_array($op,['preflight','start'],true))$args[]=$engine;
            [$rc,$out,$err]=run(array_merge([BIN_SUDO,'-n',HELPER,'anti-dpi-live'],$args),null,90.0,4096);
            $j=json_decode($out,true);
            if($rc!==0||!is_array($j)||empty($j['ok'])) {
                flash('Anti-DPI: '.herr((string)($j['error']??$out.$err)),'err');break;
            }
            audit('Anti-DPI '.$op.' engine='.$engine);
            if($op==='start')flash('Anti-DPI attivato in prova: verifica la navigazione dalla LAN e conferma entro 120 secondi. Altrimenti il watchdog ripristina.','ok');
            elseif($op==='preflight')flash('Prerequisiti Anti-DPI verificati: nessuna regola attivata.','ok');
            elseif($op==='stop')flash('Anti-DPI fermato e persistenza al boot disabilitata.','ok');
            elseif($op==='confirm')flash('Prova confermata. Puoi scegliere separatamente se renderla persistente al riavvio.','ok');
            elseif($op==='persist-enable')flash('Persistenza abilitata: al boot IPTM verifica il profilo e avvia Anti-DPI con un nuovo watchdog.','ok');
            else flash('Persistenza disattivata: il processo in corso rimane attivo fino a uno stop esplicito o al riavvio.','ok');
            break;
        }
        case 'dns_sni_activate':
        case 'dns_sni_disable': {
            $back='p=dnsguard';
            $disable=$a==='dns_sni_disable';
            // Read current rules before changing anything. Refuse unknown output.
            [$oldRc,$oldOut,$oldErr]=run([BIN_SUDO,'-n',HELPER,'su-local-get'],null,20.0,250000);
            if($oldRc!==0 || !preg_match('/^### path [^\r\n]+\n/', $oldOut,$header)) {
                flash('local.rules non leggibile: '.herr($oldOut.$oldErr),'err');break;
            }
            $original=substr($oldOut,strlen($header[0]));
            $rx='/^# IPTM_SNI_MONITOR_BEGIN\R.*?^# IPTM_SNI_MONITOR_END\R?/ms';
            if(substr_count($original,'# IPTM_SNI_MONITOR_BEGIN')>1 ||
               substr_count($original,'# IPTM_SNI_MONITOR_BEGIN')!==substr_count($original,'# IPTM_SNI_MONITOR_END')) {
                flash('Blocco SNI precedente incoerente: non sovrascrivere local.rules.','err');break;
            }
            $base=preg_replace($rx,'',$original,1);
            if(!is_string($base)) {flash('Errore nel modello regole SNI.','err');break;}
            $prepared=rtrim($base)."\n";
            if(!$disable) {
                $raw=(string)($_POST['sni_live_domains']??'');
                if(strlen($raw)>8192){flash('Elenco SNI troppo grande.','err');break;}
                $names=array_values(array_unique(array_filter(array_map('trim',preg_split('/\R/',strtolower($raw))),static fn($v)=>$v!=='')));
                if(!$names || count($names)>40){flash('Inserisci da 1 a 40 domini SNI validi.','err');break;}
                $rules=[];
                foreach($names as $idx=>$name) {
                    if(!preg_match('/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/D',$name)) {
                        flash('Dominio SNI non valido.','err');break 2;
                    }
                    $rules[]='alert tls any any -> any any (msg:"IPTM SNI '.($idx+1).'"; flow:established,to_server; tls.sni; content:"'.$name.'"; nocase; bsize:'.strlen($name).'; sid:9911900'.($idx+1).'; rev:1;)';
                }
                $prepared.="# IPTM_SNI_MONITOR_BEGIN\n".implode("\n",$rules)."\n# IPTM_SNI_MONITOR_END\n";
            }
            if(strlen($prepared)>190000){flash('Regole locali Suricata troppo grandi.','err');break;}
            if($prepared===$original){flash('Monitoraggio SNI già nello stato richiesto.');break;}
            // The existing helper backs up local.rules/YAML and runs suricata -T.
            [$rc,$out,$err]=run([BIN_SUDO,'-n',HELPER,'su-local-set'],$prepared,155.0,12000);
            if($rc!==0) {
                // A reload can fail after a successful syntax test. Attempt compensation.
                [$rrc,$rout,$rerr]=run([BIN_SUDO,'-n',HELPER,'su-local-set'],$original,155.0,12000);
                flash('Monitoraggio SNI non attivato: '.herr($out.$err).
                      ($rrc===0?' Ripristino local.rules riuscito.':' ATTENZIONE: verificare e ripristinare manualmente Suricata.'),'err');
            } else {
                audit('Suricata TLS/SNI monitoring '.$a);
                flash($disable?'Regole SNI IPTM rimosse.':'Regole SNI reali installate e ricaricate; verificare eventi EVE. Solo IDS alert, nessun DROP.','ok');
            }
            break;
        }
        case 'dnscrypt_compat_repair': {
            $back='p=dnsguard';
            [$rc,$o,$e]=run([BIN_SUDO,'-n',HELPER,'dns-guard','compat-apply'],null,65.0,10000);
            $j=json_decode($o,true);
            if($rc!==0||!is_array($j)||empty($j['ok']))
                flash('Riparazione DNSCrypt non riuscita: '.herr((string)($j['error']??$o.$e)),'err');
            else {
                audit('DNSCrypt 2.1.8 compatibility repair');
                flash(!empty($j['result']['pending_confirmation'])?
                    'Riparazione DNSCrypt in prova: verifica le query DNS e conferma nella sezione DNSCrypt prima della scadenza.':
                    'Configurazione DNSCrypt già compatibile.','ok');
            }
            break;
        }
        case 'dns_guard_preview':
        case 'dns_guard_apply': {
            $back='p=dnsguard';
            $mode=$a==='dns_guard_apply'?'apply':'preview';
            $lines=function($key,$limit=40){
                $value=(string)($_POST[$key]??'');
                $byteLimit=$key==='dpi_domains'?16*1024*1024:8192;
                if(strlen($value)>$byteLimit)throw new RuntimeException('Elenco troppo grande in byte: '.$key);
                $items=array_values(array_filter(array_map('trim',preg_split('/\R/',$value)),fn($x)=>$x!==''));
                if($limit>0 && count($items)>$limit)throw new RuntimeException('Troppi elementi nel campo '.$key);
                return $items;
            };
            $payload=['primary_stamp'=>trim((string)($_POST['primary_stamp']??'')),
              'secondary_stamp'=>trim((string)($_POST['secondary_stamp']??'')),
              'bootstrap'=>$lines('bootstrap',4),'timeout'=>(int)($_POST['timeout']??5),
              'sni_domains'=>$lines('sni_domains'),'sni_mode'=>(string)($_POST['sni_mode']??'alert'),
              'dpi_domains'=>$lines('dpi_domains',0),'dpi_clients'=>$lines('dpi_clients',32)];
            $json=json_encode($payload,JSON_THROW_ON_ERROR);
            // Bind consent to the DNS resolver fields only. SNI and anti-DPI are
            // independent previews, never enabled by the DNSCrypt apply action.
            $dnsApproval=['primary_stamp'=>$payload['primary_stamp'],'secondary_stamp'=>$payload['secondary_stamp'],
              'bootstrap'=>$payload['bootstrap'],'timeout'=>$payload['timeout']];
            $fingerprint=hash('sha256',json_encode($dnsApproval,JSON_THROW_ON_ERROR));
            if($mode==='apply') unset($_SESSION['dns_guard_ready']); // Preflight in dns_tls_guard.py apply().
            [$rc,$o,$e]=priv('dns-guard',$json,[$mode]);$res=json_decode($o,true);
            if($rc!==0||!is_array($res)||empty($res['ok'])){
                flash('DNS/TLS: '.h((string)($res['error']??trim($o.$e))), 'err');break;
            }
            if($mode==='preview'){
                $_SESSION['dns_guard_preview']=$res['result'];
                $_SESSION['dns_guard_fields']=$payload;
                // SNI-only previews remain supported; they never authorize
                // an activation of the DNS resolver stack.
                if($payload['primary_stamp']!=='' && $payload['secondary_stamp']!=='')
                    $_SESSION['dns_guard_ready']=['hash'=>$fingerprint,'until'=>time()+600];
                else unset($_SESSION['dns_guard_ready']);
                flash('Verifica completata: nessuna modifica applicata. Per attivare DNSCrypt conferma il profilo entro 10 minuti.');
            } else {
                unset($_SESSION['dns_guard_preview'],$_SESSION['dns_guard_fields']);
                audit('DNSCrypt: configurazione in prova con watchdog');
                flash('DNSCrypt attivato con watchdog automatico. Puoi completare con un clic oppure ripristinare la configurazione.');
            }
            break;
        }
        case 'dns_guard_confirm':
        case 'dns_guard_revert': {
            $back='p=dnsguard';
            $mode=$a==='dns_guard_confirm'?'confirm':'revert';
            [$rc,$out,$err]=priv('dns-guard',null,[$mode]);$response=json_decode($out,true);
            if ($rc!==0 || !is_array($response) || empty($response['ok'])) {
                flash('Transazione DNS non conclusa: verifica lo stato e il watchdog dalla console. Rif. '.iptm_request_id(), 'err');
                audit('dns-guard '.$mode.' failed rc='.$rc);
            } else {
                flash($mode==='confirm'?'Configurazione DNS confermata e watchdog annullato.':'Configurazione DNS precedente ripristinata.');
                audit('dns-guard '.$mode.' completed');
            }
            break;
        }
        case 'dns_unbound_harden': {
            $back='p=unbound';
            if (($_SESSION['role']??'viewer')!=='admin') {flash('Solo amministratore.','err');break;}
            $profile=(string)($_POST['unbound_profile']??'balanced');
            if(!in_array($profile,['balanced','strict','compatible'],true)){flash('Profilo non valido.','err');break;}
            [$rc,$out,$err]=priv('dns-harden',null,['apply',$profile]);
            $result=json_decode($out,true);
            $ok=$rc===0 && is_array($result) && !empty($result['ok']);
            flash($ok ? 'Hardening Unbound applicato e validato. Verifica la risoluzione dalla LAN.' : 'Hardening non applicato: '.herr((string)($result['error']??$err.$out)), $ok?'ok':'err');
            audit('unbound hardening '.$profile.' success='.(int)$ok); break;
        }
        case 'dns_unbound_profile': {
            [$c, $o, $e] = priv('dns-unbound-profile'); audit('dns unbound profile');
            flash($c === 0 ? trim($o) : herr($o . $e), $c === 0 ? 'ok' : 'err'); unset($GLOBALS['_kc']['dns_status']); break;
        }
        case 'dns_service': {
            $svc = (string)($_POST['service'] ?? ''); if (!in_array($svc, ['pihole-FTL', 'unbound', 'dnscrypt-proxy'], true)) { flash('Servizio DNS non valido.', 'err'); break; }
            [$c, $o, $e] = priv('dns-service', null, [$svc]); flash($c === 0 ? trim($o) : herr($o . $e), $c === 0 ? 'ok' : 'err'); unset($GLOBALS['_kc']['dns_status']); break;
        }
        case 'dnscrypt_config': {
            $proto = (string)($_POST['dnscrypt_proto'] ?? 'auto');
            if (!in_array($proto, ['auto', 'dnscrypt', 'doh'], true)) {
                flash('Protocollo DNSCrypt non valido.', 'err'); break;
            }
            [$c, $o, $e] = priv('dnscrypt-config', null, [$proto]); audit('dnscrypt config');
            flash($c === 0 ? trim($o) : herr($o . $e), $c === 0 ? 'ok' : 'err'); unset($GLOBALS['_kc']['dns_status']); break;
        }
        case 'dns_stack': {
            $mode = (string)($_POST['dns_stack_mode'] ?? 'unbound');
            if (!in_array($mode, ['unbound', 'dnscrypt', 'layered'], true)) { flash('Profilo DNS non valido.', 'err'); break; }
            [$c, $o, $e] = priv('dns-stack', null, [$mode]); audit('dns stack ' . $mode);
            flash($c === 0 ? trim($o) : herr($o . $e), $c === 0 ? 'ok' : 'err'); unset($GLOBALS['_kc']['dns_status']); break;
        }
        case 'dns_test': {
            [$c, $o, $e] = priv('dns-test'); flash(trim($o . $e) ?: ($c === 0 ? 'Test DNS completato.' : 'Test DNS non riuscito.'), $c === 0 ? 'ok' : 'err'); break;
        }
        case 'sysctl_maintenance_apply': {
            if (($_SESSION['role'] ?? 'viewer') !== 'admin') { flash('Solo un amministratore può modificare sysctl.', 'err'); break; }
            $text = trim((string)($_POST['sysctl_payload'] ?? ''));
            if ($text === '') { flash('Inserisci almeno una assegnazione chiave = valore. Il suggerimento nel campo non è una configurazione da applicare.', 'err'); break; }
            if (strlen($text) > 65536) { flash('Configurazione sysctl oltre 64 KiB.', 'err'); break; }
            $args = ['sysctl-apply', '--file', '-'];
            $apply = !empty($_POST['apply_sysctl']);
            if ($apply) $args[] = '--apply';
            [$c,$o,$e] = priv('maintenance', $text, $args);
            $j = json_decode($o, true);
            $success = $c === 0 && is_array($j) && !empty($j['ok']);
            $skipped = is_array($j) ? (array)($j['skipped_unsupported'] ?? []) : [];
            if ($success) {
                $number = $apply ? (int)($j['applied'] ?? 0) : count((array)($j['keys'] ?? []));
                $msg = $apply ? "Sysctl: $number chiave/i applicate." : "Sysctl: $number chiave/i valide; nessuna modifica eseguita.";
                if ($skipped) $msg .= ' Non disponibili sul kernel: ' . implode(', ', array_map('strval', $skipped));
            } else {
                $msg = 'Operazione sysctl non riuscita: ' . (is_array($j) ? (string)($j['error'] ?? 'verifica non riuscita') : trim($o . $e));
            }
            flash($msg, $success ? 'ok' : 'err');
            if ($apply && $success) audit('sysctl maintenance apply');
            break;
        }
        case 'dns_rethink_refresh': {
            $back='p=piholelists';
            if (($_SESSION['role']??'')!=='admin') {flash('Solo amministratore.','err');break;}
            [$rc,$out,$err]=run([BIN_SUDO,'-n',HELPER,'maintenance','rethink-refresh'],null,95.0,200000);
            $result=json_decode($out,true);
            flash(($rc===0 && is_array($result) && !empty($result['ok']))
              ? 'Catalogo RethinkDNS aggiornato: '.count($result['lists']??[]).' fonti selezionabili (senza verifica di raggiungibilità).'
              : 'Catalogo RethinkDNS non aggiornato: '.herr((string)($result['error']??$err)),
              ($rc===0 && is_array($result) && !empty($result['ok']))?'ok':'err');
            break;
        }
        case 'pihole_credentials': {
            $back='p=piholelists';
            if (($_SESSION['role']??'')!=='admin') {flash('Solo amministratore.','err');break;}
            $op=(string)($_POST['credential_op']??'');
            if(!in_array($op,['save','clear'],true)) {flash('Azione credenziali sconosciuta.','err');break;}
            if($op==='save' && empty($_SERVER['HTTPS'])) {
                flash('Richiesto HTTPS sul pannello IPTM per inviare la password applicativa Pi-hole.','err');break;
            }
            $pw=(string)($_POST['pihole_credential']??'');
            if ($op==='save' && (strlen($pw)<8 || strlen($pw)>256 || strpbrk($pw,"\r\n\0")!==false)) {
                flash('Password non valida (8-256 caratteri, niente newline).','err');break;
            }
            $json=$op==='save'?json_encode(['password'=>$pw],JSON_UNESCAPED_UNICODE):null;
            if ($op==='save' && !is_string($json)) {flash('Password non valida.','err');break;}
            [$rc,$out,$err]=run([BIN_SUDO,'-n',HELPER,'pihole-secret',$op],$json,40.0,4096);
            unset($pw,$json,$_POST['pihole_credential']);
            $result=json_decode($out,true);
            if ($rc!==0 || !is_array($result) || empty($result['ok']))
                flash('Archiviazione credenziale non riuscita: verifica GnuPG, sudoers e permessi root.','err');
            else flash($op==='clear'?'Credenziale Pi-hole cancellata.':'Credenziale Pi-hole salvata cifrata in archivio root; non inclusa nei backup.');
            break;
        }
        case 'dns_pihole_export': {
            if (($_SESSION['role'] ?? 'viewer') !== 'admin') { http_response_code(403); exit('Solo amministratore'); }
            $apiUrl = trim((string)($_POST['pihole_api_url'] ?? 'http://127.0.0.1:8089'));
            $pw = (string)($_POST['pihole_api_password'] ?? '');
            $json = json_encode(['mode'=>'read','api_url'=>$apiUrl,'password'=>$pw], JSON_UNESCAPED_SLASHES);
            if ($json === false) { http_response_code(400); exit('Input non valido'); }
            [$c,$o,$e] = run([BIN_SUDO,'-n',HELPER,'maintenance','pihole-api-json'], $json, 35.0, 4194304);
            $result=json_decode($o,true);
            header('Cache-Control: no-store, max-age=0');
            header('Pragma: no-cache');
            if ($c!==0 || !is_array($result) || empty($result['ok'])) {
                http_response_code(502);
                header('Content-Type: application/json; charset=utf-8');
                echo json_encode(['ok'=>false,'error'=>is_array($result) ? (string)($result['error']??'Errore API') : 'Pi-hole API non raggiungibile o non autorizzata'], JSON_UNESCAPED_UNICODE);
                exit;
            }
            // Cache only verification labels for ten minutes. No API credentials,
            // whitelist contents or client information are stored in the session.
            if (!empty($_POST['read_preview']) && is_array($result['catalog_status']??null)) {
                $allowed=['active'=>true,'disabled'=>true,'present'=>true,'new'=>true];
                $filtered=[];
                foreach (['adlists','regex','rethink'] as $group) {
                    $filtered[$group]=[];
                    foreach ((array)($result['catalog_status'][$group]??[]) as $key=>$state) {
                        if (is_string($key) && strlen($key)<=64 && is_string($state) && isset($allowed[$state]) && count($filtered[$group])<1500)
                            $filtered[$group][$key]=$state;
                    }
                }
                $_SESSION['iptm_pihole_verified']=['url'=>$apiUrl,'at'=>time(),'statuses'=>$filtered];
            }
            header('Content-Type: application/json; charset=utf-8');
            if (empty($_POST['read_preview'])) header('Content-Disposition: attachment; filename="pihole-whitelist-export.json"');
            echo json_encode($result, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            exit;
        }
        case 'dns_pihole_import': {
            if (($_SESSION['role'] ?? 'viewer') !== 'admin') { flash('Solo un amministratore può modificare le liste Pi-hole.', 'err'); break; }
            $rawIds = $_POST['adlists'] ?? [];
            if (!is_array($rawIds) || count($rawIds)>50) { flash('Selezione adlist non valida (massimo 50).', 'err'); break; }
            $ids=[];
            foreach($rawIds as $id) {
                if (!is_string($id) || !preg_match('/^[A-Za-z0-9_.-]{1,48}$/D',$id)) { flash('Identificativo adlist non valido.','err'); break 2; }
                $ids[$id]=$id;
            }
            $ids=array_values($ids);
            $rdIds=$_POST['rethink_ids']??[];
            if(!is_array($rdIds)){flash('Selezione RethinkDNS non valida.','err');break;}
            // Nessun limite arbitrario: il worker verifica tutti gli ID nel catalogo root verificato.
            foreach($rdIds as $rdid)if(!is_string($rdid)||!preg_match('/^rd[a-f0-9]{16}$/D',$rdid)) {flash('ID RethinkDNS non valido.','err');break 2;}
            $rxIds=$_POST['regex_presets']??[];
            if(!is_array($rxIds)||count($rxIds)>30) {flash('Selezione regex non valida.','err');break;}
            $rxUnique=[];
            foreach($rxIds as $id) {
                if(!is_string($id)||!preg_match('/^[a-z0-9-]{1,40}$/D',$id)) {flash('Regex predefinita non valida.','err');break 2;}
                $rxUnique[$id]=$id;
            }
            $whitelist=(string)($_POST['whitelist']??''); $format='txt';
            $upload=$_FILES['pihole_whitelist_file']??null;
            if($upload!==null) {
                if(!is_array($upload)||is_array($upload['error']??null)) {flash('Upload whitelist non valido.','err');break;}
                $err=(int)($upload['error']??UPLOAD_ERR_NO_FILE);
                if($err!==UPLOAD_ERR_NO_FILE) {
                    if($err!==UPLOAD_ERR_OK) {flash('Upload whitelist fallito (codice '.$err.').','err');break;}
                    $format=strtolower(pathinfo((string)($upload['name']??''),PATHINFO_EXTENSION));
                    $tmp=(string)($upload['tmp_name']??'');
                    if(!in_array($format,['txt','csv','json'],true)||(int)($upload['size']??-1)<1||
                        (int)($upload['size']??0)>1048576||!is_uploaded_file($tmp)) {flash('Whitelist: file TXT/CSV/JSON valido (max 1 MiB).','err');break;}
                    if(trim($whitelist)!=='') {flash('Usa file oppure testo, non entrambi.','err');break;}
                    $raw=@file_get_contents($tmp);
                    if($raw===false||strlen($raw)>1048576) {flash('Lettura whitelist fallita.','err');break;}
                    $whitelist=$raw;
                }
            }
            $payload=[
                'mode'=>'import','api_url'=>(string)($_POST['pihole_api_url']??'http://127.0.0.1:8089'),
                'password'=>(string)($_POST['pihole_api_password']??''),
                'whitelist'=>$whitelist,'whitelist_format'=>$format,
                'allow_regex'=>(string)($_POST['allow_regex']??''),
                'deny_regex'=>(string)($_POST['deny_regex']??''),
                'regex_ids'=>array_values($rxUnique),'adlists'=>$ids,'rethink_ids'=>array_values(array_unique($rdIds)),
                'apply'=>(($_POST['import_action'] ?? 'preview') === 'apply' || !empty($_POST['apply_import'])),
                // Multiple new adlists are staged DISABLED automatically, no redundant opt-in checkbox.
                'confirm_large'=>true,
                'gravity'=>!empty($_POST['apply_gravity']),
            ];
            if(strlen($payload['password'])>256||strlen($payload['api_url'])>90||
               strlen($payload['whitelist'])+strlen($payload['allow_regex'])+strlen($payload['deny_regex'])>2097152||
               !preg_match('//u',$payload['whitelist'].$payload['allow_regex'].$payload['deny_regex'])) {
                flash('Input non valido o troppo grande.','err');break;
            }
            $json=json_encode($payload,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);
            if($json===false) {flash('Codifica import non riuscita.','err');break;}
            $GLOBALS['_kc']=[];
            [$c,$o,$e]=run([BIN_SUDO,'-n',HELPER,'maintenance','pihole-api-json'],$json,240.0,1048576);
            $result=json_decode($o,true);
            if (is_array($result)) {
                // Display the *actual* result: a nonzero exit or ok=false must never look successful.
                $worked = ($c === 0 && ($result['ok'] ?? false) === true);
                $mode = (string)($result['mode'] ?? 'error');
                $counts = $result['inserted'] ?? $result['plan']['new'] ?? [];
                $summary = is_array($counts) ? implode(', ', array_map(
                    fn($k, $v) => $k . '=' . (int)$v, array_keys($counts), array_values($counts))) : '';
                $prefix = match ($mode) {
                    'dry-run' => 'Anteprima: nessuna voce scritta.',
                    'no-op' => 'Nessuna nuova voce da importare.',
                    'applied' => 'Importazione Pi-hole completata.',
                    default => $worked ? 'Operazione Pi-hole completata.' : 'Importazione Pi-hole NON completata.',
                };
                $why = (string)($result['error'] ?? '');
                flash($prefix . ($summary !== '' ? ' ' . $summary . '.' : '')
                    . ($why !== '' ? ' Errore: ' . $why : '')
                    . (!$worked && !empty($result['partial']) ? ' Scritture parziali: controlla il backup prima di ripetere.' : ''),
                    $worked ? 'ok' : 'err');
                if ($worked && !empty($payload['apply'])) unset($_SESSION['iptm_pihole_verified']);
                audit('Pi-hole v6 API import '.(!empty($payload['apply'])?'apply':'dry-run') . ' mode=' . $mode);
            } else flash('Import API non riuscito (exit ' . $c . '): ' . herr($o.$e),'err');
            break;
        }
        case 'dns_bundle_export': {
            if (($_SESSION['role']??'')!=='admin') { http_response_code(403); exit('Solo admin'); }
            $pass=(string)($_POST['dnsbundle_password']??'');
            $again=(string)($_POST['dnsbundle_password2']??'');
            if (strlen($pass)<14 || strlen($pass)>256 || str_contains($pass,"\n") ||
                !hash_equals($pass,$again)) {
                flash('Passphrase backup DNS: 14–256 caratteri identici nei due campi (no newline).','err');break;
            }
            iptm_dns_bundle_export_stream($pass);
        }
        case 'dns_bundle_import': {
            $back='p=dns';
            if (($_SESSION['role']??'')!=='admin') { flash('Solo amministratore.','err'); break; }
            $file=$_FILES['dnsbundle']??null;
            if (!is_array($file) || ($file['error']??UPLOAD_ERR_NO_FILE)!==UPLOAD_ERR_OK ||
                ($file['size']??0)<100 || ($file['size']??0)>12*1048576 ||
                !is_uploaded_file((string)($file['tmp_name']??''))) {
                flash('Carica un ZIP DNS valido fino a 12 MiB dalla UI; per database più grandi usa la CLI. Verifica upload_max_filesize/post_max_size PHP.','err'); break;
            }
            $bytes=@file_get_contents($file['tmp_name']);
            if (!is_string($bytes)) { flash('Impossibile leggere il file caricato.','err'); break; }
            $apply=isset($_POST['dnsbundle_apply']); $fileHash=hash('sha256',$bytes);
            // Il comando di ripristino convalida archivio, checksum e contenuto prima di scrivere.
            $encrypted=str_ends_with(strtolower((string)($file['name']??'')),'.gpg');
            if ($encrypted) {
                $pass=(string)($_POST['dnsbundle_password_import']??'');
                if (strlen($pass)<14 || strlen($pass)>256 || str_contains($pass,"\n")) {
                    flash('Passphrase di ripristino OpenPGP non valida.','err');break;
                }
                $input=$pass."\n".$bytes;
                $args=$apply?['apply-encrypted','RIPRISTINA DNS']:['inspect-encrypted'];
            } else {
                if (substr($bytes,0,4)!=="PK\x03\x04") { flash('Archivio non riconosciuto: usa .zip.gpg o ZIP legacy.','err');break; }
                $input=$bytes;
                $args=$apply?['apply','RIPRISTINA DNS']:['inspect'];
            }
            [$rc,$o,$e]=priv('dns-bundle',$input,$args);
            $res=json_decode($o,true);
            if ($rc!==0 || !is_array($res) || empty($res['ok'])) {
                $error=json_decode($e,true);
                flash('Archivio DNS rifiutato: '.substr((string)($error['error']??$o.$e),0,250),'err');break;
            }
            if (!$apply) {
                $_SESSION['dns_bundle_preview']=['n'=>count($res['files']??[]),'time'=>time(),'file_sha'=>$fileHash];
                flash('Archivio DNS controllato: '.count($res['files']??[]).' file validi. Nessuna modifica effettuata.');
            } else {
                unset($_SESSION['dns_bundle_preview']);
                audit('DNS configuration bundle applied; backup='.($res['backup']??'?'));
                flash('Configurazioni DNS ripristinate ('.(int)($res['restored']??0).' file). Servizi NON riavviati. Backup: '.(string)($res['backup']??'n/d').'. Verifica le configurazioni prima del riavvio.');
            }
            break;
        }
        
}
