<?php
/* IPTM unified QoS control plane. Old write actions intentionally retired. */
switch ($a) {
case 'qos_postinstall_ensure': {
    $back='p=sqm';
    if(($_SESSION['role']??'viewer')!=='admin'){flash('Amministratore richiesto','err');break;}
    [$c,$o,$e]=priv('qos-postinstall',null,['ensure']);$j=json_decode($o,true);
    if($c===0&&!empty($j['ok']))flash('Handoff watchdog QoS verificato: '.herr((string)($j['handoff_from']??'nessun proprietario precedente')),'ok');
    else flash('Migrazione QoS protetta sospesa: '.herr((string)($j['error']??$e??$o)),'err');
    break;
}

case 'qos_policy_stage': {
    $back='p=sqm';if(($_SESSION['role']??'viewer')!=='admin'){flash('Admin richiesto','err');break;}
    $iface=(string)($_POST['interface']??'');$raw=(string)($_POST['policy_rules']??'');$rules=[];
    if(strlen($raw)>4000||!preg_match('/^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$/D',$iface)){flash('WAN o lunghezza policy non valida','err');break;}
    $presets=iptm_qos_dscp_recommendations();
    $selected=$_POST['recommended_rules']??[];
    if(!is_array($selected)||count($selected)>count($presets)){
        flash('Selezione consigliate non valida','err');break;
    }
    foreach($selected as $key){
        if(!is_string($key)||!isset($presets[$key])){flash('Profilo consigliato sconosciuto','err');break 2;}
        $entry=$presets[$key];
        $rules[]=['protocol'=>$entry['protocol'],'port'=>$entry['port'],
            'priority'=>$entry['priority'],'direction'=>$entry['direction'],'source'=>''];
    }
    foreach(preg_split('/\r?\n/',$raw) as $line){
        $line=trim($line);if($line==='')continue;$parts=array_map('trim',explode(',',$line));
        if(count($parts)<3||count($parts)>5||!in_array($parts[0],['tcp','udp'],true)||!ctype_digit($parts[1])||
           !in_array($parts[2],['realtime','interactive','normal','background'],true)){
            flash('Regola non valida: '.herr($line),'err');break 2;
        }
        // Backwards-compatible CSV: proto,port,priority,CIDR[,direction].
        $direction=$parts[4]??'both';
        if(!in_array($direction,['both','upload','download'],true)){
            flash('Direzione regola non valida: '.herr($line),'err');break 2;
        }
        $rules[]=['protocol'=>$parts[0],'port'=>(int)$parts[1],
            'priority'=>$parts[2],'source'=>$parts[3]??'','direction'=>$direction];
    }
    [$c,$out,$err]=priv('qos-policy',json_encode(['interface'=>$iface,'rules'=>$rules]),['stage']);$j=json_decode($out,true);
    if($c!==0||empty($j['ok'])||!preg_match('/^[a-f0-9]{64}$/D',(string)($j['sha256']??''))){flash('Policy rifiutata: '.herr((string)($j['error']??$err??$out)),'err');break;}
    $_SESSION['iptm_qos_recommended_selection']=array_values(array_unique($selected));
    $_SESSION['iptm_qos_policy_stage']=['hash'=>$j['sha256'],'created'=>time()];
    flash('Anteprima DSCP salvata; nessuna regola applicata.','ok');break;
}
case 'qos_policy_apply': {
    $back='p=sqm';$stage=$_SESSION['iptm_qos_policy_stage']??null;$sha=(string)($_POST['policy_sha256']??'');
    if(($_SESSION['role']??'viewer')!=='admin'||!is_array($stage)||time()-(int)($stage['created']??0)>600||!preg_match('/^[a-f0-9]{64}$/D',$sha)||!hash_equals((string)$stage['hash'],$sha)){
        flash('Anteprima policy assente o scaduta','err');break;
    }
    [$c,$out,$err]=priv('qos-policy',null,['apply',$sha]);$j=json_decode($out,true);
    if($c!==0||empty($j['ok'])){flash('Applicazione DSCP rifiutata: '.herr((string)($j['error']??$err??$out)),'err');break;}
    unset($_SESSION['iptm_qos_policy_stage']);flash('Priorità DSCP applicate alla WAN.','ok');break;
}
case 'qos_policy_disable': {
    $back='p=sqm';if(($_SESSION['role']??'viewer')!=='admin'){flash('Admin richiesto','err');break;}
    [$c,$out,$err]=priv('qos-policy',null,['disable']);$j=json_decode($out,true);
    $ok=$c===0&&!empty($j['ok']);
    if($ok){
        $message=!empty($j['foreign_preserved'])?'Priorità IPTM rimosse. Regole esterne conservate.':
            (!empty($j['stale'])?'Profilo DSCP non più presente: stato ripulito.':'Priorità IPTM disattivate.');
        if(!empty($j['warning']))$message.=' '.herr((string)$j['warning']);
        flash($message,'ok');
    }else flash('Disattivazione DSCP non riuscita: '.herr((string)($j['error']??$err??$out)),'err');
    break;
}
case 'qos_calibrate_start': {
    $back='p=sqm';
    if (($_SESSION['role']??'viewer')!=='admin') {flash('Accesso amministratore necessario.','err');break;}
    $iface=(string)($_POST['interface']??'');
    if(!preg_match('/^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$/D',$iface)){flash('WAN calibrazione non valida.','err');break;}
    $_SESSION['iptm_qos_last_wan']=$iface;
    [$c,$o,$e]=priv('qos-engine',null,['calibrate-start',$iface]);$j=json_decode($o,true);
    flash($c===0&&!empty($j['ok'])?'Misurazione avviata in un servizio separato. I limiti CAKE non cambiano.':'Avvio calibrazione respinto: '.herr((string)($j['error']??$e??$o)),$c===0&&!empty($j['ok'])?'ok':'err');
    break;
}

case 'qos_adaptive_enable':case 'qos_adaptive_disable': {
    $back='p=sqm';
    if (($_SESSION['role']??'viewer')!=='admin') {flash('Admin necessario','err');break;}
    $command=$a==='qos_adaptive_enable'?'adaptive-enable':'adaptive-disable';
    [$c,$o,$e]=priv('qos-engine',null,[$command]);$j=json_decode($o,true);
    if($c!==0||empty($j['ok']))flash('Regolatore RTT: '.herr((string)($j['error']??$e??$o)),'err');
    else flash($command==='adaptive-enable'?'Regolatore RTT attivato, senza modificare i massimi confermati.':'Regolatore RTT disattivato; ripristino dei limiti confermati eseguito se applicabile.','ok');
    break;
}
case 'qos_guard_install': {
    $back='p=sqm';
    if (($_SESSION['role']??'viewer')!=='admin') {flash('Accesso amministratore necessario.','err'); break;}
    [$c,$o,$e]=priv('qos-engine',null,['install-guard']);
    $j=json_decode($o,true);
    flash($c===0&&!empty($j['ok'])?'Watchdog QoS indipendente attivo.':
        'Installazione guard rifiutata: '.herr((string)($j['error']??$e??$o)),$c===0?'ok':'err');
    break;
}
case 'qos_stage': {
    $back='p=sqm';
    if (($_SESSION['role']??'viewer')!=='admin') {flash('Accesso amministratore necessario.','err'); break;}
    $intFields=['up_mbit','down_mbit','overhead','timeout'];$payload=[];
    foreach($intFields as $key){
        $val=filter_var($_POST[$key]??null,FILTER_VALIDATE_INT);
        if($val===false||$val===null){flash('Valore QoS non valido: '.$key,'err');break 2;}
        $payload[$key]=$val;
    }
    $iface=(string)($_POST['interface']??'');
    if(!preg_match('/^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$/D',$iface)){flash('WAN non valida.','err');break;}
    $_SESSION['iptm_qos_last_wan']=$iface;
    $payload['interface']=$iface;$payload['diffserv']=(string)($_POST['diffserv']??'diffserv4');
    foreach(['nat','wash','ack_filter'] as $key)$payload[$key]=!empty($_POST[$key]);
    [$c,$o,$e]=priv('qos-engine',json_encode($payload,JSON_THROW_ON_ERROR),['stage']);
    $j=json_decode($o,true);
    if($c!==0||empty($j['ok'])||!preg_match('/^[a-f0-9]{64}$/D',(string)($j['sha256']??''))){
        unset($_SESSION['iptm_qos_stage']);flash('Anteprima respinta: '.herr((string)($j['error']??$e??$o)),'err');break;
    }
    $_SESSION['iptm_qos_stage']=['hash'=>$j['sha256'],'created'=>time(),'profile'=>$payload];
    flash('Anteprima QoS creata. Nessuna qdisc modificata; applica soltanto dopo aver verificato il watchdog.','ok');
    break;
}
case 'qos_apply': {
    $back='p=sqm';$pending=$_SESSION['iptm_qos_stage']??null;$hash=(string)($_POST['plan_sha256']??'');
    if(($_SESSION['role']??'viewer')!=='admin'||!is_array($pending)||time()-(int)($pending['created']??0)>600||
        !preg_match('/^[a-f0-9]{64}$/D',$hash)||!hash_equals((string)($pending['hash']??''),$hash)){
        flash('Piano scaduto o non appartenente alla sessione.','err');break;
    }
    [$c,$o,$e]=priv('qos-engine',null,['apply',$hash]);$j=json_decode($o,true);
    if($c!==0||empty($j['ok'])||!preg_match('/^[a-f0-9]{24}$/D',(string)($j['token']??''))){
        flash('Prova CAKE rifiutata: '.herr((string)($j['error']??$e??$o)),'err');break;
    }
    $_SESSION['iptm_qos_active']=['token'=>$j['token'],'created'=>time(),'profile'=>$pending['profile']];
    unset($_SESSION['iptm_qos_stage']);
    $policyNotice=(($j['ingress_policy_status']??'')==='unverified')
        ?' Priorità download non attive: policy DSCP da verificare; nessuna regola firewall modificata.' : '';
    flash('CAKE/IFB in prova con rollback automatico. Verifica rete e accesso amministrativo.'.$policyNotice,'ok');
    break;
}
case 'qos_commit':case 'qos_revert': {
    $back='p=sqm';$active=$_SESSION['iptm_qos_active']??null;$token=(string)($_POST['qos_token']??'');
    if(($_SESSION['role']??'viewer')!=='admin'||!is_array($active)||!preg_match('/^[a-f0-9]{24}$/D',$token)||
       !hash_equals((string)($active['token']??''),$token)) {flash('Token o sessione non validi.','err');break;}
    $cmd=$a==='qos_commit'?'confirm':'rollback';
    [$c,$o,$e]=priv('qos-engine',null,[$cmd,$token]);$j=json_decode($o,true);
    if($c!==0||empty($j['ok'])){flash('Transazione non conclusa: '.herr((string)($j['error']??$e??$o)),'err');break;}
    if($cmd==='confirm'){
        try{$S=S_get();$S['qos_engine']=$active['profile'];S_put($S);}
        catch(Throwable $x){flash('Kernel confermato ma stato GUI non salvato: '.herr($x->getMessage()),'err');break;}
    }
    unset($_SESSION['iptm_qos_active']);flash($cmd==='confirm'?'CAKE/IFB confermato e verificato.':'Ripristino CAKE/IFB eseguito.','ok');
    break;
}
case 'qos_disable': {
    $back='p=sqm';if(($_SESSION['role']??'viewer')!=='admin'){flash('Accesso admin necessario.','err');break;}
    // Never send a destructive command to an engine that does not own the
    // recorded state (possible immediately after an older-release handoff).
    [$sc,$so,$se]=priv('qos-engine',null,['status']);$current=json_decode($so,true);
    if($sc!==0||!is_array($current)||empty($current['ok'])){
        flash('Stato QoS non verificabile: nessuna qdisc modificata. '.herr((string)($se?:$so)),'err');break;
    }
    if(($current['state']??'')!=='confirmed'){
        flash('Nessun profilo CAKE confermato da disabilitare.','err');break;
    }
    if((string)($current['version']??'')!==APP_VERSION){
        flash('CAKE appartiene alla release '.herr((string)($current['version']??'sconosciuta')).'. Usare «Verifica e completa migrazione QoS» prima di disabilitare. Nessuna modifica eseguita.','err');break;
    }
    if(empty($current['verified'])){
        flash('Proprietà CAKE/IFB non verificata: disabilitazione sospesa. Nessuna modifica eseguita.','err');break;
    }
    [$c,$o,$e]=priv('qos-engine',null,['disable']);$j=json_decode($o,true);
    $ok=$c===0&&!empty($j['ok']);
    flash($ok?'Profilo CAKE/IFB IPTM disabilitato.':'Disabilitazione respinta: '.herr((string)($j['error']??$e??$o)),$ok?'ok':'err');break;
}
case 'qos_auto_enable':case 'qos_auto_disable': {
    $back='p=sqm';
    if(($_SESSION['role']??'viewer')!=='admin'){flash('Amministratore richiesto','err');break;}
    $cmd=$a==='qos_auto_enable'?'auto-enable':'auto-disable';
    [$c,$o,$e]=priv('qos-engine',null,[$cmd]);$j=json_decode($o,true);
    flash($c===0&&!empty($j['ok'])?'Calibrazione oraria '.($cmd==='auto-enable'?'abilitata':'disabilitata').'. I limiti attivi cambiano solo dopo verifiche sicure.':
          'Calibrazione automatica: '.herr((string)($j['error']??$e??$o)),$c===0&&!empty($j['ok'])?'ok':'err');
    break;
}
case 'upgrade_cleanup_scan': {
    $back='p=sqm';
    if(($_SESSION['role']??'viewer')!=='admin'){flash('Amministratore richiesto','err');break;}
    [$c,$o,$e]=priv('upgrade-cleanup',null,['scan']);$j=json_decode($o,true);
    if($c===0&&!empty($j['ok'])){
        $_SESSION['iptm_cleanup_scan']=['sha256'=>(string)$j['sha256'],'created'=>time()];
        flash('Inventario pulizia aggiornato: '.count((array)($j['removable']??[])).' unità ritirabili senza arrestare servizi attivi.','ok');
    }else flash('Inventario pulizia fallito: '.herr((string)($j['error']??$e??$o)),'err');
    break;
}
case 'upgrade_cleanup_retire': {
    $back='p=sqm';$st=$_SESSION['iptm_cleanup_scan']??null;
    $sha=(string)($_POST['legacy_sha256']??'');
    if(($_SESSION['role']??'viewer')!=='admin'||!is_array($st)||time()-(int)($st['created']??0)>600||
       !preg_match('/^[0-9a-f]{64}$/D',$sha)||!hash_equals((string)$st['sha256'],$sha)){
        flash('Inventario scaduto o cambiato: rigenerare verifica componenti','err');break;
    }
    [$c,$o,$e]=priv('upgrade-cleanup',null,['retire',$sha]);$j=json_decode($o,true);
    if($c===0&&!empty($j['ok'])){
        unset($_SESSION['iptm_cleanup_scan']);
        flash('Unità obsolete archiviate: '.implode(', ',(array)($j['retired']??[])).'. Copie conservate in area root protetta.','ok');
    }else flash('Ritiro legacy rifiutato: '.herr((string)($j['error']??$e??$o)),'err');
    break;
}

}
