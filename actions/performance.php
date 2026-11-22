<?php
/* Explicit opt-in LAN proxy operations; never touches iptables/CAKE. */
switch ($a) {
case 'cache_proxy_stage': {
    $back='p=performance';
    if(($_SESSION['role']??'viewer')!=='admin'){flash('Accesso amministratore richiesto.','err');break;}
    $keys=['port','disk_mib','memory_mib'];$data=[];
    foreach($keys as $key){
        $raw=filter_var($_POST[$key]??null,FILTER_VALIDATE_INT);
        if($raw===false||$raw===null){flash('Valore proxy non valido: '.$key,'err');break 2;}
        $data[$key]=$raw;
    }
    foreach (['interface','listen_ip','allowed_nets'] as $key) {
        if(!isset($_POST[$key])||!is_string($_POST[$key])){flash('Campo proxy non valido: '.$key,'err');break 2;}
    }
    $data['interface']=$_POST['interface'];$data['listen_ip']=$_POST['listen_ip'];
    $mode=$_POST['intercept_http']??'0';
    if(!is_string($mode)||!in_array($mode,['0','1'],true)){
        flash('Modalità proxy non valida.','err');break;
    }
    $data['intercept_http']=$mode==='1';
    $nets=(string)($_POST['allowed_nets']??'');
    if(strlen($nets)>500){flash('Elenco LAN troppo lungo.','err');break;}
    $data['allowed_nets']=array_values(array_filter(array_map('trim',preg_split('/[\r\n,;]+/',$nets)),fn($n)=>$n!==''));
    [$rc,$out,$err]=priv('cache-proxy',json_encode($data,JSON_THROW_ON_ERROR),['stage']);
    $result=json_decode($out,true);
    if($rc!==0||!is_array($result)||empty($result['ok'])||!preg_match('/^[a-f0-9]{64}$/D',(string)($result['sha256']??''))){
        unset($_SESSION['iptm_cache_proxy_stage']);flash('Anteprima proxy rifiutata: '.herr((string)($result['error']??$out.$err)),'err');break;
    }
    $_SESSION['iptm_cache_proxy_stage']=['hash'=>$result['sha256'],'created'=>time()];
    flash('Preferenze proxy salvate e anteprima pronta. Nessuna regola o servizio modificato.','ok');break;
}
case 'cache_proxy_apply': {
    $back='p=performance';$pending=$_SESSION['iptm_cache_proxy_stage']??null;$hash=(string)($_POST['cache_sha256']??'');
    if(($_SESSION['role']??'viewer')!=='admin'||!is_array($pending)||time()-(int)($pending['created']??0)>600||
        !preg_match('/^[a-f0-9]{64}$/D',$hash)||!hash_equals((string)$pending['hash'],$hash)){
        flash('Anteprima del proxy assente o scaduta.','err');break;
    }
    [$rc,$out,$err]=priv('cache-proxy',null,['apply',$hash]);$result=json_decode($out,true);
    if($rc!==0||empty($result['ok'])){flash('Attivazione proxy non riuscita: '.herr((string)($result['error']??$out.$err)),'err');break;}
    unset($_SESSION['iptm_cache_proxy_stage']);flash(!empty($result['redirect'])?'Proxy HTTP trasparente attivo sulla LAN (solo TCP/80).':'Proxy esplicito attivato: configura il client con l’indirizzo indicato.','ok');break;
}
case 'cache_proxy_firewall_draft': {
    $back='p=performance';
    if(($_SESSION['role']??'viewer')!=='admin'){flash('Amministratore richiesto.','err');break;}
    [$rc,$out,$err]=priv('cache-proxy',null,['status']);
    $status=$rc===0?json_decode($out,true):null;
    if(!is_array($status)||empty($status['ok'])||empty($status['active'])){
        flash('Prima attiva un proxy LAN verificato.','err');break;
    }
    $profile=(array)($status['applied_profile']??[]);
    $iface=(string)($profile['interface']??'');
    $ip=(string)($profile['listen_ip']??'');
    $port=$profile['port']??null;
    $nets=(array)($profile['allowed_nets']??[]);
    if(!preg_match('/^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$/D',$iface)||
       filter_var($ip,FILTER_VALIDATE_IP,FILTER_FLAG_IPV4)===false||
       !is_int($port)||$port<1024||$port>65535||!$nets||count($nets)>8){
        flash('Profilo proxy non attendibile.','err');break;
    }
    $lines=[];
    foreach($nets as $net){
        if(!is_string($net)||!preg_match('~^(?:[0-9]{1,3}\.){3}[0-9]{1,3}/(?:1[6-9]|2[0-9]|3[0-2])$~D',$net)){
            flash('Subnet LAN non verificata.','err');break 2;
        }
        $lines[]='-A INPUT -i '.$iface.' -s '.$net.' -d '.$ip.'/32 -p tcp --dport '.$port.' -m conntrack --ctstate NEW -j ACCEPT';
    }
    $draft=get_draft();
    if(str_contains($draft,'# >>> IPTM:cache-proxy-allow')){
        flash('Regole proxy già presenti in bozza: controlla prima il contenuto.','err');break;
    }
    $marker='# >>> IPTM:final-input';$at=strpos($draft,$marker);
    if($at===false||substr_count($draft,$marker)!==1||!str_contains($draft,'*filter')){
        flash('Impossibile trovare la sezione INPUT prima del DROP finale: nessuna modifica.','err');break;
    }
    $block='# >>> IPTM:cache-proxy-allow - Proxy locale solo da LAN (verificare prima di Apply)' . "\n"
        .implode("\n",$lines)."\n".'# <<< IPTM:cache-proxy-allow'."\n";
    if(!put_draft(substr($draft,0,$at).$block.substr($draft,$at))){
        flash('Salvataggio bozza non riuscito.','err');break;
    }
    audit('Proxy LAN: aggiunta accesso ristretto in bozza, nessuna regola applicata');
    flash('Regole INPUT del proxy aggiunte solo alla bozza. Verifica in Regole e applica con watchdog.','ok');
    break;
}
case 'cache_proxy_disable': {
    $back='p=performance';
    if(($_SESSION['role']??'viewer')!=='admin'){flash('Accesso amministratore richiesto.','err');break;}
    unset($_SESSION['iptm_cache_proxy_stage']);
    [$rc,$out,$err]=priv('cache-proxy',null,['disable']);$result=json_decode($out,true);
    flash($rc===0&&!empty($result['ok'])?'Proxy IPTM disabilitato.':'Disabilitazione proxy fallita: '.herr((string)($result['error']??$out.$err)),$rc===0&&!empty($result['ok'])?'ok':'err');break;
}
}
