<?php
/**
 * DNS/TLS topology planner shared by detection, preview and confirmation.
 * Safe by design: this module never writes an upstream, DNSCrypt, firewall or NFQUEUE rule.
 */
function iptm_dns_wizard_modes(): array {
    return [
        'keep-current'=>['Conserva configurazione attuale','Nessun cambio degli upstream DNS','Nessun prerequisito aggiuntivo'],
        'pihole-unbound'=>['Pi-hole → Unbound','DNSSEC locale e ricorsione diretta','Pi-hole e Unbound locale attivi e verificati'],
        'pihole-dnscrypt'=>['Pi-hole → DNSCrypt','Resolver esterni con trasporto cifrato','Pi-hole e DNSCrypt-Proxy attivi e verificati'],
        'pihole-layered'=>['Doppio livello · Pi-hole → Unbound → DNSCrypt','DNSSEC in Unbound e trasporto cifrato tramite DNSCrypt','Tutti e tre i servizi pronti; Unbound funziona come forwarder'],
    ];
}
function iptm_dns_wizard_capabilities(array $guardState=[]): array {
    $pairs=[]; $verified=false;
    // Reuse the existing cached privileged status; avoid a second slow sudo call on Atom N450.
    if(function_exists('dns_info')) {
        $info=dns_info();
        if(is_array($info) && empty($info['error'])) {
            foreach($info as $key=>$value) if(is_string($key) && is_scalar($value) && strlen((string)$value)<4096)
                $pairs[$key]=(string)$value;
            $verified=isset($pairs['pihole_installed']);
        }
    } else {
        [$rc,$out]=run([BIN_SUDO,'-n',HELPER,'dns-status'],null,14.0,16384);
        if($rc===0) {
            foreach(explode("\n",$out) as $line) {
                if(!str_contains($line,"\t"))continue;
                [$key,$val]=explode("\t",$line,2);
                if(in_array($key,['pihole_installed','pihole_active','unbound_installed','unbound_active',
                        'unbound_check','unbound_dnssec','dnscrypt_installed','dnscrypt_state','dnscrypt_check',
                        'dnscrypt_listener_safe','pihole_upstreams','unbound_dnscrypt_forward'],true))
                    $pairs[$key]=substr(trim($val),0,1024);
            }
            $verified=isset($pairs['pihole_installed']);
        }
    }
    $settings=S_get();
    $wan=(string)($settings['wan_if']??'');$lan=(string)($settings['lan_nets']??'');
    $pihole=($pairs['pihole_installed']??'')==='yes';
    $unbound=($pairs['unbound_installed']??'')==='yes';
    $dnscrypt=($pairs['dnscrypt_installed']??'')==='yes'||!empty($guardState['dnscrypt_installed']);
    $piReady=$pihole && ($pairs['pihole_active']??'')==='active';
    $ubReady=$unbound && ($pairs['unbound_active']??'')==='active' && ($pairs['unbound_check']??'')==='ok' && ($pairs['unbound_dnssec']??'')==='yes';
    $dcReady=$dnscrypt && ($pairs['dnscrypt_state']??'')==='active' && ($pairs['dnscrypt_check']??'')==='ok' && ($pairs['dnscrypt_listener_safe']??'')==='yes';
    $upstream=(string)($pairs['pihole_upstreams']??'');
    $actual='unknown';
    if($verified && !$pihole) $actual='missing';
    elseif($verified && $pihole){
        if(preg_match('/[#:]5335\b/',$upstream))
            $actual=($pairs['unbound_dnscrypt_forward']??'')==='yes'?'pihole-layered':'pihole-unbound';
        elseif(preg_match('/[#:]5053\b/',$upstream))$actual='pihole-dnscrypt';
        elseif($upstream!=='')$actual='external';
    }
    $ready=['keep-current'=>true,'pihole-unbound'=>$piReady&&$ubReady,
        'pihole-dnscrypt'=>$piReady&&$dcReady,'pihole-layered'=>$piReady&&$ubReady&&$dcReady];
    // Preserve a known-good active topology; otherwise propose layered only if all requirements check out.
    $recommended=isset($ready[$actual])&&$ready[$actual]?$actual:
        ($ready['pihole-layered']?'pihole-layered':($ready['pihole-unbound']?'pihole-unbound':
        ($ready['pihole-dnscrypt']?'pihole-dnscrypt':'keep-current')));
    $warnings=[];
    if(!$verified)$warnings[]='Stato DNS non leggibile: le architetture non sono verificate.';
    if($pihole&&!$piReady)$warnings[]='Pi-hole FTL non risulta attivo.';
    if($unbound&&!$ubReady)$warnings[]='Unbound non supera tutti i controlli di attività, configurazione e DNSSEC.';
    if($dnscrypt&&!$dcReady)$warnings[]='DNSCrypt non supera tutti i controlli di attività, configurazione e listener locale.';
    if(!empty($pairs['pihole_env_override'])&&$pairs['pihole_env_override']==='yes')
        $warnings[]='Gli upstream Pi-hole sono governati dall’ambiente FTLCONF_*: IPTM non deve sovrascriverli.';
    if(!empty($guardState['transaction'])&&($guardState['transaction']['state']??'')==='pending')
        $warnings[]='È già in corso una prova DNSCrypt con ripristino temporizzato.';
    return ['verified'=>$verified,'services'=>$pairs,'recommended'=>$recommended,'actual'=>$actual,
        'ready'=>$ready,'wan'=>$wan,'lan'=>$lan,'dnscrypt'=>$dnscrypt,'pihole'=>$pihole,
        'unbound'=>$unbound,'warnings'=>$warnings];
}
function iptm_dns_wizard_normalize(array $p): array {
    $profile=(string)($p['wizard_unbound']??'balanced');
    if(!in_array($profile,['balanced','strict','compatible'],true))throw new InvalidArgumentException('Profilo Unbound non valido');
    $sni=(string)($p['wizard_sni']??'alert');
    if(!in_array($sni,['alert','drop'],true))throw new InvalidArgumentException('Politica SNI non valida');
    if(array_key_exists('wizard_domains',$p) || array_key_exists('wizard_clients',$p) ||
        (string)($p['wizard_antidpi']??'0')==='1' || array_key_exists('wizard_engine',$p))
        throw new InvalidArgumentException('Anti-DPI non fa parte del wizard DNS: apri il pannello dedicato. Nessun profilo salvato.');
    $dnsProfile=(string)($p['wizard_dns_profile']??'keep-current');
    if(!array_key_exists($dnsProfile,iptm_dns_wizard_modes()))throw new InvalidArgumentException('Topologia DNS non valida');
    return ['dns_profile'=>$dnsProfile,'unbound_profile'=>$profile,'sni_mode'=>$sni];
}
/** Preserve a bounded retry draft after a failed preview; never store credentials or unbounded hostlists in PHP sessions. */
function iptm_dns_wizard_retry_capture(array $post,string $error): array {
    $limits=['wizard_dns_profile'=>40,'wizard_unbound'=>32,'wizard_sni'=>24];
    $values=[];$truncated=[];
    foreach($limits as $key=>$limit){
        if(!isset($post[$key])||!is_string($post[$key]))continue;
        $raw=$post[$key];
        if(strlen($raw)>$limit){$truncated[]=$key;$raw=substr($raw,0,$limit);}
        $values[$key]=$raw;
    }
    return ['until'=>time()+600,'values'=>$values,'error'=>substr($error,0,300),
        'truncated'=>$truncated];
}
function iptm_dns_wizard_summary(array $plan,array $cap): array {
    $warnings=$cap['warnings'];$mode=$plan['dns_profile'];
    if($mode!=='keep-current'&&!$cap['verified'])$warnings[]='Lo stato DNS non è verificato: non applicare il percorso proposto.';
    if($mode!=='keep-current'&&empty($cap['ready'][$mode]))
        $warnings[]='Il percorso selezionato non ha tutti i prerequisiti pronti: utilizza la diagnostica DNS prima di attivarlo.';
    if($mode==='pihole-layered')$warnings[]='Doppio livello: Unbound inoltra a DNSCrypt, non esegue ricorsione diretta. DNSSEC resta validato da Unbound.';
    if($plan['sni_mode']==='drop')$warnings[]='SNI DROP è solo una proposta: IPS inline ed ECH non sono verificati.';
    $warnings[]='ANTEPRIMA: nessuna variazione di Pi-hole, Unbound, DNSCrypt, iptables o NFQUEUE.';
    return array_values(array_unique($warnings));
}
function pg_dns_tls_wizard(array $guardState): void {
    $cap=iptm_dns_wizard_capabilities($guardState);$admin=($_SESSION['role']??'viewer')==='admin';
    $modes=iptm_dns_wizard_modes();$last=$_SESSION['iptm_dns_wizard_plan']??null;
    $actual=$cap['actual'];$suggested=$cap['recommended'];
    $retry=$_SESSION['iptm_dns_wizard_retry']??null;
    $retry=is_array($retry)&&($retry['until']??0)>=time()?$retry:null;
    $values=is_array($retry['values']??null)?$retry['values']:[];
    $choose=static function(string $key,string $fallback='')use($values):string {
        $candidate=$values[$key]??$fallback;
        return is_string($candidate)?$candidate:$fallback;
    };
    $actualLabel=isset($modes[$actual])?$modes[$actual][0]:($actual==='external'?'Upstream esterno o personalizzato':($actual==='missing'?'Pi-hole assente':'Non verificato'));
    echo '<section class="card iptm-dns-setup" id="dns-tls-wizard"><div class="iptm-dns-setup-head"><div><h2>Configurazione guidata DNS e privacy</h2><p>Configura il DNS senza cambiare subito la rete.</p></div><span class="b b-ACCEPT">Anteprima sicura</span></div>';
    echo '<p class="mut">Uso rapido: <b>1.</b> scegli Pi-hole → Unbound → DNSCrypt (o conserva l’esistente), <b>2.</b> genera anteprima, <b>3.</b> abilita soltanto la protezione desiderata dai controlli sottostanti. <a href="#dns-sni-live">TLS/SNI operativo</a> · <a href="#dns-zapret-manager">Anti-DPI operativo</a> · <a href="#dns-resolver-advanced">DNSCrypt</a>.</p>';
    echo '<div class="iptm-dns-detected"><div><small>Architettura rilevata</small><strong>'.h($actualLabel).'</strong></div><div><small>Pi-hole</small><strong>'.h($cap['services']['pihole_active']??'n/d').'</strong></div><div><small>Unbound</small><strong>'.h($cap['services']['unbound_active']??'n/d').'</strong></div><div><small>DNSCrypt</small><strong>'.h($cap['services']['dnscrypt_state']??'n/d').'</strong></div></div>';
    if(!$cap['verified'])echo '<div class="msg warn">Rilevamento non disponibile. Puoi esplorare i profili, ma non considerarli pronti per l’applicazione.</div>';
    if($cap['warnings']){echo '<details class="iptm-dns-inline"><summary>Avvertenze e prerequisiti ('.count($cap['warnings']).')</summary><ul>';foreach($cap['warnings'] as $w)echo '<li>'.h($w).'</li>';echo '</ul></details>';}
    if(!$admin){echo '<p>Modalità di sola lettura: nessun salvataggio disponibile.</p></section>';return;}
    if($retry){
        echo '<div class="msg warn" role="alert">Anteprima da correggere: '.h((string)($retry['error']??'')).'. I campi sono stati ripristinati per una nuova verifica.</div>';
        if(!empty($retry['truncated']))echo '<p class="mut">Alcuni campi molto lunghi non sono stati ripristinati integralmente: reinseriscili prima di salvare.</p>';
    }
    echo '<form method="post" id="iptm-dns-wizard">'.fh('p=dnsguard').'<input type="hidden" name="action" value="dns_wizard_plan">';
    echo '<h3>1. Scegli l’architettura DNS</h3><p class="mut">Pi-hole usa la porta 53. Gli altri componenti comunicano in locale.</p>';
    echo '<fieldset class="dns-profile-fieldset"><legend class="sr-only">Architettura DNS da proporre</legend><div class="dns-profile-grid">';
    foreach($modes as $value=>$descriptions){
        [$title,$purpose,$prereq]=$descriptions;
        $status=$value==='keep-current'?'Nessuna modifica':(!empty($cap['ready'][$value])?'Prerequisiti verificati':'Da verificare');
        $selected=$choose('wizard_dns_profile',$suggested)===$value?' checked':'';
        $chip=$value===$actual?'<em>In uso</em>':($value===$suggested?'<em>Consigliato</em>':'');
        echo '<label class="dns-profile-option"><input type="radio" name="wizard_dns_profile" value="'.h($value).'"'.$selected.'><span class="dns-profile-body"><strong>'.h($title).$chip.'</strong><span class="dns-profile-desc">'.h($purpose).'</span><span class="dns-profile-prereq">'.h($status).' · '.h($prereq).'</span></span></label>';
    }
    echo '</div></fieldset>';
    echo '<details class="iptm-dns-inline" id="dns-extra-privacy"><summary>2. Protezioni avanzate · facoltative</summary>';
    echo '<div class="iptm-dns-form-grid"><label class="fl">Profilo Unbound<select name="wizard_unbound"><option value="balanced"'.($choose('wizard_unbound','balanced')==='balanced'?' selected':'').'>Bilanciato (consigliato)</option><option value="compatible"'.($choose('wizard_unbound','balanced')==='compatible'?' selected':'').'>Compatibilità</option><option value="strict"'.($choose('wizard_unbound','balanced')==='strict'?' selected':'').'>Restrittivo (da testare)</option></select></label>';
    echo '<label class="fl">Analisi TLS/SNI<select name="wizard_sni"><option value="alert"'.($choose('wizard_sni','alert')==='alert'?' selected':'').'>Solo osservazione (consigliato)</option><option value="drop"'.($choose('wizard_sni','alert')==='drop'?' selected':'').'>Proposta blocco IPS (non attiva)</option></select></label></div>';
    echo '<p class="mut">Queste sono proposte: per applicare Unbound o DNSCrypt usa i controlli dedicati. ECH può nascondere l’SNI.</p></details>';
    echo '<p class="mut">3. Anti-DPI è indipendente dall’architettura DNS: <a href="#dns-zapret-manager"><b>apri la configurazione unica Zapret2/classico e la prova con rollback</b></a>. Non è necessario configurarlo per applicare DNS.</p>';
    echo '<div class="iptm-dns-next"><button class="g" type="submit">Genera anteprima della configurazione</button><span class="mut">Nessuna modifica a DNS, servizi o firewall</span></div></form>';
    if(is_array($last)&&!empty($last['hash'])&&(int)($last['until']??0)>=time()){
        echo '<div class="iptm-dns-preview"><h3>Anteprima pronta · non applicata</h3><p>Valida fino alle '.h(date('H:i:s',(int)$last['until'])).'.</p>';
        foreach($last['warnings'] as $w)echo '<p class="mut">• '.h($w).'</p>';
        $summary=$last['plan'];
        if(is_array($summary))unset($summary['antidpi']); // old 4.3.6 session plans are DNS-only here
        echo '<details class="iptm-dns-inline"><summary>Dettagli tecnici della proposta</summary><pre>'.h(json_encode($summary,JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES)).'</pre></details>';
        if(($last['plan']['dns_profile']??'keep-current')!=='keep-current'){
            $target=['pihole-unbound'=>'unbound','pihole-dnscrypt'=>'dnscrypt','pihole-layered'=>'layered'];
            $mode=$target[(string)$last['plan']['dns_profile']]??'';
            if($mode!=='')echo '<p><a class="btn g" href="?p=dns&amp;dns_target='.h($mode).'#dns-architecture">Apri applicazione architettura DNS · conferma separata</a></p>';
        }
        echo '</div>';
    }
    echo '</section>';
}
