<?php
/** Choose one actual private IPv4 address/subnet; never guess a gateway. */
function iptm_proxy_form_defaults(array $interfaces, array $saved): array {
    $best=null;
    foreach ($interfaces as $iface=>$cidrs) {
        if (!is_string($iface)||!preg_match('/^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$/D',$iface)||!is_array($cidrs))continue;
        foreach ($cidrs as $cidr) {
            if(!is_string($cidr)||!preg_match('~^((?:[0-9]{1,3}\.){3}[0-9]{1,3})/(\d{1,2})$~D',$cidr,$m))continue;
            $ip=$m[1];$prefix=(int)$m[2];
            if($prefix<16||$prefix>32||filter_var($ip,FILTER_VALIDATE_IP,FILTER_FLAG_IPV4)===false)continue;
            $parts=array_map('intval',explode('.',$ip));
            $private=$parts[0]===10||($parts[0]===172&&$parts[1]>=16&&$parts[1]<=31)||($parts[0]===192&&$parts[1]===168);
            if(!$private)continue;
            $net=net_of($cidr);
            $serverIp=$_SERVER['SERVER_ADDR']??'';
            $score=($ip===$serverIp?10:0)+(preg_match('/^(?:wg|tun|tap|docker|veth|ifb)/i',$iface)?0:1);
            if($best===null||$score>$best['score'])$best=['score'=>$score,'interface'=>$iface,'listen_ip'=>$ip,'allowed_nets'=>[$net]];
        }
    }
    $defaults=$best??['interface'=>'','listen_ip'=>'','allowed_nets'=>[]];unset($defaults['score']);
    $defaults+=['port'=>3129,'disk_mib'=>128,'memory_mib'=>16,'intercept_http'=>true];
    foreach(['interface','listen_ip','allowed_nets','port','disk_mib','memory_mib','intercept_http'] as $key) {
        if(array_key_exists($key,$saved))$defaults[$key]=$saved[$key];
    }
    return $defaults;
}

/** Read-only rules cost audit and explicit, opt-in LAN cache proxy. */
function pg_performance(): void {
    $admin=($_SESSION['role']??'viewer')==='admin';
    $scope=(($_GET['scope']??'draft')==='kernel')?'kernel':'draft';
    if($scope==='kernel') {
        [$r,$rules,$e]=priv('save');
        if($r!==0) $rules='';
    } else $rules=get_draft();
    $audit=null;$error='';
    if(trim((string)$rules)!=='') {
        [$r,$raw,$e]=priv('rules-performance',(string)$rules);
        $audit=$r===0?json_decode($raw,true):null;
        if(!is_array($audit)||empty($audit['ok']))$error=herr((string)($audit['error']??$e??$raw));
    } else $error='Rules non disponibili. Non vengono inventati risultati o modificato il firewall.';
    echo '<div class="hero"><h2>Prestazioni rete · Rules e cache HTTP</h2><p>Analisi degli overhead delle regole attive o della bozza, e proxy di cache locale facoltativo per i client LAN.</p></div>';
    echo '<section class="card"><h3>Analisi costi delle regole firewall</h3><p class="mut">L’audit è in sola lettura; i risultati segnalano rischi di prestazioni, non equivalgono a un benchmark o a una valutazione di sicurezza completa.</p>';
    echo '<nav class="row"><a class="btn" href="?p=performance&amp;scope=draft">Analizza bozza</a> <a class="btn" href="?p=performance&amp;scope=kernel">Analizza kernel attivo</a></nav>';
    echo '<p>Origine: <b>'.($scope==='kernel'?'kernel iptables-save':'bozza non applicata').'</b></p>';
    if($error!=='')echo '<p class="msg err">'.h($error).'</p>';
    if(is_array($audit)&&!empty($audit['ok'])){
        $c=(array)($audit['counts']??[]);
        echo '<div class="tiles">'.tile('Regole',(string)(int)($c['rules']??0),'Viste nel dump')
            .tile('Logging',(string)(int)($c['logging']??0),'Possibile carico CPU e disco')
            .tile('IPSet',(string)(int)($c['ipset_lookups']??0),'Verifiche nelle catene')
            .tile('Limiti DROP',(string)(int)($c['rate_drops']??0),'Possibile degrado TCP').'</div>';
        echo '<table><thead><tr><th>Priorità</th><th>Elemento</th><th>Effetto e proposta</th></tr></thead><tbody>';
        foreach(array_slice((array)($audit['findings']??[]),0,25) as $finding) {
            if(!is_array($finding))continue;
            echo '<tr><td>'.h((string)($finding['priority']??'')).'</td><td><b>'.h((string)($finding['title']??'')).'</b></td><td>'.h((string)($finding['detail']??'')).'<p class="mut">'.h((string)($finding['recommendation']??'')).'</p><p class="mut">Sicurezza: '.h((string)($finding['security_tradeoff']??'')).'</p></td></tr>';
        }
        echo '</tbody></table><p class="mut">Nessuna opzione viene disattivata automaticamente. Confronta throughput, RTT e contatori prima/dopo.</p>';
    }
    echo '<p><a class="btn" href="?p=security">Modifica le impostazioni di sicurezza</a> <a class="btn" href="?p=sqm">Gestisci CAKE e calibrazione</a></p></section>';
    [$cr,$co,$ce]=priv('cache-proxy',null,['status']);
    $cache=$cr===0?json_decode($co,true):null;
    echo '<section class="card"><h3>Proxy Squid · cache HTTP e intercettazione LAN</h3>';
    echo '<p class="mut">Modalità trasparente: quando IPTM è il gateway dei client, intercetta automaticamente soltanto HTTP TCP/80 con regole dedicate iptables/NAT. HTTPS/443 non viene decifrato, intercettato o memorizzato. Puoi anche scegliere il proxy esplicito o disabilitare tutto.</p>';
    if(!is_array($cache)||empty($cache['ok'])){
        echo '<p class="msg err">Stato proxy non disponibile: '.h(herr((string)($ce??$co))).'</p></section>';return;
    }
    echo '<p>Pacchetto Squid: <b>'.(!empty($cache['package_installed'])?'installato':'non verificato').'</b> · Binario: <b>'.(!empty($cache['installed'])?'verificato':'non trovato').'</b> · Proxy IPTM: <b>'.(!empty($cache['active'])?'attivo':'inattivo').'</b> · HTTP trasparente: <b>'.(!empty($cache['intercept_active'])?'attivo':'disattivato').'</b></p>';
    if(!empty($cache['binary']))echo '<p class=mut>Binario verificato: <code>'.h((string)$cache['binary']).'</code></p>';
    if(!empty($cache['warning']))echo '<div class="msg warn">'.h((string)$cache['warning']).'</div>';
    if(!empty($cache['pending_changes']))echo '<p class="msg warn">Preferenze salvate: le modifiche non sono ancora applicate al servizio.</p>';
    $prof=(array)($cache['profile']??[]);
    if(!empty($prof['listen_ip']))echo '<p>Indirizzo LAN: <code>'.h((string)$prof['listen_ip']).':'.(int)($prof['port']??3129).'</code>. '.(!empty($prof['intercept_http'])?'Nessuna modifica richiesta al browser HTTP se questo host è il gateway.':'Modalità esplicita: configurare il proxy nel client.').'</p>';
    if(empty($cache['installed']))echo '<p class="mut">Il binario Squid non è verificabile: <a href="?p=progs#tool-squid">verifica o reinstalla da Strumenti → Programmi</a>. Le preferenze possono comunque essere salvate senza attivare il servizio. Se APT indica installato, controlla <code>dpkg -L squid</code> e <code>command -v squid</code>.</p>';
    if($admin){
        $ifdata=sys_ifaces();$form=iptm_proxy_form_defaults($ifdata,$prof);
        echo '<form method="post" class="row">'.fh('p=performance').'<input type=hidden name=action value=cache_proxy_stage>';
        echo '<label>Interfaccia LAN<select name=interface required>';
        foreach(array_keys($ifdata) as $ifc)echo '<option value="'.h($ifc).'"'.($form['interface']===$ifc?' selected':'').'>'.h($ifc).'</option>';
        echo '</select></label>';
        echo '<label>IPv4 di ascolto (indirizzo di IPTM sulla LAN)<input name=listen_ip required value="'.h((string)$form['listen_ip']).'" placeholder="192.168.1.165"></label>';
        echo '<label>Subnet LAN autorizzate<textarea name=allowed_nets rows=3 required>'.h(implode("\n",(array)$form['allowed_nets'])).'</textarea></label>';
        echo '<label>Porta HTTP Squid<input type=number name=port min=1024 max=65535 value="'.(int)$form['port'].'" required></label>';
        echo '<label>Cache disco MiB<input type=number name=disk_mib min=64 max=1024 value="'.(int)$form['disk_mib'].'" required></label>';
        echo '<label>Cache RAM MiB<input type=number name=memory_mib min=8 max=64 value="'.(int)$form['memory_mib'].'" required></label>';
        echo '<label><input type=hidden name=intercept_http value=0><input type=checkbox name=intercept_http value=1'.(!empty($form['intercept_http'])?' checked':'').'> Intercettazione HTTP automatica (solo gateway/LAN; disattivabile)</label>';
        echo '<button type=submit class=s>Salva preferenze e prepara anteprima</button></form>';
        $pending=$_SESSION['iptm_cache_proxy_stage']??null;
        if(is_array($pending)&&time()-(int)($pending['created']??0)<600&&preg_match('/^[a-f0-9]{64}$/D',(string)($pending['hash']??''))){
            echo '<div class="msg warn">Anteprima proxy disponibile. Nessun servizio o regola modificato.</div>';
            echo '<form method="post">'.fh('p=performance').'<input type=hidden name=action value=cache_proxy_apply><input type=hidden name=cache_sha256 value="'.h((string)$pending['hash']).'"><button class=g>Conferma attivazione proxy / HTTP trasparente</button></form>';
        }
        if(!empty($cache['active'])&&!empty($prof)&&empty($prof['intercept_http'])){
            echo '<form method="post">'.fh('p=performance').'<button class=s name=action value=cache_proxy_firewall_draft>Aggiungi alla bozza regola INPUT riservata alle LAN</button></form>';

        }
        echo '<form method="post">'.fh('p=performance').'<button class=d name=action value=cache_proxy_disable>Disattiva proxy e intercettazione (anche se già disattivati)</button></form>';
    }
    echo '<p class="mut">Il proxy non modifica il gateway dei dispositivi, né i DNS o le impostazioni del browser. Nella modalità trasparente aggiunge <b>solo</b> regole iptables limitate a HTTP/80 e alla LAN: funziona se il traffico passa realmente attraverso IPTM. Per la <b>cache delle risposte DNS</b> di Pi-hole, Unbound o DNSCrypt usa <a href="?p=dns">Resolver DNS</a>: non è una cache dei contenuti HTTPS.</p></section>';
}
