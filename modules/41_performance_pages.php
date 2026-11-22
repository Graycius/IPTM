<?php
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
    echo '<section class="card"><h3>Proxy caching locale · HTTP / HTTPS CONNECT</h3>';
    echo '<p class="mut">La cache riutilizza le risposte HTTP cacheable. HTTPS resta cifrato attraverso CONNECT e <b>non</b> viene intercettato o memorizzato. Le CDN pubbliche restano quelle già scelte dai servizi DNS e dai siti: non viene creata una CDN privata.</p>';
    if(!is_array($cache)||empty($cache['ok'])){
        echo '<p class="msg err">Stato proxy non disponibile: '.h(herr((string)($ce??$co))).'</p></section>';return;
    }
    echo '<p>Squid: <b>'.(!empty($cache['installed'])?'installato':'non installato').'</b> · Servizio IPTM: <b>'.(!empty($cache['active'])?'attivo':'inattivo').'</b> · TLS: <b>nessuna intercettazione</b></p>';
    $prof=(array)($cache['profile']??[]);
    if(!empty($prof['listen_ip'])) echo '<p>Proxy esplicito: <code>'.h((string)$prof['listen_ip']).':'.(int)($prof['port']??3128).'</code>. Configurare questo indirizzo/porta sui soli client autorizzati.</p>';
    if(empty($cache['installed']))echo '<p class="mut">Squid non installato. <a href="?p=progs#tool-squid">Installa Squid da Strumenti → Programmi</a>, quindi torna qui per configurare e attivare il proxy con conferma esplicita. HTTPS non viene intercettato.</p>';
    if($admin){
        $ifaces=array_keys(sys_ifaces());
        echo '<form method="post" class="row">'.fh('p=performance').'<input type=hidden name=action value=cache_proxy_stage>';
        echo '<label>Interfaccia LAN<select name=interface>';foreach($ifaces as $ifc)echo '<option value="'.h($ifc).'"'.(($prof['interface']??'')===$ifc?' selected':'').'>'.h($ifc).'</option>';echo '</select></label>';
        echo '<label>IPv4 di ascolto (già assegnato alla LAN)<input name=listen_ip required placeholder="192.168.1.1" value="'.h((string)($prof['listen_ip']??'')).'"></label>';
        echo '<label>Subnet LAN autorizzate, una per riga<textarea name=allowed_nets rows=3 required placeholder="192.168.1.0/24">'.h(implode("\n",(array)($prof['allowed_nets']??[]))).'</textarea></label>';
        echo '<label>Porta<input type=number name=port min=1024 max=65535 value="'.(int)($prof['port']??3128).'" required></label>';
        echo '<label>Cache disco MiB<input type=number name=disk_mib min=64 max=1024 value="'.(int)($prof['disk_mib']??128).'" required></label>';
        echo '<label>Cache RAM MiB<input type=number name=memory_mib min=8 max=64 value="'.(int)($prof['memory_mib']??16).'" required></label>';
        echo '<button type=submit class=s>Verifica e prepara proxy</button></form>';
        $pending=$_SESSION['iptm_cache_proxy_stage']??null;
        if(is_array($pending)&&time()-(int)($pending['created']??0)<600&&preg_match('/^[a-f0-9]{64}$/D',(string)($pending['hash']??''))){
            echo '<div class="msg warn">Anteprima proxy disponibile. Nessun servizio o regola modificato.</div>';
            echo '<form method="post">'.fh('p=performance').'<input type=hidden name=action value=cache_proxy_apply><input type=hidden name=cache_sha256 value="'.h((string)$pending['hash']).'"><button class=g>Conferma e attiva proxy LAN</button></form>';
        }
        if(!empty($cache['active'])){
            echo '<form method="post">'.fh('p=performance').'<button class=s name=action value=cache_proxy_firewall_draft>Aggiungi alla bozza regola INPUT riservata alle LAN</button></form>';
            echo '<form method="post">'.fh('p=performance').'<button class=d name=action value=cache_proxy_disable>Disabilita proxy IPTM</button></form>';
        }
    }
    echo '<p class="mut">Il proxy non imposta gateway, NAT, iptables, DNS o configurazioni dei browser. Per Pi-hole/Unbound e cache DNS usa <a href="?p=dns">Resolver DNS</a>.</p></section>';
}
