<?php
function pg_v6convert(): void {
    $result=$_SESSION['v6_convert']??null;
    echo '<div class=hero><h2>Convertitore IPv4 → IPv6</h2><p>Prepara soltanto un’anteprima. Gli indirizzi IPv4 non hanno equivalenti IPv6 automatici: indica le corrispondenze, controlla le regole scartate e valida manualmente con ip6tables-restore.</p></div>';
    echo '<div class=card><form method=post>'.fh('p=v6convert').'<input type=hidden name=action value=ipv4_convert_preview>';
    echo '<label class=fl>Regole IPv4 da analizzare<textarea name=source_v4 rows=10 maxlength=131072 placeholder="*filter&#10;:INPUT ACCEPT [0:0]&#10;-A INPUT -p tcp --dport 22 -j ACCEPT&#10;COMMIT"></textarea></label>';
    echo '<label class=fl>Mapping indirizzi (una riga IPv4 = IPv6 per ciascuna rete)<textarea name=address_map rows=4 maxlength=8192 placeholder="192.168.1.0/24 = fd00:1::/64"></textarea></label>';
    echo '<p class=mut>Non converte automaticamente NAT IPv4, moduli specifici IPv4, ICMPv4 e target non supportati. Non deduce l’IPv6 dei dispositivi. Non tocca il firewall.</p><button class=g>Genera anteprima</button></form></div>';
    if(!is_array($result))return;
    echo '<div class=card><h3>Risultato: '.(int)$result['converted'].' regole convertite, '.count($result['skipped']).' scartate</h3>';
    if($result['skipped']){echo '<div class="msg warn"><b>Conversione parziale: non applicare senza revisione.</b></div><details open><summary>Regole da convertire manualmente</summary><pre>'.h(implode("\n",$result['skipped'])).'</pre></details>';}
    echo '<label class=fl>Anteprima ip6tables-restore<textarea rows=12 readonly>'.h($result['text']).'</textarea></label><p class=mut>Per applicare, verifica nella pagina IPv6; non è prevista una conversione diretta in produzione.</p></div>';
}

function pg_unbound_hardening(): void {
    $admin=($_SESSION['role']??'viewer')==='admin';
    echo '<div class=hero><div><h2>Hardening Unbound</h2><p>Protegge la riservatezza delle richieste DNS ricorsive. Non modifica le porte, gli upstream o Pi-hole. Salva un backup e verifica la sintassi prima del reload.</p></div></div>';
    echo '<div class=card><h3>Scegli un profilo</h3><p><b>Bilanciato:</b> minimizzazione QNAME, DNSSEC e privacy con compatibilità elevata. <b>Restrittivo:</b> minimizzazione rigorosa, può interrompere alcuni domini. <b>Compatibile:</b> evita opzioni che possono causare incompatibilità.</p>';
    echo '<form method=post>'.fh('p=unbound').'<input type=hidden name=action value=dns_unbound_harden>';
    echo '<label class=fl>Profilo Unbound<select name=unbound_profile><option value=balanced>Bilanciato (consigliato)</option><option value=strict>Restrittivo (verifica DNS prima di confermare)</option><option value=compatible>Compatibilità</option></select></label>';
    echo '<p class=mut>Il controllo esegue unbound-checkconf e, se il servizio è attivo, prova a ricaricarlo. Una verifica fallita tenta il rollback. Le modifiche non sovrascrivono configurazioni Unbound create da altri strumenti.</p>';
    echo '<button class=g '.($admin?'':'disabled').'>Verifica e applica hardening</button></form></div>';
    echo '<div class=card><h3>Parametri gestiti</h3><p>Nasconde identità e versione del resolver, attiva harden-glue e harden-dnssec-stripped, minimizza i nomi interrogati, riduce le risposte e disattiva log-queries/log-replies. DNSSEC richiede un trust anchor valido, da verificare separatamente.</p></div>';
}

/** RethinkDNS-inspired LAN client flow visibility, no app attribution. */
function pg_device_insights(): void {
    echo '<div class=hero><h2>Attività dispositivi · connessioni</h2><p>Come il monitor di rete RethinkDNS, ma per i client visti dal router: panoramica delle connessioni tracciate, senza leggere payload o attribuire traffico alle app Android.</p></div>';
    [$rc,$out,$err]=priv('device-insights');
    $j=$rc===0?json_decode($out,true):null;
    if(!is_array($j) || empty($j['ok'])) {echo '<div class="msg warn">Non è possibile leggere la tabella conntrack o i vicini IP. Verifica conntrack e ip neigh sul gateway. Nessun dato inventato.</div>';return;}
    echo '<div class=card><h3>Connessioni tracciate</h3><p class=mut>Origine dati: '.h($j['source']??'').'; dispositivi riconosciuti: '.(int)($j['neighbours']??0).'; flussi associati: '.(int)($j['connections']??0).'.'.(!empty($j['partial'])?' Campione parziale: lettura limitata a 1 MB.':'').'</p>';
    echo '<table><thead><tr><th>Client IPv4</th><th>MAC</th><th>Flussi</th><th>TCP/UDP</th><th>DNS/DoT/HTTPS</th></tr></thead><tbody>';
    foreach(array_slice($j['devices']??[],0,40) as $d) {
      if(!is_array($d))continue;
      echo '<tr><td>'.iptm_ip_html((string)($d['ip']??'')).'</td><td>'.h((string)($d['mac']??'')).'</td><td>'.(int)($d['connections']??0).'</td><td>'.(int)($d['tcp']??0).'/'.(int)($d['udp']??0).'</td><td>'.(int)($d['dns']??0).'/'.(int)($d['dot']??0).'/'.(int)($d['https']??0).'</td></tr>';
    }
    echo '</tbody></table><p class=mut>Questi numeri descrivono connessioni, non byte, richieste DNS o applicazioni. Il traffico fra client della stessa LAN che non attraversa DietPi potrebbe non essere visibile. I blocchi per MAC si impostano in Zone di rete.</p></div>';
}


/** DNSCrypt pinned resolver failover and non-mutating TLS/DPI planning. */
function pg_dns_guard(): void {
    $admin = ($_SESSION['role']??'viewer')==='admin';
    [$rc,$out,$err]=priv('dns-guard',null,['status']);
    $state=$rc===0?json_decode($out,true):null;
    $state=is_array($state)?($state['result']??[]):[];
    $recommended=(array)($state['recommended_presets']??[]);
    if(!empty($state['obsolete_doh_option'])) {
        echo '<div class="card"><h3>DNSCrypt: parametro non compatibile con la versione installata</h3>';
        echo '<p>È presente <code>doh_check_cert_hashes_on_connect</code>, assente in DNSCrypt 2.1.8. La riparazione rimuove soltanto questa direttiva, crea un backup e avvia un rollback temporizzato.</p>';
        if($admin) echo '<form method="post">'.fh('p=dnsguard').'<input type="hidden" name="action" value="dnscrypt_compat_repair"><button class="g">Ripara compatibilità DNSCrypt</button></form>';
        echo '</div>';
    }

    $initial=(array)($_SESSION['dns_guard_fields']??[]);
    $primary=(string)($initial['primary_stamp']??$recommended['primary_stamp']??'');
    $secondary=(string)($initial['secondary_stamp']??$recommended['secondary_stamp']??'');
    $bootstrap=implode("\n",(array)($initial['bootstrap']??[]));
    $timeout=(int)($initial['timeout']??5);
    $ready=$_SESSION['dns_guard_ready']??null;
    $canApply=$admin && is_array($ready) && (int)($ready['until']??0)>=time();
    echo '<div class=hero><h2>DNS e TLS · resilienza e privacy</h2><p>Scegli la catena DNS, controlla i servizi e prepara le impostazioni con un unico wizard. Le funzioni avanzate sono raccolte sotto, senza modifiche automatiche.</p></div>';
    pg_dns_tls_wizard($state);
    [$z2rc,$z2out]=priv('zapret2',null,['status']);
    $z2=$z2rc===0?json_decode($z2out,true):null;
    if(!is_array($z2) || empty($z2['ok']))$z2=[];
    $z2state=empty($z2['ok'])?'stato non verificabile (helper/permessi)':(!empty($z2['installed'])?'installato (IPTM)':(!empty($z2['external_detected'])?'rilevato esternamente (non gestito)':'non rilevato'));
    echo '<details class="card iptm-dns-fold" id="dns-components"><summary><b>Dettagli componenti rilevati</b> · DNSCrypt, Suricata e Zapret</summary><div class="iptm-dns-fold-content"><p>DNSCrypt-proxy: <b>'.(!empty($state['dnscrypt_installed'])?'installato':'non rilevato').'</b> · Suricata: <b>'.(!empty($state['suricata_installed'])?'installato':'non rilevato').'</b> · Zapret2/nfqws2: <b>'.h($z2state).'</b> · Zapret classico/nfqws: <b>'.(!empty($state['anti_dpi_installed'])?'rilevato':'non rilevato').'</b></p>';
    echo '<p class=mut>Stato IPTM: <b>'.(!empty($state['configured_by_iptm'])?'profilo DNSCrypt gestito presente':'profilo non ancora attivato').'</b>. Pi-hole, Unbound e le loro porte non vengono modificati. Per l’attivazione serve DNSCrypt-proxy installato e già attivo.</p>';
    echo '<p class=mut>Proposta: '.h($recommended['primary_name']??'Quad9').' + '.h($recommended['secondary_name']??'RESTENA').'. Fonte: <a href="'.h($recommended['source']??'https://github.com/DNSCrypt/dnscrypt-resolvers').'" target="_blank" rel="noopener noreferrer">catalogo ufficiale DNSCrypt</a>. I pin possono cambiare; la raggiungibilità sarà verificata durante l’applicazione. Le dichiarazioni di privacy dei fornitori non costituiscono certificazione no-log.</p></div></details>';
    // Root-owned independent systemd rollback, not a PHP-session countdown.
    $tx=(array)($state['transaction']??[]);
    if (($tx['state']??'')==='pending') {
        echo '<div class="card"><h3>DNSCrypt in prova · rollback automatico</h3>';
        echo '<p>Rimangono <b>'.max(0,(int)($tx['seconds_remaining']??0)).' secondi</b> prima del ripristino automatico. Verifica DNS e Pi-hole da un client LAN e conserva l’accesso console.</p>';
        if ($admin) {
            echo '<form method=post>'.fh('p=dnsguard').'<input type=hidden name=action value=dns_guard_confirm><button class=g>Conferma definitivamente DNS</button></form>';
            echo '<form method=post>'.fh('p=dnsguard').'<input type=hidden name=action value=dns_guard_revert><button class=d>Ripristina subito DNS precedente</button></form>';
        }
        echo '</div>';
    }
    [$evrc,$evout,$everr]=priv('dns-guard',null,['events']);
    $sniState=$evrc===0?json_decode($evout,true):null;$sniState=is_array($sniState)?($sniState['result']??[]):[];
    echo '<details class="card iptm-dns-fold" id="dns-tls-events"><summary><b>Eventi TLS/SNI osservati</b> · diagnostica facoltativa</summary><div class="iptm-dns-fold-content">';
    if (empty($sniState['available'])) echo '<p class=mut>Non sono disponibili eventi TLS nel file EVE. Verifica che Suricata registri gli handshake TLS.</p>';
    elseif (empty($sniState['events'])) echo '<p class=mut>Nessun SNI TLS in chiaro trovato nel campione disponibile.</p>';
    else {echo '<div class=iptm-table-scroll><table><thead><tr><th>Quando</th><th>Client</th><th>Server</th><th>SNI osservato</th></tr></thead><tbody>';
       foreach ((array)$sniState['events'] as $event)echo '<tr><td>'.h($event['timestamp']??'').'</td><td>'.h($event['source']??'').'</td><td>'.h($event['destination']??'').'</td><td>'.h($event['sni_visible']??'').'</td></tr>';
       echo '</tbody></table></div>';
    }
    echo '<p class=mut>Questa tabella legge soltanto i metadati TLS già registrati. Con ECH l’SNI visibile può essere un nome pubblico, non il dominio effettivo.</p></div></details>';
    echo '<details class="card iptm-dns-fold" id="dns-sni-live"><summary><b>TLS/SNI reale · Suricata IDS</b> · attiva regole di osservazione</summary><div class="iptm-dns-fold-content">';
    echo '<p>Genera regole <code>alert tls</code> reali in <code>local.rules</code>, verifica con <code>suricata -T</code> e ricarica Suricata. Non installa CA, non intercetta il contenuto TLS e non blocca i pacchetti. Con ECH il nome effettivo può non essere visibile.</p>';
    if($admin) {
        echo '<form method="post">'.fh('p=dnsguard').'<input type="hidden" name="action" value="dns_sni_activate">';
        echo '<label class="fl">Domini TLS/SNI da osservare (uno per riga, max 40)<textarea name="sni_live_domains" rows="3" maxlength="8192" required>'.h(implode("\n",(array)($initial['sni_domains']??[]))).'</textarea></label>';
        echo '<button class="g">Attiva monitoraggio SNI reale</button></form>';
        echo '<form method="post">'.fh('p=dnsguard').'<input type="hidden" name="action" value="dns_sni_disable"><button class="s">Rimuovi regole SNI IPTM</button></form>';
    }
    echo '<p class="mut">Gli alert diventano visibili dopo traffico TLS effettivamente osservato dalla tua interfaccia Suricata. Una regola valida non dimostra che il traffico attraversi questo host.</p></div></details>';
    echo '<details class="card iptm-dns-fold" id="dns-resolver-advanced"><summary><b>Resolver cifrati e failover</b> · configurazione avanzata DNSCrypt</summary><div class="iptm-dns-fold-content"><form method=post>'.fh('p=dnsguard');
    echo '<p class=mut>Il profilo viene controllato automaticamente durante Applica. IP e impronte dei certificati provengono dal catalogo DNSCrypt.</p>';
    echo '<label class=fl>Primario · Quad9 Secure (DNSSEC e protezione malware)<textarea name=primary_stamp rows=2 maxlength=2048 placeholder="sdns://...">'.h($primary).'</textarea></label>';
    echo '<label class=fl>Secondario · RESTENA (DoH, senza filtraggio)<textarea name=secondary_stamp rows=2 maxlength=2048 placeholder="sdns://...">'.h($secondary).'</textarea></label>';
    echo '<label class=fl>Bootstrap facoltativo (gli stamp includono già IP, nessun DNS non cifrato obbligatorio)<textarea name=bootstrap rows=2 maxlength=256 placeholder="Uno per riga, se necessario">'.h($bootstrap).'</textarea></label>';
    echo '<label class=fl>Timeout resolver (2–15 secondi)<input type=number name=timeout min=2 max=15 value="'.max(2,min(15,$timeout)).'"></label>';
    echo '<div class=iptm-form-actions><button type=submit name=action value=dns_guard_preview class=s>Controllo facoltativo</button></div>';
    echo '<p class=mut>Applica esegue direttamente i controlli di sintassi e raggiungibilità DNS, con backup e rollback automatico.</p>';
    echo '<div class=iptm-form-actions><button class=g type=submit name=action value=dns_guard_apply>Applica DNSCrypt con verifica e rollback</button></div>';
    echo '<details class="iptm-dns-inline"><summary>Ispezione TLS/SNI · anteprima opzionale</summary><label class=fl>Domini da rilevare, uno per riga<textarea name=sni_domains rows=3 maxlength=4096 placeholder="example.org">'.h(implode("\n",(array)($initial['sni_domains']??[]))).'</textarea></label>';
    echo '<label class=fl>Politica<select name=sni_mode><option value=alert'.(($initial['sni_mode']??'alert')==='alert'?' selected':'').'>Segnala (nessun blocco)</option><option value=drop'.(($initial['sni_mode']??'alert')==='drop'?' selected':'').'>Proponi DROP (solo se IPS inline attivo)</option></select></label>';
    echo '<p class=mut>La lettura riguarda solo l’SNI presente in chiaro nel ClientHello TLS. ECH può nascondere il dominio reale; TLS/QUIC non riconosciuto non viene inventato.</p></details>';
    echo '<p class="mut">Anti-DPI si configura in un unico posto: <a href="#dns-zapret-manager">installa, salva profilo, verifica, prova e conferma rollback</a>. Questa sezione DNSCrypt non ripete le hostlist.</p>';
    echo '</form></div></details>';
    echo '<details class="card iptm-dns-fold" id="dns-zapret-manager" open><summary><b>Anti-DPI selettivo · percorso unico</b> · scegli motore, installa, verifica, attiva e conferma</summary>';
    pg_zapret_manager();
    echo '</details>';
    $last=$_SESSION['dns_guard_preview']??null;
    if(is_array($last)) {
       echo '<details class="card iptm-dns-fold"><summary><b>Ultima anteprima avanzata</b> · nessuna modifica applicata</summary><pre class=iptm-guard-preview>'.h(json_encode($last,JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES)).'</pre></details>';
    }
}

/** Optional nfqws: install a verified upstream tarball and save an inert config. */
function pg_zapret_manager(): void {
    $admin=($_SESSION['role']??'viewer')==='admin';
    $engine=(string)($_GET['zapret_engine']??'zapret2');
    if (!in_array($engine,['zapret2','classic'],true))$engine='zapret2';
    $cmd=$engine==='zapret2'?'zapret2':'zapret';
    [$rc,$out,$err]=priv($cmd,null,['status']);
    $state=$rc===0?json_decode($out,true):null;
    if(!is_array($state))$state=[];
    $statusVerified=$rc===0 && !empty($state['ok']);
    $cfg=is_array($state['configuration']??null)?$state['configuration']:[];
    echo '<div class="card"><h3>Anti-DPI · Zapret2 e versione classica</h3>';
    echo '<p class="mut">I due motori mantengono binari e configurazioni separati. Predefinito: Zapret2/nfqws2. Nessun motore viene attivato né modifica NFQUEUE automaticamente.</p>';
    echo '<p><a class="btn s" href="?p=dnsguard&amp;zapret_engine=zapret2">'.($engine==='zapret2'?'● ':'').'Zapret2 · nfqws2</a> ';
    echo '<a class="btn s" href="?p=dnsguard&amp;zapret_engine=classic">'.($engine==='classic'?'● ':'').'Classico · nfqws</a></p>';
    $managed=!empty($state['installed']);
    $external=!$managed && !empty($state['external_detected']);
    $installLabel=!$statusVerified?'stato non verificabile (helper/permessi)':($managed?'installato e gestito da IPTM':($external?'rilevato esternamente (non ancora gestito da IPTM)':'non rilevato'));
    echo '<p><b>'.h($engine).'</b>: <b>'.h($installLabel).'</b> '.h((string)($state['installed_version']??''));
    echo ' · Profilo '.(!empty($state['configured'])?'salvato':'assente').'</p>';
    if($external)echo '<p class="mut">Il motore esterno non è usato automaticamente: installalo dal gestore IPTM o importa un binario verificato prima dell’attivazione.</p>';
    if($statusVerified && !$managed)echo '<p class="mut">Il controllo operativo richiede il binario gestito: '.h((string)($state['managed_binary']??'')).'.</p>';
    if(!$admin){echo '</div>';return;}
    $h='<input type="hidden" name="zapret_engine" value="'.h($engine).'">';
    echo '<h4>1. Installazione motore · se già presente, passa al profilo</h4>';
    echo '<form method="post">'.fh('p=dnsguard').$h.'<input type="hidden" name="action" value="zapret_manage"><input type="hidden" name="zapret_op" value="latest"><button class="s">Cerca ultima release '.h($engine).'</button></form>';
    $candidate=$_SESSION['iptm_zapret_latest_'.$engine]??null;
    if(is_array($candidate) && (int)($candidate['at']??0)>=time()-600) {
        echo '<p>Versione disponibile: <b>'.h((string)$candidate['tag']).'</b> · <code>'.h((string)$candidate['url']).'</code></p>';
        echo '<p class="mut">'.(empty($candidate['sha256'])?'Digest GitHub non fornito: calcolato dopo HTTPS; non garantisce autenticità del publisher.':'Digest pubblicato dalla release GitHub.').'</p>';
        echo '<form method="post">'.fh('p=dnsguard').$h.'<input type="hidden" name="action" value="zapret_manage"><input type="hidden" name="zapret_op" value="install-latest">';
        echo '<input type="hidden" name="zapret_tag" value="'.h((string)$candidate['tag']).'">';
        echo '<button>Installa '.h($engine).' '.h((string)$candidate['tag']).'</button></form>';
    }
    if($engine==='classic') {
        echo '<details><summary>Installazione classica manuale, URL + SHA-256</summary><form method="post">'.fh('p=dnsguard').$h.'<input type="hidden" name="action" value="zapret_manage"><input type="hidden" name="zapret_op" value="install">';
        echo '<label class="fl">URL HTTPS ufficiale<input name="zapret_url" required maxlength="240"></label><label class="fl">SHA-256 indipendente<input name="zapret_sha256" required pattern="[a-f0-9]{64}"></label><button>Installa binario classico</button></form></details>';
    }
    echo '<h4>2. Configura e salva il profilo (senza attivazione)</h4>';
    echo '<form method="post">'.fh('p=dnsguard').$h.'<input type="hidden" name="action" value="zapret_manage"><input type="hidden" name="zapret_op" value="configure">';
    echo '<label class="fl">Interfaccia WAN<input name="zapret_wan" pattern="[A-Za-z0-9_.:-]{1,15}" required value="'.h((string)($cfg['wan_if']??'')).'"></label>';
    echo '<label class="fl">Reti client IPv4 private (una per riga)<textarea name="zapret_clients" rows="3" maxlength="2048" required>'.h(implode("\n",(array)($cfg['clients']??[]))).'</textarea></label>';
    echo '<label class="fl">Domini (uno per riga)<textarea name="zapret_domains" rows="9" required data-antidpi-profile-domains>'.h(implode("\n",(array)($cfg['domains']??[]))).'</textarea></label>';
    echo '<label class="fl">Numero NFQUEUE<input type="number" name="zapret_queue" min="100" max="999" value="'.(int)($cfg['queue']??200).'"></label>';
    echo '<label class="fl">Profilo descrittivo (nessuna conversione automatica dei parametri nfqws1)<select name="zapret_strategy"><option value="multisplit"'.(($cfg['strategy']??'')==='multisplit'?' selected':'').'>multisplit</option><option value="fake"'.(($cfg['strategy']??'')==='fake'?' selected':'').'>fake</option></select></label>';
    echo '<button data-antidpi-profile-save>Salva profilo '.h($engine).' senza attivazione</button></form>';
    pg_antidpi_internet_sources($engine,!empty($state['configured']));
    echo '<h4>3. Anteprima e controllo prerequisiti</h4>';
    echo '<form method="post">'.fh('p=dnsguard').$h.'<input type="hidden" name="action" value="zapret_manage"><input type="hidden" name="zapret_op" value="preview"><button class="s">Genera anteprima</button></form>';
    $last=$_SESSION['zapret_preview_'.$engine]??null;
    if(is_array($last))echo '<details open><summary>Anteprima '.h($engine).' · non applicata</summary><pre>'.h(json_encode($last,JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES)).'</pre></details>';
    // Real deployment is intentionally separate from inert saved profiles.
    [$liveRc,$liveOut]=run([BIN_SUDO,'-n',HELPER,'anti-dpi-live','status'],null,8.0,2048);
    $live=$liveRc===0?json_decode($liveOut,true):null;
    if(!is_array($live) || empty($live['ok']))$live=['state'=>'unavailable'];
    echo '<h4>4. Prova reale di 120 secondi, quindi conferma o rollback</h4>';
    echo '<p>Stato NFQUEUE: <b>'.h((string)($live['state']??'unknown')).'</b>';
    if(($live['state']??'')==='pending')echo ' · rollback tra '.(int)($live['seconds_remaining']??0).' secondi';
    echo '. Prima dell’attivazione accertati che questa macchina instradi il traffico IPv4 dei client. Il profilo da solo non attiva Anti-DPI.</p>';
    echo '<form method="post">'.fh('p=dnsguard').$h.'<input type="hidden" name="action" value="antidpi_live"><input type="hidden" name="antidpi_op" value="preflight"><button class="s">Controlla gateway, binario e iptables</button></form>';
    if(($live['state']??'')==='inactive' && $managed && !empty($state['configured'])) {
        echo '<form method="post">'.fh('p=dnsguard').$h.'<input type="hidden" name="action" value="antidpi_live"><input type="hidden" name="antidpi_op" value="start">';
        echo '<button class="g">Attiva Anti-DPI con rollback (120 s)</button></form>';
    }
    if(($live['state']??'')==='pending') {
        echo '<form method="post">'.fh('p=dnsguard').$h.'<input type="hidden" name="action" value="antidpi_live"><input type="hidden" name="antidpi_op" value="confirm"><button class="g">Conferma prova Anti-DPI</button></form>';
    }
    if(($live['state']??'')==='confirmed') {
        if(empty($live['persistent'])) {
            echo '<form method="post">'.fh('p=dnsguard').$h.'<input type="hidden" name="action" value="antidpi_live"><input type="hidden" name="antidpi_op" value="persist-enable">';
            echo '<button class="g">Rendi Anti-DPI persistente al riavvio</button></form>';
        } else {
            echo '<p><b>Persistenza attiva</b> · motore: '.h((string)($live['persistent_engine']??'')).'</p>';
            echo '<form method="post">'.fh('p=dnsguard').$h.'<input type="hidden" name="action" value="antidpi_live"><input type="hidden" name="antidpi_op" value="persist-disable"><button class="s">Disabilita avvio Anti-DPI al prossimo boot</button></form>';
        }
    }
    if(in_array($live['state']??'',['pending','confirmed'],true))echo '<form method="post">'.fh('p=dnsguard').$h.'<input type="hidden" name="action" value="antidpi_live"><input type="hidden" name="antidpi_op" value="stop"><button class="d">Disattiva Anti-DPI ora e al boot</button></form>';
    echo '<p class="mut">Se il test non è pronto, IPTM non inserisce alcuna regola. Dopo aver avviato la prova, verifica dal client selezionato; la conferma è disponibile quando lo stato diventa pending. Senza conferma, il timer tenta di rimuovere la catena. La persistenza si abilita solo dopo una prova confermata; se il boot fallisce, IPTM disabilita il riavvio automatico.</p>';
    echo '<p class="mut">Prova limitata a FORWARD TCP 80/443 con --queue-bypass; avvio persistente su richiesta con watchdog al boot. Il watchdog non sostituisce un accesso console.</p>';
    echo '<p class="mut">Zapret2 usa Lua e --lua-desync. La sola etichetta della vecchia strategia non viene trasformata in argomenti eseguibili: configurazione avanzata da validare separatamente.</p></div>';
}

/** One import workflow: curated services, TXT/hosts and online collections. */
function pg_antidpi_internet_sources(string $engine, bool $configured=false): void {
    [$rc,$out,$err]=priv('anti-dpi-sources',null,['status',$engine]);
    $state=$rc===0?json_decode($out,true):null;
    if(!is_array($state)||empty($state['ok']))$state=['state'=>'unavailable','catalog'=>[]];
    $catalog=is_array($state['catalog']??null)?$state['catalog']:[];
    $ready=($state['state']??'')!=='unavailable';
    echo '<details class="iptm-dns-inline iptm-import-unico" id="antidpi-import-unico" open><summary><b>Importazione domini · unica</b> · servizi noti, TXT e liste online</summary>';
    echo '<p class="mut">Un solo percorso: <b>seleziona servizi e raccolte → completa tutti i download → importa i domini nel riquadro del profilo → controlla e salva → preflight/prova</b>. La pagina non viene ricaricata durante i download. Nessuna regola NFQUEUE viene applicata.</p>';
    if(!$configured)echo '<p class="mut">Non hai ancora un profilo salvato: puoi importare ugualmente. Completa WAN e reti client nel modulo sopra, quindi conferma l’anteprima; il profilo sarà creato insieme alla lista.</p>';
    if(($state['state']??'')==='unavailable')echo '<p class="msg warn">Helper per le liste non raggiungibile: verifica il log e i permessi prima di avviare l’importazione.</p>';
    echo '<form method="post" id="iptm-antidpi-unified-import" data-antidpi-unified>'.fh('p=dnsguard');
    echo '<input type="hidden" name="action" value="antidpi_sources"><input type="hidden" name="source_op" value="start"><input type="hidden" name="zapret_engine" value="'.h($engine).'"><input type="hidden" name="source_draft" value="">';
    echo '<h4>1. Seleziona servizi e raccolte</h4><details open><summary>Servizi noti · selezione multipla</summary>';
    echo '<p class="ops"><button type="button" class="s" data-antidpi-all="known">Seleziona tutti i servizi</button> <button type="button" class="s" data-antidpi-none="known">Deseleziona tutti</button> <span data-antidpi-count="known" role="status"></span></p>';
    echo '<div data-antidpi-known class="iptm-domain-services"></div><p class="mut">Servizi pubblici dimostrativi, non necessariamente soggetti a DPI.</p></details>';
    echo '<details open><summary>Raccolte online · Italia / Europa / globali</summary>';
    echo '<p class="ops"><button type="button" class="s" data-antidpi-all="online">Seleziona tutte le raccolte</button> <button type="button" class="s" data-antidpi-none="online">Deseleziona tutte</button> <span data-antidpi-count="online" role="status"></span></p>';
    foreach($catalog as $src){
        if(!is_array($src))continue;
        $id=(string)($src['id']??'');
        if(!preg_match('/^(?:it|global|fr|de|es|gb|nl|be|agcom_archive)$/D',$id))continue;
        echo '<label class="iptm-domain-source"><input type="checkbox" name="source_ids[]" value="'.h($id).'"> <b>'.h((string)($src['name']??$id)).'</b> <small>'.h((string)($src['note']??'')).'</small></label>';
    }
    echo '<p class="mut">Le raccolte OONI/Citizen Lab sono cataloghi di test, non prove di blocco. Le selezioni dei flag sono ricordate su questo browser, anche riaprendo la pagina.</p></details>';
    echo '<label class="fl">File locali TXT / hosts (anche multipli)<input type="file" data-antidpi-file accept=".txt,.list,.hosts,text/plain" multiple></label>';
    echo '<label class="fl">Domini incollati (facoltativi)<textarea name="source_local" rows="3"  placeholder="esempio.org · uno per riga, oppure URL, oppure righe hosts"></textarea></label>';
    echo '<h4>Modalità di importazione</h4><label class="fl">Modalità<select name="source_mode"><option value="merge">Unisci con il profilo, senza duplicati</option><option value="replace">Sostituisci tutta la hostlist (irreversibile senza backup)</option></select></label>';
    echo '<p class="mut" data-antidpi-import-info role="status" aria-live="polite">Scarica prima tutte le raccolte selezionate. Il pulsante di anteprima sarà disponibile soltanto quando ciascun download sarà terminato. Nessun limite numerico di domini; limite tecnico di 16 MiB per proteggere la memoria del gateway.</p>';
    echo '<button type="submit" class="s"'.($ready?'':' disabled').'>Scarica tutte le raccolte e inserisci i domini</button>';
    echo '<progress data-antidpi-progress hidden value="0" max="1" aria-label="Download raccolte Anti-DPI"></progress>';
    echo '<div data-antidpi-download-report role="status" aria-live="polite"></div>';
    echo '<button type="button" class="g" data-antidpi-next hidden>Prosegui: controlla e salva il profilo</button></form>'; 
    if(($state['state']??'')==='running' || ($state['state']??'')==='queued') {
        echo '<p class="mut">Un download precedente risulta ancora attivo: questa pagina può recuperarne lo stato senza interromperlo.</p>';
    }
    echo '<p class="mut">Se Anti-DPI è già attivo o persistente, arrestalo prima di modificare l’hostlist. Non scaricare liste durante l’applicazione di regole.</p></details>';
}
