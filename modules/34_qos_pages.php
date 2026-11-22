<?php
/* Unified, two-phase QoS workspace: kernel is authoritative. */
function pg_sqm() {
    $admin=($_SESSION['role']??'viewer')==='admin';
    [$rc,$raw,$err]=priv('qos-engine',null,['status']);
    $state=$rc===0?json_decode($raw,true):null;
    if(!is_array($state))$state=['state'=>'unavailable','error'=>trim($err.$raw)];
    $allSettings=S_get();
    $q=(array)($allSettings['qos_engine']??[]);
    [$cr,$cj,$ce]=priv('qos-engine',null,['calibrate-status']);
    $calibration=$cr===0?json_decode($cj,true):null;
    $measurement=(array)($calibration['calibration']??[]);
    $best=(array)($calibration['last_valid']['proposal']??[]);
    $profile=(string)($_SESSION['iptm_qos_last_wan']??$q['interface']??$state['interface']??$allSettings['setup']['wan_if']??'');
    if(($calibration['last_valid']['interface']??null)!==$profile)$best=[];
    $audit=null;
    if(preg_match('/^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$/D',$profile)){
        [$ir,$io,$ie]=priv('qos-engine',null,['inspect',$profile]);
        $audit=$ir===0?json_decode($io,true):null;
    }
    $ifaces=array_keys(sys_ifaces());
    echo '<div class="card iptm-qos-workspace"><h2>Qualità del servizio <span class="iptm-qos-subtitle">CAKE / IFB</span></h2>';
    echo '<nav class="iptm-qos-nav" aria-label="Sezioni qualità del servizio"><a href="#iptm-qos-overview">Panoramica</a><a href="#iptm-qos-shaping">CAKE e rollback</a><a href="#iptm-qos-calibration">Calibrazione e RTT</a><a href="#iptm-qos-priorities">Priorità applicative</a><a href="#iptm-qos-diagnostics">Diagnostica e migrazione</a></nav>';
    echo '<div id="iptm-qos-overview" class="iptm-qos-overview">';
    echo '<p class="mut">I limiti sono espressi in Mbit/s effettivi della connessione. Una NIC a 1 Gbit/s non indica la banda disponibile. Questa sezione non esegue shaping finché non confermi una prova protetta dal watchdog.</p>';
    echo '<table><tr><th>Stato kernel</th><th>WAN</th><th>Download</th><th>Upload</th><th>Topologia</th></tr>';
    echo '<tr><td>'.h((string)($state['state']??'n/d')).'</td><td>'.h((string)($state['interface']??'—')).'</td><td>'.h((string)($state['down_mbit']??'—')).'</td><td>'.h((string)($state['up_mbit']??'—')).'</td><td>'.(!empty($state['verified'])?'CAKE/IFB verificati':'non verificata').'</td></tr></table>';
    // One authoritative status summary, not a duplicated capability matrix.
    echo '<p class="mut">Verifica reale: '.(!empty($state['verified'])?'qdisc WAN/IFB e filtri confermati':'topologia da verificare').'. Il riconoscimento applicativo qui sotto è diagnostico e non modifica automaticamente CAKE.</p>';
    if(($state['state']??'')==='confirmed' && ($state['version']??'')!==APP_VERSION){
        echo '<div class="msg warn">CAKE è confermato da una release precedente. La migrazione automatica post-commit dovrebbe riallineare il watchdog senza rimuovere le qdisc.';
        if($admin)echo '<form method="post">'.fh('p=sqm').'<button class="s" name="action" value="qos_postinstall_ensure">Verifica e completa migrazione QoS</button></form>';
        echo '</div>';
    }
    if(in_array((string)($state['state']??''),['pending','confirmed'],true)){
        $dscpStatus=(string)($state['ingress_policy_status']??'');
        if($dscpStatus==='unverified')echo '<div class="msg warn">CAKE attivo, priorità download sospese: policy DSCP non verificata. Il redirect IFB funziona; per ripristinare le priorità, disabilita CAKE in modo controllato e riconfigura la policy.</div>';
        elseif($dscpStatus==='verified')echo '<p class="mut">Priorità download: '.h((string)($state['ingress_policy_count']??0)).' filtri verificati.</p>';
    }
    echo '<section id="iptm-qos-calibration" class="iptm-qos-section"><div class="iptm-qos-section-heading"><h3>Calibrazione e controllo RTT</h3><p class="mut">Misure, automazione e latenza sotto carico</p></div><div class="iptm-qos-control-grid">';
    echo '<div class="card iptm-qos-panel"><h3>Calibrazione manuale · Download / Upload</h3>';
    echo '<p class="mut">Due misure solo se la WAN è libera e senza CAKE attivo. Valori proposti, mai applicati automaticamente.</p>';
    echo '<p>Stato: <b>'.h((string)($measurement['state']??'idle')).'</b> · misure: '.h((string)($measurement['attempts']??0)).'/2</p>';
    if(!empty($best)) echo '<p>Ultima proposta affidabile: <b>'.h((string)($best['down_mbit']??'—')).' Mbit/s download</b> / <b>'.h((string)($best['up_mbit']??'—')).' Mbit/s upload</b>.</p>';
    if(!empty($measurement['samples'])){
        echo '<table><tr><th>Misura</th><th>Download Mbit/s</th><th>Upload Mbit/s</th><th>Motore</th></tr>';
        foreach(array_slice((array)$measurement['samples'],0,2) as $i=>$sample)echo '<tr><td>'.($i+1).'</td><td>'.h((string)($sample['download_mbit']??'—')).'</td><td>'.h((string)($sample['upload_mbit']??'—')).'</td><td>'.h((string)($sample['engine']??'—')).'</td></tr>';
        echo '</table>';
    }
    if(!empty($measurement['reason']))echo '<p class="mut">'.h((string)$measurement['reason']).'</p>';
    if(!empty($measurement['errors'])) echo '<p class="mut">Diagnosi: '.h(implode('; ',array_slice((array)$measurement['errors'],0,2))).'</p>';
    if($admin){
        echo '<form method="post" class="row">'.fh('p=sqm').'<label>WAN da misurare<select name="interface">';
        foreach($ifaces as $iface)echo '<option value="'.h($iface).'"'.($iface===$profile?' selected':'').'>'.h($iface).'</option>';
        echo '</select></label><button class="s" name="action" value="qos_calibrate_start"'.(($measurement['state']??'')==='running'?' disabled':'').'>Misura banda manualmente (genera traffico)</button></form>';
    }
    echo '</div>';
    [$ar,$ao,$ae]=priv('qos-engine',null,['auto-status']);
    $automatic=$ar===0?json_decode($ao,true):null;
    $autoEnabled=!empty($automatic['config']['enabled']);
    echo '<div class="card iptm-qos-panel"><h3>Controllo rete · ogni ora</h3>';
    echo '<p class="mut">Con CAKE attivo misura solo RTT: nessuno speedtest che saturi la connessione. Senza CAKE, il controllo automatico resta passivo: gli speedtest ad alto traffico si avviano solo su richiesta.</p>';
    echo '<p>Timer: <b>'.($autoEnabled?'abilitato':'disabilitato').'</b></p>';
    if($admin){
        $action=$autoEnabled?'qos_auto_disable':'qos_auto_enable';
        echo '<form method="post">'.fh('p=sqm').'<button class="s" name="action" value="'.h($action).'">'.($autoEnabled?'Disattiva timer automatico':'Attiva controllo orario').'</button></form>';
    }
    echo '</div>';
    if(($state['state']??'')==='confirmed'){
        $adaptive=(array)($state['adaptive']??[]);
        echo '<div class="card iptm-qos-panel"><h3>Regolatore RTT adattivo</h3>';
        echo '<p class="mut">Controlla RTT e recupera eventuali limiti ridotti da prove precedenti. Non aumenta i limiti oltre quelli confermati e non stima la banda fisica.</p>';
        echo '<p>Stato: <b>'.(!empty($adaptive['enabled'])?'abilitato':'disattivato').'</b> · RTT: '.h((string)($adaptive['last_rtt']??'—')).' ms · Upload attuale: '.h((string)($adaptive['up']??$state['up_mbit']??'—')).' Mbit/s · Download attuale: '.h((string)($adaptive['down']??$state['down_mbit']??'—')).' Mbit/s</p>';
        if($admin){
            $act=!empty($adaptive['enabled'])?'qos_adaptive_disable':'qos_adaptive_enable';
            echo '<form method="post">'.fh('p=sqm').'<button class="s" name="action" value="'.h($act).'">'.(!empty($adaptive['enabled'])?'Disattiva e ripristina limiti massimi':'Attiva regolatore RTT protetto').'</button></form>';
        }
        echo '</div>';
    }
    echo '</div></section>';
    if(($state['state']??'')==='rollback-failed') echo '<p class="msg err">Rollback automatico incompleto: non rimuovere manualmente qdisc esterne prima della verifica da console.</p>';
    if(!$admin){echo '<p class="mut">Modalità di sola lettura.</p></div>';return;}
    echo '<div id="iptm-qos-shaping" class="iptm-qos-section-heading"><h3>Configurazione CAKE e sicurezza</h3><p class="mut">Profilo, conferma, rollback e watchdog</p></div>';
    $pending=$_SESSION['iptm_qos_stage']??null;$active=$_SESSION['iptm_qos_active']??null;
    echo '<form method="post" class="row">'.fh('p=sqm').'<input type="hidden" name="action" value="qos_guard_install"><button class="s">Installa/verifica watchdog indipendente</button></form>';
    if(($state['state']??'')==='pending'&&is_array($active)){
        $token=(string)($active['token']??'');
        if(preg_match('/^[a-f0-9]{24}$/D',$token)){
            echo '<div class="msg warn"><b>Prova CAKE attiva.</b> Scadenza watchdog: '.h(date('H:i:s',(int)($state['deadline']??0))).'. Conferma solo dopo aver provato DNS, navigazione e accesso amministrativo.</div>';
            foreach(['qos_commit'=>'Conferma e conserva','qos_revert'=>'Ripristina subito'] as $action=>$label)
                echo '<form method="post" class="row">'.fh('p=sqm').'<input type="hidden" name="action" value="'.h($action).'"><input type="hidden" name="qos_token" value="'.h($token).'"><button class="'.($action==='qos_revert'?'d':'g').'">'.h($label).'</button></form>';
        }
    }elseif(($state['state']??'')==='confirmed'){
        echo '<form method="post">'.fh('p=sqm').'<button class="d" name="action" value="qos_disable">Disabilita esclusivamente qdisc gestite da IPTM</button></form>';
    }else{
        echo '<h3>Nuovo profilo · anteprima prima di applicare</h3>';
        echo '<form method="post" class="row">'.fh('p=sqm').'<input type="hidden" name="action" value="qos_stage">';
        echo '<label>WAN<select name="interface">';foreach($ifaces as $iface){echo '<option value="'.h($iface).'"'.($iface===$profile?' selected':'').'>'.h($iface).'</option>';}echo '</select></label>';
        foreach([['up_mbit','Upload',40],['down_mbit','Download',150],['overhead','Overhead (byte)',0],['timeout','Rollback automatico (s)',180]] as $f){
            $value=(int)($best[$f[0]]??($q[$f[0]]??$f[2]));echo '<label>'.h($f[1]).'<input type="number" name="'.h($f[0]).'" value="'.$value.'" required></label>';
        }
        echo '<label>Diffserv<select name="diffserv">';foreach(['besteffort','diffserv3','diffserv4','diffserv8'] as $opt)echo '<option value="'.$opt.'"'.(($q['diffserv']??'diffserv4')===$opt?' selected':'').'>'.$opt.'</option>';echo '</select></label>';
        foreach(['nat'=>'NAT','wash'=>'Wash DSCP','ack_filter'=>'ACK filter'] as $key=>$label){echo '<label><input type="checkbox" name="'.h($key).'" value="1"'.(!empty($q[$key])?' checked':'').'> '.h($label).'</label>';}
        echo '<button class="s" type="submit">Genera anteprima verificata</button></form>';
        if(is_array($pending)&&time()-(int)($pending['created']??0)<600){
            $sha=(string)($pending['hash']??'');
            echo '<div class="msg warn"><b>Profilo verificato ma non attivo.</b> SHA-256: <code>'.h($sha).'</code>. Nessuna modifica al kernel.</div>';
            echo '<form method="post">'.fh('p=sqm').'<input type="hidden" name="action" value="qos_apply"><input type="hidden" name="plan_sha256" value="'.h($sha).'"><button class="g">Applica prova CAKE/IFB con rollback</button></form>';
        }
    }
    if (function_exists('iptm_operator_insights')) iptm_operator_insights('qos');
    // IPTM-owned egress DSCP priorities. CAKE diffserv consumes these markings.
    [$pc,$pj,$pe]=priv('qos-policy',null,['status']);
    $policy=$pc===0?json_decode($pj,true):null;
    $policy=is_array($policy)?$policy:[];
    $polActive=(array)($policy['profile']??[]);
    echo '<div id="iptm-qos-priorities" class="card iptm-qos-priority-panel"><h3>Priorità applicative · DSCP IPv4 upload e download</h3>';
    echo '<p class="mut">Regole applicate nella catena IPTM dedicata in mangle/POSTROUTING. Non cambiano NAT o policy di accesso. Priorità: realtime (EF), interactive (AF41), normal (CS0), background (CS1). DSCP IPv4 già valorizzato non viene sovrascritto in upload; in download il classificatore agisce prima della IFB. Il download viene classificato con tc flower/pedit prima dell’IFB quando attivi CAKE con una policy verificata.</p>';
    echo '<p>Stato: <b>'.(!empty($policy['active'])?(!empty($policy['verified'])?'attivo e verificato':'attivo ma non verificato'):'disattivato').'</b></p>';
    echo '<p class="mut">Ripristino dopo riavvio: <b>'.(!empty($policy['persistent'])?'servizio systemd abilitato':'non verificato o non abilitato').'</b>. La riapplicazione viene rifiutata se la WAN o le catene non corrispondono al profilo salvato.</p>';
    if(!empty($polActive['rules'])){
        echo '<table><tr><th>Proto</th><th>Porta destinazione</th><th>Client sorgente</th><th>Priorità</th><th>Direzione</th></tr>';
        foreach($polActive['rules'] as $entry){echo '<tr><td>'.h((string)$entry['protocol']).'</td><td>'.h((string)$entry['port']).'</td><td>'.h((string)($entry['source']?:'tutti')).'</td><td>'.h((string)$entry['priority']).'</td><td>'.h((string)($entry['direction']??'both')).'</td></tr>';}
        echo '</table>';
    }
    if($admin){
        echo '<form method="post">'.fh('p=sqm').'<input type="hidden" name="action" value="qos_policy_stage"><label>WAN<select name="interface">';
        foreach($ifaces as $ifc)echo '<option value="'.h($ifc).'"'.($ifc===$profile?' selected':'').'>'.h($ifc).'</option>';
        echo '</select></label>';
        $presets=iptm_qos_dscp_recommendations();
        $priorSelected=(array)($_SESSION['iptm_qos_recommended_selection']??[]);
        $groups=[
            'base'=>['Essenziali','DNS, sincronizzazione e accesso remoto'],
            'meeting'=>['Videoconferenze e VoIP','Porte specifiche: verificare il servizio realmente utilizzato'],
            'remote'=>['Desktop remoto','Per accessi RDP e VNC'],
            'gaming'=>['Gaming','Porte comuni, ma non universali per tutti i titoli'],
            'iot'=>['Domotica e IoT','Per gli applicativi raggiungibili attraverso questa WAN'],
            'background'=>['Trasferimenti in background','Deprioritizzazione di copie e condivisione dati'],
        ];
        echo '<fieldset class="iptm-dscp-picker" id="iptm-dscp-selector"><legend>Regole consigliate · selezione facoltativa</legend>';
        echo '<p class="mut iptm-dscp-intro">Seleziona soltanto i servizi presenti nella tua rete. Nessuna opzione modifica il traffico finché non confermi l’anteprima. Il riconoscimento si basa sulle porte e non identifica in modo certo un’applicazione.</p>';
        echo '<div class="iptm-dscp-toolbar" role="group" aria-label="Selezione rapida regole DSCP">';
        echo '<button type="button" class="iptm-dscp-tool" data-iptm-dscp-bulk="essentials">Seleziona essenziali</button>';
        echo '<button type="button" class="iptm-dscp-tool" data-iptm-dscp-bulk="all">Seleziona tutte</button>';
        echo '<button type="button" class="iptm-dscp-tool" data-iptm-dscp-bulk="none">Deseleziona</button>';
        echo '<output id="iptm-dscp-counter" class="iptm-dscp-counter" aria-live="polite"></output></div>';
        foreach($groups as $groupId=>$group){
            echo '<section class="iptm-dscp-section" data-iptm-dscp-group="'.h($groupId).'">';
            echo '<div class="iptm-dscp-group-heading"><div><h4>'.h($group[0]).'</h4><p class="mut">'.h($group[1]).'</p></div>';
            echo '<button type="button" class="iptm-dscp-tool iptm-dscp-group-select" data-iptm-dscp-bulk="group" data-iptm-dscp-group="'.h($groupId).'">Seleziona gruppo</button></div>';
            echo '<div class="iptm-dscp-options">';
            foreach($presets as $id=>$preset){
                if(($preset['group']??'')!==$groupId)continue;
                $labelParts=explode(' · ',(string)$preset['label']);
                $dscp=array_pop($labelParts);
                $service=implode(' · ',$labelParts);
                $isSelected=in_array($id,$priorSelected,true);
                echo '<label class="iptm-dscp-option'.($isSelected?' is-selected':'').'">';
                echo '<input class="iptm-dscp-check" type="checkbox" name="recommended_rules[]" value="'.h($id).'" data-iptm-dscp-essential="'.(!empty($preset['essential'])?'1':'0').'"'.($isSelected?' checked':'').'>';
                echo '<span class="iptm-dscp-copy"><span class="iptm-dscp-title">'.h($service).' <span class="iptm-dscp-tag">'.h($dscp).'</span><span class="iptm-dscp-direction">↑↓ IPv4</span></span>';
                echo '<span class="iptm-dscp-reason">'.h($preset['reason']).'</span></span></label>';
            }
            echo '</div></section>';
        }
        echo '</fieldset>';
        echo '<label>Personalizzate: protocollo,porta,priorità,CIDR opzionale,direzione (both/upload/download)<textarea name="policy_rules" rows="5" placeholder="udp,3478,interactive,,both
tcp,22,interactive,192.168.1.0/24,upload"></textarea></label><button class="s">Anteprima priorità</button></form>';
        $pendingPolicy=$_SESSION['iptm_qos_policy_stage']??null;
        if(is_array($pendingPolicy)&&time()-(int)($pendingPolicy['created']??0)<600){
            echo '<form method="post">'.fh('p=sqm').'<input type="hidden" name="action" value="qos_policy_apply"><input type="hidden" name="policy_sha256" value="'.h((string)$pendingPolicy['hash']).'"><button class="g">Applica priorità verificate</button></form>';
        }
        if(!empty($policy['active']))echo '<form method="post">'.fh('p=sqm').'<button name="action" value="qos_policy_disable" class="d">Rimuovi solo classificatore IPTM</button></form>';
    }
    echo '</div>';
    echo '<section id="iptm-qos-diagnostics" class="iptm-qos-section"><div class="iptm-qos-section-heading"><h3>Diagnostica e migrazione</h3><p class="mut">Operazioni avanzate e componenti storici; nessun intervento automatico sulla rete</p></div><div class="iptm-qos-diagnostic-grid">';
    // Real observations, deliberately not advertised as packet-level enforcement.
    [$tr,$to,$te]=priv('qos-engine',null,['traffic-inspect']);
    $traffic=$tr===0?json_decode($to,true):null;
    if(!is_array($traffic))$traffic=[];
    echo '<div class="card iptm-qos-panel"><h3>Classificazione Layer 7 · Suricata</h3>';
    echo '<p class="mut">Riconoscimento applicativo reale dai campi app_proto nel log EVE. Sono osservazioni storiche, non un filtro DPI applicato automaticamente ai pacchetti. Non cambia DSCP, iptables o CAKE.</p>';
    $l7=(array)($traffic['layer7']??[]);
    if(!empty($l7['available'])){
        $protocols=(array)($l7['protocols']??[]);
        if($protocols){
            echo '<table><tr><th>Protocollo rilevato</th><th>Osservazioni</th><th>Classe suggerita</th></tr>';
            foreach(array_slice($protocols,0,12) as $record)if(is_array($record)){
                echo '<tr><td>'.h((string)($record['protocol']??'')).'</td><td>'.h((string)($record['observations']??0)).'</td><td>'.h((string)($record['class']??'normal')).'</td></tr>';
            }
            echo '</table>';
        }else echo '<p class="mut">Log EVE disponibile, ma nessun app_proto identificato nel campione.</p>';
    }else echo '<p class="mut">'.h((string)($l7['reason']??'Suricata non verificabile')).'</p>';
    echo '</div>';
    echo '<div class="card iptm-qos-panel"><h3>Classificazione per processo · socket locali</h3>';
    echo '<p class="mut">Riconoscimento tramite ss -tunap dei processi in esecuzione su questo gateway. Non è possibile attribuire un processo locale al traffico dei client LAN inoltrati. Le classi sono suggerimenti, senza modifica automatica delle priorità.</p>';
    $proc=(array)($traffic['process']??[]);
    if(!empty($proc['available'])){
        $processes=(array)($proc['processes']??[]);
        if($processes){
            echo '<table><tr><th>Processo</th><th>Socket</th><th>Classe suggerita</th></tr>';
            foreach(array_slice($processes,0,12) as $record)if(is_array($record)){
                echo '<tr><td>'.h((string)($record['process']??'')).'</td><td>'.h((string)($record['sockets']??0)).'</td><td>'.h((string)($record['class']??'normal')).'</td></tr>';
            }
            echo '</table>';
        }else echo '<p class="mut">Nessun processo attribuibile ai socket del gateway nel campione.</p>';
    }else echo '<p class="mut">'.h((string)($proc['reason']??'Inventario processi non verificabile')).'</p>';
    echo '</div>';
    if(is_array($audit)){
        echo '<div class="card iptm-qos-panel"><h3>Proprietà qdisc su '.h($profile).'</h3><p>Root: <b>'.h((string)$audit['root_kind']).'</b> · handle: <code>'.h((string)($audit['root_handle']??'—')).'</code> · ingress: '.h(implode(', ',(array)$audit['ingress_kinds'])).'</p>';
        echo '<p>'.h((string)$audit['reason']).'</p>';
        $owner=(array)($audit['external_owner']??[]);
        if(!empty($owner['detected']) && !empty($owner['matches_interface'])){
            echo '<div class="msg warn"><b>Gestore esterno identificato: '.h((string)($owner['unit']??'qos.service')).'</b>';
            echo '<p>Stato: '.h((string)($owner['active']??'non verificato')).' · avvio automatico: '.h((string)($owner['enabled']??'non verificato')).'</p>';
            if(!empty($owner['exec_start']))echo '<p>Installazione CAKE: <code>'.h((string)$owner['exec_start']).'</code></p>';
            if(!empty($owner['exec_stop']))echo '<p>Arresto servizio: <code>'.h((string)$owner['exec_stop']).'</code></p>';
            if(!empty($owner['exec_stop_removes_root']))echo '<p><b>Attenzione:</b> <code>systemctl stop qos.service</code> esegue ExecStop e cancella la qdisc root su '.h($profile).'. Non usarlo via SSH come scorciatoia.</p>';
            echo '<p><b>Passaggio controllato:</b> 1) conservare la configurazione e una console fisica; 2) verificare che non ci siano transazioni IPTM pendenti; 3) disabilitare il riavvio automatico del vecchio gestore solo durante una manutenzione pianificata; 4) migrare l’arresto e la qdisc dalla console con rollback verificato; 5) riaprire la pagina e verificare <code>can_stage=true</code>. Nessun trasferimento di proprietà viene effettuato da questa pagina.</p></div>';
        }
        if(empty($audit['can_stage'])) {
            echo '<div class="msg warn"><b>Migrazione CAKE richiesta · procedura sicura per '.h($profile).'</b>';
            echo '<p>Non usare <code>tc qdisc del</code>, <code>tc qdisc replace</code> o il riavvio di NetworkManager: su questo gateway la qdisc è collegata a <code>bond0</code>, che serve anche l’accesso amministrativo. Apri una console locale indipendente dalla rete.</p>';
            echo '<ol><li>Verifica chi sta gestendo la qdisc (solo lettura):</li></ol>';
            echo '<pre>tc -s qdisc show dev '.h($profile).'
sudo tc filter show dev '.h($profile).' parent ffff:
systemctl list-units --all --type=service | grep -Ei "sqm|qos|cake|iptm"
systemctl list-timers --all | grep -Ei "sqm|qos|cake|iptm"
systemctl cat iptm-qos-auto-calibration.service iptm-sqm-calibrate.service qos.service 2>/dev/null</pre>';
            echo '<p>Se <b>e solo se</b> è confermato che una specifica unità systemd gestisce CAKE/IFB, esamina <code>systemctl cat NOME.service</code> e <code>systemctl list-dependencies --reverse NOME.service</code>. Da console fisica, dopo backup e percorso di recupero verificato, il comando <code>sudo systemctl stop NOME.service</code> può eseguire un ExecStop che elimina la qdisc: non eseguirlo finché non hai verificato una procedura di recupero indipendente. Per impedirne il riavvio usa <code>sudo systemctl disable NOME.service</code>, ma soltanto dopo aver identificato timer e dipendenze e valutato gli effetti. Sostituisci NOME con quello realmente verificato; <b>non eseguire letteralmente il segnaposto</b>.</p>';
            echo '<p>Non fermare servizi per somiglianza del nome, non cancellare qdisc a mano e non modificare NetworkManager. Se il servizio contiene un comando di cleanup che rimuove il traffico o le IFB, collauda su clone o usa la procedura di migrazione dedicata. Se non riesci a identificare il proprietario, fermati.</p>';
            echo '<p>Verifica di nuovo con <code>tc -s qdisc show dev '.h($profile).'</code>; aggiorna la pagina e rigenera l’anteprima. Procedi solo quando la qdisc è libera, l’ingress/IFB non è occupato e il motore IPTM dichiara <b>can_stage=true</b>. Una qdisc CAKE ancora presente non va acquisita forzatamente.</p></div>';
        }
        echo '</div>';
    }
    [$lr,$lo,$le]=priv('upgrade-cleanup',null,['scan']);
    $legacy=$lr===0?json_decode($lo,true):null;
    echo '<div class="card iptm-qos-panel"><h3>Pulizia unità QoS/SQM obsolete</h3>';
    echo '<p class="mut">Inventario in sola lettura. Rimozione limitata a unità verificate, inattive e disabilitate. Backup recuperabile prima della modifica; nessuna qdisc, regola firewall o interfaccia viene rimossa.</p>';
    if(is_array($legacy)&&!empty($legacy['ok'])){
        echo '<table><tr><th>Unità</th><th>Esito</th><th>Motivo</th></tr>';
        foreach((array)($legacy['entries']??[]) as $entry){
            echo '<tr><td>'.h((string)($entry['unit']??'')).'</td><td>'.h((string)($entry['action']??'')).'</td><td>'.h((string)($entry['reason']??'')).'</td></tr>';
        }
        echo '</table>';
        if($admin){
            echo '<form method="post">'.fh('p=sqm').'<button class="s" name="action" value="upgrade_cleanup_scan">Registra anteprima verificata</button></form>';
            $pending=$_SESSION['iptm_cleanup_scan']??null;
            if(!empty($legacy['removable'])&&is_array($pending)&&time()-(int)($pending['created']??0)<=600&&
               hash_equals((string)$pending['sha256'],(string)$legacy['sha256'])){
                echo '<form method="post">'.fh('p=sqm').'<input type="hidden" name="legacy_sha256" value="'.h((string)$legacy['sha256']).'"><button class="d" name="action" value="upgrade_cleanup_retire">Archivia e ritira unità verificate</button></form>';
            }
        }
    }else echo '<p class="msg warn">Inventario pulizia non disponibile: '.h((string)($le??'')).'</p>';
    echo '</div>';
    echo '</div></section>';
    echo '<p class="mut">In download IPTM usa filtri tc flower sulla WAN, prima del redirect verso IFB, quando trova una policy IPv4 confermata e verificata. Le regole applicative devono essere configurate prima dell’attivazione CAKE; per cambiarle a CAKE attivo occorre disabilitare il profilo in modo controllato e riattivarlo con anteprima e watchdog.</p>';
    echo '<p class="mut">Le qdisc non riconosciute non vengono cancellate automaticamente. I profili CAKE/IFB confermati e verificati da una precedente release IPTM vengono trasferiti al watchdog corrente dopo il commit dell’aggiornamento, senza rimuovere lo shaping. Le prove pendenti e i profili non verificati bloccano il trasferimento. Prima di una nuova prova non devono essere attivi timer SQM concorrenti.</p></div>';
}
