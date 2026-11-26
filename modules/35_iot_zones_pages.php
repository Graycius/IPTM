<?php
// IPTM 4: pg_zones section moved verbatim; no runtime behavior changed.
function pg_zones() {
    if (pg_async_skeleton('zones', 'Zone IoT: filtro MAC o VLAN')) return;
    echo '<section class="card"><h2>Prima di configurare le zone</h2><p>Le regole MAC agiscono solo sul traffico che attraversa questo firewall. Dispositivi nella stessa rete possono comunicare direttamente: per isolamento reale servono VLAN o reti separate. Le regole IPv4 non proteggono IPv6.</p><p><a class="btn s" href="?p=apply">Controlla e applica la bozza</a></p></section>';
    // Ispirato a IPFire (RED/GREEN/BLUE/ORANGE) e alle zone OpenWRT/pfSense
    $S = S_get(); $if = sys_ifaces(); $L = live_state();
    $wan = (string)($S['wan_if'] ?? ''); $lan = (string)($S['lan_if'] ?? '');
    $lanNets = (string)($S['lan_nets'] ?? '');
    $guestOn = !empty($S['guest_on']); $guestNets = (string)($S['guest_nets'] ?? '');
    $isoOn = !empty($S['iso_on']);
    $pol = $L['pol'] ?? [];
    $pin = $pol['INPUT'] ?? '?'; $pfw = $pol['FORWARD'] ?? '?';

    $zones = [
        'red' => [
            'name' => 'RED · WAN',
            'color' => '#c0392b',
            'desc' => 'Rete non fidata (Internet). Tutto ciò che arriva da qui è sospetto finché non è esplicitamente permesso.',
            'if' => $wan ?: '—',
            'nets' => '0.0.0.0/0',
            'policy' => 'Ingresso verso router: ' . ($pin === 'DROP' ? 'chiuso' : $pin) . ' · Transito: ' . $pfw,
            'features' => array_filter([
                !empty($S['antispoof']) || !empty($S['spoof_on']) ? 'Anti-spoof' : '',
                !empty($S['bogon_wan']) ? 'Bogon filter' : '',
                !empty($S['portscan']) ? 'Port-scan detection' : '',
                !empty($S['crowdsec']) ? 'CrowdSec' : '',
                !empty($S['dos']) ? 'Anti SYN-flood' : '',
            ]),
        ],
        'green' => [
            'name' => 'GREEN · LAN',
            'color' => '#27ae60',
            'desc' => 'Rete fidata (casa/ufficio). Di solito può uscire su Internet; l\'accesso al router può essere limitato.',
            'if' => $lan ?: '—',
            'nets' => $lanNets ?: '—',
            'policy' => !empty($S['lockout_on']) ? 'Anti-lockout previsto dalla bozza (raggiungibilità da verificare dopo applicazione)' : 'Accesso gestione secondo regole INPUT',
            'features' => array_filter([
                !empty($S['spi']) ? 'SPI / connection tracking' : '',
                !empty($S['lan_cl']) ? 'Limite connessioni per client' : '',
                !empty($S['mac_only']) ? 'Solo MAC autorizzati' : '',
            ]),
        ],
        'blue' => [
            'name' => 'BLUE · Ospite / Wi‑Fi',
            'color' => '#2980b9',
            'desc' => 'Rete ospiti: Internet sì, LAN no (come BLUE in IPFire). Isolamento e porte minime (DNS/DHCP).',
            'if' => $guestOn ? ($guestNets ?: 'configurata') : 'non attiva',
            'nets' => $guestOn ? ($guestNets ?: '—') : '—',
            'policy' => $guestOn ? ('Porte consentite: ' . ($S['guest_ports'] ?? '53,67')) : 'Disabilitata — abilitala in Restrizioni',
            'features' => array_filter([
                $guestOn ? 'Isolamento ospite' : 'Off',
                $isoOn ? 'Isolamento reti aggiuntivo' : '',
            ]),
        ],
        'orange' => [
            'name' => 'ORANGE · DMZ / IoT',
            'color' => '#d35400',
            'desc' => 'Isolamento dei dispositivi IoT tramite MAC sul traffico che attraversa DietPi; VLAN opzionale quando supportata.',
            'if' => $isoOn ? ($S['iso_nets'] ?? 'reti isolate') : 'non dedicata',
            'nets' => $isoOn ? ($S['iso_nets'] ?? '—') : '—',
            'policy' => 'I port forward in NAT/Forward espongono servizi; limita le sorgenti quando possibile.',
            'features' => array_filter([
                $isoOn ? 'Isolamento reti' : '',
                !empty($S['svc_ban']) ? 'Ban automatico porte sensibili' : '',
            ]),
        ],
    ];

    echo '<div class=card><h2>Zone di rete</h2>';
    echo '<p class=mut>Stato illustrativo; le zone si applicano solo dopo la generazione delle regole e la conferma. Vista ispirata a <b>IPFire</b> (RED/GREEN/BLUE/ORANGE) e alle zone di <b>OpenWRT / pfSense</b>. Non sostituisce le regole: aiuta a capire <i>dove</i> si applica la policy.</p>';
    echo '<div class="iptm-zone-grid">';
    foreach ($zones as $id => $z) {
        echo '<div class="iptm-zone-summary iptm-zone-'.h($id).'">';
        echo '<h3>' . h($z['name']) . '</h3>';
        echo '<p class=mut>' . h($z['desc']) . '</p>';
        echo '<table class="iptm-zone-summary-table"><tr><td class=mut>Interfaccia</td><td><code>' . h($z['if']) . '</code></td></tr>';
        echo '<tr><td class=mut>Reti</td><td><code>' . h($z['nets']) . '</code></td></tr>';
        echo '<tr><td class=mut>Policy</td><td>' . h($z['policy']) . '</td></tr></table>';
        if ($z['features']) echo '<p class="iptm-zone-features">' . implode(' ', array_map(fn($f) => '<span class="b b-ACCEPT">' . h($f) . '</span>', $z['features'])) . '</p>';
        echo '</div>';
    }
    echo '</div>';

    // Flusso stile diagramma testuale (pfSense-like)
    echo '<h3>Flusso del traffico (semplificato)</h3>';
    echo '<pre data-iptm-layout="ui-b97e227685">';
    echo h("  [Internet] ---- RED (WAN: " . ($wan ?: '?') . ") ----+---- GREEN (LAN: " . ($lan ?: '?') . ")\n");
    echo h("                                       |\n");
    echo h("                                       +---- BLUE (Ospiti)" . ($guestOn ? " [ON]" : " [off]") . "\n");
    echo h("                                       |\n");
    echo h("                                       +---- ORANGE (DMZ/IoT)" . ($isoOn ? " [isolamento ON]" : "") . "\n");
    echo '</pre>';
    echo '<p class=ops><a class="btn s" href="?p=setup">Setup interfacce</a> <a class="btn s" href="?p=access">Restrizioni / Ospiti</a> <a class="btn s" href="?p=forward">NAT / Forward</a> <a class="btn s" href="?p=security">Sicurezza</a></p>';
    $warden=iptm_warden_state();
    echo '<div class=card><h3>Protezione IoT: modalità MAC senza VLAN</h3>';
    echo '<p>Puoi usare il rilevamento MAC/vendor offline di IPTM per proporre regole per dispositivi IoT già visibili a DietPi, senza modificare lo switch o l’access point. Seleziona i dispositivi da proteggere: un suggerimento vendor non è una classificazione automatica.</p>';
    echo '<div class="msg warn"><b>Limite della LAN condivisa:</b> il firewall vede soltanto pacchetti che attraversano DietPi. Tra due dispositivi sulla stessa Wi-Fi/LAN, ARP, traffico IP diretto e IPv6 locale possono bypassare DietPi. Per protezione completa è necessaria l’isolamento client sull’AP, una rete separata o un bridge che controlli il traffico L2.</div>';
    $legacy=iptm_warden_state();
    if (empty($legacy['ok'])) echo '<div class="msg err">Verifica delle automazioni precedenti non disponibile: la preparazione di nuove policy è sospesa.</div>';
    elseif (!empty($legacy['active']) || !empty($legacy['blockers']) || !empty($legacy['live_chains'])) {
        echo '<div class="msg warn">Rilevata una gestione IoT precedente o catene ancora presenti. Prima di attivare la nuova policy completane la disattivazione verificata; non viene cancellato nulla automaticamente.</div>';
        if (!empty($legacy['blockers'])) echo '<details><summary>Motivi del blocco</summary><p>'.h(implode('; ',array_slice($legacy['blockers'],0,8))).'</p></details>';
        if (($_SESSION['role']??'')==='admin' && !empty($legacy['detected']) && empty($legacy['blockers'])) {
            echo '<form method=post class="iptm-classic-form">'.fh('p=zones').'<input type=hidden name=action value=warden_retire><input type=hidden name=fingerprint value="'.h((string)($legacy['fingerprint']??'')).'">'
                .'<button class=s>Disattiva e archivia le automazioni precedenti</button></form>';
        }
        if (($_SESSION['role']??'')==='admin' && empty($legacy['active']) && empty($legacy['detected']) && !empty($legacy['retired']) && empty($legacy['blockers'])) {
            echo '<form method=post>'.fh('p=zones').'<input type=hidden name=action value=warden_scrub_draft><button class=s>Ripulisci le vecchie catene solo nella bozza</button></form>';
        }
    } elseif (!empty($legacy['detected'])) {
        echo '<p class=mut>Sono ancora presenti file di configurazione di una gestione precedente, non attiva. Prima di introdurre nuove policy è consigliabile archiviarli con la migrazione controllata.</p>';
        if (($_SESSION['role']??'')==='admin') echo '<form method=post>'.fh('p=zones').'<input type=hidden name=action value=warden_retire><input type=hidden name=fingerprint value="'.h((string)($legacy['fingerprint']??'')).'">'
            .'<button class=s>Archivia gestione precedente</button></form>';
    }
    $pendingMac=iptm_mac_pending_read();
    if (is_array($pendingMac)) {
        echo '<div class="msg warn"><b>Policy MAC sospesa — NON attiva e NON salvata nelle bozze firewall.</b> ';
        echo 'Selezionati '.count((array)($pendingMac['macs']??[])).' dispositivi il '.h(date('d/m/Y H:i',(int)($pendingMac['time']??time()))).'. ';
        echo 'Diagnostica: '.h((string)($pendingMac['diagnostic']??'IPv6 filter non disponibile')).'. ';
        echo 'Ripara il supporto IPv6 o disabilitalo completamente; quindi rigenera l’anteprima per rifare i controlli. Nessuna applicazione automatica.';
        if (($_SESSION['role']??'')==='admin')
            echo '<form method=post class=ops>'.fh('p=zones').'<input type=hidden name=action value=mac_pending_resume><button class=g>Riprendi piano sospeso</button></form> ';
            echo '<form method=post class=ops>'.fh('p=zones').'<input type=hidden name=action value=mac_pending_clear><button class=s>Elimina piano sospeso</button></form>';
        echo '</div>';
    }
    $ipv6Check=null;
    if (is_array($pendingMac) || (is_array($_SESSION['mac_plan']??null) && !empty($_SESSION['mac_plan']['data']['ready_to_stage'])))
        $ipv6Check=iptm_v6_diagnostic();
    if (($ipv6Check['state']??'')!=='disabled' && ($ipv6Check['filter']??'')==='unavailable')
        echo '<div class="msg warn"><b>IPv6 filter non disponibile:</b> '.h((string)($ipv6Check['backend']??'ip6tables non disponibile')).
          '. Il test non viene ignorato. Puoi conservare un piano MAC sospeso, ma non applicarlo fino alla correzione del kernel/backend o alla disabilitazione completa di IPv6. ' .
          'Diagnostica SSH: <code>ip6tables -V; sudo ip6tables -t filter -S; ip -6 addr; cat /proc/sys/net/ipv6/conf/{all,default}/disable_ipv6</code>.</div>';
    // Unified device table: selection for MAC preview and per-device blocking
    // policies share the SAME row, but retain independent POST actions.
    // HTML5 `form` ownership keeps the DOM valid (no nested forms).
    $inventory=iptm_security_read('mac-inventory');
    $inventoryReady=!empty($inventory['ok']);
    $iotPolicySaved=(array)($S['iot_policies']??[]);
    $iotPolicyCount=count(array_filter($iotPolicySaved,fn($flags)=>is_array($flags)&&$flags));
    $savedKinds=(array)($S['iot_devices']??[]);
    $selectedSaved=array_fill_keys((array)($S['iot_selected_macs']??[]),true);
    $iotSource=[];
    if ($inventoryReady) {
        foreach ((array)($inventory['devices']??[]) as $device) {
            if (!is_array($device)) continue;
            $mac=strtolower((string)($device['mac']??''));
            if (!preg_match('/^(?:[a-f0-9]{2}:){5}[a-f0-9]{2}$/D',$mac)) continue;
            $iotSource[$mac]=[
                'mac'=>$mac,'ip'=>implode(', ',(array)($device['addresses']??[])),
                'vendor'=>(string)($device['vendor']??''),
                'kind'=>(string)($savedKinds[$mac]??'unknown'),
                'hint'=>!empty($device['iot_vendor_hint']) && empty($device['locally_administered']),
                'online'=>true,
            ];
        }
    }
    foreach ($iotPolicySaved as $rawMac=>$flags) {
        $mac=strtolower((string)$rawMac);
        if (preg_match('/^(?:[a-f0-9]{2}:){5}[a-f0-9]{2}$/D',$mac) && !isset($iotSource[$mac])) {
            $iotSource[$mac]=['mac'=>$mac,'ip'=>'','vendor'=>'','kind'=>'iot','hint'=>false,'online'=>false];
        }
    }
    $suggested=count(array_filter($iotSource,fn($dev)=>$dev['hint']));
    echo '<section class="iptm-zone-policy" aria-label="Dispositivi e filtri IoT">';
    echo '<h3>Dispositivi e filtri IoT</h3><p><a class="btn s" href="?p=topology">Apri mappa interattiva della rete</a></p>';
    echo '<p class="msg"><b>Policy IoT salvate: '.(int)$iotPolicyCount.'.</b> Le sezioni IPTM:iot-&lt;mac&gt; rimangono nella bozza finché sono abilitate qui. Rimuovi i filtri soltanto deselezionandoli e salvando: nessuna disattivazione automatica.</p>'; 
    echo '<p class="mut">Una riga per dispositivo. <b>Seleziona</b> prepara l’anteprima MAC. <b>Salva tutte le selezioni</b> memorizza classi, selezione e filtri IoT in una singola bozza, senza applicazione al kernel. Passa sui flag per la descrizione completa.</p>';
    if ($inventoryReady) {
        echo '<p class="mut">Dispositivi individuati: '.count((array)($inventory['devices']??[])).' · IoT suggeriti dal vendor: '.$suggested.'. Rilevazione OUI locale, senza inviare indirizzi MAC online. <a href="?p=devices">Inventario e classificazione</a></p>';
    } else {
        echo '<div class="msg warn">Inventario MAC non disponibile. Le policy già salvate restano visibili, ma non puoi generare una nuova selezione prima della diagnosi.</div>';
    }
    $isAdmin=(($_SESSION['role']??'')==='admin');
    if ($isAdmin && $inventoryReady) {
        // This form owns interface inputs and `macs[]` checkboxes via form=.
        echo '<form id="iptm-mac-plan-form" method="post" class="iptm-classic-form">'.fh('p=zones').'<input type="hidden" name="action" value="mac_plan">';
        echo '<div class="row"><label class="fl">Interfaccia LAN<input name="lan_if" required pattern="[A-Za-z0-9_.:-]{1,15}" value="'.h((string)($S['lan_if']??'')).'" placeholder="eth0"></label>';
        echo '<label class="fl">Interfaccia Internet<input name="wan_if" required pattern="[A-Za-z0-9_.:-]{1,15}" value="'.h((string)($S['wan_if']??'')).'" placeholder="bond0"></label>';
        echo '<label class="fl">Pi-hole DNS locale<input name="dns_ip" required value="'.h((string)($S['dns_ip']??'192.168.1.165')).'" placeholder="192.168.1.165"></label></div></form>';
    }
    if ($iotSource) {
        $displayed=array_slice($iotSource,0,200,true);
        echo '<div class="iptm-table-scroll iptm-zone-table iptm-iot-unified-table" tabindex="0" role="region" aria-label="Dispositivi IoT e blocchi MAC"><table>';
        echo '<thead><tr><th scope="col">Sel.</th><th scope="col">MAC</th><th scope="col">IP</th><th scope="col">Vendor</th><th scope="col">Tipo</th><th scope="col">Policy</th></tr></thead><tbody>';
        foreach ($displayed as $mac=>$device) {
            $savedFlags=(array)($iotPolicySaved[$mac]??[]);
            // The bulk edit form owns every editable policy flag and zone classification.
            $formId='iptm-iot-bulk-form';
            $reachable=!empty($device['online']);
            echo '<tr data-iot-mac="'.h($mac).'">';
            echo '<td class="iptm-iot-select-cell" data-label="Selezione">';
            if ($isAdmin && $inventoryReady && $reachable) {
                echo '<input type="checkbox" form="iptm-mac-plan-form" class="iptm-mac-selected" data-iot-hint="'.(!empty($device['hint'])?'1':'0').'" name="macs[]" value="'.h($mac).'"'.(isset($selectedSaved[$mac])?' checked':'').' aria-label="Seleziona '.h($mac).' per l’anteprima MAC">';
            } else {
                echo '<span class="mut" title="'.($reachable?'Solo amministratore':'Dispositivo non presente nell’inventario attuale').'">—</span>';
            }
            echo '</td><td class="iptm-iot-mac" data-label="MAC"><code>'.h($mac).'</code></td>';
            echo '<td class="iptm-iot-ip" data-label="IP">'.h($device['ip']!==''?$device['ip']:'Offline / IP ignoto').'</td>';
            echo '<td class="iptm-iot-vendor" data-label="Produttore">'.h($device['vendor']!==''?$device['vendor']:'Vendor non disponibile');
            if (!empty($device['hint'])) echo ' <span class="b b-jump">IoT probabile</span>';
            echo '</td><td class="iptm-iot-zone-readonly" data-label="Tipo"><span class="iptm-zone-kind" title="Modifica la classificazione nella pagina Dispositivi">'.h(['iot'=>'IoT','trusted'=>'Fidato','guest'=>'Ospite','unknown'=>'Non classificato'][$device['kind']]??$device['kind']).'</span>';
            if ($isAdmin) {
                // Reuse the saved device type in the existing bulk-save contract.
                // Changing classifications stays in the dedicated Devices page.
                echo '<input type="hidden" form="iptm-iot-bulk-form" name="kinds['.h($mac).']" value="'.h($device['kind']).'">';
                echo '<input type="hidden" form="iptm-iot-bulk-form" name="included[]" value="'.h($mac).'">';
            }
            echo '</td><td data-label="Policy"><div class="iptm-iot-inline"><div class="iptm-iot-flags">';
            if ($isAdmin) {
                foreach (iptm_iot_policy_short_labels() as $flag=>$short) {
                    $desc=iptm_iot_policy_options()[$flag]??$short;
                    echo '<label class="iptm-iot-inline-flag" title="'.h($desc).'"><input type="checkbox" form="'.h($formId).'" name="policies['.h($mac).'][]" value="'.h($flag).'"'.(in_array($flag,$savedFlags,true)?' checked':'').' aria-label="'.h($desc).'">'.h($short).'</label>';
                }
            } else {
                echo '<span class="mut">'.h(implode(', ',array_map(fn($flag)=>iptm_iot_policy_short_labels()[$flag]??$flag,$savedFlags))?:'Nessun blocco').'</span>';
            }
            echo '</div></div></td>';
            echo '</tr>';
        }
        echo '</tbody></table></div>';
        if (count($iotSource)>200) echo '<p class="mut">Mostrati i primi 200 dispositivi: affina l’inventario per gestire quelli successivi.</p>';
        // A single form saves policy selections, classes and the preview selection.
        // Never changes the live kernel; reuses transactional policy regeneration.
        if ($isAdmin) {
            echo '<form id="iptm-iot-bulk-form" method="post">'.fh('p=zones')
                .'<input type="hidden" name="action" value="iot_bulk_save">'
                .'<button class="g" type="submit">Salva policy dei dispositivi</button>'
                .'<p class="mut">Salva tutte le righe mostrate in una sola operazione, con verifica e rollback della bozza. Il firewall live resta invariato.</p></form>';
        }
        if ($isAdmin && $inventoryReady) {
            echo '<div class="iptm-iot-bulk-actions"><button type="button" class="s" data-iptm-mac-select="all">Tutti</button> '
                .'<button type="button" class="s" data-iptm-mac-select="suggested">IoT suggeriti</button> '
                .'<button type="button" class="s" data-iptm-mac-select="none">Nessuno</button></div>';
            echo '<div class="iptm-iot-plan-options"><label title="Blocca QUIC su UDP/443 per i dispositivi selezionati"><input form="iptm-mac-plan-form" type="checkbox" name="block_quic" value="1" checked> Blocca QUIC</label> '
                .'<label title="Permette soltanto il traffico web su 80/443 e NTP 123"><input form="iptm-mac-plan-form" type="checkbox" name="strict_egress" value="1"> Uscita limitata</label></div>';
            echo '<button class="g" type="submit" form="iptm-mac-plan-form">Genera anteprima policy MAC</button>';
            echo '<p class=mut>La generazione è di sola lettura: nessuna modifica delle regole in kernel. Massimo 32 dispositivi; per gli errori controlla l’avviso riportato dopo l’invio.</p>';
        }
    } else {
        echo '<p class="mut">Nessun MAC disponibile: aggiorna l’inventario nella pagina Dispositivi.</p>';
    }
    echo '</section>';
    $macplan=$_SESSION['mac_plan']??null;
    if (is_array($macplan) && time()-(int)($macplan['time']??0)<600) {
        $planData=(array)($macplan['data']??[]);
        echo '<h4>Anteprima policy senza VLAN · '.count((array)($planData['macs']??[])).' MAC</h4>';
        echo '<table><tr><th>Verifica</th><th>Esito</th><th>Dettaglio</th></tr>';
        foreach((array)($planData['readiness']??[]) as $check) echo '<tr><td>'.h((string)($check['name']??'')).'</td><td>'.h((string)($check['status']??'')).'</td><td>'.h((string)($check['detail']??'')).'</td></tr>';
        echo '</table><details><summary>Regole IPv4 e IPv6 generate</summary><pre>';
        foreach((array)($planData['rules']??[]) as $rr) echo h((string)($rr['t']??'').' '.(string)($rr['r']??''))."\n";
        foreach((array)($planData['ipv6_rules']??[]) as $rr) echo h('IPv6 '.(string)$rr)."\n";
        echo '</pre></details>';
        foreach((array)($planData['caveats']??[]) as $note) echo '<p class=mut>'.h((string)$note).'</p>';
        $ipv6DisabledHere=iptm_gateway_ipv6_disabled();
        if ($ipv6DisabledHere) echo '<p class="msg warn">IPv6 disabilitato globalmente sul gateway: la policy MAC può essere salvata nella sola bozza IPv4. Il filtro IPv6 non sarà applicabile; la comunicazione diretta L2 fra client resta possibile.</p>';
        if (($_SESSION['role']??'')==='admin' && !empty($planData['ready_to_stage'])) echo '<form method=post>'.fh('p=zones').'<input type=hidden name=action value=mac_stage><button class=g>'.($ipv6DisabledHere?'Salva bozza IPv4 (IPv6 disabilitato)':((($ipv6Check['filter']??'')==='unavailable')?'Verifica IPv6 o conserva piano sospeso':'Salva entrambe le bozze, senza applicare')).'</button></form>';
        elseif (empty($planData['ready_to_stage'])) echo '<div class="msg err">Prerequisiti non soddisfatti: salvataggio policy bloccato.</div>';
    }
    echo '</div>';
    // Runtime VLAN is a separate, opt-in operation: it never edits firewall live.
    [$vlanRc,$vlanOut] = priv('security',json_encode(['mode'=>'status']),['vlan-manage']);
    $vlan = $vlanRc===0 ? json_decode($vlanOut,true) : null;
    echo '<details class=card><summary>Opzione avanzata: VLAN (solo con AP/switch compatibili)</summary>';
    echo '<div class=card><h3>VLAN IoT software su DietPi</h3>';
    echo '<p class=mut>Come nei firewall a zone: crea un’interfaccia Linux 802.1Q separata, ma il tagging della porta dello switch/AP e l’isolamento fra client vanno configurati sull’apparato di rete. La VLAN gestita è <b>temporanea</b> e non sopravvive al riavvio; non altera la LAN principale, il default gateway o il firewall attivo.</p>';
    if (is_array($vlan) && !empty($vlan['managed'])) {
        echo '<p>Interfaccia gestita: <b>'.h($vlan['iface']??'').'</b> · subnet '.h($vlan['network']??'').' · gateway '.h($vlan['gateway']??'').'</p>';
        if (empty($vlan['present'])) {
            if (($vlan['status']??'')==='mismatch')
                echo '<div class="msg err">Interfaccia presente ma diversa dall’ID VLAN registrato: gestione bloccata per evitare modifiche a una rete altrui.</div>';
            else echo '<div class="msg warn">VLAN registrata ma non presente nel kernel (ad esempio dopo riavvio). Non considerare operativo l’isolamento.</div>';
            if (($vlan['status']??'')!=='mismatch' && ($_SESSION['role']??'')==='admin' && empty($warden['active']) && empty($warden['detected']) && empty($warden['blockers'])) {
                echo '<form method=post class="iptm-classic-form">'.fh('p=zones').'<input type=hidden name=action value=zone_vlan_create>';
                foreach (['vlan_parent'=>'parent','vlan_id'=>'vlan_id','vlan_network'=>'network','vlan_gateway'=>'gateway'] as $key=>$attr)
                    echo '<input type=hidden name="'.h($key).'" value="'.h((string)($vlan[$attr]??'')).'">';
                echo '<p><button class=s>Ricrea VLAN gestita dopo riavvio</button></p></form>';
            }
        }
        else {
            echo '<p class=mut>VLAN presente nel kernel. Segui con la policy IoT sottostante e la procedura Applica con rollback.</p>';
            if (($_SESSION['role']??'')==='admin') {
                echo '<details><summary>Rimuovi VLAN software (solo dopo aver eliminato le policy)</summary>';
                echo '<form method=post class="iptm-classic-form">'.fh('p=zones').'<input type=hidden name=action value=zone_vlan_remove>';
                echo '<p class=mut>Rifiutata se le regole IPv4/IPv6 attive o salvate citano questa interfaccia, oppure se la sessione amministrativa la usa.</p>';
                echo '<p><button class=s>Rimuovi solo la VLAN gestita</button></p></form></details>';
            }
        }
    } elseif (!empty($warden['active']) || !empty($warden['detected']) || !empty($warden['blockers'])) {
        echo '<p class=mut>Creazione bloccata: completare prima la migrazione sicura da IoT Warden.</p>';
    } elseif (($_SESSION['role']??'')==='admin') {
        echo '<form method=post class="iptm-classic-form">'.fh('p=zones').'<input type=hidden name=action value=zone_vlan_create>';
        echo '<div class=row><label class=fl>Interfaccia parent (es. eth0, bond0)<input name=vlan_parent pattern="[A-Za-z0-9_.:-]{1,15}" required placeholder="eth0"></label>';
        echo '<label class=fl>VLAN ID (2–4094)<input name=vlan_id type=number min=2 max=4094 required placeholder=30></label>';
        echo '<label class=fl>Subnet IoT<input name=vlan_network required placeholder="192.168.30.0/24"></label>';
        echo '<label class=fl>Gateway VLAN/IP DietPi<input name=vlan_gateway required placeholder="192.168.30.1"></label></div>';
        echo '<p><button class=g type=submit>Crea interfaccia VLAN software</button></p></form>';
    }
    echo '<p class=mut>Nessuna configurazione DHCP o AP viene modificata. Il forwarding IPv4 deve essere già abilitato. Se vuoi una configurazione persistente, impostala nella gestione di rete DietPi dopo aver verificato il collaudo.</p></div>';
    $vlanIf = is_array($vlan) && !empty($vlan['present']) ? (string)($vlan['iface']??'') : '';
    $vlanNet = $vlanIf!=='' ? (string)($vlan['network']??'') : '';
    echo '<div class=card><h3>Policy IoT: coppie di zone e controllo DNS</h3>';
    echo '<p class=mut>Modello ispirato a Cisco ZBF, PAN-OS e FortiGate: permessi espliciti fra zone, stato delle connessioni e blocco predefinito. La policy entra in vigore solo dopo generazione, test e Applica con rollback.</p>';
    echo '<table><tr><th>Origine → Destinazione</th><th>Regola prevista</th></tr>';
    echo '<tr><td>IoT → Internet (WAN)</td><td>Consentito; profilo restrittivo: TCP 80/443. NAT dedicato</td></tr>';
    echo '<tr><td>IoT → LAN / altre zone</td><td>Negato, eccetto DNS locale TCP/UDP 53</td></tr>';
    echo '<tr><td>LAN/WAN → IoT</td><td>Solo ritorni ESTABLISHED,RELATED; nuove sessioni negate</td></tr>';
    echo '<tr><td>IoT → DNS esterni / VPN note</td><td>Porta 53 reindirizzata al DNS locale; 853 e protocolli VPN comuni bloccati, 443/UDP opzionalmente bloccato</td></tr>';
    echo '<tr><td>IoT → IPv6</td><td>Blocco del forwarding IPv6 predefinito; routing esplicito solo con rete IPv6 dedicata</td></tr></table>';
    echo '<p class=mut><b>Limite:</b> DoH incapsulato in TCP 443 o tunnel camuffati non sono riconoscibili completamente con sole regole iptables. Il blocco del bypass DNS non può essere assoluto; serve anche controllo degli endpoint ammessi o proxy consenziente.</p></div>';
    echo '<div class=card><h3>Crea policy per zona IoT instradata</h3><p>Richiede VLAN/subnet <b>già creata</b> su switch/AP e interfaccia sul router. La separazione software funziona solo per traffico instradato che attraversa DietPi; client nello stesso dominio L2 si parlano senza passare dal firewall. È necessaria una rete ospiti/VLAN separata sull’AP o switch. Per sicurezza viene generata solo una bozza, con <code>iptables-restore --test</code> e rollback nella pagina Applica. L’IP amministrativo corrente non può appartenere alla VLAN da isolare.</p>';
    if (($_SESSION['role']??'')==='admin' && !empty($warden['ok']) && empty($warden['active']) && empty($warden['blockers']) && empty($warden['detected'])) {
        echo '<form method=post class="iptm-classic-form">'.fh('p=zones').'<input type=hidden name=action value=zone_plan><div class=row><label class=fl>Interfaccia VLAN (es. eth0.30)<input name=iface pattern="[A-Za-z0-9_.:-]{1,15}" required value="'.h($vlanIf).'" placeholder="eth0.30"></label><label class=fl>Subnet IoT IPv4 (es. 192.168.30.0/24)<input name=network value="'.h($vlanNet).'" required placeholder="192.168.30.0/24"></label><label class=fl>DNS locale IPv4 LAN<input name=dns_ip required value="'.h($S['dns_ip']??'').'" placeholder="192.168.1.10"></label></div>';
        echo '<h4>IPv6 — obbligatorio scegliere una protezione</h4><label class=fl>Policy IPv6<select name=ipv6_mode><option value=block>Blocca il forwarding IPv6 della VLAN (consigliato senza IPv6 locale)</option><option value=route>Instrada IPv6 con DNS locale e isolamento</option></select></label>';
        echo '<div class=row><label class=fl>Subnet IoT IPv6 (per modalità instradata)<input name=network6 placeholder="fd42:30::/64"></label><label class=fl>Reti IPv6 fidate, separate da virgole<input name=trusted_nets6 placeholder="fd42:1::/64"></label><label class=fl>DNS IPv6 locale (per modalità instradata)<input name=dns_ip6 placeholder="fd42:1::53"></label></div>';
        echo '<h4>Riduzione bypass DNS/VPN</h4><div class=row><label class=fl>IP/CIDR di resolver DoH noti da bloccare (IPv4, CSV)<input name=blocked_resolvers4 placeholder="1.1.1.1/32,8.8.8.8/32"></label><label class=fl>Resolver DoH IPv6 da bloccare (CSV)<input name=blocked_resolvers6 placeholder="2606:4700:4700::1111/128"></label></div>';
        echo '<label><input type=checkbox name=block_quic value=1 checked> Blocca QUIC/UDP 443 e DoQ su 443 (può interrompere app)</label> <label><input type=checkbox name=strict_egress value=1 checked> Profilo restrittivo: consenti solo HTTP/HTTPS TCP 80/443 in uscita (escluso DNS locale; può interrompere IoT)</label>';
        echo ' <label><input type=checkbox name=block_common_resolvers value=1 checked> Blocca IP pubblici DNS/DoH più diffusi (può bloccare anche servizi web sullo stesso IP)</label>';
        echo '<p class=mut>DoH o VPN mascherati su TCP 443 non sono identificabili universalmente. Le nuove regole IPv6 sono salvate in una bozza separata: dopo la verifica occorre applicare/confermare IPv4 e IPv6 distintamente.</p><p><button class=g>Anteprima delle due famiglie</button></p><progress class=iptm-progress hidden></progress><span role=status class=mut></span></form>';
    }
    $pl=$_SESSION['zone_plan']??null;
    if (is_array($pl) && time()-($pl['time']??0)<600) {
        echo '<h4>Anteprima: '.h($pl['data']['interface']??'').' / '.h($pl['data']['network']??'').'</h4><pre>';
        foreach (($pl['data']['rules']??[]) as $r) echo h($r['t'].' '.$r['r'])."\n";
        echo '</pre><h4>IPv6: '.h($pl['data']['ipv6_mode']??'').'</h4><pre>';
        foreach (($pl['data']['ipv6_rules']??[]) as $r) echo h((string)$r)."\n";
        echo '</pre><h4>Verifica operativa rete IoT</h4><p class=mut>Controlli di sola lettura sul router: non dimostrano l’isolamento L2 né l’assenza di bypass HTTPS. Nessuna regola viene applicata.</p>';
        if (empty($pl['data']['ready_to_apply'])) echo '<div class="msg err" role="alert"><b>Prerequisiti mancanti:</b> non applicare la bozza finché i controlli bloccanti non sono risolti.</div>';
        echo '<table><tr><th>Controllo</th><th>Stato</th><th>Dettaglio</th></tr>';
        foreach (($pl['data']['readiness']??[]) as $ck) echo '<tr><td>'.h($ck['name']??'').'</td><td>'.h($ck['status']??'').'</td><td>'.h($ck['detail']??'').'</td></tr>';
        echo '</table><ul>';
        foreach (($pl['data']['caveats']??[]) as $msg) echo '<li>'.h($msg).'</li>';
        echo '</ul>';
        if (($_SESSION['role']??'')==='admin') echo '<form method=post class="iptm-classic-form">'.fh('p=zones').'<input type=hidden name=action value=zone_stage><button class=g>Salva nella bozza, NON applicare live</button><progress class=iptm-progress hidden></progress><span role=status class=mut></span></form>';
    }
    echo '</div>';
    echo '</details>';
    echo '</div>';
}

