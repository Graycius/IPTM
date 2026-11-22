<?php
/** IPTM topology: an editable *logical* map. No active probing or live firewall changes. */
function iptm_topology_kind(string $vendor, string $class): array {
    $v=strtolower($vendor);
    $rules=[
        'printer'=>['hewlett','hp inc','brother','epson','canon','lexmark','xerox'],
        'camera'=>['hikvision','dahua','reolink','axis communications'],
        'television'=>['roku','samsung','lg electronics','vizio'],
        'mobile'=>['apple','huawei','xiaomi','oneplus','oppo'],
        'router'=>['ubiquiti','mikrotik','cisco','aruba','netgear','tp-link'],
        'iot'=>['tuya','espressif','shelly','sonoff','amazon technologies'],
    ];
    foreach($rules as $kind=>$names) foreach($names as $name) {
        if(str_contains($v,$name)) return [$kind,'Suggerimento dal produttore MAC (non verificato)'];
    }
    return $class==='iot' ? ['iot','Classe impostata in IPTM'] : ['generic','Tipo non riconoscibile dal MAC'];
}
function iptm_topology_data(array $inventory,array $S): array {
    $nodes=[];$seenMac=[];$ips=[];$kinds=(array)($S['iot_devices']??[]);
    $policies=(array)($S['iot_policies']??[]);
    $selected=array_fill_keys((array)($S['iot_selected_macs']??[]),true);
    foreach((array)($inventory['devices']??[]) as $row) {
        if(!is_array($row))continue;
        $mac=strtolower((string)($row['mac']??''));
        if(!preg_match('/^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/D',$mac))continue;
        $kind=(string)($kinds[$mac]??'unknown');
        if(!in_array($kind,['trusted','guest','iot','unknown'],true))$kind='unknown';
        [$icon,$evidence]=iptm_topology_kind((string)($row['vendor']??''),$kind);
        $addresses=array_values(array_filter((array)($row['addresses']??[]),'is_string'));
        $addresses=array_slice($addresses,0,6);
        $flags=array_values(array_intersect((array)($policies[$mac]??[]),array_keys(iptm_iot_policy_options())));
        $warnings=[];
        if(!$addresses)$warnings[]='Nessun indirizzo IP rilevato (il dispositivo potrebbe essere offline)';
        if(!empty($row['locally_administered']))$warnings[]='MAC amministrato localmente/randomizzato: produttore non affidabile';
        if(in_array('forward',$flags,true) && count($flags)>1)$warnings[]='Blocco totale incompatibile con altri filtri';
        if($kind==='trusted' && in_array('forward',$flags,true))$warnings[]='Dispositivo fidato con blocco totale';
        foreach($addresses as $addr) {
            if(isset($ips[$addr]) && $ips[$addr]!==$mac)$warnings[]='IP duplicato su un altro MAC: '.$addr;
            else $ips[$addr]=$mac;
        }
        $seenMac[$mac]=true;
        $nodes[]=['mac'=>$mac,'ips'=>$addresses,'vendor'=>substr((string)($row['vendor']??''),0,100),
            'kind'=>$kind,'device_type'=>$icon,'evidence'=>$evidence,'flags'=>$flags,
            'selected'=>isset($selected[$mac]),'warnings'=>$warnings,
            'interfaces'=>array_slice(array_values(array_filter((array)($row['interfaces']??[]),'is_string')),0,4),
            'observed'=>true];
    }
    // Previously managed nodes may be absent from today's ARP/ND inventory.
    foreach($policies as $raw=>$flags) {
        $mac=strtolower((string)$raw);
        if(!preg_match('/^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/D',$mac))continue;
        if(isset($seenMac[$mac]))continue;
        $seenMac[$mac]=true;
        $kind=(string)($kinds[$mac]??'unknown');
        if(!in_array($kind,['trusted','guest','iot','unknown'],true))$kind='unknown';
        $nodes[]=['mac'=>$mac,'ips'=>[],'vendor'=>'','kind'=>$kind,'device_type'=>'generic',
            'evidence'=>'Nodo salvato in IPTM, assente nell’inventario corrente',
            'flags'=>array_values(array_intersect((array)$flags,array_keys(iptm_iot_policy_options()))),
            'selected'=>isset($selected[$mac]),'warnings'=>['Dispositivo non presente nell’inventario corrente'],
            'interfaces'=>[],'observed'=>false];
    }
    usort($nodes,fn($a,$b)=>strcmp($a['mac'],$b['mac']));
    $total=count($nodes);
    // Existing iot_bulk_save accepts at most 200 rows; exceeding this is explicit and read-only.
    $nodes=array_slice($nodes,0,200);
    $warnings=0;foreach($nodes as $n)$warnings+=count($n['warnings']);
    return ['ok'=>true,'nodes'=>$nodes,'total'=>$total,'warnings'=>$warnings,
        'wan'=>(string)($S['wan_if']??''),'lan'=>(string)($S['lan_if']??''),
        'dns'=>(string)($S['dns_ip']??''),
        'ipv6_disabled'=>function_exists('iptm_gateway_ipv6_disabled')?iptm_gateway_ipv6_disabled():null,
        'network_caveat'=>'I collegamenti sono associazioni logiche dedotte dall’inventario ARP/ND: non dimostrano cablaggio, switch, SSID o traffico L2.'];
}
function pg_topology(): void {
    if(pg_async_skeleton('topology','Mappa logica dei dispositivi'))return;
    $S=S_get();$inv=iptm_security_read('mac-inventory');
    $ready=!empty($inv['ok']) && isset($inv['devices']) && is_array($inv['devices']);
    $data=$ready?iptm_topology_data($inv,$S):['ok'=>false,'nodes'=>[], 'total'=>0,'warnings'=>0,
      'network_caveat'=>'Inventario MAC non verificato: impossibile creare associazioni.'];
    echo '<section class="card iptm-topology-page"><div class="iptm-topology-heading"><div><h2>Mappa rete e configurazione visuale</h2>';
    echo '<p class="mut">Mappa indicativa, basata sui dispositivi rilevati. Le modifiche salvano solo una bozza.</p></div>';
    echo '<span class="b">'.(int)$data['total'].' dispositivi</span></div>';
    if(!$ready)echo '<div class="msg warn">Lettura MAC non disponibile: '.h((string)($inv['error']??'helper o timeout')).'. Nessuna configurazione può essere salvata. <a href="?p=devices">Verifica inventario</a>.</div>';
    if($data['total']>200)echo '<div class="msg warn">Mostrati solo i primi 200 nodi: modifica massiva bloccata per non perdere le policy degli altri dispositivi.</div>';
    echo '<div class="iptm-topology-toolbar"><label>Trova dispositivo<input id="iptm-topo-search" type="search" placeholder="MAC, IP, vendor o zona" autocomplete="off"></label>';
    echo '<label>Zona<select id="iptm-topo-filter"><option value="all">Tutte</option><option value="trusted">Fidati</option><option value="iot">IoT</option><option value="guest">Ospiti</option><option value="unknown">Da classificare</option></select></label>';
    echo '<button type="button" class="s" id="iptm-topo-zoom-in" aria-label="Ingrandisci mappa">＋</button><button type="button" class="s" id="iptm-topo-zoom-out" aria-label="Riduci mappa">−</button><button type="button" class="s" id="iptm-topo-reset">Ripristina disposizione</button><a class="btn s" href="?p=zones">Gestione IoT completa</a></div>';
    echo '<div class="iptm-topology-shell"><div class="iptm-topology-stage" role="region" aria-label="Mappa di rete interattiva, seleziona un dispositivo per configurarlo">';
    echo '<svg id="iptm-topology-svg" role="group" viewBox="0 0 1120 690" aria-label="Mappa logica della rete"></svg></div>';
    echo '<aside class="iptm-topology-panel" id="iptm-topology-panel" aria-label="Dettaglio del dispositivo selezionato"><h3>Seleziona un nodo</h3><p>Cerca o seleziona un dispositivo.</p></aside></div>';
    if(!empty($data['ipv6_disabled'])) echo '<p class="mut">IPv6 disabilitato.</p>';
    echo '<p class="mut iptm-topology-legend">○ associazione dedotta · <span class="iptm-topology-error-dot">●</span> anomalia o incoerenza · trascina un nodo oppure usa le frecce della tastiera per spostarlo; +/− controllano lo zoom. I MAC randomizzati non identificano in modo affidabile la categoria.</p>';
    echo '<div class="iptm-topology-bottom"><h3>Avvisi e incoerenze</h3><div id="iptm-topology-issues" role="status"></div>';
    echo '<div class="iptm-topology-table-wrap"><table class="iptm-topology-table" id="iptm-topology-table"><thead><tr><th>Dispositivo</th><th>IP</th><th>Zona</th><th>Regole</th><th>Stato dati</th></tr></thead><tbody></tbody></table></div></div>';
    $canSave=$ready && $data['total']<=200 && (($_SESSION['role']??'')==='admin') && !empty($data['nodes']);
    if($canSave) {
        echo '<form id="iptm-topology-save" method="post">'.fh('p=topology')
            .'<input type="hidden" name="action" value="iot_bulk_save"><input type="hidden" name="return_to_topology" value="1">'
            .'<div id="iptm-topology-post-data"></div><button type="submit" class="g">Salva tutte le scelte nella bozza IoT</button>'
            .'<p class="mut">Salva solo una bozza. Per attivarla, usa <b>Applica</b> con recupero automatico.</p></form>';
    }
    $data['can_edit']=$canSave;
    $json=json_encode($data,JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT|JSON_INVALID_UTF8_SUBSTITUTE);
    echo '<script type="application/json" id="iptm-topology-data">'.$json.'</script></section>';
}
