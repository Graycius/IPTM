<?php
/** Multi-NIC web planning + console-only transactional runtime status. */
/** Text topology editor: bounded records and explicit grammar, never shell commands. */
function iptm_fabric_lines(string $key, int $parts, int $limit): array {
    $raw=$_POST[$key]??'';
    if(!is_string($raw)||strlen($raw)>16384||preg_match('/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/',$raw)) throw new RuntimeException('Topologia: payload non valido per '.$key);
    $rows=[];
    foreach(preg_split('/\R/',trim($raw)) as $line){
        if(trim($line)===''||str_starts_with(ltrim($line),'#')) continue;
        $cols=array_map('trim',explode('|',$line));
        if(count($cols)!==$parts) throw new RuntimeException('Topologia '.$key.': colonne attese '.$parts);
        if(count($rows)>=$limit) throw new RuntimeException('Topologia '.$key.': limite superato');
        $rows[]=$cols;
    }
    return $rows;
}
function iptm_fabric_post(): array {
    $r=['bridges'=>[],'bonds'=>[],'vlans'=>[],'zones'=>[],'policies'=>[],'switches'=>[]];
    foreach(iptm_fabric_lines('fabric_bridges',6,12) as $x)
        $r['bridges'][]=['name'=>$x[0],'ports'=>array_values(array_filter(array_map('trim',explode(',',$x[1])),'strlen')),
          'stp'=>$x[2]==='1','vlan_filtering'=>$x[3]==='1', 'zone'=>$x[4], 'address'=>$x[5]];
    foreach(iptm_fabric_lines('fabric_bonds',4,8) as $x)
        $r['bonds'][]=['name'=>$x[0],'ports'=>array_values(array_filter(array_map('trim',explode(',',$x[1])),'strlen')),
          'mode'=>$x[2],'lacp_confirmed'=>$x[3]==='1'];
    foreach(iptm_fabric_lines('fabric_vlans',6,64) as $x)
        $r['vlans'][]=['name'=>$x[0],'parent'=>$x[1],'vid'=>$x[2],'zone'=>$x[3], 'address'=>$x[4], 'dhcp_server'=>$x[5]==='1'];
    foreach(iptm_fabric_lines('fabric_zones',2,24) as $x)
        $r['zones'][]=['name'=>$x[0],'default'=>$x[1]];
    foreach(iptm_fabric_lines('fabric_policies',3,256) as $x)
        $r['policies'][]=['source'=>$x[0],'destination'=>$x[1],'action'=>$x[2]];
    $switches=[];
    foreach(iptm_fabric_lines('fabric_switches',3,12) as $x)
        $switches[$x[0]]=['name'=>$x[0], 'management_ip'=>$x[1], 'vendor'=>$x[2], 'ports'=>[]];
    foreach(iptm_fabric_lines('fabric_switch_ports',5,384) as $x){
        if(!isset($switches[$x[0]])) throw new RuntimeException('Porta di switch non dichiarato: '.$x[0]);
        $tags=$x[4]===''?[]:array_values(array_filter(array_map('trim',explode(',',$x[4])),'strlen'));
        $switches[$x[0]]['ports'][]=['name'=>$x[1],'mode'=>$x[2], 'pvid'=>$x[3], 'tagged'=>$tags];
    }
    $r['switches']=array_values($switches);
    return $r;
}
function iptm_fabric_editor_value(array $fabric,string $key): string {
    $lines=[];
    foreach($fabric[$key]??[] as $x){
        if(!is_array($x))continue;
        switch($key){
        case 'bridges': $col=[$x['name'],implode(',',$x['ports']),$x['stp']?'1':'0',$x['vlan_filtering']?'1':'0',$x['zone']??'lan',$x['address']??''];break;
        case 'bonds': $col=[$x['name'],implode(',',$x['ports']),$x['mode'],$x['lacp_confirmed']?'1':'0'];break;
        case 'vlans': $col=[$x['name'],$x['parent'],$x['vid'],$x['zone'],$x['address'],$x['dhcp_server']?'1':'0'];break;
        case 'zones': $col=[$x['name'],$x['default']];break;
        case 'policies': $col=[$x['source'],$x['destination'],$x['action']];break;
        case 'switches': $col=[$x['name'],$x['management_ip'],$x['vendor']];break;
        case 'switch_ports': $col=[];break;
        default: $col=[];
        }
        if($col)$lines[]=implode(' | ',array_map('strval',$col));
    }
    if($key==='switch_ports') foreach($fabric['switches']??[] as $sw)foreach($sw['ports']??[] as $x)
        $lines[]=implode(' | ',[$sw['name'],$x['name'],$x['mode'],$x['pvid'],implode(',',$x['tagged'])]);
    return implode("\n",$lines);
}
function iptm_multinic_input(): array {
    $raw = $_POST['nic'] ?? [];
    if (!is_array($raw) || count($raw) > 16) throw new RuntimeException('Troppe NIC richieste');
    $rows = [];
    foreach ($raw as $name => $x) {
        if (!is_string($name) || !preg_match('/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,14}$/D', $name) || !is_array($x))
            throw new RuntimeException('Nome interfaccia non valido');
        $role = (string)($x['role'] ?? 'spare');
        if ($role === 'ignore') continue;
        foreach (['address','alias_address','gateway','speed','priority'] as $field)
            if (isset($x[$field]) && !is_scalar($x[$field])) throw new RuntimeException('Campo interfaccia non valido');
        $rows[] = ['name'=>$name, 'role'=>$role,
            'address'=>trim((string)($x['address']??'')), 'alias_address'=>trim((string)($x['alias_address']??'')), 'gateway'=>trim((string)($x['gateway']??'')),
            'dhcp'=>($x['dhcp']??'')==='1',
            'capacity_mbps'=>trim((string)($x['speed']??'0')) ?: '0',
            'priority'=>trim((string)($x['priority']??'100')) ?: '100'];
    }
    return ['backend'=>(string)($_POST['backend']??''), 'strategy'=>(string)($_POST['strategy']??''), 'nics'=>$rows, 'fabric'=>iptm_fabric_post()];
}
function pg_multinic(): void {
    $ro=($_SESSION['role']??'viewer')!=='admin';
    [$rc,$out,$err]=priv('multi-nic',null,['status']);
    $status=$rc===0?json_decode($out,true):null;
    if(!is_array($status)||empty($status['ok'])){
        echo '<div class="msg err">Impossibile leggere le interfacce: '.h(substr($err?:$out,0,240)).'</div>';return;
    }
    echo '<p class="mut">Editor NetworkManager: per aggiungere o rimuovere porte bond/bridge tramite un clone inattivo usa le proprietà <code>connection.controller</code> (UUID del master) e <code>connection.port-type</code> (bond o bridge); per scollegare la porta imposta entrambe a stringa vuota. L’attivazione richiede sempre un checkpoint D-Bus e conferma.</p>';
    echo '<p class="mut">Riferimento funzionale per la gestione completa NetworkManager: <a target="_blank" rel="noopener noreferrer" href="https://github.com/cockpit-project/cockpit">Cockpit Networking</a>. Non installato da IPTM; le modifiche alla NIC di gestione richiedono sempre checkpoint e conferma.</p>';
    $inv=(array)($status['inventory']??[]);
    $ifs=[];$physical=[];$primary='';$routes=(array)($inv['default_routes']??[]);
    $default=(string)($routes[0]['dev']??'');
    foreach((array)($inv['interfaces']??[]) as $nic){
        if(!is_array($nic) || empty($nic['name']) || $nic['name']==='bonding_masters')continue;
        $ifs[(string)$nic['name']]=$nic;
        if(!empty($nic['physical']))$physical[(string)$nic['name']]=$nic;
    }
    [$frc,$fout,] = priv('net-audit',null,['pihole-dhcp']);
    $ftlRaw=$frc===0?json_decode($fout,true):null;
    $ftl=is_array($ftlRaw)?(array)($ftlRaw['fields']??[]):[];
    $ftlName=(string)($ftl['interface']??'');
    $primary=isset($ifs[$default])?$default:($ftlName!==''&&isset($ifs[$ftlName])?$ftlName:'');
    $nmActive=!empty($inv['managers']['networkmanager']['active']);
    $client=(string)($_SERVER['REMOTE_ADDR']??'');
    $clientOK=(bool)filter_var($client,FILTER_VALIDATE_IP,FILTER_FLAG_IPV4)&&$client!=='127.0.0.1';
    $spares=[];
    foreach($physical as $name=>$nic){
        if(!empty($nic['master'])||$name===$primary||$name===$default)continue;
        $spares[$name]=$nic;
    }
    if (function_exists('iptm_operator_insights')) iptm_operator_insights('network');
    echo '<div class="iptm-nm-console" id="iptm-nm-console">';
    echo '<div class="iptm-nm-head"><div><h2>Interfacce e DHCP</h2><p>Interfacce, VLAN e DHCP.</p></div>';
    echo '<a class="s" href="?p=diag">Diagnostica</a></div>';
    echo '<div class="iptm-nm-overview">';
    foreach([['Gestore',$nmActive?'NetworkManager':'Altro gestore'],['Rete primaria',$primary?:'Da scegliere'],['Uscita Internet',$default?:'Assente'],['Schede fisiche',(string)count($physical)]] as $cell)
        echo '<div><small>'.h($cell[0]).'</small><strong>'.h($cell[1]).'</strong></div>';
    echo '</div>';
    if(!$nmActive)echo '<div class="msg warn">NetworkManager non è attivo. I controlli operativi sono disabilitati; nessun cambio di gestore automatico.</div>';
    if(!$ftlName)echo '<div class="msg warn">Pi-hole non ha un’interfaccia esplicita: prima di attivare un nuovo segmento, vincola il DNS/DHCP al master primario tramite Pi-hole.</div>';
    elseif($primary!=='' && $ftlName!==$primary)echo '<div class="msg err">Pi-hole DHCP su '.h($ftlName).' anziché su '.h($primary).'. Correggi l’interfaccia Pi-hole prima di attivare la rete secondaria.</div>';
    if($ro)echo '<p class="mut">Accesso in sola lettura.</p>';
    echo '<section class="card iptm-nm-section"><div class="iptm-nm-title"><h3>Schede e collegamenti</h3><span>Stato Linux / NetworkManager</span></div>';
    echo '<div class="iptm-nm-cards">';
    foreach($ifs as $name=>$nic){
        $physicalNIC=!empty($nic['physical']);$slave=(string)($nic['master']??'');
        $protected=(!$physicalNIC || $slave!=='' || $name===$default || $name===$primary);
        $ips=(array)($nic['ipv4']??[]);$state=strtoupper((string)($nic['state']??'UNKNOWN'));
        $carrier=(string)($nic['carrier']??'?');
        $stateDescription=$state==='UP'?'Attiva':($carrier==='0'?'Cavo scollegato':($state==='DOWN'?'Non connessa':$state));
        echo '<article class="iptm-nm-card"><div class="iptm-nm-card-head"><div><strong>'.h($name).'</strong> <span class="iptm-nm-tag">'.h($physicalNIC?'Ethernet':(string)($nic['kind']??'virtuale')).'</span></div>';
        echo '<span class="iptm-nm-state" data-state="'.h($state).'">'.h($stateDescription).'</span></div>';
        if($slave!=='')echo '<p class="mut">Membro di <b>'.h($slave).'</b>: non è una NIC indipendente. Per disattivarla dal bond serve una transazione sul controller, con checkpoint e console di recupero; non usare il comando generico Disconnetti.</p>';
        echo '<div class="iptm-nm-ips"><b>IPv4</b> '.h(implode(', ',$ips)?:'Nessun indirizzo').'</div>';
        $speed=(int)($nic['speed_mbps']??0);if($speed>0)echo '<p class="mut">Velocità link: '.(int)$speed.' Mbit/s</p>';
        if(!$ro && $nmActive && $clientOK && !$protected){
            [$crc,$cout,] = priv('nm-safe',null,['check',$name,$client]);
            $check=$crc===0?json_decode($cout,true):null;
            if(is_array($check) && !empty($check['safe_to_disconnect'])){
                $owned=!empty($check['managed_profile']);
                $profileIps=$owned?(string)($check['profile_ipv4']??''):implode(', ',$ips);
                $profileMtu=(int)($check['profile_mtu']??1500);if($profileMtu<576||$profileMtu>9000)$profileMtu=1500;
                $profileMetric=(int)($check['profile_metric']??300);if($profileMetric<1||$profileMetric>9999)$profileMetric=300;
                echo '<form method="post" class="iptm-nm-editor">'.fh('p=multinic');
                echo '<input type="hidden" name="action" value="nm_profile_save"><input type="hidden" name="nm_device" value="'.h($name).'">';
                echo '<label>Indirizzi IPv4 <small>(separati da virgola)</small><input name="nm_ips" required maxlength="320" placeholder="192.168.20.1/24, 192.168.21.1/24" value="'.h($profileIps).'" autocomplete="off"></label>';
                echo '<div class="iptm-nm-settings"><label>MTU<input type="number" name="nm_mtu" min="576" max="9000" value="'.(int)$profileMtu.'" required></label>';
                echo '<label>Metrica<input type="number" name="nm_metric" min="1" max="9999" value="'.(int)$profileMetric.'" required></label></div>';
                echo '<p class="mut">Profilo salvato, ma non attivo. Gateway, DNS e DHCP invariati.</p>';
                echo '<button class="s" type="submit">'.($owned?'Aggiorna profilo':'Salva profilo').'</button></form>';
                if($owned){
                    echo '<div class="iptm-nm-actions">';
                    foreach(['up'=>'Attiva connessione','down'=>'Disattiva connessione'] as $verb=>$label){
                        echo '<form method="post">'.fh('p=multinic').'<input type="hidden" name="action" value="nm_device_control">';
                        echo '<input type="hidden" name="nm_device" value="'.h($name).'"><input type="hidden" name="nm_verb" value="'.h($verb).'">';
                        echo '<button class="s" type="submit"'.($verb==='down'?'':'').'>'.h($label).'</button></form>';
                    }
                    echo '</div>';
                }
            } else echo '<p class="mut">Non modificabile: '.h(implode(', ',(array)($check['blockers']??['controllo di sicurezza non riuscito']))).'</p>';
        } else echo '<p class="mut">'.h($protected?'Interfaccia protetta: modifica soltanto da console con recupero.':'Controllo non disponibile per questa sessione.').'</p>';
        echo '</article>';
    }
    echo '</div></section>';
    echo '<section class="card iptm-nm-section"><div class="iptm-nm-title"><h3>Bond e porte</h3><span>Profili offline dal web; aggancio live solo dalla console con checkpoint NetworkManager</span></div>';
    $bonds=[];
    foreach($ifs as $name=>$nic)if((string)($nic['kind']??'')==='bond'||preg_match('/^bond[0-9]+$/D',$name))$bonds[$name]=$nic;
    if(!$bonds)echo '<p class="mut">Nessun bond rilevato.</p>';
    foreach($bonds as $bond=>$nic){
        $ports=[];foreach($physical as $name=>$child)if(($child['master']??'')===$bond)$ports[]=$name;
        echo '<div class="iptm-nm-bond"><b>'.h($bond).'</b><p>'.h($ports?implode(' + ',$ports):'Nessuna porta rilevata').'</p><small>Attiva/disattiva porte del bond soltanto da console con checkpoint: <code>sudo iptm-helper nm-bond-live attach PORTA '.h($bond).'</code> oppure <code>sudo iptm-helper nm-bond-live detach PORTA '.h($bond).'</code>. Il distacco della porta attiva del bond è intenzionalmente bloccato.</small>';
        if(!$ro && $nmActive && $clientOK && $spares){
            echo '<form method="post" class="iptm-nm-bond-form">'.fh('p=multinic');
            echo '<input type="hidden" name="action" value="nm_bond_port"><input type="hidden" name="nm_bond" value="'.h($bond).'">';
            echo '<label>Porta disponibile<select name="nm_device">';foreach($spares as $name=>$port)echo '<option value="'.h($name).'">'.h($name).'</option>';echo '</select></label>';
            echo '<button class="s" type="submit" name="nm_bond_action" value="bond-add">Prepara porta</button>';
            echo '<button class="s" type="submit" name="nm_bond_action" value="bond-remove">Rimuovi profilo IPTM</button></form>';
            echo '<p class="mut">Solo profili IPTM inattivi. Le porte attive e quelle della sessione rimangono protette.</p>';
        }
        echo '</div>';
    }
    echo '</section>';
    echo '<section class="card iptm-nm-section" id="iptm-dhcp-wizard"><div class="iptm-nm-title"><h3>Server DHCP</h3><span>Pi-hole per la LAN; DHCP dedicato sulla seconda rete</span></div>';
    echo '<div class="iptm-nm-dhcp-grid"><div><b>Pi-hole · primario</b>';
    echo '<p>Interfaccia: <strong>'.h($ftlName?:'Non impostata').'</strong></p>';
    echo '<p>Pool: '.h((string)($ftl['start']??'n/d')).' – '.h((string)($ftl['end']??'n/d')).'</p>';
    echo '<p>Gateway: '.h((string)($ftl['router']??'n/d')).'</p>';
    echo '<p class="mut">Pi-hole resta sull’interfaccia selezionata.</p></div>';
    echo '<div><b>DHCP secondario</b>';
    if(!$spares)echo '<p>Nessuna scheda fisica indipendente disponibile.</p>';
    else {
        echo '<p>Puoi configurare la rete anche senza cavo; il server DHCP richiede collegamento e isolamento L2.</p>';
        if(!$ro){
            echo '<form method="post" class="iptm-nm-dhcp-form">'.fh('p=multinic');
            echo '<input type="hidden" name="dhcp_primary_interface" value="'.h($primary).'">';
            $primaryIp=(string)(($ifs[$primary]['ipv4']??[])[0]??'');
            echo '<input type="hidden" name="dhcp_primary_address" value="'.h($primaryIp).'">';
            foreach(['start','end','gateway'] as $field)echo '<input type="hidden" name="dhcp_primary_'.h($field).'" value="'.h((string)($ftl[$field==='gateway'?'router':$field]??'')).'">';
            echo '<label>Interfaccia secondaria<select name="dhcp_secondary_interface">';
            foreach($spares as $name=>$nic)echo '<option value="'.h($name).'">'.h($name).' · '.h((string)($nic['state']??'')).'</option>';
            echo '</select></label><label>IP server CIDR<input name="dhcp_secondary_address" placeholder="192.168.20.1/24" maxlength="32" required></label>';
            foreach([['start','Inizio pool'],['end','Fine pool'],['gateway','Gateway'],['dns','DNS Pi-hole']] as $pair)
                echo '<label>'.h($pair[1]).'<input name="dhcp_secondary_'.h($pair[0]).'" maxlength="32" placeholder="192.168.20.50" required></label>';
            echo '<button class="s" type="submit" name="action" value="dhcp_dual_preview">Controlla pool e subnet</button></form>';
            if(is_array($_SESSION['iptm_dual_dhcp_preview']??null))echo '<p class="mut">Validazione completata: il servizio DHCP <b>non è stato avviato</b>.</p>';

            echo '<div class="card"><h3>Reservation DHCP (static host)</h3>';
            echo '<p class="mut">Verifica MAC/IP/hostname rispetto a subnet e pool. <b>Controlla</b> solo valida; <b>Applica su Pi-hole</b> scrive `dhcp.hosts` tramite pihole-FTL.</p>';
            $chk=$_SESSION['iptm_dhcp_reservations_check']??null;
            if(is_array($chk)){
                if(!empty($chk['ok'])) echo '<p class="msg ok">Ultimo controllo: <b>'.(int)($chk['count']??0).'</b> reservation valide · subnet '.h((string)($chk['subnet']??'')).'</p>';
                else {
                    echo '<div class="msg err"><b>Errori reservation</b><ul>';
                    foreach((array)($chk['errors']??[]) as $e){
                        if(!is_array($e)) continue;
                        echo '<li>'.h((string)($e['code']??'err')).': '.h((string)($e['message']??'')).(isset($e['index'])?' (riga '.(((int)$e['index'])+1).')':'').'</li>';
                    }
                    if(!empty($chk['error'])) echo '<li>'.h((string)$chk['error']).'</li>';
                    echo '</ul></div>';
                }
                if(!empty($chk['warnings']) && is_array($chk['warnings'])){
                    echo '<div class="msg warn"><b>Avvisi</b><ul>';
                    foreach($chk['warnings'] as $w){
                        if(!is_array($w)) continue;
                        echo '<li>'.h((string)($w['message']??'')).'</li>';
                    }
                    echo '</ul></div>';
                }
            }
            $ftlAddr=h((string)($primaryIp??''));
            echo '<form method="post" class="iptm-classic-form">'.fh('p=multinic');
            echo '<label>Server CIDR<input name="dhcp_res_address" value="'.$ftlAddr.'" maxlength="32" required placeholder="192.168.1.1/24"></label>';
            echo '<label>Pool start<input name="dhcp_res_start" value="'.h((string)($ftl['start']??'')).'" maxlength="32" required></label>';
            echo '<label>Pool end<input name="dhcp_res_end" value="'.h((string)($ftl['end']??'')).'" maxlength="32" required></label>';
            echo '<label>Gateway<input name="dhcp_res_gateway" value="'.h((string)($ftl['router']??'')).'" maxlength="32" required></label>';
            echo '<label>Reservation (una per riga: <code>mac ip [hostname]</code> oppure JSON)<textarea name="dhcp_reservations" rows="6" maxlength="60000" placeholder="aa:bb:cc:dd:ee:ff 192.168.1.50 laptop-soggiorno"></textarea></label>';
            echo '<label><input type="checkbox" name="allow_in_pool" value="1"> Consentire IP dentro il pool dinamico (solo avviso)</label>';
            echo '<p class="ops"><button class="s" type="submit" name="action" value="dhcp_reservations_check">Controlla</button> ';
            echo '<button class="g" type="submit" name="action" value="dhcp_reservations_apply" onclick="return confirm(\'Scrivere queste reservation su Pi-hole (dhcp.hosts)?\');">Applica su Pi-hole</button></p></form></div>';

            echo '<details class="iptm-dhcp-activate"><summary>Attivazione DHCP da console</summary><p>Prima configura e attiva la scheda con IP statico e verifica che Pi-hole resti sul master primario. Per l&#39;attivazione usa il terminale locale e conferma la separazione fisica delle reti.</p><code>sudo iptm-helper net-runtime install-guard</code><p>Prepara il piano con <code>net-runtime dhcp-stage</code>, quindi usa <code>apply HASH</code> e <code>confirm TOKEN</code> entro 180 secondi. Nessuna attivazione automatica da questa pagina.</p></details>';
        }
    }
    [$nmrc,$nmout] = priv('nm-editor',null,['inventory']);
    $nmdata=$nmrc===0?json_decode($nmout,true):null;
    echo '<section class="card"><h3>NetworkManager · editor completo proprietà</h3>';
    echo '<p class="mut">Modifica i profili NetworkManager. Le connessioni attive non cambiano finché non esegui una prova protetta.</p>';
    if(is_array($nmdata)&&!empty($nmdata['ok'])){
        echo '<details><summary>Dispositivi e connessioni reali</summary><pre>'.h((string)($nmdata['devices']??'')).'</pre></details>';
        echo '<table><tr><th>UUID</th><th>Nome · tipo · interfaccia</th></tr>';
        foreach(array_slice((array)($nmdata['profiles']??[]),0,80) as $profile){
            if(!is_array($profile))continue;
            echo '<tr><td><code>'.h((string)($profile['uuid']??'')).'</code></td><td>'.h(implode(' · ',(array)($profile['properties']??[]))).'</td></tr>';
        }
        echo '</table>';
    }else echo '<p class="msg warn">NetworkManager non disponibile o inventario non leggibile.</p>';
    if(!$ro){
        echo '<form method="post">'.fh('p=multinic').'<input type="hidden" name="action" value="nm_editor_stage">';
        echo '<label>UUID connessione da clonare<input name="nm_uuid" required maxlength="36" placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"></label>';
        echo '<label>Proprietà NM in formato JSON<textarea rows="6" name="nm_properties" maxlength="8192" required placeholder="Impostazioni NM in JSON"></textarea></label>';
        echo '<button class="s">Valida e prepara un clone inattivo</button></form>';
        $pending=$_SESSION['iptm_nm_editor']??null;
        if(is_array($pending)&&time()-(int)($pending['created']??0)<900){
            $hash=(string)($pending['hash']??'');
            echo '<form method="post">'.fh('p=multinic').'<input type="hidden" name="action" value="nm_editor_apply"><input type="hidden" name="nm_sha256" value="'.h($hash).'"><p class="mut">Piano verificato: <code>'.h($hash).'</code></p><button class="g">Crea clone NetworkManager, senza attivarlo</button></form>';
        }
    }
    $clone=(string)($_SESSION['iptm_nm_clone']??'');
    if(!$ro&&preg_match('/^[a-fA-F0-9-]{36}$/D',$clone)){
        echo '<h4>Attiva clone con checkpoint NetworkManager (180 secondi)</h4>';
        echo '<form method="post">'.fh('p=multinic').'<input type="hidden" name="action" value="nm_activate_trial"><input type="hidden" name="clone_uuid" value="'.h($clone).'">';
        echo '<label>Dispositivo da riconfigurare<select name="trial_iface">';
        foreach(array_keys($ifs) as $name)echo '<option value="'.h($name).'">'.h($name).'</option>';
        echo '</select></label><button class="g">Attiva profilo in prova protetta</button></form>';
    }
    $trial=$_SESSION['iptm_nm_trial']??null;
    if(!$ro&&is_array($trial)&&time()-(int)($trial['created']??0)<180){
        $token=(string)($trial['token']??'');
        if(preg_match('/^[a-f0-9]{24}$/D',$token)){
            echo '<p class="msg warn">Checkpoint NM attivo. Prima della conferma verifica gateway, DHCP, Pi-hole, accesso web e SSH.</p>';
            foreach(['nm_trial_confirm'=>'Conferma checkpoint','nm_trial_revert'=>'Ripristina subito'] as $action=>$label)
                echo '<form method="post">'.fh('p=multinic').'<input type="hidden" name="action" value="'.h($action).'"><input type="hidden" name="trial_token" value="'.h($token).'"><button class="'.($action==='nm_trial_revert'?'d':'g').'">'.h($label).'</button></form>';
        }
    }
    echo '</section>';
    echo '</div></div></section>';
    echo '</div>'; // Removed obsolete advanced-network shortcuts card.

}
