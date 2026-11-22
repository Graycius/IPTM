<?php
/** Conservative read-only review of the actual draft / iptables-save text.
 * No firewall mutation, no claim of complete L2 coverage. Warnings are
 * grounded in exact rule lines, with an optional generator-level topology.
 */
function iptm_policy_findings(string $text, array $S = []): array {
    if (strlen($text)>2_097_152) return [['severity'=>'alto','title'=>'Bozza troppo grande','detail'=>'Analisi sospesa oltre 2 MiB','where'=>'rules.v4']];
    $findings=[];
    $add=static function(string $severity,string $title,string $detail,string $where) use (&$findings):void {
        if(count($findings)<60)$findings[]=compact('severity','title','detail','where');
    };
    $owned='';$tab='';$counts=[];$wg=(string)($S['wg_if']??'wg0');
    $iotPolicy=[];$macHooks=[];$managedIoT=[];$managedRuleMacs=[];$lan=(string)($S['lan_nets']??'');
    foreach ((array)($S['iot_policies']??[]) as $mac=>$flags) {
        if(is_string($mac) && preg_match('/^(?:[a-f0-9]{2}:){5}[a-f0-9]{2}$/iD',$mac) && is_array($flags) && $flags)
            $managedIoT[strtolower($mac)]=true;
    }
    $lockoutPorts=[];$sshLimitSeen=false;$sshLimitAt=null;$accepts=[];$unscoped=[];$repeated=[];
    foreach(explode("\n",$text) as $index=>$row){
        $line=trim($row);
        if(str_starts_with($line,'*')){$tab=substr($line,1);$owned='';continue;}
        if(str_starts_with($line,'# >>> IPTM:')){$owned=explode(' ',substr($line,11),2)[0];continue;}
        if(str_starts_with($line,'# <<< IPTM:')){$owned='';continue;}
        if($tab!=='filter'||!preg_match('/^-A\s+(INPUT|FORWARD|\S+)\s+/',$line,$mm))continue;
        $chain=$mm[1];$at='riga '.($index+1).($owned!==''?' · IPTM:'.$owned:' · regola manuale');
        if($chain==='INPUT' && preg_match('/(?:^|\s)-j ACCEPT(?:\s|$)/',$line)){
            $source='';if(preg_match('/(?:^|\s)-s\s+(\S+)/',$line,$m))$source=$m[1];
            $protocol='';if(preg_match('/(?:^|\s)-p\s+(tcp|udp)\b/',$line,$m))$protocol=$m[1];
            $ports='';if(preg_match('/--dports?\s+([0-9,:]+)/',$line,$m))$ports=$m[1];
            if($source!=='' && $lan!=='' && iptm_scope_within_lan($source,$lan) &&
               !preg_match('/(?:^|\s)(?:!\s+)?-i\s+/', $line))
                $unscoped[$owned?:'manual'][]=$at;
            if($protocol==='tcp'&&$ports!==''){
                foreach(explode(',',$ports) as $pt){
                    if($pt==='22' && $owned==='lockout')$lockoutPorts[]=[$index,$at];
                    if($pt==='22' || $pt==='80' || $pt==='443' || $pt==='53')$counts[$source.'|'.$protocol.'|'.$pt][]=[$at,$owned];
                }
            }
            if($ports!=='' && $protocol!==''){
                foreach(explode(',',$ports) as $pt){
                    if(!ctype_digit($pt))continue;
                    $key=$source.'|'.$protocol.'|'.$pt;
                    if(isset($accepts[$key]) && $owned!=='')$repeated[$owned][]=$at;
                    $accepts[$key]??=$at;
                }
            }
        }
        if($chain==='INPUT' && str_starts_with($owned,'ssh-acc') && preg_match('/(?:^|\s)--ctstate NEW\s+--syn(?:\s|$)/',$line)){$sshLimitSeen=true;$sshLimitAt??=$index;}
        if ($chain==='FORWARD' && str_starts_with($owned,'iot-') &&
            preg_match('/(?:^|\s)--mac-source\s+((?:[0-9a-f]{2}:){5}[0-9a-f]{2})/i',$line,$managedMatch))
            $managedRuleMacs[strtolower($managedMatch[1])]=true;
        if($chain==='FORWARD' && preg_match('/(?:^|\s)-o\s+'.preg_quote($wg,'/').'\b/',$line) && preg_match('/\s-j\s+ACCEPT(?:\s|$)/',$line)
           && !preg_match('/\s-s\s+|\s--ctstate\s+|\s-d\s+|\s--dport/', $line))
            $add('alto','FORWARD aperto indiscriminatamente verso WireGuard','Consente nuove connessioni verso i peer VPN. Disattiva questa riga, oppure abilita esplicitamente il percorso LAN → WireGuard.',$at);
        if($chain==='FORWARD' && preg_match('/\s-m mac\s+--mac-source\s+((?:[0-9a-f]{2}:){5}[0-9a-f]{2})/i',$line,$ma))
            $iotPolicy[strtolower($ma[1])]=true;
        if(($chain==='INPUT'||$chain==='FORWARD') && preg_match('/-m mac\s+--mac-source\s+((?:[0-9a-f]{2}:){5}[0-9a-f]{2}).*\s-j IPTM-MAC-(?:IN|FWD)/i',$line,$ma))
            $macHooks[strtolower($ma[1])]=true;
        if(str_contains($line,'IPTM-TELNET') && $owned==='limit-telnet')
            $add('basso','Limiter Telnet WAN superfluo','Un contatore sulla porta 23 non protegge una porta che rimane chiusa. Evita lavoro kernel inutile.',$at);
    }
    if($sshLimitSeen && $lockoutPorts && min(array_column($lockoutPorts,0)) < $sshLimitAt)
        $add('alto','SSH scavalca il controllo brute-force','ACCEPT di gestione prima di recent/connlimit sulla porta 22. Il generatore nuovo esclude SSH dal lockout.',implode(', ',array_slice(array_column($lockoutPorts,1),0,3)));
    // Keep actionable high-severity findings visible even on large legacy dumps:
    // group per section rather than letting hundreds of repeated INPUT accepts
    // exhaust the UI's bounded warning budget.
    foreach($unscoped as $section=>$spots)$add('alto','ACCEPT LAN senza interfaccia · '.$section,
        count($spots).' regole basate solo sull’IP sorgente; verificare ingresso LAN/WAN. Impostare la topologia in Setup e rigenerare solo le sezioni IPTM, senza alterare le regole manuali.',
        implode(', ',array_slice($spots,0,2)));
    foreach($repeated as $section=>$spots)$add('medio','Aperture sovrapposte · '.$section,
        count($spots).' autorizzazioni con subnet/protocollo/porta ripetuti. Verificare le differenze di condizioni prima di deduplicare.',
        implode(', ',array_slice($spots,0,2)));
    foreach($counts as $key=>$hits)if(count($hits)>=3){
        $parts=explode('|',$key);$add('medio','Aperture duplicate '.$parts[1].'/'.$parts[2],count($hits).' regole per lo stesso ambito: usare aggregazione delle porte nei profili IPTM.',$hits[0][0]);
    }
    // UI-managed `IPTM:iot-<mac>` rules stand alone; they do NOT need the
    // optional IPTM-MAC-IN/FWD chain. Comparing every MAC rule to that jump
    // produced false security alerts and led operators to delete working IoT ACLs.
    $unmanaged=array_values(array_diff(array_keys($iotPolicy),array_keys($macHooks),array_keys($managedRuleMacs)));
    if($unmanaged)$add('medio','Regole MAC esterne da verificare',count($unmanaged).' MAC in FORWARD senza salto IPTM-MAC né sezione IoT gestita dalla UI. Controlla Warden o le regole manuali; non eliminarle automaticamente.','FORWARD / IoT');
    $missingUi=array_values(array_diff(array_keys($managedIoT),array_keys($managedRuleMacs)));
    if($missingUi)$add('alto','Policy IoT UI assenti dalla bozza',count($missingUi).' policy salvate nella UI non hanno una regola IPTM:iot-<mac> nella bozza. Controlla le reti e rigenera; le preferenze non vengono cancellate.','Zone IoT / rigenerazione');
    $staleUi=array_values(array_diff(array_keys($managedRuleMacs),array_keys($managedIoT)));
    // Without settings context, a rules.v4 can be independently imported: no
    // claim that its sections are stale merely because $S was omitted.
    if(array_key_exists('iot_policies',$S) && $staleUi)
        $add('medio','Sezioni IoT da riconciliare',count($staleUi).' sezioni IPTM:iot-<mac> non corrispondono a policy abilitate nelle impostazioni correnti. Non rimuovere senza verifica del profilo UI.','Zone IoT / rigenerazione');
    $dns=array_values(array_intersect(['pihole','adguard','unbound','dnsmasq'],(array)($S['apps']??[])));
    if(count($dns)>1)$add('basso','Profili DNS multipli selezionati',implode(', ',$dns).': i profili aprono porte, non decidono quale resolver è realmente in ascolto; la porta 53 viene deduplicata nel nuovo generatore.','Porte software');
    if(!empty($S['iot_policies']) || $iotPolicy)$add('medio','Isolamento IoT MAC limitato al livello 3','Il traffico L2 tra dispositivi della stessa subnet (ARP, broadcast e IPv6 link-local) non attraversa necessariamente iptables; servono VLAN o isolamento client sull’AP.','Zone IoT');
    if(!empty($S['single_nic']) && !empty($S['wan_if']))
        $add('medio','WAN/LAN condivise','Impossibile certificare l’origine LAN tramite la sola interfaccia '.$S['wan_if'].'. L’anti-spoof RFC1918 sulla stessa interfaccia romperebbe il traffico legittimo; non viene generato automaticamente.','Setup / bond');
    // Prioritize real security issues over repeated housekeeping findings.
    $rank=['critico'=>0,'alto'=>1,'medio'=>2,'basso'=>3];
    usort($findings,fn($a,$b)=>($rank[$a['severity']]??4)<=>($rank[$b['severity']]??4));
    return $findings;
}
/** Compact, escaped notice. The apply action stays in existing rollback UI. */
function iptm_policy_review_ui(string $draft,array $S):string {
    $issues=iptm_policy_findings($draft,$S);
    $high=count(array_filter($issues,fn($f)=>in_array($f['severity'],['alto','critico'],true)));
    $out='<details class="card" id="iptm-policy-review"><summary><b>Revisione sicurezza e ridondanze</b> · '.count($issues).' segnalazioni'.($high?' · '.$high.' prioritarie':'').'</summary>';
    $numIoT=count(array_filter((array)($S['iot_policies']??[]),fn($f)=>is_array($f)&&$f));
    $out.='<p class="mut">Analisi della bozza in sola lettura. Le regole manuali, IoT Warden e quelle esterne restano invariate; nessuna modifica al firewall attivo.</p>';
    $out.='<p><b>Policy IoT gestite dalla UI: '.$numIoT.'</b> — conservate durante la rigenerazione se sono ancora selezionate. La loro presenza non richiede necessariamente un salto verso IPTM-MAC-FWD.</p>';
    if(!$issues)$out.='<p class="msg ok">Nessuna delle anomalie note rilevata nella bozza. Questa verifica non sostituisce un audit completo.</p>';
    else {
        $out.='<div data-iptm-layout="scroll"><table><thead><tr><th>Priorità</th><th>Problema</th><th>Verifica / correzione</th></tr></thead><tbody>';
        foreach(array_slice($issues,0,25) as $i)$out.='<tr><td>'.h($i['severity']).'</td><td><b>'.h($i['title']).'</b><p class="mut">'.h($i['where']).'</p></td><td>'.h($i['detail']).'</td></tr>';
        $out.='</tbody></table></div>';
    }
    $out.='<p class="row"><a class="btn s" href="?p=setup">Topologia WAN/LAN</a> <a class="btn s" href="?p=router">Servizi router</a> <a class="btn s" href="?p=apps">Porte software</a> <a class="btn s" href="?p=vpn">WireGuard</a> <a class="btn s" href="?p=zones">MAC/IoT</a></p>';
    if(($_SESSION['role']??'viewer')==='admin')$out.='<form method="post">'.fh('p=apply').'<input type="hidden" name="action" value="regen_now"><button class="s">Rigenera solo i blocchi IPTM nella bozza</button></form>';
    return $out.'</details>';
}
