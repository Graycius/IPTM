<?php
/** IPv4 to IPv6: conservative draft-only rule translator, no address guessing. */
function iptm_iot_policy_options(): array {
    return [
      'internet'=>'Blocca Internet (solo se WAN separata)',
      'lan'=>'Blocca accesso alle altre reti LAN',
      'dns'=>'Blocca DNS esterni sulla porta 53 (TCP/UDP)',
      'dot'=>'Blocca DNS-over-TLS sulla porta 853',
      'quic'=>'Blocca QUIC / HTTP3 (UDP 443)',
      'vpn'=>'Blocca alcune porte VPN note (non tutte le VPN)',
      'forward'=>'Blocca tutto il traffico instradato (anche LAN)',
    ];
}
function iptm_iot_policy_short_labels(): array {
    return ['internet'=>'Internet','lan'=>'LAN','dns'=>'DNS','dot'=>'DoT','quic'=>'QUIC','vpn'=>'VPN','forward'=>'Tutto'];
}
/** Filtering directions are stored in the old in/out/both format. */
function iptm_list_direction(mixed $selection): string {
    if (is_string($selection) && in_array($selection,['in','out','both'],true)) return $selection;
    if (!is_array($selection) || count($selection)>2) return 'in';
    foreach ($selection as $dir) if (!is_string($dir) || !in_array($dir,['in','out'],true)) return 'in';
    $in=in_array('in',$selection,true); $out=in_array('out',$selection,true);
    return $in && $out?'both':($out?'out':'in');
}
function iptm_v4_to_v6_preview(string $text, string $mapping): array {
    if (strlen($text)>131072 || strlen($mapping)>8192) throw new InvalidArgumentException('Input troppo grande');
    $map=[];
    foreach (preg_split('/\R/',trim($mapping)) as $line) {
        if ($line==='')continue;
        if (!preg_match('~^([0-9./]+)\s*=\s*([0-9a-fA-F:/]+)$~D',trim($line),$x))throw new InvalidArgumentException('Mapping non valido: '.$line);
        if (filter_var(explode('/',$x[1])[0],FILTER_VALIDATE_IP,FILTER_FLAG_IPV4)===false ||
            filter_var(explode('/',$x[2])[0],FILTER_VALIDATE_IP,FILTER_FLAG_IPV6)===false)throw new InvalidArgumentException('Indirizzo nel mapping non valido');
        foreach ([[$x[1],32],[$x[2],128]] as [$subnet,$maximum]) {
            $pieces=explode('/',$subnet);
            if (count($pieces)>2 || (count($pieces)===2 &&
               (!ctype_digit($pieces[1]) || (int)$pieces[1]>$maximum)))
               throw new InvalidArgumentException('Prefisso IP non valido: '.$subnet);
        }
        if (isset($map[$x[1]]) && $map[$x[1]] !== $x[2]) throw new InvalidArgumentException('Mapping IPv4 duplicato con destinazioni differenti: '.$x[1]);
        $map[$x[1]]=$x[2];
    }
    $rules=[];$skipped=[];$table='filter';$chains=[];$lines=preg_split('/\R/',$text);
    if (count($lines)>500)throw new InvalidArgumentException('Troppe regole');
    foreach ($lines as $line) {
        $r=trim($line);if($r===''||$r[0]==='#'||$r==='COMMIT')continue;
        if ($r[0]==='*') {$table=substr($r,1);if($table!=='filter')$skipped[]=$r.' — tabella diversa da filter';continue;}
        if ($table!=='filter')continue;
        if (preg_match('/^:([A-Z0-9_-]+)\s+(ACCEPT|DROP|-)\s+\[[0-9]+:[0-9]+\]$/D',$r,$m)) {
            // IPv4 ACCEPT must never become an IPv6 firewall policy silently.
            // This output is an *illustrative draft*, never auto-loaded.
            if (in_array($m[1],['INPUT','FORWARD'],true) && $m[2]==='ACCEPT')
                $skipped[]='Policy IPv4 '.$m[1].' ACCEPT: scelta IPv6 da rivedere manualmente';
            $chains[$m[1]] = in_array($m[1],['INPUT','FORWARD'],true) ? 'DROP' : $m[2];
            continue;
        }
        if (!preg_match('/^-A (INPUT|OUTPUT|FORWARD|[A-Z][A-Z0-9_-]{0,23})\s+(.+)$/D',$r,$parts)) {$skipped[]=$r.' — sintassi non supportata';continue;}
        $cmd=$r;
        $bad='';
        if (preg_match('/(?:-m (?:mac|recent|iprange|addrtype)|-j (?:DNAT|SNAT|MASQUERADE|REDIRECT|CT|MARK)|--(?:tcp-flags|icmp-type|reject-with|set-mark|match-set|to-destination|to-source)|\b(?:0x[0-9a-f]+)\b)/i',$cmd))$bad='estensione IPv4 o target non traslabile in sicurezza';
        if (preg_match('/(?:^|\s)(?:-p|--protocol)\s+(?:icmp|1)(?:\s|$)/',$cmd))$bad='ICMPv4 e ICMPv6 hanno tipi diversi';
        if (preg_match('/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:\/[0-9]{1,2})?\b/',$cmd)) {
            $cmd=preg_replace_callback('/(?<![A-Za-z0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:\/[0-9]{1,2})?/',function($m)use($map,&$bad){
               if(!isset($map[$m[0]])) {$bad='Manca mapping IPv4→IPv6 per '.$m[0];return $m[0];}
               return $map[$m[0]];
            },$cmd);
        }
        if (preg_match('/(?:\d{1,3}\.){3}\d{1,3}/',$cmd))
            $bad='Indirizzo IPv4 residuo: mapping non completo';
        // A strict allowlist: no bare extensions, shell substitutions or unconstrained tokens.
        if(!preg_match('/^[A-Za-z0-9 _.:\/!,-]+$/D',$cmd))$bad='caratteri o opzioni non supportate';
        if (preg_match_all('/(?:^|\s)(-m|--match|-j|--jump|-g|--goto)\s+([^\s]+)/', $cmd, $matches, PREG_SET_ORDER)) {
            foreach ($matches as $match) {
                $allowed = in_array($match[1], ['-m','--match'], true) ? ['conntrack','multiport','limit','comment','tcp','udp'] : ['ACCEPT','DROP','REJECT','RETURN','LOG'];
                if (!in_array($match[2], $allowed, true) || in_array($match[1], ['-g','--goto'], true)) $bad='modulo/target non autorizzato';
            }
        }
        if($bad!==''){$skipped[]=$r.' — '.$bad;continue;}
        $rules[]=$cmd;
    }
    $hdr='*filter'."\n";
    foreach($chains as $chain=>$policy) $hdr.=':'.$chain.' '.$policy.' [0:0]'."\n";
    return ['text'=>$hdr.implode("\n",$rules).($rules?"\n":"")."COMMIT\n",'converted'=>count($rules),'skipped'=>$skipped,'complete'=>count($skipped)===0];
}

function iptm_direction_checkboxes(string $name, string $current): string {
    $out='';foreach(['in'=>'Ingresso','out'=>'Uscita'] as $dir=>$label){
        $checked=($current==='both'||$current===$dir)?' checked':'';
        $out.='<label class="iptm-direction"><input type=checkbox name="'.h($name).'[]" value="'.$dir.'"'.$checked.'> '.$label.'</label> ';
    }return $out;
}
