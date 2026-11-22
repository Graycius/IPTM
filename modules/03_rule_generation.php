<?php
// ===================== IMPOSTAZIONI "STILE DD-WRT" -> REGOLE GESTITE =====================
// Le impostazioni (settings.json) generano blocchi di regole delimitati da
//   # >>> IPTM:<id> ...   /   # <<< IPTM:<id>
// dentro rules.v4. Il resto del file (le tue regole) non viene toccato.
function S_def(): array {
    return ['iot_strategy' => 'auto', 'wan_if' => '', 'lan_if' => '', 'wan_rfc1918_spoof' => 1, 'external_ifs' => '', 'lan_ingress_map' => '', 'wg_lan_to_vpn' => 0, 'single_nic' => 0, 'lan_nets' => '', 'masq_ifs' => '', 'drop_chain' => '', 'nat_masq' => 0, 'mss' => 0, 'dns_redirect' => 0, 'dns_ip' => '', 'dot_block' => 0,
        'spi' => 0, 'antispoof' => 0, 'antispoof_mc' => 0, 'spoof_on' => 0, 'spoof_if' => '', 'spoof_nets' => '', 'invalid' => 0, 'blockping' => 0, 'ident' => 0, 'multicast' => 0,
        'icmp_limit' => 0, 'icmp_echo_rate' => '2/sec', 'icmp_echo_burst' => 5, 'icmp_other_rate' => '5/sec', 'icmp_other_burst' => 10, 'igmp_accept' => 0,
        'lan_tcp_accept' => 0, 'docker_accept' => 0, 'docker_nets' => '172.16.0.0/12', 'bcast_accept' => 0, 'dhcp_accept' => 1, 'coap_accept' => 0, 'lan_out_fwd' => 0, 'cs_set_match' => 0,
        'dos' => 0, 'dos_name' => 'synflood', 'dos_syn' => 50, 'dos_burst' => 100, 'ssh_limit' => 0, 'ssh_port' => 22, 'telnet_limit' => 0, 'telnet_port' => 23, 'lim_hits' => 4, 'lim_secs' => 60,
        'ssh_acc' => 0, 'ssh_nets' => '', 'ssh_acc_port' => 22, 'ssh_conn' => 10, 'ssh_hits' => 15, 'ssh_secs' => 60, 'ssh_name' => 'sshbf',
        'crowdsec' => 0, 'cs_set' => '', 'cs_in' => CS_CHAIN, 'cs_fwd' => CS_CHAIN, 'cs_docker' => 1, 'conn_limit' => 0, 'cl_max' => 50, 'rpfilter' => 0, 'bw_on' => 0, 'bw_up' => 2000, 'bw_down' => 10000, 'mac_only' => 0, 'mac_allow' => '', 'alg_ftp' => 0, 'alg_tftp' => 0, 'alg_sip' => 0, 'fqdn_rules' => '', 'wg_on' => 0, 'wg_port' => 51820, 'wg_if' => 'wg0', 'wg_input' => 0, 'wg_lan' => 1, 'wg_net' => '', 'iso_on' => 0, 'iso_nets' => '', 'guest_on' => 0, 'guest_nets' => '', 'guest_ports' => '53,67', 'guest_allow' => '', 'mac_block' => '', 'quic_block' => 0, 'lan_cl' => 0, 'lan_cl_max' => 1000, 'svc_ban' => 0, 'sb_ports' => '22,23,3389,5900', 'sb_hits' => 6, 'sb_secs' => 60, 'sb_ban' => 3600, 'ui_nets' => '', 'bad_mss' => 0, 'udp_rl' => 0, 'ul_rate' => 200, 'ul_burst' => 400, 'web_rl' => 0, 'wl_rate' => 50, 'wl_burst' => 100, 'wl_ports' => '80,443', 'amp_block' => 0, 'bl_log' => 0, 'manual_allow' => '',
        'closeports' => 0, 'close_range' => '1:1023', 'final_drop' => 0, 'logdrop_on' => 0, 'ld_src_rate' => '10/sec', 'ld_src_burst' => 20, 'ld_glob_rate' => '200/sec', 'ld_glob_burst' => 400, 'ld_prefix' => 'IPT-DROP: ',
        'raw_lo' => 0, 'raw_drop' => 0, 'raw_tcp' => '135,137,138,139,445', 'raw_udp' => '135,137,138,139,445,1900',
        'log_in' => 0, 'log_out' => 0, 'log_drop' => 0, 'log_rate' => '10/min', 'loopback' => 0, 'dmz_on' => 0, 'dmz_ip' => '', 'dmz_excl' => '22', 'fwd' => [], 'acl' => [], 'svc_in' => [], 'svc_fwd' => [], 'apps' => [],
        'continuity_priority' => 1, 'lockout_on' => 0, 'mgmt_ports' => '22,80,443,8089,8489', 'drop_frag' => 0, 'portscan' => 0, 'ps_hits' => 14, 'ps_secs' => 60, 'ps_ban' => 3600, 'bogon_wan' => 0, 'lan_flood' => 0, 'lf_rate' => 200, 'lf_burst' => 400, 'egress_smtp' => 0, 'egress_allow' => '', 'egress_ports' => '',
        'stealth' => 0, 'synproxy' => 0, 'sp_ports' => '', 'tarpit' => 0, 'dns_rebind' => 0, 'raw_invalid' => 0, 'arp_protect' => 0, 'tcp_fastopen_off' => 0, 'glob_new_limit' => 0, 'gn_rate' => 100, 'gn_burst' => 200,
        'harden' => ['rpf' => '2'], 'custom_opts' => [], 'aliases' => [], 'blocklists' => [], 'geo_on' => 0, 'geo_codes' => '', 'geo_dir' => 'in', 'manual_block' => '', 'knock_on' => 0, 'knock_ports' => '7000,8000,9000', 'knock_target' => '22', 'knock_secs' => 30, 'knock_nets' => '',
        'iot_devices' => [], 'iot_policies' => [], 'api_token' => '', 'notify' => ['tg_token' => '', 'tg_chat' => '', 'webhook' => '', 'ev' => ['apply', 'confirm', 'revert', 'rollback', 'loginfail'], 'rule_on' => 0, 'rule_min' => 20, 'rule_patterns' => 'DROP,REJECT,IPTM-DROP,IPTM-IN,IPTM-OUT,CROWDSEC'], 'ti' => ['abuseipdb' => '', 'greynoise' => '', 'otx' => '', 'virustotal' => '', 'urlscan' => '', 'ipapi' => 0, 'threatfox' => 1, 'urlhaus' => 1, 'cache_hours' => 24], 'v6' => ['on' => 0, 'mode' => 'host', 'lan_if' => '', 'wan_if' => '', 'lan_prefix' => 'fe80::/10', 'icmp' => 1, 'dhcp6' => 1, 'ssh' => 1, 'ssh_port' => 22, 'ports' => '', 'log' => 0], 'sqm' => ['on' => 0, 'iface' => '', 'down' => 0, 'up' => 0, 'mode' => 'cake', 'diffserv' => 'diffserv4', 'ack_filter' => 1, 'nat' => 1, 'wash' => 0, 'overhead' => 'ethernet', 'prio_interactive' => 1, 'prio_voip' => 1, 'prio_games' => 1, 'prio_bulk_low' => 1, 'game_ports' => '27000:27050,3074,7777,25565', 'voip_ports' => '5060,5061,10000:10100', 'bulk_ports' => '6881:6999', 'auto' => 0, 'autocal' => 0, 'interval_min' => 60, 'last_cal' => 0]];
}
function S_get(): array { return $GLOBALS['_Sc'] ??= S_load(); }

/** Legacy "tcp,udp" / "udp,tcp" / "both" represents two distinct iptables rules. */
function svc_proto_choices(string $proto): array {
    $p = strtolower((string)preg_replace('/\s+/', '', $proto));
    return in_array($p, ['tcp,udp', 'udp,tcp', 'both'], true) ? ['tcp', 'udp'] : [$proto];
}
/** Configurable source-CIDR -> ingress-interface bindings. The parser never
 * trusts arbitrary strings in settings.json or from imported configurations. */
function iptm_lan_ingress_pairs(string $raw): array {
    if ($raw==='' || strlen($raw)>1024) return [];
    $parts=explode(',',$raw);
    if (count($parts)>16) return [];
    $map=[];
    foreach ($parts as $entry) {
        if (!preg_match('~^((?:[0-9]{1,3}\.){3}[0-9]{1,3})/(8|9|[12][0-9]|3[0-2])=([A-Za-z0-9][A-Za-z0-9_.+-]{0,14})$~D',$entry,$m)) return [];
        if (!filter_var($m[1],FILTER_VALIDATE_IP,FILTER_FLAG_IPV4) ||
            !v_ok('if',$m[3]) || $m[3]==='lo') return [];
        $bits=(int)$m[2];$mask=((-1 << (32-$bits)) & 0xffffffff);
        if ((ip2long($m[1]) & $mask)!==ip2long($m[1])) return [];
        $cidr=$m[1].'/'.$bits;
        if (isset($map[$cidr])) return [];
        $map[$cidr]=$m[3];
    }
    return $map;
}
function iptm_lan_ingress_map_valid(string $value): bool {
    return $value==='' || count(iptm_lan_ingress_pairs($value))===count(explode(',',$value));
}
/** Interfaces carrying local addresses in a trusted source network cannot be
 * labelled 'external', even if the operator imports a malicious configuration. */
function iptm_trusted_ingress_interfaces(array $S): array {
    $trusted=[];
    $lan=(string)($S['lan_if']??'');
    if ($lan!=='' && v_ok('if',$lan)) $trusted[$lan]=true;
    foreach(iptm_lan_ingress_pairs((string)($S['lan_ingress_map']??'')) as $iface)
        $trusted[$iface]=true;
    if (function_exists('sys_ifaces')) foreach ((array)sys_ifaces() as $iface=>$addresses) {
        if (!is_string($iface) || !v_ok('if',$iface)) continue;
        foreach ((array)$addresses as $addr) {
            if (!is_string($addr)) continue;
            $local=explode('/',$addr,2)[0];
            if (iptm_scope_within_lan($local,(string)($S['lan_nets']??''))) {
                $trusted[$iface]=true;break;
            }
        }
    }
    return $trusted;
}
/** Explicit external interfaces are eligible only after live topology proof.
 * A double-NAT, shared bond, VPN or a private WAN MUST NOT receive RFC1918 DROP. */
function iptm_external_spoof_ifaces(array $S): array {
    if (empty($S['wan_rfc1918_spoof']) || !function_exists('sys_ifaces') ||
        !empty($S['single_nic'])) return [];
    $trusted=iptm_trusted_ingress_interfaces($S);
    $wan=(string)($S['wan_if']??'');
    if ($wan!=='' && $wan===(string)($S['lan_if']??'')) return [];
    $requested=[];
    if($wan!=='')$requested[]=$wan;
    $raw=(string)($S['external_ifs']??'');
    if(strlen($raw)>255 || !v_ok('ifs',$raw)) return [];
    foreach (explode(',',$raw) as $iface) if($iface!=='')$requested[]=$iface;
    $verified=[];$ifaces=(array)sys_ifaces();
    foreach(array_unique($requested) as $iface) {
        if (!v_ok('if',$iface) || $iface==='' || $iface==='lo' ||
            isset($trusted[$iface]) || preg_match('/^(?:wg|tun|tap|docker|veth|ifb|br-)/i',$iface)) continue;
        $addresses=(array)($ifaces[$iface]??[]);
        if(count($addresses)!==1)continue;
        $ip=explode('/',(string)$addresses[0],2)[0];
        if (filter_var($ip,FILTER_VALIDATE_IP,FILTER_FLAG_IPV4|FILTER_FLAG_NO_PRIV_RANGE|FILTER_FLAG_NO_RES_RANGE))
            $verified[]=$iface;
    }
    return $verified;
}
/** A single interface shared by local clients and an upstream cannot prove
 * the packet came from the LAN. Never apply a guessed LAN match to it. */
function iptm_lan_ingress(array $S): string {
    $wan=(string)($S['wan_if']??'');$lan=(string)($S['lan_if']??'');
    if (!empty($S['single_nic']) || ($wan!=='' && $lan===$wan)) return '';
    if ($lan!=='' && v_ok('if',$lan) && $lan!==$wan) return '-i '.$lan;
    $external=iptm_external_spoof_ifaces($S);
    if ($wan!=='' && trim((string)($S['external_ifs']??''))==='' && $external===[$wan]) return '! -i '.$wan;
    return '';
}
/** Resolve source subnet to the real LAN, VLAN or VPN ingress. Explicit
 * mappings win only when the interface exists and is neither WAN nor external. */
function iptm_ingress_for_source(string $source,array $S): string {
    if (!iptm_scope_within_lan($source,(string)($S['lan_nets']??''))) return '';
    $wan=(string)($S['wan_if']??'');
    $shared=!empty($S['single_nic']) || ($wan!=='' && $wan===(string)($S['lan_if']??''));
    if ($shared) return '';
    $known=function_exists('sys_ifaces') ? (array)sys_ifaces() : [];
    $externals=iptm_external_spoof_ifaces($S);
    $selected='';$best=-1;
    foreach(iptm_lan_ingress_pairs((string)($S['lan_ingress_map']??'')) as $cidr=>$iface) {
        if (!iptm_scope_within_lan($source,$cidr)) continue;
        if ($iface===$wan || in_array($iface,$externals,true) || $iface==='lo' ||
            !array_key_exists($iface,$known)) continue;
        $prefix=(int)explode('/',$cidr,2)[1];
        if ($prefix>$best) {$best=$prefix;$selected=$iface;}
        elseif($prefix===$best && $selected!==$iface) return '';
    }
    if($selected!=='')return '-i '.$selected;
    if ($known) {
        $matches=[];
        foreach ($known as $iface=>$addresses) {
            if (!is_string($iface) || !v_ok('if',$iface) || $iface===$wan ||
                $iface==='lo' || in_array($iface,$externals,true) ||
                preg_match('/^(?:veth|docker|ifb|br-)/',$iface))continue;
            foreach ((array)$addresses as $cidr) {
                if (!is_string($cidr) || !preg_match('~^\d{1,3}(?:\.\d{1,3}){3}/(?:\d|[12]\d|3[0-2])$~D',$cidr))continue;
                if(iptm_scope_within_lan($source,$cidr)){$matches[$iface]=true;break;}
            }
        }
        if(count($matches)===1)return '-i '.array_key_first($matches);
    }
    // A single verified public WAN can be excluded conservatively, but not
    // when there are other external interfaces (they might admit spoofed LAN IPs).
    if ($wan!=='' && trim((string)($S['external_ifs']??''))==='' && $externals===[$wan])return '! -i '.$wan;
    return '';
}
/** Only source-scoped ACCEPTs from IPTM-managed sections may be narrowed.
 * Do not rewrite manual policy, DROP rules or foreign chains. */
function iptm_scope_managed_rule(string $line,array $S,string $chain,bool $acceptOnly=true): string {
    if (!str_starts_with($line,'-A '.$chain.' ') ||
        preg_match('/(?:^|\s)(?:!\s+)?-i\s+/', $line) ||
        preg_match('/(?:^|\s)!\s+-s\s+/', $line))return $line;
    if($acceptOnly && !preg_match('/(?:^|\s)-j ACCEPT(?:\s|$)/',$line))return $line;
    if(!preg_match('/(?:^|\s)-s\s+(\d{1,3}(?:\.\d{1,3}){3}(?:\/\d{1,2})?)(?:\s|$)/',$line,$m))return $line;
    $match=iptm_ingress_for_source($m[1],$S);
    return $match===''?$line:preg_replace('/^-A '.preg_quote($chain,'/').'\s+/', '-A '.$chain.' '.$match.' ',$line,1);
}
function iptm_scope_input_accept(string $line,array $S): string {
    return iptm_scope_managed_rule($line,$S,'INPUT');
}
function iptm_scope_within_lan(string $source,string $nets): bool {
    $src=explode('/',$source,2);$ip=filter_var($src[0],FILTER_VALIDATE_IP,FILTER_FLAG_IPV4);
    $mask=isset($src[1]) && ctype_digit($src[1])?(int)$src[1]:32;
    if(!$ip||$mask<0||$mask>32)return false;
    $val=ip2long($ip);
    foreach(explode(',',$nets) as $candidate){
        $n=explode('/',trim($candidate),2);
        if(count($n)!==2 || !filter_var($n[0],FILTER_VALIDATE_IP,FILTER_FLAG_IPV4) || !ctype_digit($n[1]))continue;
        $p=(int)$n[1];if($p<0||$p>32||$mask<$p)continue;
        $bit=$p===0?0:((-1<<(32-$p)) & 0xffffffff);
        if(($val & $bit)===(ip2long($n[0]) & $bit))return true;
    }
    return false;
}
function iptm_public_wan_verified(array $S): bool {
    return in_array((string)($S['wan_if']??''),iptm_external_spoof_ifaces($S),true);
}
/** A service row can contain multiple ports; exclude only unsafe SSH opens. */
function iptm_safe_router_input_rows(array $rows,array $S,array &$warn): array {
    $sshInMgmt=in_array((string)($S['ssh_acc_port']??22),
        array_map('trim',explode(',',(string)($S['mgmt_ports']??''))),true);
    if (empty($S['ssh_acc']) || (empty($S['ssh_nets']) &&
        (empty($S['lockout_on']) || empty($S['lan_nets']) || !$sshInMgmt))) return $rows;
    $ssh=(int)($S['ssh_acc_port']??22);$out=[];
    foreach($rows as $r){
       if(!is_array($r)||empty($r['on']) || ($r['proto']??'')!=='tcp' ||
          strtoupper((string)($r['act']??'ACCEPT'))!=='ACCEPT'){$out[]=$r;continue;}
       $ports=(string)($r['ports']??'');
       if($ports==='' || str_contains($ports,'@')){$out[]=$r;continue;}
       $pieces=explode(',',$ports);$safe=[];$modified=false;
       foreach($pieces as $piece){
           $bounds=explode(':',$piece,2);
           if(!ctype_digit($bounds[0]) || (isset($bounds[1]) && !ctype_digit($bounds[1]))){$safe[]=$piece;continue;}
           $lo=(int)$bounds[0];$hi=(int)($bounds[1]??$bounds[0]);
           if($lo<=$ssh && $ssh<=$hi){$modified=true;
              if($lo<$ssh)$safe[]=$lo===$ssh-1?(string)$lo:$lo.':'.($ssh-1);
              if($ssh<$hi)$safe[]=$ssh+1===$hi?(string)$hi:($ssh+1).':'.$hi;
           }else $safe[]=$piece;
       }
       if($modified){$warn[]='SSH '.$ssh.' rimosso da apertura INPUT generica: usare controllo SSH protetto.';
           if(!$safe)continue;
           // A split range may exceed multiport's 15-slot limit: fail closed.
           if(!v_ok('ports',implode(',',$safe)))continue;
           $r['ports']=implode(',',$safe);
       }
       $out[]=$r;
    }
    return $out;
}
/** Do not allow broad, implicit LAN -> WireGuard or duplicate WG egress. */
function iptm_safe_forward_rows(array $rows,array $S,array &$warn): array {
    $wg=(string)($S['wg_if']??'wg0');$result=[];
    foreach($rows as $r){
       if(!is_array($r) || empty($r['on'])){$result[]=$r;continue;}
       $accept=strtoupper((string)($r['act']??'ACCEPT'))==='ACCEPT';
       $src=trim((string)($r['src']??''));$dst=trim((string)($r['dst']??''));
       $ct=trim((string)($r['ct']??''));$oif=(string)($r['oif']??'');$iif=(string)($r['iif']??'');
       $proto=trim((string)($r['proto']??''));$ports=trim((string)($r['ports']??''));
       if($accept && $oif===$wg && $src==='' && $dst==='' && $ct==='' && $proto==='' && $ports===''){
          $warn[]='FORWARD aperto verso '.$wg.' escluso: attiva esplicitamente LAN → WireGuard se necessario.';continue;
       }
       if($accept && !empty($S['wg_on']) && !empty($S['wg_lan']) && $iif===$wg && $oif==='' && $src==='' && $dst==='' && $ct==='' && $proto==='' && $ports===''){
          $warn[]='FORWARD WireGuard duplicato: salto già gestito dal modulo VPN.';continue;
       }
       if($accept && !empty($S['spi']) && str_replace(' ','',$ct)==='RELATED,ESTABLISHED' && $src==='' && $iif==='' && $oif==='' && $proto==='' && $ports===''){
           $warn[]='Risposta RELATED,ESTABLISHED ridondante rispetto a SPI.';continue;
       }
       $result[]=$r;
    }
    return $result;
}
/** Merge defaults anche nei sotto-array (ti, notify, v6, …) così le chiavi nuove sopravvivono agli upgrade. */
function settings_with_defaults(array $s): array {
    $d = S_def();
    $s = array_merge($d, $s);
    // JSON imports and legacy settings can contain arrays where scalars are
    // expected. Do not let them reach str_starts_with(), interpolated rules,
    // or numeric comparisons. Retain defaults rather than throwing during UI.
    foreach ($d as $key => $default) {
        if (is_array($default)) {
            if (!is_array($s[$key])) $s[$key] = $default;
        } elseif (is_string($default)) {
            if (!is_string($s[$key]) && !is_int($s[$key]) && !is_float($s[$key])) $s[$key] = $default;
            else $s[$key] = (string)$s[$key];
        } elseif (is_int($default)) {
            if (is_int($s[$key])) continue;
            if (is_string($s[$key]) && preg_match('/^-?[0-9]{1,10}$/D', $s[$key]))
                $s[$key] = (int)$s[$key];
            else $s[$key] = $default;
        }
    }
    foreach (['ti', 'notify', 'v6', 'sqm', 'harden'] as $k) {
        if (!isset($d[$k]) || !is_array($d[$k])) continue;
        $cur = (isset($s[$k]) && is_array($s[$k])) ? $s[$k] : [];
        $s[$k] = array_merge($d[$k], $cur);
    }
    foreach (['fwd', 'acl', 'svc_in', 'svc_fwd', 'custom_opts', 'aliases', 'blocklists', 'apps', 'iot_devices', 'iot_policies'] as $k) {
        if (!isset($s[$k]) || !is_array($s[$k])) $s[$k] = $d[$k] ?? [];
    }
    // Normalize legacy/imported MAC keys and discard malformed flags without
    // erasing valid per-device UI restrictions. Duplicate case variants merge
    // their blocking flags (safe union) instead of silently losing policies.
    $iot=[];$allowedIoT=function_exists('iptm_iot_policy_options') ? array_keys(iptm_iot_policy_options()) : ['internet','lan','dns','dot','quic','vpn','forward'];
    foreach ($s['iot_policies'] as $mac=>$flags) {
        if (!is_string($mac) || !preg_match('/^(?:[a-f0-9]{2}:){5}[a-f0-9]{2}$/iD',$mac) || !is_array($flags)) continue;
        $key=strtolower($mac);
        $valid=array_values(array_filter($flags,fn($flag)=>is_string($flag) && in_array($flag,$allowedIoT,true)));
        if (!$valid) continue;
        $iot[$key]=array_values(array_unique(array_merge((array)($iot[$key]??[]),$valid)));
        if(in_array('forward',$iot[$key],true))$iot[$key]=['forward'];
    }
    $s['iot_policies']=$iot;
    // Legacy composite protocol is not a valid iptables -p argument. Expand
    // only service rows, never arbitrary/manual firewall rules. The operation
    // is idempotent and keeps settings_schema / on / after / source unchanged.
    foreach (['svc_in', 'svc_fwd'] as $key) {
        $expanded = [];
        foreach ($s[$key] as $r) {
            if (!is_array($r)) continue;
            // Discard malformed rows rather than potentially widening ACLs.
            $fields = ['name','iif','oif','src','dst','proto','ports','ct','act'];
            $bad = false;
            foreach ($fields as $field) {
                if (array_key_exists($field, $r) && !is_string($r[$field])) { $bad = true; break; }
            }
            if ($bad || (isset($r['on']) && !is_scalar($r['on'])) ||
                (isset($r['after']) && !is_scalar($r['after']))) continue;
            foreach (svc_proto_choices((string)($r['proto'] ?? '')) as $p) {
                $copy = $r;
                $copy['proto'] = $p;
                $expanded[] = $copy;
            }
        }
        $s[$key] = $expanded;
    }
    return $s;
}

/**
 * Migrazioni cumulative settings.json → schema SETTINGS_SCHEMA.
 * Ogni step riceve e restituisce l'array impostazioni; l'ordine è per chiave numerica crescente.
 * @return array{0: array, 1: list<string>} [settings, log messaggi]
 */
function settings_migrate(array $s): array {
    $log = [];
    $from = (int)($s['settings_schema'] ?? 0);
    if ($from > SETTINGS_SCHEMA) {
        // file più nuovo dell'app: non degradare, solo normalizza
        return [settings_with_defaults($s), ['schema file ' . $from . ' > app ' . SETTINGS_SCHEMA . ': nessuna migrazione discendente']];
    }
    // ---- step ≤ 30: normalizzazioni storiche (pre-schema) ----
    $steps = [];
    $steps[30] = function (array $s) use (&$log): array {
        foreach (['ssh_hits', 'lim_hits'] as $k) {
            $n = max(1, min(20, (int)($s[$k] ?? 4)));
            if ((int)($s[$k] ?? 0) !== $n) { $s[$k] = $n; $log[] = "$k limitato a 1..20 (xt_recent)"; }
        }
        // set CrowdSec numerati non vanno in bozza
        if (preg_match('/^crowdsec6?-blacklists(-\d+)?(,crowdsec6?-blacklists(-\d+)?)*$/', (string)($s['cs_set'] ?? ''))) {
            $s['cs_set'] = ''; $log[] = 'cs_set: rimossi set crowdsec-blacklists automatici';
        }
        if (!empty($s['v6']['cs_sets']) && preg_match('/^crowdsec6?-blacklists(-\d+)?(,crowdsec6?-blacklists(-\d+)?)*$/', (string)$s['v6']['cs_sets'])) {
            $s['v6']['cs_sets'] = ''; $log[] = 'v6.cs_sets: rimossi set automatici';
        }
        foreach (['cs_in', 'cs_fwd'] as $k) {
            if (in_array($s[$k] ?? '', ['crowdsec-input', 'crowdsec-forward'], true)) {
                $s[$k] = defined('CS_CHAIN') ? CS_CHAIN : 'CROWDSEC_CHAIN';
                $log[] = "$k: catena legacy → " . $s[$k];
            }
        }
        return $s;
    };
    // ---- 31..39: posti liberi per fix intermedi ----
    $steps[36] = function (array $s) use (&$log): array {
        // VirusTotal / TI: assicurati struttura array
        if (isset($s['ti']) && !is_array($s['ti'])) { $s['ti'] = []; $log[] = 'ti: convertito in array'; }
        if (isset($s['notify']) && !is_array($s['notify'])) { $s['notify'] = []; $log[] = 'notify: convertito in array'; }
        return $s;
    };
    $steps[37] = function (array $s) use (&$log): array {
        if (!isset($s['custom_opts']) || !is_array($s['custom_opts'])) { $s['custom_opts'] = []; $log[] = 'custom_opts inizializzato'; }
        return $s;
    };
    $steps[40] = function (array $s) use (&$log): array {
        // Porte software (3.9.40)
        if (!isset($s['apps']) || !is_array($s['apps'])) {
            $s['apps'] = [];
            $log[] = 'apps[] (porte software) inizializzato';
        } else {
            $s['apps'] = array_values(array_unique(array_filter(array_map(
                fn($x) => preg_replace('/[^a-z0-9_]/', '', (string)$x),
                $s['apps']
            ), fn($x) => $x !== '')));
        }
        return $s;
    };
    $steps[41] = function (array $s) use (&$log): array {
        // schema esplicito + default annidati + tipi booleani comuni
        $boolKeys = ['spi','antispoof','invalid','final_drop','lockout_on','crowdsec','dns_redirect','nat_masq','wg_on','portscan','stealth'];
        foreach ($boolKeys as $k) {
            if (array_key_exists($k, $s)) $s[$k] = empty($s[$k]) ? 0 : 1;
        }
        // svc_in / svc_fwd: ogni riga deve essere array con chiavi base
        foreach (['svc_in', 'svc_fwd'] as $k) {
            if (!is_array($s[$k] ?? null)) { $s[$k] = []; continue; }
            $rows = [];
            foreach ($s[$k] as $r) {
                if (!is_array($r)) continue;
                $rows[] = array_merge(['on' => 1, 'name' => '', 'iif' => '', 'src' => '', 'dst' => '', 'proto' => '', 'ports' => '', 'ct' => '', 'act' => 'ACCEPT', 'after' => 0], $r);
            }
            $s[$k] = $rows;
        }
        $log[] = 'schema 41: tipi booleani e servizi normalizzati';
        return $s;
    };

    $steps[42] = function (array $s) use (&$log): array {
        // Preserve legacy behaviour: migration never disables external IoT Warden.
        if (!in_array($s['iot_strategy'] ?? 'auto', ['auto','warden','iptm_zone','iptm_mac','none'], true)) {
            $s['iot_strategy'] = 'auto';
            $log[] = 'strategia IoT sconosciuta: conservata modalità auto';
        }
        return $s;
    };

    // 5.30.9: remove dangerous wide opens in persisted settings.
    $steps[43] = function (array $s) use (&$log): array {
        if (!empty($s['lan_tcp_accept'])) { $s['lan_tcp_accept'] = 0; $log[] = 'LAN TCP indiscriminato disattivato'; }
        if (!empty($s['docker_accept'])) { $s['docker_accept'] = 0; $log[] = 'Accesso totale container→host disattivato'; }
        if (in_array('docker', (array)($s['apps'] ?? []), true)) {
            $s['apps'] = array_values(array_diff((array)$s['apps'], ['docker']));
            $log[] = 'API Docker 2375/2376 rimossa dalle aperture automatiche';
        }
        return $s;
    };

    $steps[44] = function (array $s) use (&$log): array {
        // Never turn off explicit IPv4/IPv6 policies during migration.
        // New installs default to continuity-first; existing installs can opt out.
        if (!array_key_exists('continuity_priority', $s)) {
            $s['continuity_priority'] = 1;
            $log[] = 'continuità rete abilitata per nuove bozze';
        }
        return $s;
    };

    $steps[45] = function (array $s) use (&$log): array {
        // New optional scopes: preserve existing gateway topology and policies.
        if (!array_key_exists('lan_if',$s)) $s['lan_if']='';
        if (!array_key_exists('wan_rfc1918_spoof',$s)) $s['wan_rfc1918_spoof']=1;
        if (!array_key_exists('wg_lan_to_vpn',$s)) $s['wg_lan_to_vpn']=0;
        $log[]='scope ingress LAN e policy WireGuard esplicite disponibili (solo bozza)';
        return $s;
    };

    $steps[46] = function (array $s) use (&$log): array {
        if (!array_key_exists('external_ifs',$s)) $s['external_ifs']='';
        if (!array_key_exists('lan_ingress_map',$s)) $s['lan_ingress_map']='';
        $log[]='ingress LAN/VLAN e interfacce esterne opzionali, senza applicazione automatica';
        return $s;
    };

    ksort($steps, SORT_NUMERIC);
    $cur = $from;
    foreach ($steps as $ver => $fn) {
        if ($ver <= $from) continue;
        if ($ver > SETTINGS_SCHEMA) break;
        $s = $fn($s);
        $cur = $ver;
        $log[] = "applicato step schema → $ver";
    }
    $s = settings_with_defaults($s);
    $s['settings_schema'] = SETTINGS_SCHEMA;
    if ($from < SETTINGS_SCHEMA) {
        $log[] = "migrazione completata: schema $from → " . SETTINGS_SCHEMA . " (app " . APP_VERSION . ")";
    }
    return [$s, $log];
}

function S_load(): array {
    $f = DATA_DIR . '/settings.json';
    // Never treat unreadable, empty or malformed existing settings as a clean
    // installation. Doing so could silently substitute the default policy.
    if (is_link($f)) throw new RuntimeException('Impostazioni non leggibili: symlink rifiutato');
    $present = is_file($f);
    $rawText = $present ? @file_get_contents($f) : '';
    if (!is_string($rawText) || ($present && (trim($rawText) === '' || strlen($rawText) > 2097152)))
        throw new RuntimeException('Impostazioni preesistenti vuote, illeggibili o eccessive: nessuna migrazione');
    $raw = [];
    if ($present) {
        try {
            $decoded = json_decode($rawText, false, 256, JSON_THROW_ON_ERROR);
            if (!$decoded instanceof stdClass)
                throw new RuntimeException('settings.json deve contenere un oggetto: migrazione bloccata');
            $raw = json_decode($rawText, true, 256, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new RuntimeException('settings.json JSON malformato: migrazione bloccata', 0, $e);
        }
    }
    $GLOBALS['_settings_read_sha'] = hash('sha256', $rawText);
    $from = (int)($raw['settings_schema'] ?? 0);
    [$s, $log] = settings_migrate($raw);
    // persisti solo se c'era un file (o migrazione reale) e lo schema è cambiato / log non vuoto di migrazione
    $needWrite = is_file($f) && ($from < SETTINGS_SCHEMA || (!empty($log) && $from !== SETTINGS_SCHEMA));
    if (!$needWrite && !is_file($f) && $from === 0) {
        // nuovo install: non scrivere finché l'utente non salva
        $needWrite = false;
    }
    if ($needWrite) {
        $backupDir = DATA_DIR . '/backups';
        if (is_link($backupDir) || (!is_dir($backupDir) && !@mkdir($backupDir, 0700, true)) || !is_dir($backupDir))
            throw new RuntimeException('Migrazione bloccata: directory backup non sicura o non disponibile');
        if (is_link($f) || !is_file($f) || !is_readable($f))
            throw new RuntimeException('Migrazione bloccata: origine impostazioni non leggibile o simbolica');
        // Snapshot byte-for-byte, atomico, prima di qualsiasi conversione di schema.
        $legacyRaw = @file_get_contents($f);
        if (!is_string($legacyRaw) || $legacyRaw === '')
            throw new RuntimeException('Migrazione bloccata: configurazione originale vuota o illeggibile');
        $backupPath = $backupDir . '/settings.migrate-' . date('Ymd-His') . '-' . bin2hex(random_bytes(4)) . '.json';
        if (!atomic_data_write($backupPath, $legacyRaw, 0600) ||
            !hash_equals(hash('sha256', $legacyRaw), hash_file('sha256', $backupPath)))
            throw new RuntimeException('Migrazione bloccata: backup originale assente o non verificato');
        $s['_migrated_at'] = date('c');
        $s['_migrated_from'] = $from;
        S_put($s); // same lock + atomic update as every other settings write
        if (function_exists('audit') && $from < SETTINGS_SCHEMA) {
            audit('settings_migrate ' . $from . '→' . SETTINGS_SCHEMA . ' ' . implode('; ', array_slice($log, 0, 8)));
        }
        // avviso one-shot in sessione
        if ($from < SETTINGS_SCHEMA && PHP_SAPI !== 'cli') {
            $_SESSION['settings_migrated'] = ['from' => $from, 'to' => SETTINGS_SCHEMA, 'log' => $log];
        }
    }
    return $s;
}
/** Rotazione conservativa: 10 backup automatici per tipologia. Le copie
 * manuali etichettate, settings.prev.json e i journal di ripristino non sono
 * soggetti a questa pulizia. Si toccano solo file regolari nel DATA_DIR locale. */
function iptm_rotate_backups(string $kind, int $keep = 10, ?string $fresh = null): int {
    if ($keep < 1 || $keep > 100 || !in_array($kind, ['settings', 'rules.v4', 'rules.v6', 'draft', 'draft6', 'settings-v6', 'live'], true)) return 0;
    $dir = DATA_DIR . '/backups';
    if (!is_dir($dir) || is_link($dir)) return 0;
    $files = [];
    foreach (scandir($dir) ?: [] as $name) {
        if ($kind === 'settings') $valid = (bool)preg_match('/^settings\.[A-Za-z0-9._-]+\.json$/D', $name);
        elseif (str_starts_with($kind, 'rules.v')) $valid = (bool)preg_match('/^' . preg_quote($kind, '/') . '\.\d{8}-\d{6}(?:-[a-fA-F0-9]{8})?$/D', $name);
        elseif ($kind === 'live') $valid = (bool)preg_match('/^live\.minimal-\d{8}-\d{6}\.rules$/D', $name);
        else $valid = (bool)preg_match('/^' . preg_quote($kind, '/') . '\.(?:minimal|reset)-\d{8}-\d{6}\.(?:json|rules)$/D', $name);
        if (!$valid) continue;
        $path = $dir . '/' . $name;
        if (!is_file($path) || is_link($path)) continue;
        $st = @lstat($path);
        if (!is_array($st)) continue;
        $files[] = ['path' => $path, 'name' => $name, 'mtime' => $st['mtime'], 'ino' => $st['ino'], 'fresh' => ($path === $fresh ? 1 : 0)];
    }
    usort($files, static fn($a, $b) => ($b['fresh'] <=> $a['fresh']) ?: (($b['mtime'] <=> $a['mtime']) ?: strcmp($b['name'], $a['name'])));
    $deleted = 0;
    foreach (array_slice($files, $keep) as $old) {
        $st = @lstat($old['path']);
        if (!is_array($st) || $st['ino'] !== $old['ino'] || is_link($old['path']) || !is_file($old['path'])) continue;
        if (@unlink($old['path'])) $deleted++;
    }
    return $deleted;
}

/** Fail-closed snapshot before any destructive reset. All present files must
 * be copied successfully. Missing optional files are harmless, symlinks aren't. */
function iptm_backup_reset_files(array $mapping): void {
    $dir = DATA_DIR . '/backups';
    if (is_link($dir) || (!is_dir($dir) && !@mkdir($dir,0700,true)))
        throw new RuntimeException('Directory backup non sicura o non scrivibile: reset annullato.');
    foreach ($mapping as $src => $dest) {
        if (!preg_match('/^[A-Za-z0-9_.-]{1,90}$/D', $src.$dest))
            throw new RuntimeException('Nome backup non valido.');
        $source = DATA_DIR . '/' . $src;
        if (!file_exists($source) && !is_link($source)) continue;
        if (!is_file($source) || is_link($source))
            throw new RuntimeException('File originale non regolare: reset annullato.');
        $content = @file_get_contents($source);
        if (!is_string($content) || !atomic_data_write($dir . '/' . $dest,$content,0600))
            throw new RuntimeException('Backup reset incompleto: nessun dato verrà cancellato.');
    }
}

/** Elenco backup impostazioni (più recente prima). */
function settings_backup_list(int $max = 30): array {
    $dir = DATA_DIR . '/backups';
    $files = glob($dir . '/settings.[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9][0-9][0-9].json') ?: [];
    // anche migrate / reset / minimal
    foreach (glob($dir . '/settings.*.json') ?: [] as $f) {
        if (!in_array($f, $files, true)) $files[] = $f;
    }
    usort($files, fn($a, $b) => filemtime($b) <=> filemtime($a));
    return array_slice(array_values(array_unique($files)), 0, $max);
}

/** Copia settings.json in prev + archivio: la rotazione avviene dopo il commit. */
function settings_snapshot(string $reason = ''): ?string {
    $f = DATA_DIR . '/settings.json';
    if (!is_file($f)) return null;
    $raw = @file_get_contents($f);
    if (!is_string($raw) || $raw === '') return null;
    $backupDir = DATA_DIR . '/backups';
    if (is_link($backupDir) || (!is_dir($backupDir) && !@mkdir($backupDir, 0700, true))) return null;
    // Archive name includes random bytes: two writes in the same second may not
    // replace each other's recovery point. Backups contain credentials (0600).
    $ts = date('Ymd-His');
    $tag = $reason !== '' ? substr((string)preg_replace('/[^a-z0-9_-]/i', '', $reason), 0, 32) : '';
    $suffix = bin2hex(random_bytes(5));
    $name = 'settings.' . $ts . ($tag !== '' ? '-' . $tag : '') . '-' . $suffix . '.json';
    $dest = $backupDir . '/' . $name;
    $written = @file_put_contents($dest, $raw, LOCK_EX);
    if ($written !== strlen($raw) || !@chmod($dest, 0600)) { @unlink($dest); return null; }
    // One-step recovery remains stable for the existing UI; its failure does
    // not invalidate the independent timestamped snapshot above.
    @file_put_contents(DATA_DIR . '/settings.prev.json', $raw, LOCK_EX);
    @chmod(DATA_DIR . '/settings.prev.json', 0600);
    return $dest;
}

/** Ripristina impostazioni da un file di backup (path assoluto o basename in backups/). */
function settings_restore_from(string $path): array {
    $base = basename($path);
    if ($path === 'prev' || $base === 'settings.prev.json') {
        $file = DATA_DIR . '/settings.prev.json';
    } elseif ($base === $path || !str_contains($path, '/')) {
        $file = DATA_DIR . '/backups/' . $base;
    } else {
        $file = $path;
    }
    // sicurezza: solo dentro DATA_DIR
    $real = realpath($file);
    $root = realpath(DATA_DIR);
    if ($real === false || $root === false ||
        !str_starts_with($real, rtrim($root, '/') . '/') || !is_file($real)) {
        return ['ok' => false, 'msg' => 'Backup impostazioni non trovato.'];
    }
    $backupDir = realpath(DATA_DIR . '/backups');
    $isPrev = ($real === $root . '/settings.prev.json');
    $inBackups = ($backupDir !== false && str_starts_with($real, $backupDir . '/') &&
        preg_match('/^settings\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*\.json$/D', basename($real)));
    if (!$isPrev && !$inBackups) {
        return ['ok' => false, 'msg' => 'Nome file non valido per un backup impostazioni.'];
    }
    $j = json_decode((string)file_get_contents($real), true);
    if (!is_array($j) || $j === []) return ['ok' => false, 'msg' => 'Backup illeggibile o vuoto.'];
    // Usa lo stesso lock/snapshot/rename atomico del normale salvataggio.
    [$s, $log] = settings_migrate($j);
    $s['settings_schema'] = SETTINGS_SCHEMA;
    $s['_restored_from'] = basename($real);
    $s['_restored_at'] = date('c');
    S_put($s);
    // rigenera bozza dai settings ripristinati
    global $M;
    if (!isset($M) || !is_array($M)) {
        $M = function_exists('get_draft') ? parse_rules(get_draft()) : parse_rules(function_exists('zero_skeleton') ? zero_skeleton() : "*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n");
    }
    $w = [];
    if (function_exists('regen')) {
        // bozza: mantieni regole manuali, rigenera blocchi gestiti
        $w = regen($M, $s);
        if (function_exists('save_model')) save_model();
    }
    if (function_exists('audit')) audit('settings_rollback from=' . basename($real));
    return ['ok' => true, 'msg' => 'Impostazioni ripristinate da «' . basename($real) . '». Bozza aggiornata (non ancora applicata al kernel).'
        . ($w ? ' Avvisi: ' . implode('; ', $w) : ''), 'S' => $s];
}

function S_put(array $s) {
    // Do not regenerate a firewall bypass from a legacy toggle or app entry.
    $s['lan_tcp_accept'] = 0;
    $s['docker_accept'] = 0;
    $s['apps'] = array_values(array_diff((array)($s['apps'] ?? []), ['docker']));
    $s['settings_schema'] = SETTINGS_SCHEMA;
    $json = json_encode($s, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    if (!is_string($json)) throw new RuntimeException('Impossibile serializzare le impostazioni');
    $f = DATA_DIR . '/settings.json';
    $lock = fopen(DATA_DIR . '/settings.lock', 'c');
    if (!$lock || !flock($lock, LOCK_EX)) { if (is_resource($lock)) fclose($lock); throw new RuntimeException('Lock impostazioni non disponibile'); }
    try {
        $prev = is_file($f) ? (string)file_get_contents($f) : '';
        $expected = $GLOBALS['_settings_read_sha'] ?? null;
        if ($expected !== null && !hash_equals($expected, hash('sha256', $prev))) {
            throw new RuntimeException('Conflitto: impostazioni modificate da un’altra richiesta. Ricarica la pagina.');
        }
        $snapshotPath = null;
        if ($prev !== '' && $prev !== $json && ($snapshotPath = settings_snapshot()) === null) {
            throw new RuntimeException('Backup impostazioni non riuscito: salvataggio annullato.');
        }
        $tmp = DATA_DIR . '/.settings.' . bin2hex(random_bytes(6)) . '.tmp';
        $written = file_put_contents($tmp, $json, LOCK_EX);
        if ($written === false || $written !== strlen($json)) { @unlink($tmp); throw new RuntimeException('Scrittura impostazioni incompleta'); }
        @chmod($tmp, 0600);
        if (!rename($tmp, $f)) { @unlink($tmp); throw new RuntimeException('Sostituzione atomica impostazioni fallita'); }
        iptm_rotate_backups('settings', 10, $snapshotPath); // dopo commit, preserva la nuova copia anche con timestamp uguale
        $GLOBALS['_settings_read_sha'] = hash('sha256', $json);
        $GLOBALS['_Sc'] = $s;
    } finally {
        flock($lock, LOCK_UN); fclose($lock);
    }
}
const CHAIN_RESERVED = ['ACCEPT', 'DROP', 'REJECT', 'RETURN', 'QUEUE', 'LOG', 'ULOG', 'NFLOG', 'NFQUEUE', 'DNAT', 'SNAT', 'MASQUERADE', 'REDIRECT', 'NETMAP', 'TCPMSS', 'TARPIT', 'SYNPROXY', 'CT', 'NOTRACK', 'MARK', 'CONNMARK', 'CLASSIFY', 'TOS', 'TTL', 'HL', 'DSCP', 'ECN', 'TRACE', 'TPROXY', 'AUDIT', 'CHECKSUM', 'SET', 'INPUT', 'FORWARD', 'OUTPUT', 'PREROUTING', 'POSTROUTING'];
function v_ok(string $t, string $v): bool {
    switch ($t) {
        case 'if': return $v === '' || (bool)preg_match('/^[A-Za-z0-9_.+-]{1,15}$/', $v);
        case 'nets':
            if ($v === '') return true;
            foreach (explode(',', $v) as $n) { [$b, $m] = array_pad(explode('/', $n, 2), 2, '32'); if (!filter_var($b, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) || !preg_match('/^\d{1,2}$/', $m) || (int)$m > 32) return false; }
            return true;
        case 'ip': return $v === '' || (bool)filter_var($v, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4);
        case 'port': return $v === '' || (preg_match('/^[1-9]\d{0,4}$/', $v) && (int)$v <= 65535);   // niente zeri iniziali: iptables li rifiuta ("080")
        case 'ports':
            if ($v === '') return true;
            $w = 0;   // multiport accetta al massimo 15 porte e un intervallo ne conta 2; niente zeri iniziali né intervalli a=b
            foreach (explode(',', $v) as $x) { if (!preg_match('/^([1-9]\d{0,4})(?::([1-9]\d{0,4}))?$/', $x, $m)) return false; $a = (int)$m[1]; $b = isset($m[2]) ? (int)$m[2] : $a; if ($b > 65535 || $a > $b || (isset($m[2]) && $a === $b)) return false; $w += isset($m[2]) ? 2 : 1; }
            return $w <= 15;
        case 'lrate': return (bool)preg_match('/^[1-9]\d{0,4}\/(sec|min|hour|day)$/', $v) && (substr($v, -4) !== '/sec' || (int)$v <= 10000);   // -m limit: max 10000/sec
        case 'rate': return (bool)preg_match('/^[1-9]\d{0,4}\/(sec|min|hour|day)$/', $v);
        case 'name': return (bool)preg_match('/^[\p{L}\p{N} _.\-()\/:+,→]{0,40}$/u', $v);
        case 'macs': return $v === '' || (bool)preg_match('/^([0-9a-f]{2}(:[0-9a-f]{2}){5})(,[0-9a-f]{2}(:[0-9a-f]{2}){5})*$/', $v);
        case 'ifs': return $v === '' || (bool)preg_match('/^[A-Za-z0-9_.+-]{1,15}(,[A-Za-z0-9_.+-]{1,15})*$/D', $v);
        case 'lanmap': return iptm_lan_ingress_map_valid($v);
        case 'chain': return $v === '' || (preg_match('/^[A-Za-z0-9_][A-Za-z0-9_.-]{0,27}$/', $v) && !in_array($v, CHAIN_RESERVED, true));   // niente "-" iniziale né nomi di target/catene built-in
        case 'setlist': return (bool)preg_match('/^([A-Za-z0-9_.-]{1,31}(,[A-Za-z0-9_.-]{1,31})*)?$/', $v);
        case 'setname': return (bool)preg_match('/^[A-Za-z0-9_.-]{1,31}$/', $v);
        case 'prefix': return (bool)preg_match('/^[A-Za-z0-9 _:.\-]{0,28}$/', $v);
        case 'ct': return $v === '' || (bool)preg_match('/^(NEW|ESTABLISHED|RELATED|INVALID|UNTRACKED)(,(NEW|ESTABLISHED|RELATED|INVALID|UNTRACKED))*$/', $v);
        case 'cc': return $v === '' || (bool)preg_match('/^([A-Za-z]{2})(,[A-Za-z]{2})*$/', $v);
        case 'dir': return in_array($v, ['in', 'out', 'both'], true);
        case 'time': return (bool)preg_match('/^(([01]\d|2[0-3]):[0-5]\d|24:00)$/', $v);
    }
    return false;
}
function port_opt(string $p, string $f = 'dport'): string { return str_contains($p, ',') ? "-m multiport --{$f}s $p" : "--$f $p"; }
function acl_clients(string $txt): array {
    $ok = []; $bad = [];
    foreach (preg_split('/[\s,;]+/', trim($txt), -1, PREG_SPLIT_NO_EMPTY) as $t) {
        if (preg_match('/^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/', $t)) $ok[] = '-m mac --mac-source ' . strtoupper($t);
        elseif (preg_match('/^@([A-Za-z][A-Za-z0-9_-]{1,24})$/', $t, $m) && isset(alias_map(S_get())['nets'][$m[1]])) $ok[] = '-m set --match-set al_' . $m[1] . ' src';
        elseif (preg_match('/^([\d.]+)-([\d.]+)$/', $t, $m) && v_ok('ip', $m[1]) && v_ok('ip', $m[2])) $ok[] = '-m iprange --src-range ' . $t;
        elseif (v_ok('nets', $t) && strpos($t, ',') === false) $ok[] = '-s ' . $t;
        else $bad[] = $t;
    }
    return [$ok, $bad];
}
function acl_time(array $p): array {   // finestre orarie -> frammenti "-m time" in UTC (xt_time lavora in UTC)
    $names = array_keys(DAYS); $days = array_values(array_intersect($names, (array)($p['days'] ?? []))); if (!$days) $days = $names;
    $m = fn($s) => (int)substr($s, 0, 2) * 60 + (int)substr($s, 3, 2);
    $a = $m($p['from'] ?? '00:00'); $b = $m($p['to'] ?? '24:00'); if ($b <= $a) $b += 1440;
    if (count($days) === 7 && $a === 0 && $b === 1440) return [''];
    $off = intdiv((int)date('Z'), 60); $seg = [];
    foreach ($days as $d) {
        $di = array_search($d, $names, true); $s0 = $a - $off; $e0 = $b - $off;
        for ($k = (int)floor($s0 / 1440); $k <= (int)floor(($e0 - 1) / 1440); $k++) {
            $ss = max($s0, $k * 1440) - $k * 1440; $ee = min($e0, ($k + 1) * 1440) - $k * 1440;
            $seg["$ss-$ee"][$names[(($di + $k) % 7 + 7) % 7]] = 1;
        }
    }
    $o = []; $hm = fn($x) => $x >= 1440 ? '23:59:59' : sprintf('%02d:%02d', intdiv($x, 60), $x % 60);
    foreach ($seg as $k => $wd) {
        [$ss, $ee] = array_map('intval', explode('-', $k)); $f = '-m time';
        if (!($ss === 0 && $ee >= 1440)) $f .= ' --timestart ' . $hm($ss) . ' --timestop ' . $hm($ee);
        if (count($wd) < 7) $f .= ' --weekdays ' . implode(',', array_filter($names, fn($n) => isset($wd[$n])));
        $o[] = $f;
    }
    return $o ?: [''];
}
function acl_targets(array $p): array {
    $o = [];
    foreach ((array)($p['svc'] ?? []) as $k) {
        if (!isset(SVC[$k])) continue;
        if ($k === 'all') { $o[] = ''; continue; }
        [$pp, $ports] = explode(':', SVC[$k][1], 2);
        foreach (explode(',', $pp) as $proto) $o[] = "-p $proto " . port_opt($ports);
    }
    foreach (preg_split('/[\s;]+/', trim((string)($p['custom'] ?? '')), -1, PREG_SPLIT_NO_EMPTY) as $c)
        if (preg_match('/^(tcp|udp):(.+)$/', $c, $mm) && v_ok('ports', $mm[2])) $o[] = "-p {$mm[1]} " . port_opt($mm[2]);
    foreach (preg_split('/\R/', trim((string)($p['urls'] ?? '')), -1, PREG_SPLIT_NO_EMPTY) as $u) {
        $u = trim($u); if (preg_match('/^[A-Za-z0-9._\/ -]{2,60}$/', $u)) $o[] = '-p tcp -m multiport --dports 80,443 -m string --string "' . $u . '" --algo bm --icase';
    }
    return $o;
}
function wan_ready(array $S): bool { return !empty($S['single_nic']) ? $S['lan_nets'] !== '' : $S['wan_if'] !== ''; }
function sec_opt(string $id): string {   // sezione generata -> opzione che la produce (usato dall'import)
    foreach (['antispoof-' => 'antispoof', 'spoof-' => 'spoof_on', 'cs-' => 'crowdsec', 'spi-' => 'spi', 'invalid-' => 'invalid', 'icmp' => 'icmp_limit', 'igmp' => 'igmp_accept', 'dos' => 'dos',
        'ssh-acc' => 'ssh_acc', 'close-' => 'closeports', 'final-' => 'final_drop', 'logdrop' => 'logdrop_on', 'raw-lo-' => 'raw_lo', 'raw-drop' => 'raw_drop', 'dot' => 'dot_block',
        'mss' => 'mss', 'connlimit' => 'conn_limit', 'isolate' => 'iso_on', 'guest-' => 'guest_on', 'quic' => 'quic_block', 'lancl' => 'lan_cl', 'svcban' => 'svc_ban', 'raw-rpf' => 'rpfilter', 'badmss' => 'bad_mss', 'bw-up' => 'bw_on', 'bw-down' => 'bw_on', 'mac-only' => 'mac_only', 'udprl' => 'udp_rl', 'webrl' => 'web_rl', 'amp' => 'amp_block', 'dns-redir' => 'dns_redirect', 'nat-masq' => 'nat_masq', 'lan-tcp' => 'lan_tcp_accept', 'docker-net' => 'docker_accept', 'bcast' => 'bcast_accept', 'dhcp-in' => 'dhcp_accept', 'coap-mdns' => 'coap_accept', 'lan-out' => 'lan_out_fwd', 'cs-set' => 'cs_set_match'] as $p => $o) if (str_starts_with($id, $p)) return $o;
    return '';
}
function svc_rule(string $chain, array $r, array $AL = []): string {
    $p = $r['proto'] ?? ''; $ports = $r['ports'] ?? ''; $s = $r['src'] ?? ''; $d = $r['dst'] ?? ''; $ex = [];
    if (str_starts_with($ports, '@')) $ports = $AL['ports'][substr($ports, 1)] ?? '';
    if (str_starts_with($s, '@')) { $ex[] = '-m set --match-set al_' . substr($s, 1) . ' src'; $s = ''; }
    if (str_starts_with($d, '@')) { $ex[] = '-m set --match-set al_' . substr($d, 1) . ' dst'; $d = ''; }
    $f = ['chain' => $chain, 'i' => $r['iif'] ?? '', 'o' => $r['oif'] ?? '', 's' => $s, 'd' => $d, 'p' => $p, 'sport' => '', 'dport' => '', 'sports' => '', 'dports' => '', 'ports' => '', 'ctstate' => $r['ct'] ?? '', 'extra' => implode(' ', $ex), 'target' => ($r['act'] ?? 'ACCEPT'), 'targs' => ''];
    if ($ports !== '' && in_array($p, ['tcp', 'udp'], true)) { if (str_contains($ports, ',')) $f['dports'] = $ports; else $f['dport'] = $ports; }
    return rule_build($f);
}
/** Expand composite protocol rows into distinct IPv4 service rules.
 * This also handles old drafts regenerated from settings that predate 3.9.93.
 * The original single-protocol rule builder remains unchanged.
 */
function svc_rules(string $chain, array $rows, array $AL = []): array {
    $out = [];
    foreach ($rows as $r) {
        if (!is_array($r)) continue;
        // Every row is untrusted until the runtime validates its field types.
        // Silently widening a malformed rule would be worse than omitting it.
        $valid = true;
        foreach (['iif','oif','src','dst','proto','ports','ct','act'] as $field) {
            if (isset($r[$field]) && !is_string($r[$field])) { $valid = false; break; }
        }
        if (!$valid) continue;
        foreach (svc_proto_choices((string)($r['proto'] ?? '')) as $p) {
            $one = $r;
            $one['proto'] = $p;
            $source = trim((string)($one['src'] ?? ''));
            $unscoped = in_array($source, ['', '0.0.0.0/0', '0/0', '0.0.0.0'], true)
                && trim((string)($one['iif'] ?? '')) === '';
            $portText = trim((string)($one['ports'] ?? ''));
            $isAlias = str_starts_with($portText, '@');
            $effective = $isAlias ? (string)($AL['ports'][substr($portText, 1)] ?? '') : $portText;
            $accept = strtoupper((string)($one['act'] ?? 'ACCEPT')) === 'ACCEPT';
            // Never turn an unresolved or malformed port alias into an
            // unrestricted rule. This applies to FORWARD as well as INPUT,
            // and to DROP as well as ACCEPT (avoid blocking legitimate traffic).
            if ($isAlias && ($effective === '' || !v_ok('ports', $effective))) continue;
            if ($portText !== '' && in_array($p, ['tcp','udp'], true) && !v_ok('ports', $effective)) continue;
            if ($portText !== '' && !in_array($p, ['tcp','udp'], true)) continue;
            // An unresolved alias silently becomes an unrestricted host service
            // in svc_rule(). A valid empty port list must never open all TCP/UDP.
            if ($chain === 'INPUT' && $accept && in_array($p, ['tcp','udp'], true)) {
                if ($effective === '' || !v_ok('ports', $effective)) continue;
                if ($p === 'tcp') {
                    $sensitive = false;
                    foreach (explode(',', $effective) as $entry) {
                        $bits = explode(':', $entry, 2);
                        $lo = (int)$bits[0]; $hi = (int)($bits[1] ?? $bits[0]);
                        if ($lo <= 2376 && $hi >= 2375) { $sensitive = true; break; }
                    }
                    if ($sensitive) continue; // Docker root API never auto-exposed.
                }
            }
            $sshOpen = ($effective === '');
            foreach (preg_split('/[\s,]+/', $effective, -1, PREG_SPLIT_NO_EMPTY) as $portPart) {
                if (ctype_digit($portPart) && (int)$portPart === 22) $sshOpen = true;
                if (preg_match('/^(\d+):(\d+)$/D', $portPart, $range)
                    && (int)$range[1] <= 22 && 22 <= (int)$range[2]) $sshOpen = true;
            }
            if ($chain === 'INPUT' && $p === 'tcp' && $accept && $unscoped && $sshOpen) continue;
            $out[] = svc_rule($chain, $one, $AL);
        }
    }
    return $out;
}
/**
 * IPTM 3.9.98: invariant for the shared bond0 WAN/LAN and for VPN/Docker.
 * Legacy keys remain in settings for safe upgrades but cannot emit hazardous rules.
 * No live changes; this function only transforms proposed settings.
 */
function iptm_unsafe_flag_keys(): array {
    return ['rpfilter','synproxy','raw_lo','raw_invalid','bogon_wan','spoof_on',
            'drop_frag','bad_mss','tarpit','svc_ban','mac_only'];
}
/** Only actual private IPv4/CGNAT source scopes qualify for automatic LAN trust.
 * A /0 (or a public network copied into LAN settings) must never open SSH or
 * the management UI to the whole WAN. Public routed networks need explicit
 * custom ACLs instead of implicit 'trusted LAN' privileges.
 */
function iptm_trusted_lan_nets(string $raw, array &$notes = []): string {
    $safe = [];
    foreach (preg_split('/[\s,;]+/', trim($raw), -1, PREG_SPLIT_NO_EMPTY) as $scope) {
        $parts = explode('/', $scope, 2);
        $ip = $parts[0];
        $validMask = count($parts) === 1 || preg_match('/^\d{1,2}$/D', $parts[1]);
        $mask = $validMask ? (isset($parts[1]) ? (int)$parts[1] : 32) : -1;
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) || $mask < 8 || $mask > 32) {
            $notes[] = 'Subnet LAN non attendibile o non valida esclusa dalla bozza: ' . $scope;
            continue;
        }
        $v = ip2long($ip);
        $isTrusted = false;
        foreach ([['10.0.0.0',8], ['172.16.0.0',12], ['192.168.0.0',16], ['100.64.0.0',10]] as [$base,$prefix]) {
            if ($mask < $prefix) continue;
            $bits = (0xffffffff << (32 - $prefix)) & 0xffffffff;
            if (($v & $bits) === (ip2long($base) & $bits)) { $isTrusted = true; break; }
        }
        if (!$isTrusted) {
            $notes[] = 'Rete pubblica o non attendibile esclusa dagli accessi automatici LAN: ' . $scope;
            continue;
        }
        $bits = $mask === 32 ? 0xffffffff : ((0xffffffff << (32 - $mask)) & 0xffffffff);
        $net = long2ip($v & $bits) . '/' . $mask;
        if (!in_array($net, $safe, true)) $safe[] = $net;
    }
    return implode(',', $safe);
}
function iptm_safe_settings(array $S, array &$notes = []): array {
    $S['lan_nets'] = iptm_trusted_lan_nets((string)($S['lan_nets'] ?? ''), $notes);
    // A legacy ssh_nets=/0 must not turn rate-limited SSH into WAN access.
    // SSH exceptions are managed from private LAN/VPN scopes, not public CIDR.
    $S['ssh_nets'] = iptm_trusted_lan_nets((string)($S['ssh_nets'] ?? ''), $notes);
    // Configurations may arrive from old settings.json / import, not only from
    // validated form inputs. Never interpolate untrusted interface tokens.
    foreach (['wan_if', 'lan_if', 'wg_if'] as $ifaceKey) {
        if (isset($S[$ifaceKey]) && !v_ok('if', (string)$S[$ifaceKey])) {
            $notes[] = 'Interfaccia non valida: ' . $ifaceKey . ' (nessuna regola generata per quel nome).';
            $S[$ifaceKey] = '';
        }
    }
    if (isset($S['masq_ifs']) && !v_ok('ifs', (string)$S['masq_ifs'])) {
        $notes[] = 'Interfacce NAT non valide: uscita non generata finché non vengono corrette.';
        // Empty the WAN too to avoid implicit fallback to an unintended route.
        $S['masq_ifs'] = '';
        $S['nat_masq'] = 0;
        $S['lan_out_fwd'] = 0;
    }
    foreach (['lan_tcp_accept', 'docker_accept'] as $key) {
        if (!empty($S[$key])) $notes[] = 'Apertura generica non sicura ignorata: ' . $key;
        $S[$key] = 0;
    }
    if (in_array('docker', (array)($S['apps'] ?? []), true)) {
        $S['apps'] = array_values(array_diff((array)$S['apps'], ['docker']));
        $notes[] = 'API Docker 2375/2376: apertura automatica rimossa';
    }
    // A broad host-service ACCEPT would reintroduce the removed lan-tcp bypass.
    // Do not rewrite manually authored rules or active firewall state.
    $safeRows = [];
    foreach ((array)($S['svc_in'] ?? []) as $r) {
        if (!is_array($r) || empty($r['on'])) { $safeRows[] = $r; continue; }
        $protos = svc_proto_choices((string)($r['proto'] ?? ''));
        $ports = trim((string)($r['ports'] ?? ''));
        $accept = strtoupper((string)($r['act'] ?? 'ACCEPT')) === 'ACCEPT';
        $blocked = $accept && $ports === '' && (in_array('tcp', $protos, true) || in_array('udp', $protos, true)
            || ((string)($r['proto'] ?? '') === '' && trim((string)($r['iif'] ?? '')) !== 'lo')); 
        if ($accept && in_array('tcp', $protos, true) && $ports !== '') {
            foreach (preg_split('/[\s,]+/', $ports, -1, PREG_SPLIT_NO_EMPTY) as $part) {
                if (ctype_digit($part) && in_array((int)$part, [2375,2376], true)) $blocked = true;
                if (preg_match('/^(\d+):(\d+)$/D', $part, $p)
                    && (int)$p[1] <= 2376 && (int)$p[2] >= 2375) $blocked = true;
            }
        }
        if ($blocked) {
            $notes[] = 'Servizio INPUT troppo ampio o API Docker esposta: riga esclusa dalla bozza.';
            continue;
        }
        $safeRows[] = $r;
    }
    $S['svc_in'] = $safeRows;
    // A same-interface connection cannot distinguish upstream and LAN by -i.
    // raw table runs before INPUT and FORWARD; do not drop legitimate discovery
    // or client traffic before per-service firewall rules have a chance.
    $wanIf = trim((string)($S['wan_if'] ?? ''));
    $shared = !empty($S['single_nic'])
        || ($wanIf !== '' && $wanIf === trim((string)($S['lan_if'] ?? '')))
        || ($wanIf !== '' && function_exists('sys_ifaces')
            && count((array)(sys_ifaces()[$wanIf] ?? [])) > 1);
    if (!empty($S['raw_drop']) && ($shared || $wanIf === '')) {
        $S['raw_drop'] = 0;
        $notes[] = 'Filtro raw disattivato nella bozza: necessita di una WAN dedicata; il filtro INPUT/FORWARD resta in funzione.';
    }
    if (in_array('minidlna', (array)($S['apps'] ?? []), true) &&
        in_array('1900', explode(',', (string)($S['raw_udp'] ?? '')), true)) {
        $S['raw_udp'] = implode(',', array_diff(explode(',', $S['raw_udp']), ['1900']));
        $notes[] = 'MiniDLNA: SSDP 1900 escluso dal blocco raw';
    }
    // Connectivity-first is deliberately opt-out. It affects only nonessential,
    // indiscriminate rate drops; application-specific explicit ACLs are retained.
    // Never silently tear down an active firewall, DNS daemon or network link.
    if (!empty($S['continuity_priority'])) {
        foreach (['dos', 'conn_limit', 'lan_cl', 'udp_rl', 'web_rl',
                  'glob_new_limit', 'lan_flood', 'portscan'] as $key) {
            if (!empty($S[$key])) {
                $notes[] = 'Continuità rete: limite generico ' . $key . ' escluso dalla bozza (può bloccare traffico lecito).';
                $S[$key] = 0;
            }
        }
        // Explicit choices such as IoT isolation, QUIC, DoT or service DROP
        // still take effect. Warn in the UI rather than secretly overriding.
        if (!empty($S['quic_block'])) $notes[] = 'QUIC: il blocco UDP 443 può interrompere videochiamate, gaming e app senza fallback TCP.';
        if (!empty($S['dot_block'])) $notes[] = 'DoT: il blocco 853 può interrompere i client configurati per DNS cifrato esterno.';
        if (!empty($S['iso_on']) || !empty($S['guest_on'])) $notes[] = 'Segmentazione: verifica che le eccezioni DNS, DHCP e gestione siano raggiungibili dalle zone previste.';
    }
    foreach (iptm_unsafe_flag_keys() as $key) {
        if (!empty($S[$key])) $notes[] = 'Protezione anti-lockout: opzione ' . $key . ' ignorata nella nuova bozza.';
        $S[$key] = 0;
    }
    // Shared-interface WAN identification is ambiguous on bond0. Unscoped WAN
    // chains can match LAN packets; disable those optional filters in such setups.
    // A WAN bridge/bond may have both LAN and upstream IPv4 addresses on one NIC.
    // Detect this even when legacy settings did not mark single_nic or lan_if.
    $wan = (string)($S['wan_if'] ?? '');
    $wanAddrs = ($wan !== '' && function_exists('sys_ifaces')) ? (sys_ifaces()[$wan] ?? []) : [];
    $sharedWan = !empty($S['single_nic']) || ($wan !== '' && $wan === (string)($S['lan_if'] ?? '')) || count($wanAddrs) > 1;
    if ($sharedWan) {
        foreach (['multicast','web_rl','blockping','ident','amp_block','log_out','portscan'] as $key) {
            if (!empty($S[$key])) $notes[] = 'WAN e LAN condividono l’interfaccia: ' . $key . ' non generata.';
            $S[$key] = 0;
        }
    }
    if (!empty($S['lan_nets']) && (!empty($S['spi']) || !empty($S['final_drop']) || !empty($S['continuity_priority']))) {
        $S['lockout_on'] = 1;
        $must = ['22', '80', '443', '8089', '8489'];
        $ports = array_filter(array_map('trim', explode(',', (string)($S['mgmt_ports'] ?? ''))),
                              fn($p) => preg_match('/^[0-9]{1,5}$/D', $p) && (int)$p >= 1 && (int)$p <= 65535);
        $ports = array_values(array_diff(array_unique(array_map(fn($p) => (string)(int)$p, $ports)), $must));   // normalizza ("080" -> "80") ed evita doppioni
        $S['mgmt_ports'] = implode(',', array_merge(array_slice($ports, 0, 15 - count($must)), $must));        // multiport: max 15 porte in tutto
    }
    return $S;
}
/** Reject even forced or imported unsafe raw rules; never silently alter unknown rules. */
function iptm_reject_unsafe_rules(string $txt): string {
    $lines = explode("\n", $txt);
    $section = '';
    $hasSshGuard=str_contains($txt,'# >>> IPTM:ssh-acc');
    foreach ($lines as $n => $line) {
        if (preg_match('/^\s*# >>> IPTM:([A-Za-z0-9_.-]+)/', $line, $m)) {
            $section = $m[1]; continue;
        }
        if (preg_match('/^\s*# <<< IPTM:/', $line)) { $section = ''; continue; }
        if (!preg_match('/^\s*-A\s+\S+\s+/', $line)) continue;
        // Fail closed only for IPTM-owned sections; user rules are diagnosed
        // separately and must not be rewritten without their owner's decision.
        $owned = $section !== '';
        $unsafeManaged = $owned && (
            ($section === 'lan-tcp' && preg_match('/^-A\s+INPUT\b.*\s-p\s+tcp\b.*\s-j\s+ACCEPT\b/', $line)) ||
            (str_starts_with($section, 'svc-in-') && preg_match('/^-A\s+INPUT\b.*\s-p\s+tcp\b.*\s-j\s+ACCEPT\b/', $line)
                && !preg_match('/--dports?\s+/', $line)) ||
            ($section === 'apps' && str_contains($line, 'IPTM-app:docker')
                && preg_match('/\s-j\s+ACCEPT\b/', $line)) ||
            ($section === 'raw-drop' && preg_match('/^-A\s+PREROUTING\b.*\s-j\s+DROP\b/', $line)
                && !preg_match('/\s-i\s+/', $line)) ||
            ($section === 'lockout' && preg_match('/(?:^|\s)-s\s+0\.0\.0\.0\/0\b/', $line)) ||
            ($section === 'lockout' && $hasSshGuard && preg_match('/\s-p\s+tcp\b/', $line) &&
                preg_match('/--dports?\s+([0-9,:]+)/',$line,$ports) &&
                in_array('22',explode(',',$ports[1]),true) && preg_match('/\s-j\s+ACCEPT\b/',$line)) ||
            ($section === 'svc-fwd' && preg_match('/^-A\s+FORWARD\b.*\s-o\s+wg[a-zA-Z0-9_.-]*\b/', $line) &&
                preg_match('/\s-j\s+ACCEPT\b/',$line) &&
                !preg_match('/\s(?:-s|-d|--ctstate|--dport|--dports)\s+/', $line))
        );
        $unsafe = ($unsafeManaged ||
            (str_contains($line, '--invert') && str_contains($line, '-m rpfilter')) ||
            (bool)preg_match('/\s-j\s+SYNPROXY(?:\s|$)/', $line) ||
            (bool)preg_match('/\s-j\s+TARPIT(?:\s|$)/', $line) ||
            (bool)preg_match('/^-A\s+(PREROUTING|OUTPUT)\b.*\s-j\s+CT\s+--notrack\b/', $line) ||
            (bool)preg_match('/^-A\s+PREROUTING\b.*--ctstate\s+INVALID\b.*\s-j\s+DROP\b/', $line) ||
            (bool)preg_match('/^-A\s+FORWARD\s+-j\s+IPTM-WAN-FWI\s*$/', trim($line))
        );
        if ($unsafe) return 'Bozza IPv4 non applicabile: regola ad alto rischio alla riga ' . ($n+1)
            . ' (' . trim($line) . '). Eliminala o rigenera la bozza protetta. “Forza” non aggira questo controllo.';
    }
    return '';
}
function gen_sections(array $S): array {
    $sec = []; $warn = []; $S = iptm_safe_settings($S, $warn); $lan = array_values(array_filter(explode(',', $S['lan_nets']))); $single = !empty($S['single_nic']); $ready = wan_ready($S); $wanc = [];
    // Non applica correzioni implicite: segnala combinazioni che possono
    // impedire la navigazione ai client quando il gateway conserva OUTPUT.
    if (!empty($S['final_drop']) && $lan && empty($S['lan_out_fwd']))
        $warn[] = 'Navigazione client: final_drop attivo senza lan_out_fwd. Il preflight controllerà anche eventuali regole FORWARD manuali, le risposte ESTABLISHED e ogni subnet LAN.';
    if (!empty($S['dns_redirect']) && empty($S['dhcp_accept']))
        $warn[] = 'DNS/DHCP: redirect DNS attivo con eccezione DHCP INPUT disabilitata; verificare porta UDP 67/68 per Pi-hole DHCP.';
    if (empty($S['nat_masq']) && $lan && $S['wan_if'] !== '')
        $warn[] = 'Navigazione client: NAT/MASQUERADE disabilitato. Serve un percorso di ritorno esplicito sul router a monte, altrimenti i client non navigano.';
    if (!$lan && !empty($S['apps']))
        $warn[] = 'Porte software: nessuna LAN configurata. Aperture locali sospese; le porte VPN con ambito pubblico restano esplicite.';
    $DT = $S['drop_chain'] !== '' ? $S['drop_chain'] : 'DROP'; $AL = alias_map($S);
    $add = function (string $id, string $title, string $t, string $c, string $an, int $pr, array $rules) use (&$sec) {
        $rules = array_values(array_filter($rules, fn($r) => $r !== '' && ($r[0] === '#' || lint_rule($r))));
        // Only exact duplicates inside one IPTM-owned generated section.
        // Never deduplicate across owners or reorder user/CrowdSec/Docker rules.
        if (!str_starts_with($id, 'cust-')) $rules = array_values(array_unique($rules));
        if ($rules) $sec[] = compact('id', 'title', 't', 'c', 'an', 'pr', 'rules');
    };
    // $W: regole "solo dal/verso il lato WAN" (segnaposto {W}). Interfacce separate -> -i/-o WAN; interfaccia unica -> catena IPTM-WAN-* con RETURN per le LAN.
    $W = function (string $id, string $title, string $t, string $c, string $an, int $pr, array $bodies, string $d = 'i') use (&$wanc, $S, $single, $add) {
        if (!$single) { $m = $S['wan_if'] !== '' ? '-' . $d . ' ' . $S['wan_if'] : ''; $add($id, $title, $t, $c, $an, $pr, array_map(fn($b) => preg_replace('/ {2,}/', ' ', str_replace('{W}', $m, $b)), $bodies)); return; }
        $wanc["$t|$c|$d"][] = compact('id', 'title', 'an', 'pr', 'bodies');
    };
    $J = fn(...$a) => implode(' ', array_filter($a, fn($x) => $x !== '' && $x !== null));
    $needw = function (string $what) use (&$warn, $ready) { if (!$ready) { $warn[] = "$what: definisci la WAN (o LAN + «interfaccia unica») in Setup."; return false; } return true; };
    // ---------- DHCP: il DISCOVER/REQUEST dei client ha sorgente 0.0.0.0 e destinazione 255.255.255.255,
    // quindi non combacia con nessuna regola «-s LAN» e con policy DROP / SPI / porte privilegiate chiuse viene scartato.
    if (!empty($S['dhcp_accept'])) {
        $dni = ($lanIngress=iptm_lan_ingress($S)) !== '' ? $lanIngress.' ' : '';   // DHCP 0.0.0.0 richiede vincolo LAN verificabile
        $add('dhcp-in', 'DHCP: client → server (UDP 68→67) e risposte server → client (UDP 67→68)', 'filter', 'INPUT', 'top', 2,
            ["-A INPUT {$dni}-p udp --sport 68 --dport 67 -j ACCEPT", "-A INPUT {$dni}-p udp --sport 67 --dport 68 -j ACCEPT"]);
    }
    // ---------- raw
    if ($S['raw_lo']) { $add('raw-lo-pre', 'raw: il loopback non viene tracciato', 'raw', 'PREROUTING', 'top', 10, ['-A PREROUTING -i lo -j CT --notrack', '-A PREROUTING -i lo -j ACCEPT']); $add('raw-lo-out', 'raw: loopback in uscita non tracciato', 'raw', 'OUTPUT', 'top', 10, ['-A OUTPUT -o lo -j CT --notrack']); }
    if ($S['raw_drop'] && $S['wan_if'] !== '') {
        $wanMatch = '-i ' . $S['wan_if'];
        $r = [];
        if ($S['raw_tcp'] !== '') $r[] = '-A PREROUTING ' . $wanMatch . ' -p tcp ' . port_opt($S['raw_tcp']) . ' -j DROP';
        if ($S['raw_udp'] !== '') $r[] = '-A PREROUTING ' . $wanMatch . ' -p udp ' . port_opt($S['raw_udp']) . ' -j DROP';
        $add('raw-drop', 'Scarta traffico WAN verso porte bloccate', 'raw', 'PREROUTING', 'top', 20, $r);
    }
    // ---------- catena di log
    if ($S['logdrop_on'] && $S['drop_chain'] !== '') {
        $add('logdrop', 'Catena ' . $DT . ' (log con limiti per sorgente)', 'filter', $DT, 'top', 10, [
            "-A $DT -m hashlimit --hashlimit-name logdrop --hashlimit-mode srcip --hashlimit-upto {$S['ld_src_rate']} --hashlimit-burst {$S['ld_src_burst']} -m limit --limit {$S['ld_glob_rate']} --limit-burst {$S['ld_glob_burst']} -j LOG --log-prefix \"{$S['ld_prefix']}\" --log-level 4",
            "-A $DT -j DROP"]);
    }
    // ---------- anti-spoofing / SPI / blacklist
    if (!empty($S['wan_rfc1918_spoof'])) {
        $safeExt=iptm_external_spoof_ifaces($S);
        if ($safeExt) foreach (['INPUT','FORWARD'] as $chain) {
            $rules=[];
            foreach($safeExt as $ifname)foreach(['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'] as $net)
                $rules[]='-A '.$chain.' -i '.$ifname.' -s '.$net.' -j DROP';
            $add('wan-rfc1918-'.strtolower($chain),'Anti-spoof RFC1918 sulle interfacce esterne pubbliche verificate','filter',$chain,'top',0,$rules);
        }
        $requested=array_unique(array_filter(array_merge([(string)($S['wan_if']??'')],explode(',',(string)($S['external_ifs']??'')))));
        $unverified=array_values(array_diff($requested,$safeExt));
        if($unverified)$warn[]='Anti-spoof RFC1918 NON attivato su '.implode(', ',$unverified).': ingresso non verificato come esterno pubblico distinto, oppure WAN/LAN condivisa o doppio NAT.';
    }
    if ($S['antispoof']) foreach (['INPUT', 'FORWARD'] as $c) $add('antispoof-' . strtolower($c), "Anti-spoofing ($c)", 'filter', $c, 'top', 5, array_merge(["-A $c ! -i lo -s 127.0.0.0/8 -j DROP"], $S['antispoof_mc'] ? ["-A $c -s 224.0.0.0/4 -j DROP"] : []));
    if ($S['spoof_on'] && $S['spoof_if'] !== '' && $S['spoof_nets'] !== '') foreach (['INPUT', 'FORWARD'] as $c) $add('spoof-' . strtolower($c), "Sorgenti spoofate su {$S['spoof_if']} ($c)", 'filter', $c, 'top', 6, ["-A $c -i {$S['spoof_if']} -s {$S['spoof_nets']} -j $DT"]);
    // ---------- CrowdSec: nessuna regola generata. Gli agganci (INPUT/FORWARD/DOCKER-USER -> CROWDSEC_CHAIN) li crea e li reinserisce il bouncer a ogni avvio:
    // salti scritti qui lo costringerebbero a fallire («Too many links») e lascerebbero INPUT senza protezione. L'app gli indica le catene (cs_sync) e lo riavvia dopo «Applica».
    // ---------- liste, GeoIP, blocco manuale. Le reti private/LAN sono SEMPRE escluse: firehol_level1 contiene i «bogons» e bloccherebbe la tua LAN
    $PRIV = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', '169.254.0.0/16', '100.64.0.0/10', '224.0.0.0/4']; $nlr = [];
    $NL = function (string $chain, string $flag) use (&$add, &$nlr, $lan, $PRIV) {   // catena "solo traffico non locale"
        if (isset($nlr[$chain])) return; $nlr[$chain] = 1; $ex = $PRIV; foreach ($lan as $n) if (!in_array($n, $ex, true)) $ex[] = $n;
        $add($chain . '-ret', "Esclusioni LAN e reti private ($chain)", 'filter', $chain, 'top', 0, array_map(fn($n) => "-A $chain $flag $n -j RETURN", $ex));
    };
    $alw = preg_split('/[\s,;]+/', trim((string)$S['manual_allow']), -1, PREG_SPLIT_NO_EMPTY);
    if ($alw) {   // lista bianca: valutata PRIMA di CrowdSec, liste e blocco manuale
        $add('allow-in', 'Lista bianca IP (INPUT)', 'filter', 'INPUT', 'top', 1, ['-A INPUT -m set --match-set iptm_allow src -j ACCEPT']);
        $add('allow-fw', 'Lista bianca IP (FORWARD)', 'filter', 'FORWARD', 'top', 1, ['-A FORWARD -m set --match-set iptm_allow src -j ACCEPT']);
    }
    $man = preg_split('/[\s,;]+/', trim($S['manual_block']), -1, PREG_SPLIT_NO_EMPTY);
    if ($man) {
        $add('manual-in', 'Blocco manuale IP (INPUT)', 'filter', 'INPUT', 'top', 3, ['-A INPUT -m set --match-set iptm_manual src -j DROP']);
        $add('manual-fw', 'Blocco manuale IP (FORWARD)', 'filter', 'FORWARD', 'top', 3, ['-A FORWARD -m set --match-set iptm_manual src -j DROP', '-A FORWARD -m set --match-set iptm_manual dst -j DROP']);
        $add('manual-out', 'Blocco manuale IP (OUTPUT)', 'filter', 'OUTPUT', 'top', 3, ['-A OUTPUT -m set --match-set iptm_manual dst -j DROP']);
    }
    $bin = []; $bout = [];
    $blg = fn($c, $set, $d) => !empty($S['bl_log']) ? ["-A $c -m set --match-set $set $d -m limit --limit 5/min --limit-burst 10 -j LOG --log-prefix \"IPTM-BL: \" --log-level 4"] : [];
    foreach (list_sets($S) as $set => $dir) { if ($dir !== 'out') { array_push($bin, ...$blg('IPTM-BL', $set, 'src')); $bin[] = "-A IPTM-BL -m set --match-set $set src -j DROP"; } if ($dir !== 'in') { array_push($bout, ...$blg('IPTM-BLD', $set, 'dst')); $bout[] = "-A IPTM-BLD -m set --match-set $set dst -j DROP"; } }
    if ($bin) { $NL('IPTM-BL', '-s'); $add('bl-sets', 'Liste IP: scarto delle sorgenti', 'filter', 'IPTM-BL', 'top', 10, $bin); $add('bl-jump-in', 'Liste IP (INPUT)', 'filter', 'INPUT', 'est', 2, ['-A INPUT -j IPTM-BL']); $add('bl-jump-fw', 'Liste IP (FORWARD)', 'filter', 'FORWARD', 'top', 2, ['-A FORWARD -j IPTM-BL']); }
    if ($bout) { $NL('IPTM-BLD', '-d'); $add('bl-sets-d', 'Liste IP: scarto delle destinazioni', 'filter', 'IPTM-BLD', 'top', 10, $bout); $add('bl-jump-fw-d', 'Liste IP (FORWARD, uscita)', 'filter', 'FORWARD', 'top', 9, ['-A FORWARD -j IPTM-BLD']); $add('bl-jump-out', 'Liste IP (OUTPUT)', 'filter', 'OUTPUT', 'top', 9, ['-A OUTPUT -j IPTM-BLD']); }
    if ($S['lockout_on'] && $lan && $S['mgmt_ports'] !== '') {
        $ports=array_values(array_filter(explode(',', $S['mgmt_ports'])));
        if (!empty($S['ssh_acc'])) {
            $ssh=(int)$S['ssh_acc_port'];
            $ports=array_values(array_filter($ports,fn($p)=>(int)$p!==$ssh));
            $warn[]='SSH '.$ssh.' escluso dall’anti-lockout: nuovi SYN soggetti a connlimit/recent; connessioni stabilite conservate.';
        }
        if($ports)$add('lockout', 'Anti-lockout: porte di gestione LAN escluse da SSH protetto', 'filter','INPUT','top',7,
            array_map(fn($n)=>'-A INPUT -s '.$n.' -p tcp '.port_opt(implode(',',$ports)).' -j ACCEPT',$lan));
    }
    if ($S['knock_on']) {
        $kp = array_values(array_filter(explode(',', $S['knock_ports']))); $kt = $S['knock_target']; $ks = $S['knock_nets'] !== '' ? '-s ' . $S['knock_nets'] . ' ' : '';
        if (count($kp) < 2 || $kt === '') $warn[] = 'Port knocking: servono almeno 2 porte e la porta da aprire.';
        else {
            $r = ["-A INPUT {$ks}-p tcp --dport $kt -m recent --rcheck --seconds {$S['knock_secs']} --name KNOCKOK -j ACCEPT"];
            foreach ($kp as $i => $pt) { $last = $i === count($kp) - 1; $chk = $i ? "-m recent --rcheck --seconds 15 --name KNOCK$i " : ''; $set = '-m recent --set --name ' . ($last ? 'KNOCKOK' : 'KNOCK' . ($i + 1));
                $r[] = "-A INPUT {$ks}-p tcp --dport $pt {$chk}{$set} -j DROP"; }
            $add('knock', 'Port knocking verso la porta ' . $kt, 'filter', 'INPUT', 'est', 12, $r);
        }
    }
    // Restore replies and loopback even if SPI is disabled: older imported
    // rules.v4 may still have INPUT/FORWARD DROP and otherwise lose browsing,
    // DNS replies or dashboard access after a regeneration. Filter top rules
    // for IoT, manual blocks and source blacklists still run first.
    if (empty($S['spi']) && !empty($S['continuity_priority'])) {
        $add('conn-return-in', 'Continuità: risposte e loopback', 'filter', 'INPUT', 'est', 8,
            ['-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT', '-A INPUT -i lo -j ACCEPT']);
        $add('conn-return-fw', 'Continuità: risposte connessioni LAN', 'filter', 'FORWARD', 'est', 18,
            ['-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT']);
    }
    if ($S['spi']) {
        $add('spi-in', 'SPI Firewall (INPUT)', 'filter', 'INPUT', 'top', 10, ['-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT', '-A INPUT -i lo -j ACCEPT']);
        $add('spi-fw', 'SPI Firewall (FORWARD)', 'filter', 'FORWARD', 'top', 10, ['-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT']);
    }
    // ---------- pacchetti non validi, ICMP, flood
    if ($S['invalid']) {
        $badflags = ['ALL NONE', 'ALL ALL', 'ALL FIN,URG,PSH', 'SYN,RST SYN,RST', 'SYN,FIN SYN,FIN', 'FIN,RST FIN,RST', 'FIN,SYN FIN,SYN', 'SYN,URG SYN,URG', 'FIN,ACK FIN'];
        $add('invalid-in', 'Scarta pacchetti non validi / scansioni', 'filter', 'INPUT', 'est', 10, array_merge([
            '-A INPUT -p tcp --tcp-flags FIN,ACK FIN,ACK -m conntrack --ctstate INVALID -j DROP',
            '-A INPUT -p tcp --tcp-flags RST,ACK RST,ACK -m conntrack --ctstate INVALID -j DROP',
            "-A INPUT -m conntrack --ctstate INVALID -j $DT",
            "-A INPUT -p tcp ! --syn -m conntrack --ctstate NEW -j $DT"],
            array_map(fn($x) => "-A INPUT -p tcp --tcp-flags $x -j $DT", $badflags)));
        $add('invalid-fw', 'Scarta pacchetti non validi (FORWARD)', 'filter', 'FORWARD', 'est', 10, [
            '-A FORWARD -p tcp --tcp-flags RST RST -m conntrack --ctstate INVALID -j DROP',
            '-A FORWARD -p tcp --tcp-flags FIN FIN -m conntrack --ctstate INVALID -j DROP',
            "-A FORWARD -m conntrack --ctstate INVALID -j $DT"]);
    }
    if ($S['icmp_limit']) $add('icmp', 'ICMP: ping con limite per sorgente', 'filter', 'INPUT', 'est', 15, [
        "-A INPUT -p icmp --icmp-type echo-request -m hashlimit --hashlimit-name icmp-echo --hashlimit-mode srcip --hashlimit-upto {$S['icmp_echo_rate']} --hashlimit-burst {$S['icmp_echo_burst']} -j ACCEPT", '-A INPUT -p icmp --icmp-type echo-request -j DROP',
        "-A INPUT -p icmp -m hashlimit --hashlimit-name icmp-other --hashlimit-mode srcip --hashlimit-upto {$S['icmp_other_rate']} --hashlimit-burst {$S['icmp_other_burst']} -j ACCEPT", '-A INPUT -p icmp -j DROP']);
    if ($S['igmp_accept']) $add('igmp', 'Accetta IGMP multicast (query del modem)', 'filter', 'INPUT', 'est', 16, ['-A INPUT -p igmp -m addrtype --dst-type MULTICAST -j ACCEPT']);
    // --- servizi opzionali LAN, Docker, multicast e CoAP ---
    if (!empty($S['cs_set_match']) && ($S['cs_set'] ?? '') === '') {
        // match-set classico crowdsec-blacklists (oltre al jump del bouncer)
        $add('cs-set-in', 'CrowdSec set diretto (INPUT)', 'filter', 'INPUT', 'est', 3, ['-A INPUT -m set --match-set crowdsec-blacklists src -j DROP']);
        $add('cs-set-fw', 'CrowdSec set diretto (FORWARD)', 'filter', 'FORWARD', 'top', 2, ['-A FORWARD -m set --match-set crowdsec-blacklists src -j DROP']);
        if (!empty($S['cs_docker'])) $add('cs-set-du', 'CrowdSec set su DOCKER-USER', 'filter', 'DOCKER-USER', 'top', 2, ['-A DOCKER-USER -m set --match-set crowdsec-blacklists src -j DROP', '-A DOCKER-USER -j RETURN']);
    }
    if (!empty($S['coap_accept']) && $lan) {
        $r = [];
        // Never expose discovery over WAN. Bind to the LAN source; if ingress
        // is known, the postprocess also pins these ACCEPTs to LAN ingress.
        foreach ($lan as $n) {
            $r[] = "-A INPUT -s $n -p udp --dport 5353 -d 224.0.0.251 -j ACCEPT";
            $r[] = "-A INPUT -s $n -p udp --dport 5683 -d 224.0.1.187 -j ACCEPT";
            $r[] = "-A INPUT -s $n -p udp --dport 5683 -d 255.255.255.255 -j ACCEPT";
        }
        $add('coap-mdns', 'mDNS e CoAP (Shelly / discovery) dalla LAN', 'filter', 'INPUT', 'est', 35, $r);
    }
    if (!empty($S['bcast_accept']) && $lan) {
        $r = [];
        foreach ($lan as $n) $r[] = "-A INPUT -s $n -p udp -d 255.255.255.255 -j ACCEPT";
        $add('bcast', 'Broadcast UDP dalla LAN', 'filter', 'INPUT', 'est', 36, $r);
    }
    if (!empty($S['docker_accept']) && trim((string)($S['docker_nets'] ?? '')) !== '') {
        $ri = []; $rf = [];
        foreach (preg_split('/[\s,;]+/', $S['docker_nets'], -1, PREG_SPLIT_NO_EMPTY) as $n) {
            $ri[] = "-A INPUT -s $n -j ACCEPT";
            $rf[] = "-A FORWARD -d $n -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT";
        }
        if ($ri) $add('docker-net', 'Rete Docker: accesso all\'host (INPUT)', 'filter', 'INPUT', 'est', 37, $ri);
        if ($rf) $add('docker-fwd', 'Rete Docker: risposte verso container (FORWARD)', 'filter', 'FORWARD', 'est', 38, $rf);
    }
    if (!empty($S['lan_tcp_accept']) && $lan) {
        $r = [];
        foreach ($lan as $n) $r[] = "-A INPUT -s $n -p tcp -j ACCEPT";
        $add('lan-tcp', 'Tutto il TCP dalla LAN verso l\'host (come FIX 1 rules.v4)', 'filter', 'INPUT', 'end', 55, $r);
    }
    if (!empty($S['lan_out_fwd']) && $lan) {
        $outs = array_values(array_unique(array_filter(array_map('trim', explode(',',
            (string)($S['masq_ifs'] !== '' ? $S['masq_ifs'] : ($S['wan_if'] ?? '')))))));
        if (!$outs) {
            $warn[] = 'Permesso LAN→Internet non generato: indica una interfaccia di uscita. Non usare ACCEPT senza -o.';
        } else {
            // RETURN means continue evaluating FORWARD: never ACCEPT to a
            // configured LAN just because ingress and egress share bond0.
            $add('lan-egress-local', 'Non autorizzare LAN→LAN per errore', 'filter',
                'IPTM-LAN-EGRESS', 'top', 1,
                array_map(fn($n) => "-A IPTM-LAN-EGRESS -d $n -j RETURN", $lan));
            $add('lan-egress-out', 'Uscita verso le interfacce autorizzate', 'filter',
                'IPTM-LAN-EGRESS', 'top', 10,
                array_map(fn($o) => "-A IPTM-LAN-EGRESS -o $o -j ACCEPT", $outs));
            $add('lan-out', 'LAN verso Internet', 'filter', 'FORWARD', 'est', 40,
                array_map(fn($n) => "-A FORWARD -s $n -j IPTM-LAN-EGRESS", $lan));
        }
    }

    if ($S['blockping'] && $needw('Blocco ping WAN')) $W('blockping', 'Blocca richieste anonime dal WAN (ping)', 'filter', 'INPUT', 'est', 20, ['-A INPUT {W} -p icmp --icmp-type echo-request -j DROP']);
    if ($S['ident'] && $needw('Filtro IDENT')) {
        $idact = !empty($S['stealth']) ? 'DROP' : 'REJECT --reject-with tcp-reset';
        $W('ident', 'Filtro IDENT (porta 113)', 'filter', 'INPUT', 'est', 30, ["-A INPUT {W} -p tcp --dport 113 -j $idact"]);
    }
    if ($S['multicast'] && $needw('Filtro multicast')) {
        $W('mcast-in', 'Filtra multicast dal WAN (INPUT)', 'filter', 'INPUT', 'est', 40, ['-A INPUT {W} -d 224.0.0.0/4 -j DROP', '-A INPUT {W} -p igmp -j DROP']);
        $W('mcast-fw', 'Filtra multicast dal WAN (FORWARD)', 'filter', 'FORWARD', 'est', 40, ['-A FORWARD {W} -d 224.0.0.0/4 -j DROP']);
    }
    foreach (['ssh' => ['SSH', 'ssh_limit', 'ssh_port']] as $k => [$lbl, $on, $pt]) if ($S[$on] && $needw("Limite $lbl")) {
        $b = '-A INPUT {W} -p tcp --dport ' . $S[$pt] . ' -m conntrack --ctstate NEW -m recent --name IPTM-' . strtoupper($k);
        $W('limit-' . $k, "Limita accesso $lbl dal WAN", 'filter', 'INPUT', 'est', $k === 'ssh' ? 50 : 51, ["$b --update --seconds {$S['lim_secs']} --hitcount {$S['lim_hits']} -j DROP", "$b --set"]);
    }
    if ($S['dos']) $add('dos', 'Anti DoS: SYN flood per sorgente', 'filter', 'INPUT', 'est', 60, ["-A INPUT -p tcp --syn -m hashlimit --hashlimit-name {$S['dos_name']} --hashlimit-mode srcip --hashlimit-above {$S['dos_syn']}/sec --hashlimit-burst {$S['dos_burst']} -j $DT"]);
    if (!empty($S['conn_limit'])) $add('connlimit', 'Limite di connessioni simultanee per IP (INPUT)', 'filter', 'INPUT', 'est', 61, ["-A INPUT -p tcp --syn -m connlimit --connlimit-above {$S['cl_max']} --connlimit-mask 32 -j $DT"]);
    foreach (fq_parse((string)($S['fqdn_rules'] ?? '')) as $id => $q) {   // regole per nome di dominio (alias FQDN risolti dall'helper ogni 1 ora)
        if ($q['act'] === 'block') $add('fqb-' . $id, "Blocca domini «{$id}»: " . implode(', ', array_slice($q['hosts'], 0, 4)), 'filter', 'FORWARD', 'est', 8, ["-A FORWARD -m set --match-set fq_$id dst -j DROP"]);
        else $add('fqa-' . $id, "Consenti domini «{$id}»: " . implode(', ', array_slice($q['hosts'], 0, 4)), 'filter', 'FORWARD', 'top', 4, ["-A FORWARD -m set --match-set fq_$id dst -j ACCEPT"]);
    }
    $macs2 = array_slice(array_values(array_filter(explode(',', (string)$S['mac_allow']))), 0, 40);
    if (!empty($S['mac_only']) && $macs2 && $S['lan_nets'] !== '') $add('mac-only', 'Solo i dispositivi autorizzati (MAC) dalla LAN', 'filter', 'FORWARD', 'top', 3, array_map(fn($n) => "-A FORWARD -s $n" . implode('', array_map(fn($m) => " -m mac ! --mac-source $m", $macs2)) . ' -j DROP', $lan));
    if (!empty($S['bw_on']) && $S['wan_if'] !== '' && empty($S['single_nic'])) {   // policer per host (scarta oltre la soglia; TCP si adatta)
        $add('bw-up', 'Limite di banda in uscita per host', 'filter', 'FORWARD', 'est', 17, array_map(fn($n) => $J('-A FORWARD', "-s $n -o {$S['wan_if']}", "-m hashlimit --hashlimit-above {$S['bw_up']}kb/s --hashlimit-mode srcip --hashlimit-name bwup -j DROP"), $lan ?: ['0.0.0.0/0']));
        $add('bw-down', 'Limite di banda in ingresso per host', 'filter', 'FORWARD', 'est', 18, array_map(fn($n) => $J('-A FORWARD', "-d $n -i {$S['wan_if']}", "-m hashlimit --hashlimit-above {$S['bw_down']}kb/s --hashlimit-mode dstip --hashlimit-name bwdown -j DROP"), $lan ?: ['0.0.0.0/0']));
    }
    $alg = []; if (!empty($S['alg_ftp'])) $alg[] = '-A PREROUTING -p tcp --dport 21 -j CT --helper ftp'; if (!empty($S['alg_tftp'])) $alg[] = '-A PREROUTING -p udp --dport 69 -j CT --helper tftp'; if (!empty($S['alg_sip'])) $alg[] = '-A PREROUTING -p udp --dport 5060 -j CT --helper sip';
    if ($alg) $add('raw-alg', 'raw: helper ALG (FTP/TFTP/SIP) per connessioni correlate', 'raw', 'PREROUTING', 'top', 40, $alg);
    if (!empty($S['wg_on']) && (int)$S['wg_port'] > 0) {   // VPN WireGuard: interfaccia selezionabile (wg0, wg1, ...)
        $wgIf = preg_match('/^[A-Za-z0-9_.-]{1,15}$/', (string)($S['wg_if'] ?? '')) ? $S['wg_if'] : 'wg0';
        if ($needw('VPN WireGuard')) $W('wg-in', 'VPN WireGuard: porta UDP dal WAN', 'filter', 'INPUT', 'est', 30, ["-A INPUT {W} -p udp --dport {$S['wg_port']} -j ACCEPT"]);
        if (!empty($S['wg_input'])) $add('wg-rin', 'VPN WireGuard (' . $wgIf . '): i client raggiungono il router', 'filter', 'INPUT', 'est', 31, ["-A INPUT -i $wgIf -j ACCEPT"]);
        if (!empty($S['wg_lan_to_vpn']) && $lan)
            $add('wg-lan-to-vpn','LAN → peer WireGuard (abilitazione esplicita)','filter','FORWARD','est',29,
                array_map(fn($net)=>'-A FORWARD -s '.$net.' -o '.$wgIf.' -j ACCEPT',$lan));
        if (!empty($S['wg_lan'])) $add('wg-fwd', 'VPN WireGuard (' . $wgIf . '): i client raggiungono LAN e Internet', 'filter', 'FORWARD', 'est', 27, ["-A FORWARD -i $wgIf -j ACCEPT", "-A FORWARD -o $wgIf -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"]);
    }
    // ---------- segmentazione (zone/VLAN come UniFi, Fortinet, pfSense)
    $iso = array_values(array_filter(explode(',', (string)$S['iso_nets'])));
    if (!empty($S['iso_on']) && count($iso) >= 2) { $r = []; foreach ($iso as $a) foreach ($iso as $b) if ($a !== $b) $r[] = "-A FORWARD -s $a -d $b -j $DT"; $add('isolate', 'Isolamento tra le reti indicate', 'filter', 'FORWARD', 'top', 6, $r); }
    $gn = array_values(array_filter(explode(',', (string)$S['guest_nets'])));
    if (!empty($S['guest_on']) && $gn) {
        $fr = []; $ir = [];
        foreach ($gn as $g) {
            $fr[] = "-A FORWARD -s $g -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT";
            foreach (array_filter(explode(',', (string)$S['guest_allow'])) as $x) $fr[] = "-A FORWARD -s $g -d $x -j ACCEPT";
            foreach (['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'] as $pv) $fr[] = "-A FORWARD -s $g -d $pv -j $DT";
            $ir[] = "-A INPUT -s $g -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT";
            if ($S['guest_ports'] !== '') foreach (['udp', 'tcp'] as $pr) $ir[] = "-A INPUT -s $g -p $pr " . port_opt($S['guest_ports']) . ' -j ACCEPT';
            $ir[] = "-A INPUT -s $g -j $DT";
        }
        $add('guest-fw', 'Rete ospiti: niente accesso alle reti private (FORWARD)', 'filter', 'FORWARD', 'top', 5, $fr);
        $add('guest-in', 'Rete ospiti: al router solo i servizi indicati (INPUT)', 'filter', 'INPUT', 'est', 5, $ir);
    }
    // Per-device MAC policies. Match only packets entering through the LAN and
    // crossing the gateway, never output packets generated by DietPi itself.
    // Without WAN/LAN separation, 'internet' is skipped: -o bond0 alone can
    // also match traffic for local clients and cut their connection.
    foreach ((array)($S['iot_policies'] ?? []) as $mac => $flags) {
        if (!is_string($mac) || !preg_match('/^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/D', $mac)
            || !is_array($flags)) continue;
        // Settings may contain untrusted imported nested flags: never let
        // array_intersect stringify an array or widen a security rule.
        $allowedFlags=array_keys(iptm_iot_policy_options());
        $on = array_values(array_unique(array_filter($flags,
            fn($flag)=>is_string($flag) && in_array($flag,$allowedFlags,true))));
        if (!$on) continue;
        // Preserve UI-managed MAC restrictions across VLANs and mixed LAN
        // interfaces. A single guessed -i would silently disable other IoT ACLs.
        $match = '-m mac --mac-source ' . $mac;
        $r = [];
        if (in_array('forward', $on, true)) $r[] = '-A FORWARD ' . $match . ' -j DROP';
        else {
            if (in_array('internet', $on, true)) {
                if ($single || empty($S['wan_if'])) $warn[] = 'IoT ' . $mac . ': blocco Internet ignorato: WAN non isolabile dalla LAN. Usa VLAN o due interfacce.';
                else $r[] = '-A FORWARD ' . $match . ' -o ' . $S['wan_if'] . ' -j DROP';
            }
            if (in_array('lan', $on, true) && !$lan)
                $warn[]='IoT '.$mac.': blocco LAN selezionato nella UI, ma manca una subnet LAN valida; la regola non può essere generata.';
            if (in_array('lan', $on, true)) foreach ($lan as $net)
                if (v_ok('nets', $net)) $r[] = '-A FORWARD ' . $match . ' -d ' . $net . ' -j DROP';
            if (in_array('dns', $on, true)) foreach (['tcp','udp'] as $proto)
                $r[] = '-A FORWARD ' . $match . ' -p ' . $proto . ' --dport 53 -j DROP';
            if (in_array('dot', $on, true)) foreach (['tcp','udp'] as $proto)
                $r[] = '-A FORWARD ' . $match . ' -p ' . $proto . ' --dport 853 -j DROP';
            if (in_array('quic', $on, true)) $r[] = '-A FORWARD ' . $match . ' -p udp --dport 443 -j DROP';
            if (in_array('vpn', $on, true)) {
                $r[] = '-A FORWARD ' . $match . ' -p udp -m multiport --dports 500,4500,1194,51820 -j DROP';
                $r[] = '-A FORWARD ' . $match . ' -p tcp --dport 1723 -j DROP';
            }
        }
        if ($r) $add('iot-' . str_replace(':','',$mac), 'IoT ' . $mac . ': filtri selezionati', 'filter', 'FORWARD', 'top', 1, $r);
    }
    $macs = array_values(array_filter(explode(',', (string)$S['mac_block'])));
    if ($macs) foreach (['INPUT', 'FORWARD'] as $c) $add('mac-' . strtolower($c), "Quarantena dispositivi per MAC ($c)", 'filter', $c, 'top', 2, array_map(fn($m) => "-A $c -m mac --mac-source $m -j DROP", $macs));
    if (!empty($S['quic_block'])) {
        if (!$lan) $warn[] = 'Blocco QUIC non generato: configura prima le subnet LAN.';
        else $add('quic', 'Blocca QUIC dalla LAN', 'filter', 'FORWARD', 'est', 26,
            array_map(fn($n) => $J('-A FORWARD', "-s $n", '-p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable'), $lan));
    }
    if (!empty($S['lan_cl'])) $add('lancl', 'Limite connessioni simultanee per client', 'filter', 'FORWARD', 'est', 16, array_map(fn($n) => $J('-A FORWARD', "-s $n", "-p tcp --syn -m connlimit --connlimit-above {$S['lan_cl_max']} --connlimit-mask 32 -j $DT"), $lan ?: ['0.0.0.0/0']));
    if (!empty($S['svc_ban']) && $S['sb_ports'] !== '' && $needw('Ban automatico servizi')) foreach (['INPUT' => 'in', 'FORWARD' => 'fwd'] as $c => $k) {   // come l'«overload table» di pfSense
        $det = "-A $c {W} -p tcp " . port_opt($S['sb_ports']) . ' -m conntrack --ctstate NEW -m recent --name IPTM-SVC' . $k;
        $W('svcban-chk-' . $k, "Ban automatico: sorgenti già bannate ($c)", 'filter', $c, 'est', 19, ["-A $c {W} -m recent --name IPTM-BAN --rcheck --seconds {$S['sb_ban']} -j DROP"]);
        $W('svcban-' . $k, "Ban automatico: troppi tentativi sui servizi indicati ($c)", 'filter', $c, 'est', 52, ["$det --update --seconds {$S['sb_secs']} --hitcount {$S['sb_hits']} -m recent --name IPTM-BAN --set -j DROP", "$det --set"]);
    }
    if (!empty($S['bad_mss'])) foreach (['INPUT', 'FORWARD'] as $c) $add('badmss-' . strtolower($c), "Scarta SYN con MSS anomalo ($c)", 'filter', $c, 'est', 11, ["-A $c -p tcp --syn -m tcpmss --mss 0:535 -j $DT"]);
    if (!empty($S['udp_rl'])) $add('udprl', 'Limite nuovi flussi UDP per sorgente (INPUT)', 'filter', 'INPUT', 'est', 62, ["-A INPUT -p udp -m conntrack --ctstate NEW -m hashlimit --hashlimit-name udpflood --hashlimit-mode srcip --hashlimit-above {$S['ul_rate']}/sec --hashlimit-burst {$S['ul_burst']} -j $DT"]);
    if (!empty($S['web_rl']) && $S['wl_ports'] !== '' && $needw('Limite connessioni web dal WAN')) foreach (['INPUT' => 'in', 'FORWARD' => 'fwd'] as $c => $k)
        $W('webrl-' . $k, "Limite nuove connessioni web dal WAN ($c)", 'filter', $c, 'est', 63, ["-A $c {W} -p tcp " . port_opt($S['wl_ports']) . " -m conntrack --ctstate NEW -m hashlimit --hashlimit-name webrl$k --hashlimit-mode srcip --hashlimit-above {$S['wl_rate']}/sec --hashlimit-burst {$S['wl_burst']} -j $DT"]);
    if (!empty($S['amp_block']) && $needw('Blocco amplificazione UDP')) $W('amp', 'Scarta risposte UDP non richieste da servizi di amplificazione (WAN)', 'filter', 'INPUT', 'est', 35, ['-A INPUT {W} -p udp -m multiport --sports 19,53,111,123,137,161,389,1900,5353,11211 -m conntrack --ctstate NEW -j DROP']);
    if (!empty($S['rpfilter'])) $add('raw-rpf', 'raw: reverse path filter (sorgenti incoerenti con il routing)', 'raw', 'PREROUTING', 'top', 30, ['-A PREROUTING -p udp --sport 68 --dport 67 -j ACCEPT', '-A PREROUTING -m rpfilter --invert -j DROP']);
    if ($S['dot_block']) {
        if (!$lan) $warn[] = 'Blocco DoT non generato: configura prima le subnet LAN.';
        else {
            $r = [];
            foreach ($lan as $n) {
                $r[] = "-A FORWARD -s $n -p tcp --dport 853 -j REJECT --reject-with tcp-reset";
                $r[] = "-A FORWARD -s $n -p udp --dport 853 -j REJECT --reject-with icmp-port-unreachable";
            }
            $add('dot', 'Blocca DoT dalla LAN', 'filter', 'FORWARD', 'top', 0, $r);
        }
    }
    // ---------- protezioni aggiuntive (da pfSense/OPNsense, CIS, iptables-essentials)
    if ($S['drop_frag']) foreach (['INPUT', 'FORWARD'] as $c) $add('frag-' . strtolower($c), "Scarta frammenti IP ($c)", 'filter', $c, 'est', 9, ["-A $c -f -j DROP"]);
    if ($S['bogon_wan']) {
        if (!iptm_public_wan_verified($S)) $warn[] = 'Filtro bogon WAN sospeso: serve una WAN pubblica dedicata e verificata; escluso su LAN condivisa o doppio NAT.';
        else foreach (['INPUT', 'FORWARD'] as $c) $add('bogon-' . strtolower($c), "Scarta sorgenti private/bogon dal WAN ($c)", 'filter', $c, 'top', 4, array_merge(["-A $c -i {$S['wan_if']} -p udp --sport 67:68 --dport 67:68 -j ACCEPT"], array_map(fn($n) => "-A $c -i {$S['wan_if']} -s $n -j DROP", ['0.0.0.0/8', '10.0.0.0/8', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16', '224.0.0.0/3'])));
    }
    if ($S['portscan']) {
        $ps_hits = max(5, min(50, (int)($S['ps_hits'] ?? 14)));
        $ps_secs = max(10, min(600, (int)($S['ps_secs'] ?? 60)));
        $ps_ban  = max(60, min(86400, (int)($S['ps_ban'] ?? 3600)));
        $NL('IPTM-PS', '-s'); $NL('IPTM-PSD', '-s');
        $add('ps-chk', 'Port scan: sorgenti già segnalate (ban ' . $ps_ban . 's)', 'filter', 'IPTM-PS', 'top', 10, ["-A IPTM-PS -m recent --name IPTM-PSCAN --rcheck --seconds $ps_ban -j DROP"]);
        $add('ps-chk-jump', 'Port scan (controllo)', 'filter', 'INPUT', 'est', 4, ['-A INPUT -j IPTM-PS']);
        $add('ps-det', 'Port scan: rilevamento su porte chiuse (≥' . $ps_hits . ' in ' . $ps_secs . 's)', 'filter', 'IPTM-PSD', 'top', 10, [
            "-A IPTM-PSD -p tcp --syn -m recent --name IPTM-PSHIT --rcheck --seconds $ps_secs --hitcount $ps_hits -m recent --name IPTM-PSCAN --set -j $DT",
            '-A IPTM-PSD -p tcp --syn -m recent --name IPTM-PSHIT --set']);
        $add('ps-det-jump', 'Port scan (rilevamento)', 'filter', 'INPUT', 'end', 85, ['-A INPUT -j IPTM-PSD']);
    }
    // Stealth: prefer pure DROP (no ICMP unreachable / TCP reset) – inspired by stealth options in commercial firewalls
    if (!empty($S['stealth'])) {
        // Override common REJECT with DROP where we previously used REJECT for visibility reduction
        // (ident is kept as REJECT because some clients hang without a response; blockping already DROP)
    }
    // SYNPROXY – modern SYN flood protection (kernel ≥ 3.12, requires nf_synproxy_core)
    // Inspired by FortiGate DoS profiles and Linux SYNPROXY best practices.
    // Empty sp_ports = all NEW SYN; otherwise only the listed ports (web/SSH typically).
    if (!empty($S['synproxy'])) {
        $sp = [];
        $ports = trim((string)($S['sp_ports'] ?? ''));
        if ($ports !== '') {
            $sp[] = '-A INPUT -p tcp ' . port_opt($ports) . ' -m conntrack --ctstate INVALID,UNTRACKED -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460';
        } else {
            $sp[] = '-A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -m conntrack --ctstate INVALID,UNTRACKED -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460';
        }
        $sp[] = '-A INPUT -m conntrack --ctstate INVALID -j DROP';
        $add('synproxy', 'SYNPROXY (anti SYN flood avanzato' . ($ports !== '' ? ', porte ' . $ports : '') . ')', 'filter', 'INPUT', 'est', 11, $sp);
    }
    // TARPIT on closed privileged ports (slows scanners dramatically) – inspired by advanced iptables setups
    if (!empty($S['tarpit']) && !empty($S['closeports']) && $S['close_range'] !== '') {
        $add('tarpit', 'TARPIT su porte privilegiate chiuse', 'filter', 'INPUT', 'end', 81, [
            "-A INPUT -p tcp " . port_opt($S['close_range']) . " -j TARPIT"]);
    }
    // Rebinding is about addresses *inside DNS answers*, not the IP destination
    // of the packet. A legacy FORWARD --sport 53 -d RFC1918 DROP rule broke
    // legitimate DNS replies to LAN clients. Never synthesize that rule.
    if (!empty($S['dns_rebind'])) {
        $warn[] = 'DNS rebinding: proteggi le risposte nel resolver Pi-hole/Unbound/DNSCrypt, NON con una regola FORWARD basata sull’IP di destinazione.';
    }
    // Scarta INVALID il prima possibile (raw PREROUTING) – riduce carico conntrack
    if (!empty($S['raw_invalid'])) {
        $add('raw-inv', 'Scarta INVALID in raw (prima del tracking)', 'raw', 'PREROUTING', 'top', 5, [
            '-A PREROUTING -m conntrack --ctstate INVALID -j DROP']);
    }
    // Limite globale di nuove connessioni verso il router (protezione da flood distribuiti)
    if (!empty($S['glob_new_limit'])) {
        $gr = max(1, (int)($S['gn_rate'] ?? 100)); $gb = max(1, (int)($S['gn_burst'] ?? 200));
        $add('glob-new', 'Limite globale nuove connessioni (INPUT)', 'filter', 'INPUT', 'est', 13, [
            "-A INPUT -p tcp --syn -m conntrack --ctstate NEW -m hashlimit --hashlimit-name globnew --hashlimit-mode dstip --hashlimit-above {$gr}/sec --hashlimit-burst $gb -j $DT"]);
    }
    if ($S['lan_flood']) $add('lanflood', 'Limite di nuove connessioni per client', 'filter', 'FORWARD', 'est', 15, ["-A FORWARD -p tcp --syn -m hashlimit --hashlimit-name lanflood --hashlimit-mode srcip --hashlimit-above {$S['lf_rate']}/sec --hashlimit-burst {$S['lf_burst']} -j $DT"]);
    if ($S['egress_smtp'] || $S['egress_ports'] !== '') {
        $r = []; if ($S['egress_smtp']) { if ($S['egress_allow'] !== '') $r[] = "-A FORWARD -s {$S['egress_allow']} -p tcp --dport 25 -j ACCEPT"; $r[] = "-A FORWARD -p tcp --dport 25 -j $DT"; }
        if ($S['egress_ports'] !== '') foreach (['tcp', 'udp'] as $p) $r[] = "-A FORWARD -p $p " . port_opt($S['egress_ports']) . " -j $DT";
        $add('egress', 'Filtro in uscita (SMTP e porte indicate)', 'filter', 'FORWARD', 'est', 25, $r);
    }
    // ---------- servizi del router, SSH per reti, chiusura
    $safeInput=iptm_safe_router_input_rows((array)$S['svc_in'],$S,$warn);
    $sin = fn($after) => svc_rules('INPUT', array_values(array_filter($safeInput, fn($r) => !empty($r['on']) && (!empty($r['after'])) === $after)), $AL);
    if ($x = $sin(false)) $add('svc-in-a', 'Servizi del router (INPUT)', 'filter', 'INPUT', 'end', 40, $x);
    $sshInMgmt=in_array((string)$S['ssh_acc_port'],
        array_map('trim',explode(',',(string)($S['mgmt_ports']??''))),true);
    if ($S['ssh_acc'] && ($S['ssh_nets'] !== '' || ($S['lockout_on'] && $sshInMgmt && $lan))) {
        // Never count normal SSH data/ACK packets as new login attempts.
        // An existing management session must survive even with SPI disabled.
        $r = ["-A INPUT -p tcp --dport {$S['ssh_acc_port']} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"];
        $sshTrusted=array_values(array_filter(explode(',', $S['ssh_nets'])));
        // Existing anti-lockout permitted all configured LANs to manage SSH.
        // Keep those admins reachable, but force their NEW SYN through the
        // same recent/connlimit checks instead of an unrestricted ACCEPT.
        if (!empty($S['lockout_on']) && $sshInMgmt)
            $sshTrusted=array_values(array_unique(array_merge($sshTrusted,$lan)));
        foreach ($sshTrusted as $n) {
            if (!v_ok('nets',$n) || $n==='') continue;
            $b = "-A INPUT -s $n -p tcp --dport {$S['ssh_acc_port']} -m conntrack --ctstate NEW --syn";
            $r[] = "$b -m connlimit --connlimit-above {$S['ssh_conn']} --connlimit-mask 32 -j $DT";
            $r[] = "$b -m recent --name {$S['ssh_name']} --update --seconds {$S['ssh_secs']} --hitcount {$S['ssh_hits']} -j $DT";
            $r[] = "$b -m recent --name {$S['ssh_name']} --set -j ACCEPT";
        }
        // Trusted management LANs bypass connection-attempt penalties when
        // continuity is prioritized; non-trusted sources never gain new access.
        $priority = 6; // top priority, before other generated accepts; SSH is not in lockout
        $add('ssh-acc', 'SSH: controllo solo nuove connessioni', 'filter', 'INPUT', 'top', $priority, $r);
    } elseif ($S['ssh_acc']) {
        $warn[]='SSH protetto richiesto ma nessuna subnet attendibile valida: configura le reti SSH o abilita anti-lockout con LAN verificata; nessun ACCEPT SSH inventato.';
    }
    if ($x = $sin(true)) $add('svc-in-b', 'Servizi del router (INPUT, dopo SSH)', 'filter', 'INPUT', 'end', 60, $x);
    if (function_exists('apps_rules') && ($ar = apps_rules($S))) $add('apps', 'Porte software (programmi abilitati)', 'filter', 'INPUT', 'end', 65, $ar);
    if ($S['closeports'] && $S['close_range'] !== '') $add('close-input', 'Scarta le porte privilegiate non autorizzate', 'filter', 'INPUT', 'end', 80, ["-A INPUT -p tcp " . port_opt($S['close_range']) . " -j $DT", "-A INPUT -p udp " . port_opt($S['close_range']) . " -j $DT"]);
    if ($S['final_drop']) foreach (['INPUT', 'FORWARD'] as $c) $add('final-' . strtolower($c), "Scarta tutto il resto ($c)", 'filter', $c, 'end', 99, ["-A $c -j $DT"]);
    if ($x = svc_rules('FORWARD', array_values(array_filter(iptm_safe_forward_rows((array)$S['svc_fwd'],$S,$warn), fn($r) => !empty($r['on']))), $AL)) $add('svc-fwd', 'Regole di transito (FORWARD)', 'filter', 'FORWARD', 'end', 40, $x);
    // ---------- log
    $lr = $S['log_rate'];
    if ($S['log_in'] && $needw('Log ingresso')) $W('log-in', 'Log nuove connessioni in ingresso dal WAN', 'filter', 'INPUT', 'est', 90, ["-A INPUT {W} -m conntrack --ctstate NEW -m limit --limit $lr -j LOG --log-prefix \"IPTM-IN: \" --log-level 4"]);
    if ($S['log_out'] && $needw('Log uscita')) $W('log-out', 'Log nuove connessioni verso il WAN', 'filter', 'FORWARD', 'est', 90, ["-A FORWARD {W} -m conntrack --ctstate NEW -m limit --limit $lr -j LOG --log-prefix \"IPTM-OUT: \" --log-level 4"], 'o');
    if ($S['log_drop']) foreach (['INPUT', 'FORWARD'] as $c) $add('log-drop-' . strtolower($c), "Log pacchetti scartati ($c)", 'filter', $c, 'end', 90, ["-A $c -m limit --limit $lr -j LOG --log-prefix \"IPTM-DROP: \" --log-level 4"]);
    // ---------- NAT / mangle
    if ($S['nat_masq']) {
        // A shared physical interface must NEVER produce an unscoped -o WAN
        // MASQUERADE: doing so hides modem-side, Docker and WireGuard traffic.
        // Honor explicit output interfaces only inside the source-scoped chain.
        if ($single && $lan) {
            // La limitazione del NAT alle sorgenti LAN è il funzionamento
            // corretto, non un avviso. La pagina Setup la descrive come stato.
            $singleOuts = array_values(array_unique(array_filter(array_map('trim', explode(',',
                $S['masq_ifs'] !== '' ? $S['masq_ifs'] : $S['wan_if'])))));
            if (!$singleOuts) {
                $warn[] = 'NAT Single-NIC non generato: scegli l’interfaccia WAN o le interfacce di uscita in Rete → WAN, LAN e NAT.';
            } else {
                $add('nat-masq-ret', 'NAT: esclusione LAN→LAN', 'nat', 'IPTM-MASQ', 'top', 0,
                    array_map(fn($n) => "-A IPTM-MASQ -d $n -j RETURN", $lan));
                $add('nat-masq-do', 'NAT / Masquerade in uscita', 'nat', 'IPTM-MASQ', 'top', 10,
                    array_map(fn($iface) => '-A IPTM-MASQ -o ' . $iface . ' -j MASQUERADE', $singleOuts));
                // Una regola di ingresso per ogni LAN, mai una sorgente globale.
                $add('nat-masq', 'NAT: salto dalla LAN', 'nat', 'POSTROUTING', 'end', 10,
                    array_map(fn($n) => '-A POSTROUTING -s ' . $n . ' -j IPTM-MASQ', $lan));
            }
        } elseif ($S['masq_ifs'] !== '') {
            $outIfs = array_values(array_unique(array_filter(array_map('trim', explode(',', $S['masq_ifs'])))));
            $scoped = [];
            foreach ($lan as $net) foreach ($outIfs as $iface)
                $scoped[] = $J('-A POSTROUTING', '-s ' . $net, '-o ' . $iface, '-j MASQUERADE');
            if ($scoped) $add('nat-masq', 'NAT / Masquerade per subnet LAN', 'nat', 'POSTROUTING', 'end', 10, $scoped);
            else $warn[] = 'NAT non generato: inserisci almeno una subnet LAN (es. 192.168.10.0/24). Non verrà creato un masquerade globale.';
        } elseif (!$single && $S['wan_if'] !== '' && $lan) {
            // Stesso criterio prudenziale di IPTM 6.11.3: NAT solo per CIDR
            // espliciti. Mai usare la fallback 0.0.0.0/0 quando manca la LAN.
            $add('nat-masq', 'NAT / Masquerade per subnet LAN', 'nat', 'POSTROUTING', 'end', 10,
                 array_map(fn($n) => $J('-A POSTROUTING', '-o ' . $S['wan_if'], '-s ' . $n, '-j MASQUERADE'), $lan));
        } else $warn[] = 'NAT non generato: configura almeno una rete LAN e l’interfaccia di uscita in Rete → WAN, LAN e NAT.';
    }
    if ($S['mss']) $add('mss', 'Clamp MSS al PMTU', 'mangle', 'FORWARD', 'end', 10, ['-A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu']);
    // Priorità traffico (DSCP → tin CAKE, stile cFosSpeed)
    if (!empty($S['sqm']['on']) && empty($S['qos_engine']['interface']) && function_exists('sqm_prio_rules')) {
        $prules = sqm_prio_rules($S);
        $byc = [];
        foreach ($prules as $r) {
            if (preg_match('/^-A (OUTPUT|FORWARD) /', $r, $m)) $byc[$m[1]][] = $r;
        }
        foreach ($byc as $chain => $rs) {
            $add('sqm-prio-' . strtolower($chain), 'QoS prioritizzazione DSCP (CAKE/cFos-like) su ' . $chain, 'mangle', $chain, 'end', 20, $rs);
        }
    }
    if ($S['dns_redirect']) {
        if ($S['dns_ip'] === '' || !$lan) $warn[] = 'Redirect DNS: servono IP del DNS locale e reti LAN.';
        else { $r = []; foreach ($lan as $n) foreach (['udp', 'tcp'] as $p) $r[] = $J('-A PREROUTING', '-s ' . $n, '! -d ' . $S['dns_ip'], "-p $p --dport 53", '-j DNAT --to-destination ' . $S['dns_ip'] . ':53'); $add('dns-redir', 'Forza i client LAN a usare il DNS locale', 'nat', 'PREROUTING', 'top', 10, $r); }
    }
    // ---------- port forwarding / DMZ
    $fn = $fa = $lb = $lm = [];
    foreach ($S['fwd'] as $r) {
        if (empty($r['on'])) continue;
        $isr = str_contains($r['eport'], ':'); $dp = $r['tport'] !== '' ? $r['tport'] : $r['eport'];
        $to = $r['ip'] . ($r['tport'] !== '' ? ':' . $r['tport'] : ($isr ? '' : ':' . $r['eport']));
        $fn[] = '# ' . ($r['name'] ?: 'forward'); $fa[] = '# ' . ($r['name'] ?: 'forward');
        foreach ($r['proto'] === 'both' ? ['tcp', 'udp'] : [$r['proto']] as $p) {
            $s = $r['src'] !== '' ? '-s ' . $r['src'] : '';
            $fn[] = $J('-A PREROUTING {W}', $s, '-m addrtype --dst-type LOCAL', "-p $p --dport " . $r['eport'], '-j DNAT --to-destination ' . $to);
            $fa[] = $J('-A FORWARD', '-d ' . $r['ip'], $s, "-p $p --dport $dp", '-j ACCEPT');
            if ($S['loopback'] && $lan) {
                foreach ($lan as $n) $lb[] = $J('-A PREROUTING', '-s ' . $n, '-m addrtype --dst-type LOCAL', "-p $p --dport " . $r['eport'], '-j DNAT --to-destination ' . $to);
                foreach ($lan as $n) $lm[] = $J('-A POSTROUTING', '-s ' . $n, '-d ' . $r['ip'], "-p $p --dport $dp", '-j MASQUERADE');
            }
        }
    }
    if ($fn) { if (!$ready) $warn[] = 'Port forward: WAN non definita, le regole valgono per qualsiasi pacchetto destinato a questo host.'; $W('fwd-nat', 'Port forwarding (DNAT)', 'nat', 'PREROUTING', 'top', 20, $fn); $add('fwd-acc', 'Port forwarding (permessi FORWARD)', 'filter', 'FORWARD', 'est', 20, $fa); }
    if ($lb) { $add('fwd-loop', 'NAT loopback (accesso dalla LAN)', 'nat', 'PREROUTING', 'top', 21, $lb); $add('fwd-loop-m', 'NAT loopback (masquerade)', 'nat', 'POSTROUTING', 'end', 20, $lm); }
    if ($S['dmz_on'] && $S['dmz_ip'] !== '') {
        $ex = $S['dmz_excl']; $r = [];
        foreach (['tcp', 'udp'] as $p) $r[] = $J('-A PREROUTING {W}', '-m addrtype --dst-type LOCAL', "-p $p", $ex !== '' ? '-m multiport ! --dports ' . $ex : '', '-j DNAT --to-destination ' . $S['dmz_ip']);
        $W('dmz', 'DMZ host ' . $S['dmz_ip'], 'nat', 'PREROUTING', 'top', 90, $r);
        $add('dmz-acc', 'DMZ (permesso FORWARD)', 'filter', 'FORWARD', 'est', 90, ['-A FORWARD -d ' . $S['dmz_ip'] . ' -m conntrack --ctstate DNAT -j ACCEPT']);
    }
    // ---------- restrizioni di accesso (prima di SPI/established: valgono anche per connessioni già aperte)
    foreach ($S['acl'] as $i => $p) {
        if (empty($p['on'])) continue;
        [$cl, ] = acl_clients((string)$p['clients']); if (!$cl) { if ($S['lan_nets'] === '') { $warn[] = 'Criterio «' . $p['name'] . '»: nessun client e nessuna LAN definita.'; continue; } $cl = array_map(fn($n) => '-s ' . $n, $lan); }
        $tg = acl_targets($p); if (!$tg) { $warn[] = 'Criterio «' . $p['name'] . '»: scegli almeno un servizio o parola chiave.'; continue; }
        $r = ['# Criterio: ' . ($p['name'] ?: 'senza nome')];
        foreach ($cl as $c) foreach (acl_time($p) as $t) foreach ($tg as $f) $r[] = $J('-A FORWARD', $c, $t, $f, '-j DROP');
        $add('acl-' . ($i + 1), 'Restrizione: ' . ($p['name'] ?: 'criterio ' . ($i + 1)), 'filter', 'FORWARD', 'top', 7, $r);
    }
    // ---------- catene WAN (solo interfaccia unica)
    $cn = ['filter|INPUT|i' => 'IPTM-WAN-IN', 'filter|FORWARD|i' => 'IPTM-WAN-FWI', 'filter|FORWARD|o' => 'IPTM-WAN-FWO', 'nat|PREROUTING|i' => 'IPTM-WAN-PRE'];
    foreach ($wanc as $k => $list) {
        [$t, $c, $d] = explode('|', $k); $ch = $cn[$k] ?? null; if (!$ch || !$lan) continue;
        $add("wan-$ch-ret", "Esclusione LAN ($ch)", $t, $ch, 'top', 0, array_map(fn($n) => "-A $ch -" . ($d === 'i' ? 's' : 'd') . " $n -j RETURN", $lan));
        $min = 999; $an = $list[0]['an'];
        foreach ($list as $x) { $min = min($min, $x['pr']); $add($x['id'], $x['title'], $t, $ch, 'top', $x['pr'], array_map(fn($b) => preg_replace(['/^-A \S+ /', '/ \{W\}/', '/\{W\} ?/', '/ {2,}/'], ['-A ' . $ch . ' ', '', '', ' '], $b), $x['bodies'])); }
        $add("wan-$ch-jump", "Salto a $ch (solo traffico WAN)", $t, $c, $an, $min, ["-A $c -j $ch"]);
    }
    foreach (($S['custom_opts'] ?? []) as $co) {   // opzioni create dall'utente (analisi regole manuali o inserimento diretto)
        if (empty($co['on'])) continue; $by = [];
        foreach (($co['rules'] ?? []) as $cr) {
            if (!isset(BUILTIN[$cr['t'] ?? '']) || !lint_rule((string)($cr['r'] ?? ''))) { $warn[] = 'Opzione «' . ($co['name'] ?? '?') . '»: regola non valida saltata.'; continue; }
            $by[$cr['t'] . '|' . rchain($cr['r'])][] = $cr['r'];
        }
        foreach ($by as $k => $rs) {
            [$t, $c] = explode('|', $k, 2); $an = (in_array($co['an'] ?? 'end', ['top', 'est', 'end'], true) || preg_match('/^rk:[0-9a-f]{12}$/', (string)($co['an'] ?? ''))) ? $co['an'] : 'end';
            $add('cust-' . preg_replace('/[^A-Za-z0-9_.-]/', '', (string)($co['id'] ?? 'x')) . '-' . $t . '-' . preg_replace('/[^A-Za-z0-9_.-]/', '', $c), 'Opzione «' . copt_clean_name((string)($co['name'] ?? '')) . '»', $t, $c, $an, (int)($co['pr'] ?? 50), $rs);
        }
    }
    // The raw table runs before filter: a blanket raw DROP must not shadow
    // an explicitly allowed local service port (Samba, MiniDLNA, etc.).
    // Scope this repair to IPTM-owned generated raw-drop only.
    $allowedPorts = ['tcp' => [], 'udp' => []];
    foreach ($sec as $section) {
        if (($section['t'] ?? '') !== 'filter' || ($section['c'] ?? '') !== 'INPUT') continue;
        foreach ($section['rules'] as $row) {
            if (!str_contains($row, '-j ACCEPT') ||
                !(preg_match('/(?:^|\s)-s\s+\S+/', $row) || preg_match('/(?:^|\s)-i\s+\S+/', $row))) continue;
            if (!preg_match('/(?:^|\s)-p\s+(tcp|udp)(?:\s|$)/', $row, $pp)) continue;
            if (!preg_match('/--dports?\s+([0-9,:]+)/', $row, $pm)) continue;
            foreach (explode(',', $pm[1]) as $port) if (ctype_digit($port))
                $allowedPorts[$pp[1]][$port] = true;
        }
    }
    foreach ($sec as &$section) {
        if (($section['id'] ?? '') !== 'raw-drop') continue;
        $filtered = [];
        foreach ($section['rules'] as $row) {
            if (!preg_match('/(?:^|\s)-p\s+(tcp|udp)(?:\s|$)/', $row, $pp)
                || !preg_match('/--dports?\s+([0-9,:]+)/', $row, $pm)) { $filtered[] = $row; continue; }
            $parts = explode(',', $pm[1]);
            $rest = array_values(array_filter($parts, fn($port) => !isset($allowedPorts[$pp[1]][$port])));
            if (count($rest) !== count($parts)) {
                $warn[] = 'raw-drop: porte ' . $pp[1] . ' abilitate in INPUT escluse dal blocco preliminare.';
                if (!$rest) continue;
                $row = str_replace($pm[1], implode(',', $rest), $row);
            }
            $filtered[] = $row;
        }
        $section['rules'] = $filtered;
    }
    unset($section);
    // Scope only generated INPUT accepts, never hand-written or CrowdSec rules.
    foreach($sec as &$section){
        if(($section['t']??'')!=='filter' || ($section['c']??'')!=='INPUT' ||
           !in_array($section['id'],['lockout','ssh-acc','svc-in-a','svc-in-b','apps','coap-mdns','bcast','guest-in'],true))continue;
        $section['rules']=array_map(function($r)use($S,$section){
            if (($section['id']??'')==='ssh-acc' &&
                preg_match('/^-A INPUT\s+/', $r) &&
                preg_match('/(?:^|\s)-s\s+\d{1,3}(?:\.\d{1,3}){3}(?:\/\d{1,2})?(?:\s|$)/',$r) &&
                !preg_match('/(?:^|\s)(?:!\s+)?-i\s+/', $r)) {
                if(preg_match('/(?:^|\s)-s\s+(\S+)/',$r,$match)) {
                    $ingress=iptm_ingress_for_source($match[1],$S);
                    if($ingress!=='')return preg_replace('/^-A INPUT\s+/', '-A INPUT '.$ingress.' ', $r, 1);
                }
            }
            return iptm_scope_input_accept($r,$S);
        },$section['rules']);
    }
    unset($section);
    // Scope generated LAN FORWARD permissions and NAT ingress. POSTROUTING
    // cannot match -i and is deliberately not modified. Never change IoT
    // DROP policies or hand-written rules.
    foreach ($sec as &$section) {
        $id=(string)($section['id']??'');$table=$section['t']??'';$chain=$section['c']??'';
        if ($table==='filter' && $chain==='FORWARD' &&
            in_array($id,['svc-fwd','wg-lan-to-vpn','guest-fwd','lan-out'],true)) {
            $section['rules']=array_map(static function($row) use ($S,$id) {
                if ($id==='lan-out' && preg_match('/(?:^|\s)-j IPTM-LAN-EGRESS(?:\s|$)/',$row))
                    return iptm_scope_managed_rule($row,$S,'FORWARD',false);
                return iptm_scope_managed_rule($row,$S,'FORWARD');
            },$section['rules']);
        }
        if ($table==='nat' && $chain==='PREROUTING' &&
            in_array($id,['dns-redir','fwd-loop'],true)) {
            $section['rules']=array_map(static fn($row)=>iptm_scope_managed_rule($row,$S,'PREROUTING',false),$section['rules']);
        }
    }
    unset($section);
    $unknownIngress=[];
    foreach ($lan as $net) if(iptm_ingress_for_source($net,$S)==='') $unknownIngress[]=$net;
    if($unknownIngress)
        $warn[]='Ingressi LAN non verificati per '.implode(', ',$unknownIngress).': alcuni permessi restano limitati alla sola sorgente IP. Assegna l’interfaccia corretta in Setup, evita regole ampie su WAN non fidate.';
    if(iptm_lan_ingress($S)==='' && $lan &&
       (!empty($S['single_nic']) ||
        ((string)($S['wan_if']??'')!=='' && (string)($S['wan_if']??'')===(string)($S['lan_if']??''))))
        $warn[]='WAN/LAN condivisa: la stessa interfaccia non autentica la provenienza; mantieni anti-spoof a monte e valuta VLAN/AP isolation.';
    $sec = array_values(array_filter($sec, fn($s) => !empty($s['rules'])));
    return [$sec, $warn];
}
function ensure_table(array &$M, string $name) {
    if (tb($M, $name) >= 0) return;
    $items = []; foreach (BUILTIN[$name] ?? [] as $c) $items[] = ['t' => 'chain', 'n' => $c, 'p' => 'ACCEPT'];
    $last = -1; foreach ($M as $k => $b) if ($b['k'] === 'table') $last = $k;
    array_splice($M, $last + 1, 0, [['k' => 'table', 'name' => $name, 'items' => $items]]);
}
function anchor_index(array $items, string $ch, string $an): int {
    $ix = chain_rules($items, $ch);
    if (str_starts_with($an, 'rk:')) {   // subito dopo la regola con quella chiave (mantiene la posizione di una regola manuale convertita)
        foreach (array_reverse($ix) as $i) if (substr(md5(rkey($items[$i]['r'])), 0, 12) === substr($an, 3)) return $i + 1;
        return ins_index($items, $ch, 'smart');
    }
    if ($an === 'top') return $ix ? $ix[0] : count($items);
    if ($an === 'est') {
        foreach ($ix as $i) {
            if (!$items[$i]['on']) continue; $f = rule_parse($items[$i]['r']);
            if ($f['target'] === 'ACCEPT' && stripos($f['ctstate'], 'ESTABLISHED') !== false && $f['ctstate'][0] !== '!' && $f['i'] === '' && $f['s'] === '') return $i + 1;
        }
        return $ix ? $ix[0] : count($items);
    }
    return ins_index($items, $ch, 'smart');
}
function in_region(array $items, int $idx): bool {   // true se $idx cade dentro un blocco IPTM
    $open = false; for ($j = 0; $j < $idx && $j < count($items); $j++) { $x = $items[$j]; if ($x['t'] !== 'c') continue; if (str_starts_with($x['x'], '# >>> IPTM:')) $open = true; elseif (str_starts_with($x['x'], '# <<< IPTM:')) $open = false; }
    return $open;
}
function out_of_region(array $items, int $idx): int {
    if (!in_region($items, $idx)) return $idx;
    for ($j = $idx; $j < count($items); $j++) if ($items[$j]['t'] === 'c' && str_starts_with($items[$j]['x'], '# <<< IPTM:')) return $j + 1;
    return $idx;
}
function ensure_chain(array &$M, string $t, string $c) {
    $ti = tb($M, $t); if ($ti < 0 || chain_ok($t, $M[$ti]['items'], $c)) return;
    $last = 0; foreach ($M[$ti]['items'] as $i => $it) if ($it['t'] === 'chain') $last = $i + 1;
    array_splice($M[$ti]['items'], $last, 0, [['t' => 'chain', 'n' => $c, 'p' => '-']]);
}
/** Detect only IPTM-owned DoT/DNS blocks. Never infer protection from
 * unrelated/manual rules and never mutate either the kernel or rules.v4. */
function iptm_dns_guard_sections(array $M): array {
    $found=[];
    foreach($M as $table){
        if(($table['k']??'')!=='table')continue;
        $name=(string)($table['name']??'');$active='';$rows=[];
        foreach(($table['items']??[]) as $it){
            if(($it['t']??'')==='c' && preg_match('/^# >>> IPTM:(dot|dns-redir)(?:\s|$)/',(string)($it['x']??''),$m)){
                if($active!=='')throw new RuntimeException('Blocco DNS/DoT annidato: rigenerazione annullata.');
                $active=$m[1];$rows=[];continue;
            }
            if($active==='')continue;
            if(($it['t']??'')==='c' && trim((string)($it['x']??''))==='# <<< IPTM:'.$active){
                if(isset($found[$active]))throw new RuntimeException('Blocco DNS/DoT duplicato: operazione annullata.');
                $expectedTable=$active==='dot'?'filter':'nat';
                $expectedChain=$active==='dot'?'FORWARD':'PREROUTING';
                if($name!==$expectedTable || !$rows)throw new RuntimeException('Blocco DNS/DoT in tabella imprevista o vuoto.');
                foreach($rows as $r)if(!str_starts_with($r,'-A '.$expectedChain.' '))
                    throw new RuntimeException('Blocco DNS/DoT con catena imprevista.');
                $found[$active]=['t'=>$name,'c'=>$expectedChain,'rules'=>$rows];
                $active='';$rows=[];continue;
            }
            if(($it['t']??'')!=='rule'||empty($it['on']))throw new RuntimeException('Blocco DNS/DoT incompleto: rigenerazione annullata.');
            $rows[]=(string)$it['r'];
        }
        if($active!=='')throw new RuntimeException('Blocco DNS/DoT non chiuso: rigenerazione annullata.');
    }
    return $found;
}
/** Return protected section names which would be lost when replacing rules.v4. */
function iptm_dns_guard_losses(string $file,string $draft): array {
    $was=iptm_dns_guard_sections(parse_rules($file));
    $now=iptm_dns_guard_sections(parse_rules($draft));
    return array_values(array_diff(array_keys($was),array_keys($now)));
}
/** Validate the complete old generated rules against the configured LANs.
 * Never guess an ingress, enable a new source scope, or adopt an arbitrary DNAT. */
function iptm_dns_guard_restore_plan(array $S,string $disk): array {
    if(trim($disk)==='' || strlen($disk)>4194304)throw new RuntimeException('rules.v4 su disco non disponibile o troppo grande.');
    $blocks=iptm_dns_guard_sections(parse_rules($disk));
    if(!$blocks)throw new RuntimeException('Nessuna protezione IPTM:dot o IPTM:dns-redir da recuperare sul disco.');
    $notes=[];$S=iptm_safe_settings($S,$notes);
    $nets=array_values(array_filter(explode(',',(string)($S['lan_nets']??''))));
    if(!$nets)throw new RuntimeException('Configura prima le reti LAN nelle impostazioni; nessuna modifica eseguita.');
    $restore=[];
    foreach($blocks as $id=>$block){
        $rows=$block['rules'];$normalized=[];
        foreach($rows as $row){
            // A scoped -i (or ! -i WAN) may be present in older saved policies.
            $r=preg_replace('/^(-A (?:FORWARD|PREROUTING)) (?:(?:-i|! -i) [A-Za-z0-9_.+\-]{1,15} )/','$1 ',$row,1);
            $normalized[]=$r;
        }
        $ip='';$expected=[];
        if($id==='dns-redir'){
            foreach($normalized as $r){
                if(!preg_match('/--to-destination ((?:[0-9]{1,3}\.){3}[0-9]{1,3}):53$/D',$r,$m) ||
                   !filter_var($m[1],FILTER_VALIDATE_IP,FILTER_FLAG_IPV4) ||
                   ($ip!=='' && $ip!==$m[1]))throw new RuntimeException('DNAT DNS presente su disco ma non univoco/valido: nessuna modifica.');
                $ip=$m[1];
            }
            if(!iptm_scope_within_lan($ip,implode(',',$nets)))
                throw new RuntimeException('IP del DNS su disco esterno alle LAN configurate: verifica manuale richiesta.');
        }
        foreach($nets as $net)foreach(['udp','tcp'] as $proto){
            if($id==='dot')$expected[]='-A FORWARD -s '.$net.' -p '.$proto.' --dport 853 -j REJECT --reject-with '.($proto==='tcp'?'tcp-reset':'icmp-port-unreachable');
            else $expected[]='-A PREROUTING -s '.$net.' ! -d '.$ip.' -p '.$proto.' --dport 53 -j DNAT --to-destination '.$ip.':53';
        }
        sort($expected);sort($normalized);
        if($normalized!==$expected)
            throw new RuntimeException('Il blocco '.$id.' su disco non coincide con le reti/opzioni attese: recupero automatico rifiutato; usa il confronto manuale.');
        if($id==='dot')$S['dot_block']=1;
        else {$S['dns_redirect']=1;$S['dns_ip']=$ip;}
        $restore[]=$id;
    }
    return [$S,$restore];
}
function strip_regions(array &$M) {
    foreach ($M as &$b) {
        if ($b['k'] !== 'table') continue;
        $o = []; $in = false;
        foreach ($b['items'] as $it) {
            if ($it['t'] === 'c' && str_starts_with($it['x'], '# >>> IPTM:')) { $in = true; continue; }
            if ($it['t'] === 'c' && str_starts_with($it['x'], '# <<< IPTM:')) { $in = false; continue; }
            if (!$in && !($it['t'] === 'chain' && str_starts_with($it['n'], 'IPTM-'))) $o[] = $it;
        }
        if (!$in) $b['items'] = $o;   // regione non chiusa: non tocco nulla
    }
}
function regen(array &$M, array $S, bool $allowDnsGuardRemoval = false): array {
    // Rebuilding a draft must not silently erase preexisting IPTM DNS/DoT
    // protection when saved UI flags disagree. Explicit removal is separate.
    $previous=iptm_dns_guard_sections($M);
    strip_regions($M); [$secs, $warn] = gen_sections($S);
    if(!$allowDnsGuardRemoval){
        $generated=array_column($secs,'id');
        foreach($previous as $id=>$old){
            if(in_array($id,$generated,true))continue;
            // Preserve only rules which match the *current* LANs and are safe
            // to regenerate. An incompatibility requires operator review.
            $probeS=$S;
            if($id==='dot')$probeS['dot_block']=1;
            else {
                if(!preg_match('/--to-destination ((?:[0-9]{1,3}\.){3}[0-9]{1,3}):53$/',implode("\n",$old['rules']),$m))
                    throw new RuntimeException('Vecchio DNAT DNS non verificabile: nessuna regola cancellata.');
                $probeS['dns_ip']=$m[1];$probeS['dns_redirect']=1;
            }
            // Validate by the exact canonical shape; arbitrary legacy DNAT
            // must never be silently blessed as an IPTM-managed policy.
            $txt='*'.$old['t']."\n:".$old['c']." ACCEPT [0:0]\n# >>> IPTM:".$id."\n".implode("\n",$old['rules'])."\n# <<< IPTM:".$id."\nCOMMIT\n";
            try {iptm_dns_guard_restore_plan($probeS,$txt);}catch(RuntimeException $e){
                throw new RuntimeException('Protezione '.$id.' già presente ma non riallineata: '.$e->getMessage());
            }
            $secs[]=['id'=>$id,'title'=>$id==='dot'?'Blocca DoT dalla LAN':'Forza i client LAN a usare il DNS locale',
                't'=>$old['t'],'c'=>$old['c'],'an'=>'top','pr'=>$id==='dot'?0:10,'rules'=>$old['rules']];
            $warn[]='Preservate le regole '.$id.' della bozza: impostazioni DNS non allineate. Riallinea dal file rules.v4 nella pagina Setup.';
        }
    }
    $groups = []; foreach ($secs as $s) $groups[$s['t'] . '|' . $s['c'] . '|' . $s['an']][] = $s;
    $ord = ['top' => 0, 'est' => 1, 'end' => 2];
    uksort($groups, fn($a, $b) => ($ord[explode('|', $a)[2]] ?? 3) <=> ($ord[explode('|', $b)[2]] ?? 3));
    foreach ($groups as $k => $ss) {
        [$t, $c, $an] = explode('|', $k); ensure_table($M, $t);
        ensure_chain($M, $t, $c);
        $ti = tb($M, $t);
        if (!chain_ok($t, $M[$ti]['items'], $c)) { $warn[] = "Catena $t/$c inesistente: sezioni saltate."; continue; }
        usort($ss, fn($a, $b) => $a['pr'] <=> $b['pr']); $blk = [];
        foreach ($ss as $s) {
            $blk[] = ['t' => 'c', 'x' => '# >>> IPTM:' . $s['id'] . ' - ' . $s['title'] . ' (generato: non modificare a mano)'];
            foreach ($s['rules'] as $r) $blk[] = $r[0] === '#' ? ['t' => 'c', 'x' => $r] : ['t' => 'rule', 'r' => $r, 'on' => true];
            $blk[] = ['t' => 'c', 'x' => '# <<< IPTM:' . $s['id']];
        }
        $at = out_of_region($M[$ti]['items'], anchor_index($M[$ti]['items'], $c, $an));
        array_splice($M[$ti]['items'], $at, 0, $blk);
    }
    if ($S['spi']) { $ti = tb($M, 'filter'); foreach ($M[$ti]['items'] as &$it) if ($it['t'] === 'chain' && in_array($it['n'], ['INPUT', 'FORWARD'], true)) $it['p'] = 'DROP'; unset($it); }
    return $warn;
}
