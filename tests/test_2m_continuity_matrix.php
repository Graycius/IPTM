<?php
/**
 * Deterministic 2,097,152-scenario regression for IPTM rule generator.
 * Only builds memory models. NEVER invokes iptables or modifies rules.v4.
 * php -d memory_limit=256M tests/test_2m_matrix.php
 */
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

$flags = ['spi','invalid','lockout_on','ssh_acc','raw_drop','nat_masq','lan_out_fwd','dot_block',
          'quic_block','final_drop','wg_on','dhcp_accept','antispoof','closeports','dns_redirect','raw_lo','continuity_priority'];
$profiles = [
    ['name'=>'single_nic','lan'=>'192.168.50.0/24,10.77.0.0/24','wan'=>'bond0','li'=>'bond0','single'=>1,'masq'=>'','okLan'=>2,'okWan'=>0],
    ['name'=>'dedicated_wan','lan'=>'192.168.50.0/24,10.77.0.0/24','wan'=>'eth0','li'=>'br0','single'=>0,'masq'=>'','okLan'=>2,'okWan'=>1],
    ['name'=>'no_wan','lan'=>'192.168.50.0/24','wan'=>'','li'=>'br0','single'=>0,'masq'=>'','okLan'=>1,'okWan'=>0],
    ['name'=>'no_lan','lan'=>'','wan'=>'eth0','li'=>'br0','single'=>0,'masq'=>'','okLan'=>0,'okWan'=>1],
    ['name'=>'unmarked_shared','lan'=>'10.77.0.0/24','wan'=>'br0','li'=>'br0','single'=>0,'masq'=>'','okLan'=>1,'okWan'=>0],
    ['name'=>'two_uplinks','lan'=>'10.77.0.0/24,192.168.50.0/24','wan'=>'eth0','li'=>'br0','single'=>0,'masq'=>'eth0,wg0','okLan'=>2,'okWan'=>1],
    ['name'=>'invalid_lan','lan'=>'0.0.0.0/0,198.51.100.0/24,192.168.50.7/wrong,192.168.50.0/24','wan'=>'eth0','li'=>'br0','single'=>0,'masq'=>'','okLan'=>1,'okWan'=>1],
    ['name'=>'bad_iface','lan'=>'10.77.0.0/24','wan'=>'eth0 -j ACCEPT','li'=>'br0','single'=>0,'masq'=>'','okLan'=>1,'okWan'=>0],
    ['name'=>'bridge_only','lan'=>'172.20.5.0/24','wan'=>'bond0','li'=>'bond0','single'=>1,'masq'=>'','okLan'=>1,'okWan'=>0],
    ['name'=>'vpn_uplink','lan'=>'192.168.10.0/24','wan'=>'eth0','li'=>'br0','single'=>0,'masq'=>'wg0','okLan'=>1,'okWan'=>1],
    ['name'=>'pppoe_uplink','lan'=>'10.0.5.0/24','wan'=>'ppp0','li'=>'br0','single'=>0,'masq'=>'','okLan'=>1,'okWan'=>1],
    ['name'=>'cgnat_lan','lan'=>'100.64.17.0/24','wan'=>'eth0','li'=>'br0','single'=>0,'masq'=>'','okLan'=>1,'okWan'=>1],
    ['name'=>'three_lans','lan'=>'10.5.1.0/24,192.168.52.0/24,172.25.8.0/24','wan'=>'eth0','li'=>'br0','single'=>0,'masq'=>'','okLan'=>3,'okWan'=>1],
    ['name'=>'untrusted_lan','lan'=>'203.0.113.0/24','wan'=>'eth0','li'=>'br0','single'=>0,'masq'=>'','okLan'=>0,'okWan'=>1],
    ['name'=>'empty_both','lan'=>'','wan'=>'','li'=>'','single'=>0,'masq'=>'','okLan'=>0,'okWan'=>0],
    ['name'=>'shared_multi_wan','lan'=>'192.168.90.0/24,10.2.3.0/24','wan'=>'bond0','li'=>'bond0','single'=>1,'masq'=>'bond0,wg0','okLan'=>2,'okWan'=>0],
];

$assertions=0;$cases=0;$families=[];
function check2m(bool $test, string $error, int $case, string $profile, int $mask): void {
    global $assertions;
    $assertions++;
    if (!$test) throw new RuntimeException("Scenario=$case profile=$profile flags=$mask: $error");
}
function sec2m(array $sec,string $id): ?array {foreach($sec as $x) if($x['id']===$id)return $x;return null;}
$start = microtime(true);
// All 2^17 masks for each of 16 independent network topologies => exactly 2,097,152.
foreach ($profiles as $pi=>$top) {
    $limit = 131072;
    $families[$top['name']] = $limit;
    $base = S_def();
    $base['lan_nets'] = $top['lan']; $base['wan_if']=$top['wan']; $base['lan_if']=$top['li'];
    $base['single_nic']=$top['single'];$base['masq_ifs']=$top['masq'];
    $base['ssh_nets']=$top['lan']; $base['dns_ip']='192.168.50.5';
    $base['mgmt_ports']='22,80,443,8089,8489';
    for ($mask=0;$mask<$limit;$mask++) {
        $s=$base;
        foreach ($flags as $bit=>$key) $s[$key]=($mask>>$bit)&1;
        [$sections,$warnings] = gen_sections($s);
        $cases++;
        $names = array_column($sections,'id');
        $raw = sec2m($sections,'raw-drop');
        $egress = sec2m($sections,'lan-out');
        $egressLocal = sec2m($sections,'lan-egress-local');
        $egressOut = sec2m($sections,'lan-egress-out');
        $nat = sec2m($sections,'nat-masq');
        $dot = sec2m($sections,'dot');
        $quic = sec2m($sections,'quic');
        $lockout = sec2m($sections,'lockout');
        $ssh = sec2m($sections,'ssh-acc');
        $returnIn = sec2m($sections,'conn-return-in');
        $returnFw = sec2m($sections,'conn-return-fw');
        $safeOn = (bool)$s['continuity_priority'];
        check2m((bool)$returnIn === ($safeOn && empty($s['spi'])), 'Input return traffic not guarded', $cases,$top['name'],$mask);
        check2m((bool)$returnFw === ($safeOn && empty($s['spi'])), 'Forward return traffic not guarded', $cases,$top['name'],$mask);
        if ($returnIn) check2m(in_array('-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT',$returnIn['rules'],true),
            'Input conntrack return missing', $cases,$top['name'],$mask);
        if ($returnFw) check2m(in_array('-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT',$returnFw['rules'],true),
            'Forward conntrack return missing', $cases,$top['name'],$mask);
        if ($safeOn && $top['okLan'] > 0) check2m($lockout !== null,
            'Admin LAN access not generated', $cases,$top['name'],$mask);
        check2m(!in_array('lan-tcp',$names,true) && !in_array('docker-net',$names,true),'Legacy wildcard INPUT generated',$cases,$top['name'],$mask);
        check2m(!in_array('raw-lo-pre',$names,true) && !in_array('raw-lo-out',$names,true),'Raw no-track unexpectedly enabled',$cases,$top['name'],$mask);
        check2m((bool)$raw === (bool)($s['raw_drop'] && $top['okWan']),'Raw drop wrong interface scope',$cases,$top['name'],$mask);
        if ($raw) foreach ($raw['rules'] as $r) check2m(str_contains($r,'-i ' . $top['wan'] . ' '),'Raw drop has no WAN ingress match',$cases,$top['name'],$mask);
        $shouldEgress=($s['lan_out_fwd'] && $top['okLan']>0 && ($top['okWan'] || $top['single'] || $top['name']==='unmarked_shared'));
        check2m((bool)$egress === (bool)$shouldEgress,'LAN egress unexpectedly absent/present',$cases,$top['name'],$mask);
        check2m((bool)$egressLocal === (bool)$egress && (bool)$egressOut === (bool)$egress,'Incomplete egress chain',$cases,$top['name'],$mask);
        if ($egress) {
            foreach ($egress['rules'] as $r) check2m(str_contains($r,'-j IPTM-LAN-EGRESS')&&!str_contains($r,'-j ACCEPT'),'LAN egress global accept',$cases,$top['name'],$mask);
            foreach ($egressOut['rules'] as $r) check2m(preg_match('/ -o (eth0|wg0|bond0|br0|ppp0) -j ACCEPT$/D',$r)===1,'Unscoped egress accept',$cases,$top['name'],$mask);
            check2m(count($egressLocal['rules'])===$top['okLan'],'Missing LAN destination exclusions',$cases,$top['name'],$mask);
        }
        check2m((bool)$nat === (bool)($s['nat_masq'] && $top['okLan'] && ($top['okWan'] || $top['single'] || $top['name']==='unmarked_shared')),'NAT unexpectedly absent/present',$cases,$top['name'],$mask);
        if ($nat) foreach ($nat['rules'] as $r) check2m(str_contains($r,' -s ')&&!str_contains($r,'0.0.0.0/0'),'NAT with global source',$cases,$top['name'],$mask);
        check2m((bool)$dot === (bool)($s['dot_block'] && $top['okLan']),'DoT mismatch',$cases,$top['name'],$mask);
        check2m((bool)$quic === (bool)($s['quic_block'] && $top['okLan']),'QUIC mismatch',$cases,$top['name'],$mask);
        if ($dot) foreach ($dot['rules'] as $r) check2m(str_contains($r,' -s ') && str_contains($r,'--dport 853'),'DoT unscoped',$cases,$top['name'],$mask);
        if ($quic) foreach ($quic['rules'] as $r) check2m(str_contains($r,' -s ') && str_contains($r,'--dport 443'),'QUIC unscoped',$cases,$top['name'],$mask);
        if ($lockout) foreach ($lockout['rules'] as $r) check2m(!str_contains($r,'0.0.0.0/0')&&str_contains($r,' -s '),'Untrusted management exception',$cases,$top['name'],$mask);
        if ($ssh) foreach ($ssh['rules'] as $r) check2m(!str_contains($r,'0.0.0.0/0')&&!str_contains($r,'/wrong')&&!str_contains($r,'198.51.100.'),'Untrusted SSH exception',$cases,$top['name'],$mask);
        if ($s['dns_redirect'] && $top['okLan']) {
            $dns=sec2m($sections,'dns-redir');
            check2m((bool)$dns,'Missing constrained DNS redirect',$cases,$top['name'],$mask);
            if ($dns)foreach($dns['rules'] as $r)check2m(str_contains($r,' -s ') && str_contains($r,' -j DNAT'),'Unscoped DNS DNAT',$cases,$top['name'],$mask);
        }
        if (!($mask & 8191) && (($cases%65536)==0)) fwrite(STDERR,'.');
    }
}
// Targeted attack variations: from imported legacy settings and aliases.
$bad=S_def();$bad['lan_nets']='0.0.0.0/0,192.168.50.7/xx,192.168.50.0/24';$bad['ssh_nets']='0.0.0.0/0,192.168.50.7/xx,192.168.50.0/24';
$bad['ssh_acc']=1;$bad['lockout_on']=1;$bad['raw_drop']=1;$bad['wan_if']='eth0 -j ACCEPT';
[$sec,$warn]=gen_sections($bad);
check2m(sec2m($sec,'raw-drop')===null,'Invalid WAN created raw drop',$cases,'attack',0);
$ssh=sec2m($sec,'ssh-acc');
check2m($ssh!==null && count($ssh['rules'])===3,'Unsafe SSH networks survived',$cases,'attack',0);
foreach($ssh['rules'] as $r)check2m(str_contains($r,'-s 192.168.50.0/24'),'SSH network not sanitized',$cases,'attack',0);
$al=['ports'=>['miss'=>'','db'=>'2375','range'=>'2300:2400','ssh'=>'22','safe'=>'9000']];
$rows=[];foreach(['miss','db','range','ssh','safe'] as $p)$rows[]=['on'=>1,'proto'=>'tcp','ports'=>'@'.$p,'act'=>'ACCEPT','src'=>'192.168.50.0/24'];
$rules=svc_rules('INPUT',$rows,$al);
check2m(count($rules)===2,'Unsafe aliases incorrectly emitted or good alias missing',$cases,'attack',0);
check2m(str_contains(implode("\n",$rules),'--dport 22')&&str_contains(implode("\n",$rules),'--dport 9000'),'Safe alias regression',$cases,'attack',0);
// Alias with no TCP port and UDP wildcard must never expose the host.
$rows=[['on'=>1,'proto'=>'udp','ports'=>'@miss','act'=>'ACCEPT','src'=>'192.168.50.0/24']];
check2m(svc_rules('INPUT',$rows,$al)===[],'UDP alias unresolved and exposed all ports',$cases,'attack',0);
// Risk-heavy services and defaults: safety mode must suppress nonessential
// broad rate limits while keeping explicit policy restrictions unchanged.
foreach ([0,1] as $safe) {
    $risk=S_def();$risk['continuity_priority']=$safe;
    $risk['lan_nets']='192.168.50.0/24';$risk['wan_if']='eth0';$risk['lan_if']='br0';
    $risk['dos']=1;$risk['conn_limit']=1;$risk['lan_cl']=1;$risk['udp_rl']=1;
    $risk['web_rl']=1;$risk['glob_new_limit']=1;$risk['lan_flood']=1;$risk['portscan']=1;
    $risk['dot_block']=1;$risk['quic_block']=1;
    [$sec,$warn]=gen_sections($risk);$ids=array_column($sec,'id');
    foreach(['dos','connlimit','lancl','udprl','glob-new','lanflood','ps-chk'] as $label)
        check2m(in_array($label,$ids,true)===(!$safe), 'Continuity suppresses high-false-positive rules only when selected: '.$label, $cases,'targeted',$safe);
    check2m(in_array('dot',$ids,true)&&in_array('quic',$ids,true), 'Explicit DNS/QUIC policies were silently changed',$cases,'targeted',$safe);
    check2m(($safe && count($warn)>0)||!$safe, 'Continuity warnings not visible',$cases,'targeted',$safe);
}
$report=[
 'version'=>'5.20.29', 'result'=>'PASS', 'scenarios'=>$cases,
 'assertions'=>$assertions, 'option_count'=>count($flags), 'continuity_priority_tested'=>true,
 'topologies'=>$families, 'method'=>'16 full 2^17 state spaces, exhaustive for selected flags on each selected topology',
 'coverage'=>'Selected 17 flags exhaustively crossed with 16 topologies and targeted high-risk toggles; does not prove real-client connectivity',
 'kernel_tested'=>false, 'elapsed_seconds'=>round(microtime(true)-$start,3),
];
if ($cases!==2097152) throw new RuntimeException('Scenario mismatch '.$cases);
echo json_encode($report,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES)."\n";
