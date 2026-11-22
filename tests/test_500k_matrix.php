<?php
/**
 * Deterministic 500,000-scenario regression for IPTM rule generator.
 * Only builds memory models. NEVER invokes iptables or modifies rules.v4.
 * php -d memory_limit=256M tests/test_500k_matrix.php
 */
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

$flags = ['spi','invalid','lockout_on','ssh_acc','raw_drop','nat_masq','lan_out_fwd','dot_block',
          'quic_block','final_drop','wg_on','dhcp_accept','antispoof','closeports','dns_redirect','raw_lo'];
$profiles = [
    ['name'=>'single_nic','lan'=>'192.168.50.0/24,10.77.0.0/24','wan'=>'bond0','li'=>'bond0','single'=>1,'masq'=>'','okLan'=>2,'okWan'=>0],
    ['name'=>'dedicated_wan','lan'=>'192.168.50.0/24,10.77.0.0/24','wan'=>'eth0','li'=>'br0','single'=>0,'masq'=>'','okLan'=>2,'okWan'=>1],
    ['name'=>'no_wan','lan'=>'192.168.50.0/24','wan'=>'','li'=>'br0','single'=>0,'masq'=>'','okLan'=>1,'okWan'=>0],
    ['name'=>'no_lan','lan'=>'','wan'=>'eth0','li'=>'br0','single'=>0,'masq'=>'','okLan'=>0,'okWan'=>1],
    ['name'=>'unmarked_shared','lan'=>'10.77.0.0/24','wan'=>'br0','li'=>'br0','single'=>0,'masq'=>'','okLan'=>1,'okWan'=>0],
    ['name'=>'two_uplinks','lan'=>'10.77.0.0/24,192.168.50.0/24','wan'=>'eth0','li'=>'br0','single'=>0,'masq'=>'eth0,wg0','okLan'=>2,'okWan'=>1],
    ['name'=>'invalid_lan','lan'=>'0.0.0.0/0,198.51.100.0/24,192.168.50.7/wrong,192.168.50.0/24','wan'=>'eth0','li'=>'br0','single'=>0,'masq'=>'','okLan'=>1,'okWan'=>1],
    ['name'=>'bad_iface','lan'=>'10.77.0.0/24','wan'=>'eth0 -j ACCEPT','li'=>'br0','single'=>0,'masq'=>'','okLan'=>1,'okWan'=>0],
];

$assertions=0;$cases=0;$families=[];
function check500(bool $test, string $error, int $case, string $profile, int $mask): void {
    global $assertions;
    $assertions++;
    if (!$test) throw new RuntimeException("Scenario=$case profile=$profile flags=$mask: $error");
}
function sec500(array $sec,string $id): ?array {foreach($sec as $x) if($x['id']===$id)return $x;return null;}
$start = microtime(true);
// 7 complete 2^16 topologies plus first 41,248 masks of the eighth => exactly 500,000.
foreach ($profiles as $pi=>$top) {
    $limit = $pi < 7 ? 65536 : 41248;
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
        $raw = sec500($sections,'raw-drop');
        $egress = sec500($sections,'lan-out');
        $egressLocal = sec500($sections,'lan-egress-local');
        $egressOut = sec500($sections,'lan-egress-out');
        $nat = sec500($sections,'nat-masq');
        $dot = sec500($sections,'dot');
        $quic = sec500($sections,'quic');
        $lockout = sec500($sections,'lockout');
        $ssh = sec500($sections,'ssh-acc');
        check500(!in_array('lan-tcp',$names,true) && !in_array('docker-net',$names,true),'Legacy wildcard INPUT generated',$cases,$top['name'],$mask);
        check500(!in_array('raw-lo-pre',$names,true) && !in_array('raw-lo-out',$names,true),'Raw no-track unexpectedly enabled',$cases,$top['name'],$mask);
        check500((bool)$raw === (bool)($s['raw_drop'] && $top['okWan']),'Raw drop wrong interface scope',$cases,$top['name'],$mask);
        if ($raw) foreach ($raw['rules'] as $r) check500(str_contains($r,'-i eth0 '),'Raw drop has no eth0 ingress match',$cases,$top['name'],$mask);
        $shouldEgress=($s['lan_out_fwd'] && $top['okLan']>0 && ($top['okWan'] || $top['single'] || $top['name']==='unmarked_shared'));
        check500((bool)$egress === (bool)$shouldEgress,'LAN egress unexpectedly absent/present',$cases,$top['name'],$mask);
        check500((bool)$egressLocal === (bool)$egress && (bool)$egressOut === (bool)$egress,'Incomplete egress chain',$cases,$top['name'],$mask);
        if ($egress) {
            foreach ($egress['rules'] as $r) check500(str_contains($r,'-j IPTM-LAN-EGRESS')&&!str_contains($r,'-j ACCEPT'),'LAN egress global accept',$cases,$top['name'],$mask);
            foreach ($egressOut['rules'] as $r) check500(preg_match('/ -o (eth0|wg0|bond0|br0) -j ACCEPT$/D',$r)===1,'Unscoped egress accept',$cases,$top['name'],$mask);
            check500(count($egressLocal['rules'])===$top['okLan'],'Missing LAN destination exclusions',$cases,$top['name'],$mask);
        }
        check500((bool)$nat === (bool)($s['nat_masq'] && $top['okLan'] && ($top['okWan'] || $top['single'] || $top['name']==='unmarked_shared')),'NAT unexpectedly absent/present',$cases,$top['name'],$mask);
        if ($nat) foreach ($nat['rules'] as $r) check500(str_contains($r,' -s ')&&!str_contains($r,'0.0.0.0/0'),'NAT with global source',$cases,$top['name'],$mask);
        check500((bool)$dot === (bool)($s['dot_block'] && $top['okLan']),'DoT mismatch',$cases,$top['name'],$mask);
        check500((bool)$quic === (bool)($s['quic_block'] && $top['okLan']),'QUIC mismatch',$cases,$top['name'],$mask);
        if ($dot) foreach ($dot['rules'] as $r) check500(str_contains($r,' -s ') && str_contains($r,'--dport 853'),'DoT unscoped',$cases,$top['name'],$mask);
        if ($quic) foreach ($quic['rules'] as $r) check500(str_contains($r,' -s ') && str_contains($r,'--dport 443'),'QUIC unscoped',$cases,$top['name'],$mask);
        if ($lockout) foreach ($lockout['rules'] as $r) check500(!str_contains($r,'0.0.0.0/0')&&str_contains($r,' -s '),'Untrusted management exception',$cases,$top['name'],$mask);
        if ($ssh) foreach ($ssh['rules'] as $r) check500(!str_contains($r,'0.0.0.0/0')&&!str_contains($r,'/wrong')&&!str_contains($r,'198.51.100.'),'Untrusted SSH exception',$cases,$top['name'],$mask);
        if ($s['dns_redirect'] && $top['okLan']) {
            $dns=sec500($sections,'dns-redir');
            check500((bool)$dns,'Missing constrained DNS redirect',$cases,$top['name'],$mask);
            if ($dns)foreach($dns['rules'] as $r)check500(str_contains($r,' -s ') && str_contains($r,' -j DNAT'),'Unscoped DNS DNAT',$cases,$top['name'],$mask);
        }
        if (!($mask & 8191) && (($cases%65536)==0)) fwrite(STDERR,'.');
    }
}
// Targeted attack variations: from imported legacy settings and aliases.
$bad=S_def();$bad['lan_nets']='0.0.0.0/0,192.168.50.7/xx,192.168.50.0/24';$bad['ssh_nets']='0.0.0.0/0,192.168.50.7/xx,192.168.50.0/24';
$bad['ssh_acc']=1;$bad['lockout_on']=1;$bad['raw_drop']=1;$bad['wan_if']='eth0 -j ACCEPT';
[$sec,$warn]=gen_sections($bad);
check500(sec500($sec,'raw-drop')===null,'Invalid WAN created raw drop',$cases,'attack',0);
$ssh=sec500($sec,'ssh-acc');
check500($ssh!==null && count($ssh['rules'])===4,'Unsafe SSH networks survived',$cases,'attack',0);
foreach($ssh['rules'] as $r)if(str_contains($r,'--ctstate NEW'))check500(str_contains($r,'-s 192.168.50.0/24'),'SSH network not sanitized',$cases,'attack',0);
$al=['ports'=>['miss'=>'','db'=>'2375','range'=>'2300:2400','ssh'=>'22','safe'=>'9000']];
$rows=[];foreach(['miss','db','range','ssh','safe'] as $p)$rows[]=['on'=>1,'proto'=>'tcp','ports'=>'@'.$p,'act'=>'ACCEPT','src'=>'192.168.50.0/24'];
$rules=svc_rules('INPUT',$rows,$al);
check500(count($rules)===2,'Unsafe aliases incorrectly emitted or good alias missing',$cases,'attack',0);
check500(str_contains(implode("\n",$rules),'--dport 22')&&str_contains(implode("\n",$rules),'--dport 9000'),'Safe alias regression',$cases,'attack',0);
// Alias with no TCP port and UDP wildcard must never expose the host.
$rows=[['on'=>1,'proto'=>'udp','ports'=>'@miss','act'=>'ACCEPT','src'=>'192.168.50.0/24']];
check500(svc_rules('INPUT',$rows,$al)===[],'UDP alias unresolved and exposed all ports',$cases,'attack',0);
$report=[
 'version'=>'5.20.28', 'result'=>'PASS', 'scenarios'=>$cases,
 'assertions'=>$assertions, 'option_count'=>count($flags),
 'topologies'=>$families, 'method'=>'7 full 2^16 state spaces plus 41248 states from the eighth',
 'coverage'=>'Generator behavior under selected flag/topology combinations; not exhaustive of all possible network configurations',
 'kernel_tested'=>false, 'elapsed_seconds'=>round(microtime(true)-$start,3),
];
if ($cases!==500000) throw new RuntimeException('Scenario mismatch '.$cases);
echo json_encode($report,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES)."\n";
