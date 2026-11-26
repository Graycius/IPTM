<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';
$features=['spi','invalid','lockout_on','ssh_acc','raw_drop','nat_masq','lan_out_fwd','dot_block','quic_block','final_drop','wg_on','dhcp_accept','antispoof','closeports'];
$topologies=[
    ['name'=>'single','lan'=>'192.168.50.0/24,10.77.0.0/24','wan'=>'bond0','single'=>1],
    ['name'=>'separate','lan'=>'192.168.50.0/24,10.77.0.0/24','wan'=>'eth0','single'=>0],
    ['name'=>'no_wan','lan'=>'192.168.50.0/24,10.77.0.0/24','wan'=>'','single'=>0],
];
$assertions=0;$cases=0;$errors=[];
function must($v,$why){global $assertions,$errors;$assertions++;if(!$v){$errors[]=$why;if(count($errors)>4){fwrite(STDERR,implode("\n",$errors));exit(1);}}}
function getsec($s,$id){foreach($s as $x)if($x['id']===$id)return $x;return null;}
for($m=0;$m<16384;$m++){
 foreach($topologies as $top){
  $s=S_def();
  foreach($features as $i=>$name)$s[$name]=($m>>$i)&1;
  $s['lan_nets']=$top['lan'];$s['wan_if']=$top['wan'];$s['single_nic']=$top['single'];$s['ssh_nets']=$top['lan'];$s['mgmt_ports']='22,80,443,8089,8489';
  [$blocks,$warnings]=gen_sections($s);$cases++;
  $names=array_column($blocks,'id');$local=getsec($blocks,'lan-egress-local');$allow=getsec($blocks,'lan-egress-out');$jump=getsec($blocks,'lan-out');
  $wanOK=($top['name']==='separate');
  must(!in_array('lan-tcp',$names,true),'lan_tcp section returned');
  must(!in_array('docker-net',$names,true),'docker_net section returned');
  $raw=getsec($blocks,'raw-drop');
  must($raw===null||$wanOK,'raw drop present without dedicated WAN');
  if($raw)foreach($raw['rules'] as $r)must(str_contains($r,'-i eth0'),'raw not WAN scoped');
  if(!empty($s['lan_out_fwd'])&&$top['wan']){
   must($local&&$allow&&$jump,'missing egress sections '.$top['name']);
   foreach(explode(',',$top['lan']) as $net)must(in_array('-A IPTM-LAN-EGRESS -d '.$net.' -j RETURN',$local['rules'],true),'missing LAN exclusion');
   foreach($jump['rules'] as $r)must(str_contains($r,'-j IPTM-LAN-EGRESS')&&!str_contains($r,'-j ACCEPT'),'LAN jump accepts too widely');
   foreach($allow['rules'] as $r)must(str_contains($r,'-o '.$top['wan']).'','output interface not restricted');
  }else{
   must(!$allow&&!$jump&&!$local,'egress built without WAN');
  }
  $dot=getsec($blocks,'dot');
  if($dot)foreach($dot['rules'] as $r)must(str_contains($r,'-s ')&&str_contains($r,'--dport 853'),'DoT not LAN scoped');
  $quic=getsec($blocks,'quic');
  if($quic)foreach($quic['rules'] as $r)must(str_contains($r,'-s ')&&str_contains($r,'--dport 443'),'QUIC not LAN scoped');
  $n=getsec($blocks,'nat-masq');if($n)foreach($n['rules'] as $r)must(str_contains($r,'-s '),'NAT scope missing');
  must(!in_array('raw-inv',$names,true),'unsafe raw-inv unexpectedly produced');
 }
}
$bad=S_def();$bad['lan_nets']='192.168.50.0/24';$bad['wan_if']='bond0';$bad['single_nic']=1;
$bad['svc_in']=[['on'=>1,'proto'=>'tcp','ports'=>'','act'=>'ACCEPT','src'=>'192.168.50.0/24'],['on'=>1,'proto'=>'tcp','ports'=>'2375,8080','act'=>'ACCEPT','src'=>'192.168.50.0/24'],['on'=>1,'proto'=>'tcp','ports'=>'8090','act'=>'ACCEPT','src'=>'192.168.50.0/24']];
[$sections,$warn]=gen_sections($bad);$a=getsec($sections,'svc-in-a');must($a&&count($a['rules'])===1&&str_contains($a['rules'][0],'8090'),'unsafe svc_in passed');
$bad['svc_in']=[['on'=>1,'proto'=>'','ports'=>'','act'=>'ACCEPT','src'=>'172.16.0.0/12']];
[$sec,$warn]=gen_sections($bad);must(!getsec($sec,'svc-in-a'),'wildcard protocol accepted');
$tpl='*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n';
$M=parse_rules(str_replace('\\n',"\n",$tpl));$s=S_def();$s['lan_nets']='192.168.50.0/24,10.77.0.0/24';$s['wan_if']='bond0';$s['single_nic']=1;$s['spi']=1;$s['lan_out_fwd']=1;$s['dot_block']=1;$s['ssh_acc']=1;$s['ssh_nets']=$s['lan_nets'];$s['lockout_on']=1;
// Multiple LANs must not silently become management networks.
[$ambiguous,$ambiguousWarnings]=gen_sections($s);
must(!getsec($ambiguous,'lockout'),'Ambiguous LANs implicitly granted management access');
$s['mgmt_nets']='192.168.50.0/24';
regen($M,$s);$serialized=ser($M);
$positions=array_map(fn($x)=>strpos($serialized,'# >>> IPTM:'.$x),['dot','lan-out','ssh-acc','lockout']);
must($positions[0]!==false&&$positions[1]!==false&&$positions[0]<$positions[1],'DoT shadowed by lan-out after regen');
must($positions[2]!==false&&$positions[3]!==false&&$positions[2]<$positions[3],'SSH rate limits bypassed by unrestricted lockout');
[$explicit]=gen_sections($s);
$lockRules=getsec($explicit,'lockout')['rules']??[];
must(count($lockRules)>0,'Explicit management network has no lockout rules');
foreach($lockRules as $rule){
    must(str_contains($rule,'-s 192.168.50.0/24 '),'Lockout escaped explicit management network');
    if(preg_match('/--dports?\s+(\S+)/',$rule,$ports))
        must(!in_array((string)$s['ssh_acc_port'],explode(',',$ports[1]),true),'SSH port bypasses rate limits through lockout');
    else must(false,'Lockout missing port constraint');
}
must(str_contains($serialized,':IPTM-LAN-EGRESS -'),'no custom egress chain');
$again=$M;regen($again,$s);must(ser($again)===$serialized,'regen not idempotent');
// Exhaustive 4-state combinations for every pair in the extended option list.
$other=['iso_on','guest_on','dns_redirect','icmp_limit','mss',
        'log_drop','logdrop_on','coap_accept','igmp_accept','dos',
        'lan_tcp_accept','docker_accept'];
$all=array_merge($features,$other);$pairCases=0;
for($i=0;$i<count($all);$i++)for($j=$i+1;$j<count($all);$j++){
 for($mask=0;$mask<4;$mask++){
  $s=S_def();$s[$all[$i]]=$mask&1;$s[$all[$j]]=($mask>>1)&1;
  $s['lan_nets']='192.168.50.0/24,10.77.0.0/24';
  $s['wan_if']='bond0';$s['single_nic']=1;
  [$sec,$warn]=gen_sections($s);$ids=array_column($sec,'id');$pairCases++;
  must(!in_array('lan-tcp',$ids,true)&&!in_array('docker-net',$ids,true), 'wide INPUT bypass produced');
  must(!in_array('raw-drop',$ids,true), 'unscoped raw block produced');
 }
}
// LAN-only application presets must never become globally reachable.
$appCfg=S_def();$appCfg['apps']=['pihole','mysql','docker'];
[$blocks,$w]=gen_sections($appCfg);
must(!getsec($blocks,'apps'), 'LAN applications open to WAN with missing LAN');
$appCfg['apps']=['pihole','mysql','docker','wireguard'];
[$blocks,$w]=gen_sections($appCfg);
$appRules=(getsec($blocks,'apps')['rules'] ?? []);
must(count($appRules)===1&&str_contains($appRules[0],'--dport 51820')
     &&str_contains($appRules[0],'IPTM-app:wireguard'), 'VPN exception not explicit');
$appCfg['lan_nets']='192.168.50.0/24';
[$blocks,$w]=gen_sections($appCfg);
$appRules=implode("\n",getsec($blocks,'apps')['rules'] ?? []);
must(str_contains($appRules,'IPTM-app:mysql')&&str_contains($appRules,'-s 192.168.50.0/24')
     &&!str_contains($appRules,'IPTM-app:docker'), 'app source mismatch');
// A malformed /0 or a public CIDR must not become a trusted LAN source.
$w=[];$scope=iptm_trusted_lan_nets('0.0.0.0/0,8.8.8.0/24,192.168.50.9/24,192.168.50.0/24',$w);
must($scope==='192.168.50.0/24'&&count($w)===2,'LAN source validation broken: '.$scope);
$old='*filter' . "\n:INPUT DROP [0:0]\n";
$old.="# >>> IPTM:lan-tcp\n-A INPUT -s 192.168.50.0/24 -p tcp -j ACCEPT\n# <<< IPTM:lan-tcp\nCOMMIT\n";
must(iptm_reject_unsafe_rules($old)!=='','legacy generic TCP still accepted');
$old='*raw' . "\n:PREROUTING ACCEPT [0:0]\n# >>> IPTM:raw-drop\n-A PREROUTING -p udp --dport 1900 -j DROP\n# <<< IPTM:raw-drop\nCOMMIT\n";
must(iptm_reject_unsafe_rules($old)!=='','legacy raw not scoped');
$one='*filter' . "\n:INPUT DROP [0:0]\n# >>> IPTM:lockout\n-A INPUT -s 0.0.0.0/0 -p tcp --dport 22 -j ACCEPT\n# <<< IPTM:lockout\nCOMMIT\n";
must(iptm_reject_unsafe_rules($one)!=='','global management ACCEPT not blocked');
$good='*filter' . "\n:INPUT DROP [0:0]\n# >>> IPTM:lockout\n-A INPUT -s 192.168.50.0/24 -p tcp --dport 22 -j ACCEPT\n# <<< IPTM:lockout\nCOMMIT\n";
must(iptm_reject_unsafe_rules($good)==='','valid scoped management rejected');
if($errors){fwrite(STDERR,implode("\n",$errors)."\n");exit(1);}
echo 'PASS '.$cases.' exhaustive 14-toggle scenarios + '.$pairCases.' pair combinations, '.$assertions.' assertions, application scopes, regen ordering/idempotence'."\n";
