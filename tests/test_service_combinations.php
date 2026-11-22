<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';
$n=0;$checks=0;
$aliases=['missing'=>'','good'=>'8089','broken'=>'0:any','range'=>'8000:8010'];
$ports=['@missing','@good','@broken','@range','8089','', '0:65535','65536'];
$protocols=['tcp','udp','icmp',''];
$targets=['ACCEPT','DROP'];
$chains=['INPUT','FORWARD'];
$sources=['10.1.2.0/24','192.168.1.0/24',''];
foreach($ports as $port)foreach($protocols as $proto)foreach($targets as $target)foreach($chains as $chain)foreach($sources as $src){
 $row=['on'=>1,'proto'=>$proto,'ports'=>$port,'act'=>$target,'src'=>$src];
 $rules=svc_rules($chain,[$row],['ports'=>['good'=>'8089','broken'=>'0:any','range'=>'8000:8010']]);
 $n++;
 $effective = str_starts_with($port,'@') ? (['@good'=>'8089','@range'=>'8000:8010'][''.$port]??'') : $port;
 if(str_starts_with($port,'@')&&$effective===''){
    $checks++;if($rules)throw new RuntimeException('Unresolved alias became firewall rule: '.$port.' '.$chain.' '.$target);
 }
 if($port!==''&&$proto!=='tcp'&&$proto!=='udp'){
    $checks++;if($rules)throw new RuntimeException('Port ignored by protocol: '.$proto.' '.$port);
 }
 if($rules){
    $checks++;if(count($rules)!==1||!str_starts_with($rules[0],'-A '.$chain.' '))throw new RuntimeException('Misrouted chain');
    if($proto==='tcp'||$proto==='udp'){
      $checks++;if($effective!==''&&!str_contains($rules[0],'--dport'))throw new RuntimeException('Lost specified port');
    }
 }
}
// For invalid nested JSON, no error or new global FORWARD rule may result.
foreach ([['ports'=>[]],['proto'=>[]],['src'=>[]],['act'=>[]]] as $part) {
    $rows=[array_merge(['on'=>1,'proto'=>'tcp','ports'=>'22','src'=>'10.0.0.0/8','act'=>'ACCEPT'],$part)];
    $checks++;if(svc_rules('FORWARD',$rows,['ports'=>[]])!==[])throw new RuntimeException('Malformed row accepted');
}
echo "PASS scenarios=$n assertions=$checks\n";
