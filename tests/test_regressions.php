<?php
declare(strict_types=1);
// No shell, kernel, network or external services are invoked by these tests.
function alias_map($s){return ['ports'=>[]];}
function list_sets($s){return [];}
function fq_parse($s){return [];}
$root = dirname(__DIR__);
require $root . '/modules/00_bootstrap.php';
require $root . '/modules/01_core_utilities.php';
require $root . '/modules/02_rule_model.php';
require $root . '/modules/03_rule_generation.php';
require $root . '/modules/12_policy_analysis.php';
function tested(string $name,bool $ok): void { echo ($ok?'PASS ':'FAIL ').$name."\n"; if (!$ok) exit(1); }
function throws(callable $f):bool {try{$f();return false;}catch(InvalidArgumentException $e){return true;}}
function jumpLines(array $rules):string {return implode("\n", $rules);}
// Brute-force lock history remains bounded without forgetting an active IP.
 $now=time();$entries=['192.168.1.10'=>[$now-900,$now-10,$now-2], '192.168.1.11'=>[$now-901], 'bad'=>[$now-1]];
 $clean=iptm_login_failures_prune($entries,$now,'192.168.1.10',100);
 tested('T26 login throttling prunes expired and invalid entries',count($clean)===1&&count($clean['192.168.1.10'])===2);
 $many=[];for($i=1;$i<=25;$i++)$many['fd00::'.dechex($i)]=[$now-$i];
 $many['fd00::1000']=[$now-1,$now-2,$now-3,$now-4,$now-5];
 $small=iptm_login_failures_prune($many,$now,'fd00::1000',3);
 tested('T27 login rate limit retains current blocked IP under eviction',isset($small['fd00::1000'])&&count($small['fd00::1000'])===5);
// strict CIDR parsing
 tested('T01 invalid mask cannot become /0', !ip_in_nets('203.0.113.5','192.168.1.0/not-a-number'));
 tested('T02 negative mask is invalid', !ip_in_nets('203.0.113.5','192.168.1.0/-1'));
 tested('T03 out-of-range prefix rejected', !ip_in_nets('192.168.1.5','192.168.1.0/33'));
 tested('T04 valid /24 matches', ip_in_nets('192.168.1.5','192.168.1.0/24'));
 tested('T05 valid /24 excludes other host', !ip_in_nets('192.168.2.5','192.168.1.0/24'));
 tested('T06 IPv6 prefix exact', iptm_ip6_in_nets('fd12::ff',['fd12::/16']));
 tested('T07 IPv6 prefix mismatch', !iptm_ip6_in_nets('fd13::ff',['fd12::/16']));
 tested('T08 IPv6 garbage mask rejected', !iptm_ip6_in_nets('fd12::1',['fd12::/bogus']));
 tested('T09 IPv6 /129 rejected', !iptm_ip6_in_nets('fd12::1',['fd12::/129']));
 tested('T10 IPv6 /0 matches', iptm_ip6_in_nets('2606:4700::1111',['::/0']));
// FORWARD unresolved aliases must not become no-port rules
 $rows=[['on'=>1,'proto'=>'tcp','ports'=>'@missing','act'=>'ACCEPT','src'=>'10.0.0.0/8']];
 tested('T11 unknown FORWARD alias cannot ACCEPT wildcard',svc_rules('FORWARD',$rows,['ports'=>[]]) === []);
 $rows[0]['act']='DROP';
 tested('T12 unknown FORWARD alias cannot DROP wildcard',svc_rules('FORWARD',$rows,['ports'=>[]]) === []);
 $rows[0]['ports']='@ok';$rows[0]['act']='ACCEPT';
 tested('T13 valid FORWARD alias preserved',strpos(jumpLines(svc_rules('FORWARD',$rows,['ports'=>['ok'=>'443']])),'--dport 443')!==false);
 $rows[0]['ports']='@invalid';
 tested('T14 malformed FORWARD port alias rejected',svc_rules('FORWARD',$rows,['ports'=>['invalid'=>'bad']]) === []);
 $rows[0]['proto']='all';$rows[0]['ports']='443';
 tested('T15 port cannot be discarded by a non-port protocol',svc_rules('FORWARD',$rows,['ports'=>[]]) === []);
// legacy settings that encode arbitrary types must not throw or open ports
 $s=S_def();$s['lan_nets']=['10.0.0.0/8'];$s['final_drop']=[];
 $s['svc_in']=[['on'=>1,'proto'=>'tcp','ports'=>['0:65535'],'src'=>'10.0.0.0/8'],['on'=>1,'proto'=>'tcp','ports'=>'8443','src'=>'10.0.0.0/8']];
 $fixed=settings_with_defaults($s);
 tested('T16 invalid scalar restored to default',is_string($fixed['lan_nets'])&&$fixed['lan_nets']==='');
 tested('T17 invalid integer restored to default',is_int($fixed['final_drop']));
 tested('T18 malformed service dropped, valid retained',count($fixed['svc_in'])===1 && $fixed['svc_in'][0]['ports']==='8443');
// Prevent unsafe apply with unknown uplink (but do not regress legitimate explicit host-mode)
 $txt="*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n";
 $s=S_def();$s['lan_nets']='192.168.50.0/24';$s['wan_if']='';$s['masq_ifs']='';$s['continuity_priority']=1;
 $result=iptm_client_navigation_gate($txt,$s);
 tested('T19 unsafe unknown uplink blocks apply',str_contains($result['block'],'Applicazione sospesa'));
 $s['continuity_priority']=0;
 tested('T20 opt-out reports warning, no mandatory block',iptm_client_navigation_gate($txt,$s)['block']==='');
 $s['continuity_priority']=1;$txt=str_replace(':FORWARD DROP',':FORWARD ACCEPT',$txt);
 tested('T21 allow-default forward reports without block',iptm_client_navigation_gate($txt,$s)['block']==='');
// Root-executed downloads are HTTPS-only; local archive upload remains available.
 tested('T22 HTTPS URL accepted',iptm_update_url_parts('https://example.com/update.zip')['scheme']==='https');
 tested('T23 HTTP LAN update accepted',iptm_update_url_parts('http://example.com/update.zip')['scheme']==='http');
 tested('T24 HTTPS->HTTP redirect rejected',throws(fn()=>iptm_update_redirect_target('https://example.com/a.zip','http://example.com/b.zip')));
 $s=S_def();$s['lan_nets']='192.168.50.0/24';$s['wan_if']='eth0';$s['lan_if']='br0';$s['apps']=[];
 [$sections,$warnings]=gen_sections($s);
 tested('T25 normal rule generator succeeds',is_array($sections)&&count($sections)>0);
// The original input-file incident: sshbf's recent/connlimit must NOT count
// existing SSH data packets; new SYN must be checked before any LAN management ACCEPT.
 $s=S_def(); $s['ssh_acc']=1; $s['ssh_nets']='192.168.1.0/24';
 $s['lockout_on']=1; $s['lan_nets']='192.168.1.0/24';
 $s['continuity_priority']=1; [$sections,$warnings]=gen_sections($s);
 $ssh=array_values(array_filter($sections,fn($x)=>$x['id']==='ssh-acc'))[0]??[];
 $lock=array_values(array_filter($sections,fn($x)=>$x['id']==='lockout'))[0]??[];
 $sn=$ssh['rules']??[];
 tested('T28 established SSH has unconditional session protection',count(array_filter($sn,fn($x)=>str_contains($x,'--ctstate ESTABLISHED,RELATED')&&str_contains($x,'-j ACCEPT')))===1);
 tested('T29 SSH recent/connlimit only count NEW SYN',count(array_filter($sn,fn($x)=>(str_contains($x,'-m recent')||str_contains($x,'-m connlimit'))&&!str_contains($x,'--ctstate NEW --syn')))===0);
 tested('T30 SSH rate limiter precedes management exemptions and excludes port 22',($ssh['pr']??99)<($lock['pr']??0) && !str_contains(implode("\n", $lock['rules']??[]),'--dport 22') && !preg_match('/--dports [^\n]*\b22\b/', implode("\n",$lock['rules']??[])));
 $s['continuity_priority']=0; [$sections,$warnings]=gen_sections($s);
 $ssh=array_values(array_filter($sections,fn($x)=>$x['id']==='ssh-acc'))[0]??[];
 tested('T31 legacy mode still protects established SSH',count(array_filter($ssh['rules']??[],fn($x)=>str_contains($x,'--ctstate ESTABLISHED,RELATED')))===1);
 tested('T32 HTTP to HTTPS redirect accepted',iptm_update_redirect_target('http://example.com/a.zip','https://example.com/b.zip')==='https://example.com/b.zip');
 tested('T33 HTTP to HTTP redirect accepted',iptm_update_redirect_target('http://example.com/a.zip','/b.zip')==='http://example.com/b.zip');
 tested('T34 URL credentials rejected',throws(fn()=>iptm_update_url_parts('http://admin:pass@example.com/a.zip')));
 tested('T35 loopback DNS update server refused',throws(fn()=>iptm_update_curl_pin('127.0.0.1',80)));
 echo "PASS: 35 targeted security and correctness regressions\n";
