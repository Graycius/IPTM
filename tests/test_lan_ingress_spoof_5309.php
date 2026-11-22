<?php
declare(strict_types=1);
function sys_ifaces(): array { return $GLOBALS['_if']??[]; }
require __DIR__.'/bootstrap.php';
$n=0;
function ck5309(bool $pass,string $msg):void {global $n;$n++;if(!$pass){fwrite(STDERR,"FAIL 5309 #$n $msg\n");exit(1);}}
function r5309(array $sections,string $id):string {foreach($sections as $x)if(($x['id']??'')===$id)return implode("\n",$x['rules']);return '';}
$GLOBALS['_if']=['eth0'=>['8.8.8.2/24'],'bond0'=>['192.168.1.165/24'],
    'wg0'=>['10.19.165.1/24'],'bond0.10'=>['192.168.10.165/24'],
    'ppp0'=>['1.1.1.1/24'],'eth1'=>['172.16.1.2/24']];
$s=S_def();$s['wan_if']='eth0';$s['lan_if']='bond0';
$s['lan_nets']='192.168.1.0/24,10.19.165.0/24,192.168.10.0/24';
$s['wan_rfc1918_spoof']=1;$s['ssh_acc']=1;$s['lockout_on']=1;
$s['ssh_nets']='192.168.1.0/24,10.19.165.0/24,192.168.10.0/24';
$s['mgmt_ports']='22,80,443';$s['lan_out_fwd']=1;
$s['masq_ifs']='eth0';$s['dns_redirect']=1;$s['dns_ip']='192.168.1.165';
$s['svc_in']=[['on'=>1,'src'=>'192.168.10.0/24','proto'=>'tcp','ports'=>'445','act'=>'ACCEPT']];
$s['svc_fwd']=[['on'=>1,'src'=>'192.168.10.0/24','dst'=>'1.2.3.4/32','proto'=>'tcp','ports'=>'443','act'=>'ACCEPT']];
[$sec,$warn]=gen_sections($s);
$ssh=r5309($sec,'ssh-acc');
foreach([['192.168.1.0/24','bond0'],['10.19.165.0/24','wg0'],['192.168.10.0/24','bond0.10']] as [$cidr,$iface]){
 ck5309(str_contains($ssh,'-i '.$iface.' -s '.$cidr),'correct SSH '.$iface);
 ck5309(str_contains(r5309($sec,'lan-out'),'-i '.$iface.' -s '.$cidr.' -j IPTM-LAN-EGRESS'),'FORWARD limited '.$iface);
 ck5309(str_contains(r5309($sec,'dns-redir'),'-i '.$iface.' -s '.$cidr),'DNS NAT limited '.$iface);
}
ck5309(str_contains(r5309($sec,'svc-in-a'),'-i bond0.10 -s 192.168.10.0/24'),'SMB INPUT restricted');
ck5309(str_contains(r5309($sec,'svc-fwd'),'-i bond0.10 -s 192.168.10.0/24'),'svc FORWARD restricted');
$input=r5309($sec,'wan-rfc1918-input');$forward=r5309($sec,'wan-rfc1918-forward');
ck5309(substr_count($input,'-i eth0')===3,'WAN three blocks');
ck5309(substr_count($forward,'-i eth0')===3,'WAN forward three blocks');
ck5309(str_contains($input,'-i eth0 -s 192.168.0.0/16 -j DROP'),'RFC1918 src drop');
$s['external_ifs']='ppp0,eth1,bond0,wg0';
$protected=iptm_external_spoof_ifaces($s);
ck5309($protected===['eth0','ppp0'],'only public untrusted interfaces');
[$sec,$warn]=gen_sections($s);
ck5309(substr_count(r5309($sec,'wan-rfc1918-input'),'-j DROP')===6,'two external ifaces INPUT');
ck5309(substr_count(r5309($sec,'wan-rfc1918-forward'),'-j DROP')===6,'two external ifaces FORWARD');
ck5309(str_contains(implode('|',$warn),'eth1'),'private external skipped with warning');
ck5309(!str_contains(r5309($sec,'wan-rfc1918-input'),'-i bond0'),'LAN not accidentally blocked');
ck5309(!str_contains(r5309($sec,'wan-rfc1918-input'),'-i wg0'),'VPN not accidentally blocked');
$s['external_ifs']='eth1'; // explicit but not verifiable: cannot use generic '! -i WAN'
$GLOBALS['_if']['bond0.10']=[];
ck5309(iptm_ingress_for_source('192.168.10.0/24',$s)==='', 'unknown LAN blocked from guessing !WAN with other externals');
$s['lan_ingress_map']='192.168.10.0/24=bond0.10';
ck5309(iptm_ingress_for_source('192.168.10.0/24',$s)==='-i bond0.10','manual scoped ingress with link up but no IP');
ck5309(v_ok('lanmap',$s['lan_ingress_map']),'manual map accepted');
foreach(['','192.168.1.0/24=bond0','192.168.1.0/24=bond0,10.19.165.0/24=wg0'] as $value)
 ck5309(v_ok('lanmap',$value),'valid mapping '.strlen($value));
foreach(['0.0.0.0/0=eth0','192.168.1.5/24=bond0','192.168.1.0/24=lo',
 '192.168.1.0/24=eth0;DROP','192.168.1.0/24=eth0,','192.168.1.0/24=eth0,192.168.1.0/24=bond0',
 '192.168.1.0/24=-eth0','192.168.1.0/24=eth0 -j ACCEPT',
 str_repeat('192.168.1.0/24=bond0,',80)] as $value)
 ck5309(!v_ok('lanmap',$value),'reject invalid/injection mapping '.substr($value,0,40));
ck5309(iptm_ingress_for_source('172.16.8.0/24',$s)==='','foreign source not trusted');
$s['lan_ingress_map']='192.168.1.0/24=eth0';
ck5309(iptm_ingress_for_source('192.168.1.0/24',$s)==='-i bond0','reject manually mapped WAN; infer actual LAN');
$s['lan_ingress_map']='192.168.1.0/24=bond0';$s['single_nic']=1;
ck5309(iptm_external_spoof_ifaces($s)===[],'shared network no spoof block');
ck5309(iptm_ingress_for_source('192.168.1.0/24',$s)==='','single nic no false ingress match');
$s['single_nic']=0;$s['external_ifs']='';$s['lan_ingress_map']='';
$GLOBALS['_if']['eth0']=['192.168.2.2/24'];
ck5309(iptm_external_spoof_ifaces($s)===[],'private WAN no RFC1918 blanket drop');
[$secs,$notes]=gen_sections($s);
ck5309(r5309($secs,'wan-rfc1918-input')==='','private WAN no spoof INPUT');
ck5309(str_contains(implode(' ', $notes),'NON attivato'),'private WAN warning');
$s['bogon_wan']=1;[$secs,$notes]=gen_sections($s);
ck5309(r5309($secs,'bogon-input')==='','bogon option no unsafe private WAN DROP');
ck5309(str_contains(implode(' ',$notes),'bogon_wan'),'unsafe bogon option disabled with warning');
$GLOBALS['_if']['eth0']=['8.8.8.2/24','192.168.2.2/24'];
ck5309(iptm_external_spoof_ifaces($s)===[],'mixed IP WAN no spoof');
$GLOBALS['_if']['eth0']=['8.8.8.2/24'];
$s['external_ifs']='eth0';
ck5309(iptm_external_spoof_ifaces($s)===['eth0'],'deduplicate external interfaces');
$s['external_ifs']='eth0 -j ACCEPT';
ck5309(!v_ok('ifs',$s['external_ifs']),'invalid external iface rejected');
ck5309(iptm_external_spoof_ifaces($s)===[],'invalid external config fails safely');
$s['external_ifs']='';
ck5309(iptm_scope_managed_rule('-A INPUT ! -s 192.168.1.0/24 -j ACCEPT',$s,'INPUT')==='-A INPUT ! -s 192.168.1.0/24 -j ACCEPT','negated source unchanged');
ck5309(iptm_scope_managed_rule('-A INPUT -s 192.168.1.0/24 -j DROP',$s,'INPUT')==='-A INPUT -s 192.168.1.0/24 -j DROP','DROP never modified by accept scoper');
ck5309(iptm_scope_managed_rule('-A POSTROUTING -s 192.168.1.0/24 -j MASQUERADE',$s,'PREROUTING',false)==='-A POSTROUTING -s 192.168.1.0/24 -j MASQUERADE','POSTROUTING not incorrectly bound');
ck5309(iptm_scope_managed_rule('-A INPUT -i bond0 -s 192.168.1.0/24 -j ACCEPT',$s,'INPUT')==='-A INPUT -i bond0 -s 192.168.1.0/24 -j ACCEPT','existing interface preserved');
ck5309(iptm_lan_ingress_map_valid('192.168.1.0/24=bond0'),'form saved mapping valid');
ck5309(str_contains((string)file_get_contents(dirname(__DIR__).'/modules/00_bootstrap.php'),"'external_ifs' => 'ifs', 'lan_ingress_map' => 'lanmap'"),'UI fields persisted');
ck5309(str_contains((string)file_get_contents(dirname(__DIR__).'/modules/24_network_pages.php'),'Anti-spoof RFC1918 attivabile su'),'UI shows effective spoof scope');
ck5309(str_contains((string)file_get_contents(dirname(__DIR__).'/modules/24_network_pages.php'),'ingresso non verificato'),'UI shows unresolved LAN');
echo "PASS lan-ingress-spoof-5309: $n tests\n";
