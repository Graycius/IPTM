<?php
declare(strict_types=1);
function sys_ifaces():array{return $GLOBALS['_if']??[];}
require __DIR__.'/bootstrap.php';
require dirname(__DIR__).'/modules/42_policy_review.php';
$case=0;
function check5307(bool $pass,string $desc):void {
    global $case;$case++;
    if(!$pass){fwrite(STDERR,"FAIL $case $desc\n");exit(1);}
}
function section5307(array $secs,string $id):array{
    foreach($secs as $s)if($s['id']===$id)return $s;
    return ['rules'=>[],'pr'=>null];
}
$s=S_def();$s['wan_if']='eth0';$s['lan_if']='bond0';$s['lan_nets']='192.168.50.0/24';
$s['ssh_acc']=1;$s['ssh_nets']='192.168.50.0/24';$s['lockout_on']=1;$s['mgmt_ports']='22,80,443,8089';
$s['apps']=['borgmatic','pihole','adguard','unbound','dnsmasq','mysql','nextcloud'];
$s['wg_on']=1;$s['wg_lan']=1;$s['wg_if']='wg0';
$s['svc_in']=[['on'=>1,'src'=>'192.168.50.0/24','proto'=>'tcp','ports'=>'22,80,8080','act'=>'ACCEPT']];
$s['svc_fwd']=[['on'=>1,'oif'=>'wg0','act'=>'ACCEPT'],['on'=>1,'iif'=>'wg0','act'=>'ACCEPT'],['on'=>1,'dst'=>'172.16.0.0/12','ct'=>'RELATED,ESTABLISHED','act'=>'ACCEPT']];
$s['spi']=1;
$GLOBALS['_if']=['eth0'=>['8.8.8.2/24'],'bond0'=>['192.168.50.10/24']];
[$secs,$warnings]=gen_sections($s);
$wan=section5307($secs,'wan-rfc1918-input');
check5307(count($wan['rules'])===3,'RFC1918 WAN public protection 3 networks');
check5307(str_contains($wan['rules'][0],'-i eth0 -s 10.0.0.0/8 -j DROP'),'WAN pinning');
check5307(section5307($secs,'wan-rfc1918-forward')['pr']===0,'WAN spoof drop FORWARD priority');
$ssh=section5307($secs,'ssh-acc');$lock=section5307($secs,'lockout');
check5307($ssh['pr']<$lock['pr'],'SSH control before mgmt');
check5307(!str_contains(implode(' ',$lock['rules']),'--dports 22,'),'SSH removed from lockout');
check5307(str_contains(implode(' ',$lock['rules']),'-i bond0 -s 192.168.50.0/24'),'lockout interface pin');
check5307(str_contains(implode(' ',$ssh['rules']),'-i bond0 -s 192.168.50.0/24'),'SSH interface pin');
check5307(!str_contains(implode(' ',section5307($secs,'svc-in-a')['rules']),'--dports 22,'),'svc_input SSH removed');
check5307(str_contains(implode(' ',section5307($secs,'svc-in-a')['rules']),'--dports 80,8080'),'other services preserved');
check5307(!str_contains(implode(' ',section5307($secs,'apps')['rules']),'--dport 22'),'borgmatic SSH duplicate removed');
$app=implode("\n",section5307($secs,'apps')['rules']);
check5307(substr_count($app,'--dport 53')+substr_count($app,'--dports 53,')<=2,'DNS port aggregation');
check5307(str_contains($app,'IPTM-app:mysql'),'unshared app still present');
check5307(str_contains($app,'-i bond0 -s 192.168.50.0/24'),'application LAN ingress pinned');
check5307(section5307($secs,'svc-fwd')['rules']===[],'unsafe WG FWD + duplicate SPI/WG removed');
$s['wg_lan_to_vpn']=1;[$sec2]=gen_sections($s);
$wg=section5307($sec2,'wg-lan-to-vpn')['rules'];
check5307(count($wg)===1&&str_contains($wg[0],'-s 192.168.50.0/24 -o wg0 -j ACCEPT'),'explicit LAN->VPN only');
$s['single_nic']=1;$s['wan_if']='bond0';$s['lan_if']='';[$ss,$warnings]=gen_sections($s);
check5307(section5307($ss,'wan-rfc1918-input')['rules']===[],'shared WAN never RFC1918-drop');
check5307(str_contains(implode(' ',$warnings),'condivisa'),'shared warning');
$s['single_nic']=0;$s['wan_if']='eth0';$GLOBALS['_if']['eth0']=['192.168.2.2/24'];
[$ss,$warnings]=gen_sections($s);
check5307(section5307($ss,'wan-rfc1918-input')['rules']===[],'double NAT WAN no RFC1918 drop');
$GLOBALS['_if']['eth0']=['8.8.8.2/24','192.168.2.2/24'];[$ss]=gen_sections($s);
check5307(section5307($ss,'wan-rfc1918-input')['rules']===[],'mixed WAN cannot auto-drop');
$s['wan_if']='eth0 -j ACCEPT';$ss=iptm_safe_settings($s);check5307($ss['wan_if']==='','malicious WAN interface rejected');
check5307(iptm_scope_within_lan('192.168.50.21/32','192.168.50.0/24'),'source within net');
check5307(!iptm_scope_within_lan('192.168.60.0/24','192.168.50.0/24'),'unrelated private address not trusted');
$raw="*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n# >>> IPTM:lockout\n-A INPUT -s 192.168.50.0/24 -p tcp -m multiport --dports 22,80,443 -j ACCEPT\n# <<< IPTM:lockout\n# >>> IPTM:ssh-acc\n-A INPUT -s 192.168.50.0/24 -p tcp --dport 22 -m conntrack --ctstate NEW --syn -m recent --set -j ACCEPT\n# <<< IPTM:ssh-acc\n# >>> IPTM:svc-fwd\n-A FORWARD -o wg0 -j ACCEPT\n# <<< IPTM:svc-fwd\n# >>> IPTM:iot-001122334455\n-A FORWARD -m mac --mac-source 00:11:22:33:44:55 -j DROP\n# <<< IPTM:iot-001122334455\nCOMMIT\n";
$problems=iptm_policy_findings($raw,['lan_nets'=>'192.168.50.0/24','wg_if'=>'wg0','iot_policies'=>['00:11:22:33:44:55'=>['forward']]]);
$heads=implode('|',array_column($problems,'title'));
check5307(str_contains($heads,'SSH scavalca'),'detect legacy SSH bypass');
check5307(str_contains($heads,'FORWARD aperto indiscriminatamente'),'detect broad VPN');
check5307(str_contains($heads,'ACCEPT LAN senza interfaccia'),'detect missing ingress');
check5307(!str_contains($heads,'Salti MAC IoT incompleti'),'UI-managed MAC does not require Warden hook');
check5307(str_contains($heads,'livello 3'),'L2 warning');
check5307(count(iptm_policy_findings(str_repeat('x',2_100_000)))===1,'bounded audit fails closed');
check5307(iptm_policy_findings("*filter\n:INPUT DROP [0:0]\nCOMMIT\n")===[],'clean draft no fake issue');
check5307(!str_contains((string)file_get_contents(dirname(__DIR__).'/modules/41_performance_pages.php'),'intercept_http'),'legacy HTTP interception absent');
$S=S_def();$S['lan_nets']='192.168.50.0/24';$S['wan_if']='eth0';$S['single_nic']=0;
$GLOBALS['_if']['eth0']=['8.8.8.2/24'];
check5307(str_contains(iptm_scope_input_accept('-A INPUT -s 192.168.50.0/24 -p tcp --dport 445 -j ACCEPT',$S),'-i bond0'),'source matched to LAN instead of broad non-WAN');
check5307(!str_contains(iptm_scope_input_accept('-A INPUT -s 192.168.60.0/24 -p tcp --dport 445 -j ACCEPT',$S),'! -i eth0'),'unrelated subnet unchanged');
// The legacy draft must be rejected at apply preflight, not only in the UI.
check5307(str_contains(iptm_reject_unsafe_rules($raw),'non applicabile'),'legacy broad WG/SSH managed apply rejected');
$safe= str_replace('-A FORWARD -o wg0 -j ACCEPT','-A FORWARD -o wg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT',$raw);
$safe= str_replace('--dports 22,80,443','--dports 80,443',$safe);
check5307(iptm_reject_unsafe_rules($safe)==='','stateful VPN and safe lockout pass preflight');
$safeSsh=str_replace("# >>> IPTM:lockout\n-A INPUT -s 192.168.50.0/24 -p tcp -m multiport --dports 22,80,443 -j ACCEPT\n# <<< IPTM:lockout\n", '', $raw);
check5307(!str_contains(implode('|',array_column(iptm_policy_findings($safeSsh,['lan_nets'=>'192.168.50.0/24']),'title')),'SSH scavalca'),'audit SSH does not fabricate bypass when lockout absent');
$real=S_def();$real['coap_accept']=1;$real['dhcp_accept']=1;$real['lan_nets']='192.168.50.0/24';$real['wan_if']='eth0';$real['lan_if']='bond0';
[$sections]=gen_sections($real);
check5307(str_contains(implode(' ',section5307($sections,'coap-mdns')['rules']),'-i bond0 -s 192.168.50.0/24'),'CoAP binds to LAN not WAN');
check5307(str_contains(implode(' ',section5307($sections,'dhcp-in')['rules']),'-i bond0 -p udp'),'DHCP 0.0.0.0 is interface pinned');
echo "PASS policy-5307: $case tests\n";
