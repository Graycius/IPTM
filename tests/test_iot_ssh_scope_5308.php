<?php
declare(strict_types=1);
function sys_ifaces():array{return $GLOBALS['_if']??[];}
require __DIR__.'/bootstrap.php';
require dirname(__DIR__).'/modules/30_features_core.php';
require dirname(__DIR__).'/modules/42_policy_review.php';
$n=0;
function ck5308(bool $ok,string $name):void {global $n;$n++;if(!$ok){fwrite(STDERR,"FAIL #$n $name\n");exit(1);}}
function sect5308(array $all,string $id):array{foreach($all as $x)if(($x['id']??'')===$id)return $x['rules'];return [];}
$nets=['192.168.1.0/24','10.19.165.0/24','192.168.10.0/24'];
$GLOBALS['_if']=['eth0'=>['8.8.8.8/24'],'bond0'=>['192.168.1.165/24'],
               'wg0'=>['10.19.165.1/24'],'bond0.10'=>['192.168.10.165/24']];
$s=S_def();$s['wan_if']='eth0';$s['lan_if']='bond0';$s['lan_nets']=implode(',',$nets);
$s['ssh_acc']=1;$s['lockout_on']=1;$s['ssh_nets']='';$s['mgmt_ports']='22,80,443';
$s['svc_in']=[['on'=>1,'proto'=>'tcp','src'=>'192.168.10.0/24','ports'=>'22,139,445','act'=>'ACCEPT']];
$s['apps']=['dnsmasq','mysql','deconz'];
$macs=[];
for($i=1;$i<=14;$i++){$mac=sprintf('aa:bb:cc:00:11:%02x',$i);$macs[]=$mac;$s['iot_policies'][$mac]=['lan','dot','quic','vpn'];}
[$sections,$warn]=gen_sections($s);
$ssh=implode("\n",sect5308($sections,'ssh-acc'));
ck5308(count(sect5308($sections,'ssh-acc'))===10,'three protected SSH subnets plus established');
foreach([['192.168.1.0/24','bond0'],['10.19.165.0/24','wg0'],['192.168.10.0/24','bond0.10']] as [$cidr,$iface]) {
    ck5308(str_contains($ssh,'-i '.$iface.' -s '.$cidr.' -p tcp --dport 22'),'SSH subnet uses correct interface '.$cidr);
    ck5308(str_contains($ssh,'-i '.$iface.' -s '.$cidr.' -p tcp --dport 22 -m conntrack --ctstate NEW --syn -m recent'),'SSH recent scoped '.$cidr);
    ck5308(str_contains($ssh,'-i '.$iface.' -s '.$cidr.' -p tcp --dport 22 -m conntrack --ctstate NEW --syn -m connlimit'),'SSH connlimit scoped '.$cidr);
}
ck5308(str_contains($ssh,'--ctstate ESTABLISHED,RELATED -j ACCEPT'),'SSH established session preserved');
ck5308(!str_contains(implode(' ',sect5308($sections,'lockout')),'--dports 22,'),'lockout excludes SSH');
$svc=implode("\n",sect5308($sections,'svc-in-a'));
ck5308(str_contains($svc,'-i bond0.10 -s 192.168.10.0/24'),'SMB uses VLAN ingress');
ck5308(!str_contains($svc,'--dports 22,139,445'),'SMB scope no duplicate ssh port');
ck5308(count(array_filter($sections,fn($x)=>str_starts_with((string)$x['id'],'iot-')))==14,'fourteen UI IoT sections retained');
foreach($macs as $mac){$iot=sect5308($sections,'iot-'.str_replace(':','',$mac));
  ck5308(count($iot)===8,'IoT LAN3 + DoT2 + QUIC1 + VPN2 '.$mac); // corrected below if counts differ
  ck5308(str_contains(implode(' ',$iot),'--mac-source '.$mac),'MAC preserved '.$mac);
}
$raw="*filter\n:FORWARD DROP [0:0]\n";
foreach($sections as $sec){if(!str_starts_with((string)($sec['id']??''),'iot-'))continue;
  $raw.="# >>> IPTM:".$sec['id']." - UI\n".implode("\n",$sec['rules'])."\n# <<< IPTM:".$sec['id']."\n";}
$raw.="COMMIT\n";
$find=iptm_policy_findings($raw,$s);$titles=implode('|',array_column($find,'title'));

ck5308(!str_contains($titles,'Salti MAC'),'UI policies require no Warden hook');
ck5308(!str_contains($titles,'Policy IoT UI assenti'),'every saved IoT policy present');
ck5308(!str_contains($titles,'Regole MAC esterne'),'managed IoT not external');
$missing=$s;$missing['iot_policies'][$macs[0]]=['forward'];
$missingRaw=str_replace('# >>> IPTM:iot-'.str_replace(':','',$macs[0]).' - UI','# >>> IPTM:other-'.str_replace(':','',$macs[0]).' - UI',$raw);
ck5308(str_contains(implode('|',array_column(iptm_policy_findings($missingRaw,$missing),'title')),'Policy IoT UI assenti'),'missing UI block is detected');
$stale=$s;unset($stale['iot_policies'][$macs[0]]);
ck5308(str_contains(implode('|',array_column(iptm_policy_findings($raw,$stale),'title')),'Sezioni IoT da riconciliare'),'orphan section only warning, not removal');
$manual="*filter\n:FORWARD DROP [0:0]\n-A FORWARD -m mac --mac-source 11:22:33:44:55:66 -j DROP\nCOMMIT\n";
ck5308(str_contains(implode('|',array_column(iptm_policy_findings($manual,['iot_policies'=>[]]),'title')),'Regole MAC esterne'),'non-UI ACL marked external');
$shared=$s;$shared['single_nic']=1;$shared['wan_if']='bond0';
[$sc,$notes]=gen_sections($shared);
ck5308(sect5308($sc,'wan-rfc1918-input')===[],'shared NIC no destructive anti-spoof');
ck5308(count(array_filter($sc,fn($x)=>str_starts_with((string)$x['id'],'iot-')))==14,'shared NIC retains 14 IoT');
ck5308(!str_contains(implode(' ',sect5308($sc,'iot-'.str_replace(':','',$macs[0]))),'-i bond0'),'MAC controls not accidentally pinned to guessed LAN');
$noSsh=$s;$noSsh['mgmt_ports']='80,443';$noSsh['continuity_priority']=0;$noSsh['spi']=0;$noSsh['final_drop']=0;[$ns,$note]=gen_sections($noSsh);
ck5308(sect5308($ns,'ssh-acc')===[],'no invented SSH exception when excluded from management');
ck5308(str_contains(implode(' ',$note),'nessuna subnet attendibile'),'missing SSH subnet warns');
$bad=$s;$bad['iot_policies']['AA:BB:CC:00:11:01']=['quic',['malicious'],'forward'];
$bad['iot_policies']['../../bad']=['lan'];
$normalized=settings_with_defaults($bad);
ck5308(isset($normalized['iot_policies'][$macs[0]]),'uppercase MAC key normalized');
ck5308($normalized['iot_policies'][$macs[0]]===['forward'],'malformed nested flags ignored; forward dominant');
ck5308(!isset($normalized['iot_policies']['../../bad']),'malicious MAC key ignored');
$broken=$s;$broken['lan_nets']='';$broken['iot_policies']=[$macs[0]=>['lan']];
[$bc,$bw]=gen_sections($broken);
ck5308(sect5308($bc,'iot-'.str_replace(':','',$macs[0]))===[],'no phantom LAN block without subnet');
ck5308(str_contains(implode(' ',$bw),'manca una subnet LAN'),'missing LAN block warning');
ck5308(str_contains((string)file_get_contents(dirname(__DIR__).'/modules/15_apps_services.php'),'Deseleziona servizi senza listener'),'optional apps cleanup UI');
ck5308(str_contains((string)file_get_contents(dirname(__DIR__).'/modules/35_iot_zones_pages.php'),'Policy IoT salvate'),'IoT status visible in UI');
echo "PASS iot-ssh-5308: $n tests\n";
