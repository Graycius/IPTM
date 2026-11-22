<?php
require __DIR__.'/bootstrap.php';
function guard5311(bool $ok,string $label): void {if(!$ok)throw new RuntimeException($label);}
function guard5311_rows(array $M,string $id): array {return iptm_dns_guard_sections($M)[$id]['rules']??[];}
$settings=S_def();
$settings['lan_nets']='192.168.1.0/24,10.19.165.0/24,192.168.10.0/24';
$settings['dns_ip']='192.168.1.165';
$settings['dns_redirect']=1;$settings['dot_block']=1;
$M=parse_rules("*filter\n:INPUT ACCEPT [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n*nat\n:PREROUTING ACCEPT [0:0]\n:INPUT ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\nCOMMIT\n");
regen($M,$settings);$disk=ser($M);
guard5311(count(guard5311_rows($M,'dot'))===6,'DoT six rules across three LANs');
guard5311(count(guard5311_rows($M,'dns-redir'))===6,'DNS six rules across three LANs');
guard5311(iptm_dns_guard_losses($disk,$disk)===[],'no false loss');
$off=$settings;$off['dot_block']=0;$off['dns_redirect']=0;
$draft=$M;$warnings=regen($draft,$off);
guard5311(guard5311_rows($draft,'dot')===guard5311_rows($M,'dot'),'ordinary regen preserves DoT');
guard5311(guard5311_rows($draft,'dns-redir')===guard5311_rows($M,'dns-redir'),'ordinary regen preserves DNS DNAT');
guard5311(str_contains(implode(' ',$warnings),'Preservate'),'regeneration warns if flags disagree');
$again=$draft;regen($again,$off);guard5311(ser($again)===ser($draft),'preservation idempotent');
$removed=$M;regen($removed,$off,true);
guard5311(guard5311_rows($removed,'dot')===[]&&guard5311_rows($removed,'dns-redir')===[],'explicit remove only');
guard5311(iptm_dns_guard_losses($disk,ser($removed))===['dot','dns-redir'],'detect both missing before apply');
[$res,$ids]=iptm_dns_guard_restore_plan($off,$disk);
guard5311($ids===['dot','dns-redir'] && $res['dot_block']===1 && $res['dns_redirect']===1 && $res['dns_ip']==='192.168.1.165','recover settings from disk');
$recovery=$removed;regen($recovery,$res);
guard5311(iptm_dns_guard_losses($disk,ser($recovery))===[],'recovered full firewall draft');
// Pre-5.30.9 already scoped by ingress: recovery must not invent a new interface.
$scoped=preg_replace('/(-A (?:FORWARD|PREROUTING)) -s /','$1 -i bond0 -s ',$disk);
[$res2,$ids2]=iptm_dns_guard_restore_plan($off,$scoped);
guard5311($ids2===['dot','dns-redir'],'recover scoping -i');
// Extra, malicious, duplicated, or foreign targets must never be silently trusted.
$broken=str_replace('-A FORWARD -s 192.168.1.0/24 -p tcp --dport 853 -j REJECT --reject-with tcp-reset',
    '-A FORWARD -s 0.0.0.0/0 -p tcp --dport 853 -j ACCEPT',$disk);
$refused=false;try{iptm_dns_guard_restore_plan($off,$broken);}catch(RuntimeException $e){$refused=true;}
guard5311($refused,'reject unexpected broad allow');
$broken=str_replace('192.168.1.165:53','8.8.8.8:53',$disk);
$refused=false;try{iptm_dns_guard_restore_plan($off,$broken);}catch(RuntimeException $e){$refused=true;}
guard5311($refused,'reject external DNS destination');
$foreign=$disk."\n-A FORWARD -s 0.0.0.0/0 -j ACCEPT\n";
guard5311(iptm_dns_guard_losses($disk,$foreign)===[],'unrelated manual rules do not change tracked IDs');
$ui=file_get_contents(dirname(__DIR__).'/modules/24_network_pages.php');
guard5311(str_contains($ui,"dd_radio(\$S, 'dot_block'")&&str_contains($ui,"dd_radio(\$S, 'dns_redirect'")&&str_contains($ui,'dns_guard_restore_disk'),'Setup exposes DNS guard toggles and restore button');
$controller=file_get_contents(dirname(__DIR__).'/modules/22_actions_controller.php');
guard5311(str_contains($controller,"'dns_guard_restore_disk' => 'system'"),'handler routes');
$transaction=file_get_contents(dirname(__DIR__).'/modules/11_firewall_transaction.php');
guard5311(str_contains($transaction,'iptm_dns_guard_losses(rules_live(),$txt)'),'apply guard checks persistent rules');
echo "PASS 5.30.12 DoT DNS loss-prevention and recovery\n";
