<?php
declare(strict_types=1);
$dir=sys_get_temp_dir().'/iptm-cas-'.bin2hex(random_bytes(5));
if(!mkdir($dir,0700,true))throw new RuntimeException('Temp dir unavailable');
define('DATA_DIR',$dir);define('RULES_FILE',$dir.'/live.rules');
file_put_contents(RULES_FILE,"*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n");
require dirname(__DIR__) . '/modules/01_core_utilities.php';
function cas_assert($ok,$name){if(!$ok)throw new RuntimeException($name);echo "PASS $name\n";}
function cleanup_tree($dir){foreach(scandir($dir) as $p)if($p!=='.'&&$p!=='..')@unlink($dir.'/'.$p);@rmdir($dir);}
try {
  file_put_contents(DATA_DIR.'/draft.rules', 'A');
  cas_assert(get_draft()==='A','R01 snapshot obtained');
  file_put_contents(DATA_DIR.'/draft.rules', 'B');
  $rejected=false;
  try {put_draft('C');}catch(RuntimeException $e){$rejected=true;}
  cas_assert($rejected&&file_get_contents(DATA_DIR.'/draft.rules')==='B','R02 stale version rejected');
  cas_assert(get_draft()==='B' && put_draft('C') && file_get_contents(DATA_DIR.'/draft.rules')==='C','R03 atomic matching commit');
  cas_assert(iptm_draft_remove_if_same('B')===false,'R04 confirmed draft does not delete changed draft');
  cas_assert(file_get_contents(DATA_DIR.'/draft.rules')==='C','R05 conflicting draft preserved');
  if(!function_exists('pcntl_fork')) {echo "SKIP R06 concurrent two-writer transaction: pcntl absent\n";exit(0);}
  file_put_contents(DATA_DIR.'/draft.rules','base');
  $children=[];
  foreach(['X','Y'] as $id){
    $pid=pcntl_fork();if($pid===-1)throw new RuntimeException('fork failed');
    if($pid===0){
      $read=get_draft();
      file_put_contents(DATA_DIR.'/ready'.$id,'1');
      $deadline=microtime(true)+6;
      while(!is_file(DATA_DIR.'/go')&&microtime(true)<$deadline)usleep(2000);
      if(!is_file(DATA_DIR.'/go'))exit(3);
      try {$ok=put_draft($id);file_put_contents(DATA_DIR.'/result'.$id,$ok?'success':'failure');}
      catch(RuntimeException $e){file_put_contents(DATA_DIR.'/result'.$id,'conflict');}
      exit(0);
    }
    $children[$id]=$pid;
  }
  $deadline=microtime(true)+6;
  while((!is_file(DATA_DIR.'/readyX')||!is_file(DATA_DIR.'/readyY'))&&microtime(true)<$deadline)usleep(2000);
  cas_assert(is_file(DATA_DIR.'/readyX')&&is_file(DATA_DIR.'/readyY'),'R06 both writers started with same snapshot');
  file_put_contents(DATA_DIR.'/go','1');
  foreach($children as $pid)pcntl_waitpid($pid,$status);
  $results=[file_get_contents(DATA_DIR.'/resultX'),file_get_contents(DATA_DIR.'/resultY')];
  sort($results);
  cas_assert($results===['conflict','success'],'R07 concurrent CAS exactly one winner');
  $winner=file_get_contents(DATA_DIR.'/draft.rules');
  cas_assert(in_array($winner,['X','Y'],true),'R08 draft remains complete after racing writes');
}finally { cleanup_tree($dir); }
