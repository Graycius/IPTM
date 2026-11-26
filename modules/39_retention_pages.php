<?php
/** Retention workspace; only fixed typed helper operations, never direct disk access. */
function iptm_retention_fields(): array {
    return ['backup_days'=>['Backup automatici: giorni',7,730], 'backup_keep'=>['Backup protetti per categoria',3,100], 'report_days'=>['Report diagnostici/Lynis: giorni',7,365], 'report_keep'=>['Report recenti protetti',3,100], 'stats_days'=>['Statistiche: giorni',14,365], 'max_backup_mib'=>['Budget backup automatici (MiB)',128,65536], 'log_copies'=>['Archivi log IPTM compressi',3,90]];
}
function iptm_retention_value(mixed $v): int|false {
    return is_int($v)||(is_string($v)&&preg_match('/^[0-9]{1,8}$/D',$v))?filter_var($v,FILTER_VALIDATE_INT):false;
}
function pg_retention(): void {
    $admin=($_SESSION['role']??'')==='admin';$status=iptm_view_probe('retention',['status']);
    iptm_view_start('Ultima rotazione','Timer giornaliero iptm-retention.timer. Non rimuove backup manuali, configurazioni attive, recuperi pendenti o log di altri programmi.');
    if(empty($status['ok'])){iptm_view_error((string)$status['error']);iptm_view_end();return;}
    $last=(array)($status['last_run']??[]);$rows=[];
    foreach(['time'=>'Ultima esecuzione UTC','deleted'=>'Elementi eliminati','reclaimed_bytes'=>'Byte recuperati','logs'=>'Rotazione log IPTM'] as $k=>$label)$rows[]=[$label,$last[$k]??'Non ancora eseguita'];
    iptm_view_table(['Indicatore','Valore'],$rows,'Risultati dell’ultima esecuzione');
    foreach((array)($last['warnings']??[]) as $msg)echo '<p class="msg warn">'.iptm_view_text($msg).'</p>';
    foreach((array)($last['errors']??[]) as $msg)echo '<p class="msg err">'.iptm_view_text($msg).'</p>';
    iptm_view_end();
    iptm_view_start('Politica di conservazione','La rotazione protegge sempre i backup più recenti. In caso di quota superata considera solo backup con almeno 24 ore di età.');
    $policy=(array)($status['policy']??[]);$valid=true;
    foreach(iptm_retention_fields() as $k=>[$label,$min,$max]){ $n=iptm_retention_value($policy[$k]??null); if($n===false||$n<$min||$n>$max)$valid=false; }
    if(!$valid)echo '<p class="msg warn">Politica incompleta o non valida: salvataggio disabilitato per non sostituire impostazioni sconosciute.</p>';
    if($admin&&$valid)iptm_view_form('retention','retention_save');
    foreach(iptm_retention_fields() as $k=>[$label,$min,$max]){
        $id='iptm-ret-'.$k;
        echo '<div class="iptm-workspace-field"><label for="'.h($id).'">'.iptm_view_text($label).'</label><input id="'.h($id).'" type="number" name="'.h($k).'" value="'.h(iptm_retention_value($policy[$k]??null)===false?'':$policy[$k]).'" min="'.$min.'" max="'.$max.'" required'.($admin&&$valid?'':' disabled').'></div>';
    }
    if($admin&&$valid)iptm_view_submit('Salva politica');
    iptm_view_end();
    iptm_view_start('Anteprima e manutenzione','Calcola gli elementi eliminabili senza cancellarli. La rotazione reale opera in background con la politica salvata, non con un elenco fissato dall’anteprima.');
    echo iptm_view_link('retention','Calcola anteprima',['preview'=>'1']);
    if(($_GET['preview']??'')==='1'){
        $view=iptm_view_probe('retention',['preview']);
        if(empty($view['ok']))iptm_view_error((string)$view['error']);else{
            echo '<p>'.(int)($view['total']??0).' elementi · '.number_format((int)($view['reclaim_bytes']??0)/1048576,2,',','.').' MiB recuperabili.</p>';
            $rows=[];foreach((array)($view['groups']??[]) as $group=>$row)if(is_array($row))$rows[]=[$group,$row['items']??null,number_format((int)($row['bytes']??0)/1048576,2,',','.')];
            iptm_view_table(['Categoria','Elementi','MiB'],$rows,'Elementi eliminabili');
            foreach((array)($view['warnings']??[]) as $w)echo '<p class="msg warn">'.iptm_view_text($w).'</p>';
        }
    }
    if($admin){iptm_view_form('retention','retention_run');iptm_view_submit('Esegui rotazione in background','s');}
    iptm_view_end();
}
