<?php
/* Dispatch after central CSRF/role gate. No live network mutation. */
if ($a==='diag_manage') {
    $back='p=diag';
    try {$request=iptm_diagnostic_request($_POST);} catch(InvalidArgumentException $e) {
        flash($e->getMessage(),'err');$request=null;
    }
    if($request!==null) {
        $op=$request['op'];
        [$rc,$out,$err]=run([BIN_SUDO,'-n',HELPER,'diag',$op],$request['payload'],12.0,16384);
        $result=$rc===0?json_decode($out,true):null;
        if(!is_array($result)||($result['ok']??false)!==true) {
            flash('Operazione diagnostica non riuscita (exit '.(int)$rc.'). '.($rc===124?'Timeout del worker: riprova dopo aver controllato la diagnostica.':'Verifica helper e stato del worker.'),'err');
        } else {
            flash($op==='start'?'Simulazione avviata. Controlla la barra di progresso.':($op==='clear'?'Report IPTM eliminati. Il journal di sistema non è stato cancellato.':'Operazione diagnostica completata.'));
        }
    }
}
