<?php
/* IPTM diagnostic maintenance: admin-only through central POST/CSRF gate. */
switch ($a) {
case 'diag_manage': {
    $back='p=diag';
    $op=(string)($_POST['diag_op']??'');
    if (!in_array($op,['start','clear'],true)) {flash('Operazione diagnostica non valida.','err');break;}
    $level=(string)($_POST['diag_level']??'preflight');
    if($op==='start' && !in_array($level,['schema','preflight','isolated'],true)) {flash('Livello diagnostico non valido.','err');break;}
    $payload=$op==='start' ? json_encode(['include_network'=>!empty($_POST['diag_network']),'level'=>$level],JSON_THROW_ON_ERROR) : null;
    [$rc,$out,$err]=run([BIN_SUDO,'-n',HELPER,'diag',$op],$payload,12.0,16384);
    $j=json_decode($out,true);
    if ($rc!==0 || !is_array($j) || empty($j['ok'])) {
       flash('Diagnostica non avviata: '.h((string)($j['error']??herr($out.$err))), 'err');break;
    }
    flash($op==='start'?'Simulazione avviata. Nessun cambiamento live, procedura monitorata nella barra di progresso.':'Report IPTM eliminati. Il journal di sistema non è stato cancellato.');
    break;
}
}
