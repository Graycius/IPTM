<?php
// ===================== DOWNLOAD BACKUP =====================
if (isset($_GET['dl']) && is_string($_GET['dl']) && str_starts_with($_GET['dl'],'rules.v')) {
    if (($_SESSION['role'] ?? '') !== 'admin') { http_response_code(403); exit('Solo admin'); }
    try {$data=iptm_rules_backup_read($_GET['dl']);} catch(RuntimeException $e) {http_response_code(404);exit('Backup non disponibile');}
    header('Content-Type: text/plain'); header('Cache-Control: private, no-store'); header('X-Content-Type-Options: nosniff');
    header('Content-Disposition: attachment; filename="'.$_GET['dl'].'"'); echo $data; exit;
}
if (($_GET['dl'] ?? '') === 'config-bundle') {
    if (($_SESSION['role'] ?? '') !== 'admin') { http_response_code(403); exit('Solo admin'); }
    header('Content-Type: application/json; charset=utf-8'); header('Content-Disposition: attachment; filename="iptm-config-' . APP_VERSION . '.json"');
    header('Cache-Control: private, no-store'); header('X-Content-Type-Options: nosniff');
    echo iptm_export_config(); exit;
}
if (($_GET['dl'] ?? '') === 'traffic-ca') {
    [$c, $pem] = priv('traffic-ca');
    if ($c !== 0 || !str_contains($pem, 'BEGIN CERTIFICATE')) { http_response_code(404); exit('Certificato non disponibile'); }
    header('Content-Type: application/x-x509-ca-cert');
    header('Content-Disposition: attachment; filename="iptm-traffic-ca.pem"');
    header('Cache-Control: private, no-store'); header('X-Content-Type-Options: nosniff');
    echo $pem; exit;
}

// SQM job read-only JSON; no draft parse and no PHP session lock while polling.
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'GET' && ($_GET['p'] ?? '') === 'sqm'
    && ($_GET['fragment'] ?? '') === 'sqm-job') {
    if (session_status() === PHP_SESSION_ACTIVE) session_write_close();
    // Job status must not launch sudo on each poll: the former 12-second
    // helper deadline produced spurious timeout 124 on the Atom N450.
    $statusPath = DATA_DIR . '/sqm-manual-job.status';
    if (is_file($statusPath) && !is_link($statusPath) && is_readable($statusPath)
        && ($statusSize = @filesize($statusPath)) !== false && $statusSize <= 4096) {
        $out = (string)@file_get_contents($statusPath,false,null,0,4097); $rc = 0; $err = '';
        if(strlen($out)>4096){$rc=1;$out='';$err='Stato job troppo grande';}
        if ($out === '') { $rc = 1; $err = 'Stato job vuoto'; }
    } elseif (is_file($statusPath) || is_link($statusPath)) {
        $rc=1; $out=''; $err='Stato SQM non leggibile o non sicuro: controlla proprietà e permessi del file di stato.';
    } elseif (is_dir(DATA_DIR) && is_readable(DATA_DIR)) {
        $rc=0; $out='state=idle'; $err='';
    } else {
        $rc=1; $out=''; $err='Cartella dati SQM non leggibile: controlla le autorizzazioni sul DietPi.';
    }
    $map=[];
    foreach (preg_split('/\r?\n/', $out) as $line) {
        if (preg_match('/^(state|mode|exit|finished|started|message)=(.*)$/D', $line, $m))
            $map[$m[1]] = substr($m[2],0,350);
    }
    if ($rc === 0 && ($map['state'] ?? '') === 'running') {
        $started = (int)($map['started'] ?? 0);
        if ($started <= 0 || $started > time()+60 || time() - $started > 300) {
            $map = ['state'=>'failed','mode'=>'error','message'=>'Job SQM scaduto: controlla la diagnostica, limiti conservati'];
        }
    }
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store, private');
    $failure = trim($err . ' ' . $out);
    if ($rc !== 0) $failure = 'Helper SQM (exit ' . $rc . '): ' .
        ($failure !== '' ? herr(substr($failure, 0, 350)) : 'risposta non disponibile; verifica sudo -n /usr/local/sbin/iptm-helper sqm-calibrate-status da SSH');
    echo json_encode(['ok'=>$rc === 0, 'state'=>$rc === 0 ? ($map['state'] ?? 'unknown') : 'error',
        'mode'=>$map['mode'] ?? '', 'message'=>$rc === 0 ? ($map['message'] ?? '') : $failure],
        JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}

