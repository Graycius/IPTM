<?php
// ===================== DOWNLOAD BACKUP =====================
if (isset($_GET['dl']) && preg_match('/^rules\.v[46]\.\d{8}-\d{6}$/D', (string)$_GET['dl'])) {
    if (($_SESSION['role'] ?? '') !== 'admin') { http_response_code(403); exit('Solo admin'); }
    $base = realpath(DATA_DIR . '/backups');
    $path = $base !== false ? realpath(DATA_DIR . '/backups/' . $_GET['dl']) : false;
    if ($base === false || $path === false || !str_starts_with($path, $base . DIRECTORY_SEPARATOR) || !is_file($path) || is_link(DATA_DIR . '/backups/' . $_GET['dl'])) {
        http_response_code(404); exit('Backup non trovato');
    }
    header('Content-Type: text/plain'); header('Cache-Control: private, no-store'); header('X-Content-Type-Options: nosniff');
    header('Content-Disposition: attachment; filename="' . basename($path) . '"');
    header('X-Content-Type-Options: nosniff');
    readfile($path); exit;
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
        $out = (string)@file_get_contents($statusPath); $rc = 0; $err = '';
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
        if ($started <= 0 || time() - $started > 300) {
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

