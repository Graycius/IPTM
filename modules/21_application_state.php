<?php
// Anti-DPI staged import: browser stays on the page while the privileged
// worker finishes every HTTPS download. Expose only bounded domain chunks,
// after authentication, and never mutate a profile or firewall via GET.
if (($_SERVER['REQUEST_METHOD']??'')==='GET' && (string)($_GET['p']??'')==='dnsguard'
    && (isset($_GET['source_poll']) || isset($_GET['source_chunk']))) {
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store, private');
    header('X-Content-Type-Options: nosniff');
    if (($_SESSION['role']??'viewer')!=='admin') {http_response_code(403);echo '{"ok":false,"error":"Accesso negato"}';exit;}
    $engine=(string)($_GET['zapret_engine']??'');
    if(!in_array($engine,['zapret2','classic'],true)) {http_response_code(400);echo '{"ok":false,"error":"Motore non valido"}';exit;}
    if (isset($_GET['source_chunk'])) {
        $token=(string)($_GET['source_token']??'');
        $offset=(string)($_GET['source_offset']??'');
        if (!preg_match('/^[a-f0-9]{24}$/D',$token) || !preg_match('/^(?:0|[1-9][0-9]{0,7})$/D',$offset)) {
            http_response_code(400);echo '{"ok":false,"error":"Token o offset non valido"}';exit;
        }
        $command=['anti-dpi-sources','fetch',$token,$engine,$offset,'1000'];
    } else {
        $command=['anti-dpi-sources','status',$engine];
    }
    if(session_status()===PHP_SESSION_ACTIVE)session_write_close();
    [$exit,$response,$stderr]=run(array_merge([BIN_SUDO,'-n',HELPER],$command),null,10.0,1024*1024);
    $body=json_decode($response,true);
    if($exit!==0 || !is_array($body) || empty($body['ok'])) {
        http_response_code(503);
        echo json_encode(['ok'=>false,'error'=>(string)($body['error']??'Worker liste non disponibile')],JSON_UNESCAPED_UNICODE);
        exit;
    }
    echo json_encode($body,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR);exit;
}
// Lightweight Lynis polling: no page rendering, no APT/iptables status work.
if (($_SERVER['REQUEST_METHOD']??'')==='GET' && ($_GET['p']??'')==='health' && isset($_GET['lynis_poll'])) {
    if (($_SESSION['role']??'viewer')!=='admin') {http_response_code(403);exit('Accesso riservato');}
    if (session_status()===PHP_SESSION_ACTIVE) session_write_close();
    header('Cache-Control: private, no-store');
    header('Content-Type: application/json; charset=utf-8');
    [$rc,$raw]=priv('security',null,['lynis-status']);
    $status=json_decode((string)$raw,true);
    if ($rc!==0 || !is_array($status) || empty($status['ok'])) {
        http_response_code(503);echo '{"ok":false,"state":"unknown"}';exit;
    }
    echo json_encode($status,JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR);exit;
}
// Administrator-only diagnostic JSON/API; no session cookies in response body.
if (($_SERVER['REQUEST_METHOD']??'')==='GET' && (string)($_GET['p']??'')==='diag'
    && (isset($_GET['diag_poll']) || isset($_GET['diag_export']))) {
    if (($_SESSION['role']??'viewer')!=='admin') {http_response_code(403);exit('Accesso riservato');}
    $export=isset($_GET['diag_export']);
    if (session_status()===PHP_SESSION_ACTIVE) session_write_close();
    header('Cache-Control: private, no-store');
    header('X-Content-Type-Options: nosniff');
    header('Content-Type: application/json; charset=utf-8');
    if($export) header('Content-Disposition: attachment; filename="iptm-diagnostics.json"');
    [$rc,$data,$err]=run([BIN_SUDO,'-n',HELPER,'diag',$export?'snapshot':'status'],null,$export?45.0:8.0,1048576);
    if($rc!==0 || !is_array(json_decode($data,true))) {http_response_code(503);echo '{"ok":false,"error":"diagnostica non disponibile"}';exit;}
    echo $data;exit;
}
// ===================== STATO =====================
// A read-only fragment must not hold the PHP session lock while parsing the
// draft or invoking slow helper diagnostics; the session was authenticated above.
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'GET') {
    $fragment = (string)($_GET['fragment'] ?? '');
    if (in_array($fragment, ['status','stats','dnsaudit','health','zones','piholehealth'], true)
        && $fragment === (string)($_GET['p'] ?? '') && session_status() === PHP_SESSION_ACTIVE) {
        session_write_close();
    }
}
$draftTxt = get_draft(); $rev = hash('sha256',$draftTxt);
// Safe-by-default lazy model: only audited read-only pages can skip
// parsing the full firewall draft. Every unknown/legacy page preserves
// previous behavior so old UI routes never receive a missing $M model.
$iptmLightReadOnlyPages = ['status','stats','sqm','multinic','health','piholehealth','dnsaudit','progs','guide'];
$iptmNeedsRulesModel = ($_SERVER['REQUEST_METHOD'] ?? '') !== 'GET'
    || !in_array((string)($_GET['p'] ?? 'status'), $iptmLightReadOnlyPages, true);
$M = $iptmNeedsRulesModel ? parse_rules($draftTxt) : [];

function fh(?string $back = null): string {
    global $rev; return '<input type=hidden name=csrf value="' . h($_SESSION['csrf']) . '"><input type=hidden name=rev value="' . $rev . '"><input type=hidden name=back value="' . h($back ?? ($_SERVER['QUERY_STRING'] ?? '')) . '">';
}
function save_model() {
    global $M, $rev;
    $serialized = ser($M);
    if (!put_draft($serialized)) throw new RuntimeException('Impossibile salvare la bozza: spazio o permessi insufficienti.');
    $rev = hash('sha256',$serialized); // subsequent saves in this request use the new revision
}

