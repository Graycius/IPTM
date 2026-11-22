<?php
// ===================== BOOT / AUTENTICAZIONE =====================
session_set_cookie_params(['httponly' => true, 'samesite' => 'Strict', 'secure' => !empty($_SERVER['HTTPS']), 'path' => '/', 'lifetime' => 0]);
ini_set('session.use_strict_mode', '1');
ini_set('session.use_only_cookies', '1');
ini_set('session.cookie_httponly', '1');
session_name('iptmgr'); session_start();
iptm_security_headers(true);
if (!ip_ok()) { http_response_code(403); exit('Accesso negato da questo indirizzo (vedi ALLOWED_NETS).'); }
if (!empty($_SESSION['u']) && time() - (int)($_SESSION['t'] ?? time()) > IDLE_SECS) { $_SESSION = []; session_regenerate_id(true); }   // sessione scaduta per inattivita'
if (!empty($_SESSION['u'])) $_SESSION['t'] = time();
if (empty($_SESSION['csrf']) || !is_string($_SESSION['csrf']) || !preg_match('/^[a-f0-9]{64}$/D', $_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(32));

// API read-only con token in header, mai in URL — prima del login HTML
if (isset($_GET['api']) && function_exists('api_dispatch')) {
    api_dispatch((string)$_GET['api']);
}


if (!is_dir(DATA_DIR) || !is_writable(DATA_DIR)) {
    $u = function_exists('posix_getpwuid') ? posix_getpwuid(posix_geteuid())['name'] : 'www-data';
    exit(shell_page('Configurazione', '<h2>Cartella dati mancante</h2><p>Esegui come root:</p><pre>mkdir -p ' . h(DATA_DIR) . ' &amp;&amp; chown ' . h($u) . ': ' . h(DATA_DIR) . ' &amp;&amp; chmod 700 ' . h(DATA_DIR) . '</pre><p>poi ricarica la pagina.</p>'));
}
$uin = (string)(S_get()['ui_nets'] ?? '');   // restrizione opzionale (Sicurezza → Accesso alla gestione)
if ($uin !== '' && !ip_in_nets(preg_replace('/^::ffff:/', '', $_SERVER['REMOTE_ADDR'] ?? ''), $uin)) { http_response_code(403); exit('Accesso negato: indirizzo non incluso tra le reti di gestione.'); }
$authF = DATA_DIR . '/auth.json'; $tokF = DATA_DIR . '/setup-token.txt';

function shell_page(string $title, string $body): string {
    return '<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>' . h($title) . '</title><link rel="stylesheet" href="?iptm_asset=app.css&amp;v=' . APP_VERSION . '"><div class="wrap narrow">' . $body . '</div>';
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!hash_equals($_SESSION['csrf'], (string)($_POST['csrf'] ?? ''))) {
        if (($_POST['action'] ?? '')==='antidpi_sources' && ($_POST['source_async'] ?? '')==='1') {
            header('Content-Type: application/json; charset=utf-8');
            header('Cache-Control: no-store, private');
            http_response_code(419);
            echo json_encode(['ok'=>false,'error'=>'Token CSRF scaduto: ricarica IPTM e riprova. Nessun download avviato.']);
            exit;
        }
        http_response_code(400); exit('Token CSRF non valido: ricarica la pagina.');
    }
    $a = (string)($_POST['action'] ?? '');
    $bk = (string)($_POST['back'] ?? ''); $back = preg_match('/^[\w=&.%:-]*$/', $bk) ? $bk : 'p=status';
    if ($a === 'setup' && !users_get() && is_file($tokF)) {
        $pw = (string)($_POST['pw'] ?? '');
        if (!hash_equals(trim((string)file_get_contents($tokF)), trim((string)($_POST['token'] ?? '')))) flash('Codice di setup errato.', 'err');
        elseif (strlen($pw) < MIN_PW || $pw !== ($_POST['pw2'] ?? '')) flash('Password troppo corta (min ' . MIN_PW . ') o diversa dalla conferma.', 'err');
        else { users_put(['admin' => ['hash' => iptm_password_hash($pw), 'role' => 'admin', 'totp' => '']]); @unlink($tokF); flash('Password impostata: accedi.'); }
        go();
    }
    if ($a === 'login' && users_get()) {
        $ff = DATA_DIR . '/fails.json'; $ip = (string)($_SERVER['REMOTE_ADDR'] ?? 'unknown');
        $flock = fopen($ff . '.lock', 'c');
        if (!$flock || !flock($flock, LOCK_EX)) { if (is_resource($flock)) fclose($flock); http_response_code(503); exit('Rate-limit temporaneamente non disponibile'); }
        $stored = is_file($ff) ? @file_get_contents($ff) : null;
        $decoded = is_string($stored) ? json_decode($stored,true,64) : [];
        if (!is_array($decoded)) { flock($flock, LOCK_UN); fclose($flock); http_response_code(503); exit('Storico dei tentativi non valido: login sospeso, non azzerato'); }
        $fl = iptm_login_failures_prune($decoded,time(),$ip);
        $fl[$ip] ??= [];
        if (count($fl[$ip]) >= 5) { flock($flock, LOCK_UN); fclose($flock); flash('Troppi tentativi: riprova tra 10 minuti.', 'err'); go(); }
        $U = users_get(); $nm = strtolower(trim((string)($_POST['user'] ?? 'admin'))) ?: 'admin'; $u = $U[$nm] ?? null;
        $okp = iptm_password_verify((string)($_POST['pw'] ?? ''), is_array($u) ? (string)($u['hash'] ?? '') : null); $oko = $okp && $u && (empty($u['totp']) || totp_ok($u['totp'], (string)($_POST['otp'] ?? '')));
        if ($oko) { flock($flock, LOCK_UN); fclose($flock); session_regenerate_id(true); $_SESSION['u'] = $nm; $_SESSION['role'] = in_array($u['role'] ?? '', ['admin', 'viewer'], true) ? $u['role'] : 'viewer'; $_SESSION['csrf'] = bin2hex(random_bytes(32)); $_SESSION['t'] = time(); audit('login'); notify('login', "Accesso di $nm da $ip"); go('p=status'); }
        $fl[$ip][] = time(); $tmpf = $ff . '.' . bin2hex(random_bytes(5)) . '.tmp';
        $payload = json_encode($fl);
        if (!is_string($payload) || file_put_contents($tmpf, $payload, LOCK_EX) !== strlen((string)$payload) || !rename($tmpf, $ff)) { @unlink($tmpf); flock($flock, LOCK_UN); fclose($flock); http_response_code(503); exit('Impossibile aggiornare il rate-limit'); }
        flock($flock, LOCK_UN); fclose($flock); sleep(1); notify('loginfail', "Accesso fallito per «{$nm}» da $ip"); flash($okp ? 'Codice 2FA errato.' : 'Credenziali errate.', 'err'); go();
    }
    if ($a === 'logout') { session_destroy(); header('Location: ?p=status', true, 303); exit; }
}

function flashes(): string {
    $o = ''; foreach ($_SESSION['flash'] ?? [] as [$t, $m]) $o .= '<div class="msg ' . $t . '">' . h($m) . '</div>'; unset($_SESSION['flash']); return $o ? '<div id=toasts>' . $o . '</div>' : '';
}
if (!users_get()) {
    if (!is_file($tokF)) { file_put_contents($tokF, bin2hex(random_bytes(8))); chmod($tokF, 0600); }
    exit(shell_page('Setup', '<div class=card><h2>Prima configurazione</h2>' . flashes() . '<p>Per sicurezza leggi il codice di setup dal server:</p><pre>cat ' . h($tokF) . '</pre><form method=post><input type=hidden name=csrf value="' . h($_SESSION['csrf']) . '"><input type=hidden name=action value=setup>
<label class=fl><span>Codice di setup</span><input name=token required></label><label class=fl><span>Nuova password (min ' . MIN_PW . ' caratteri)</span><input type=password name=pw required></label><label class=fl><span>Conferma</span><input type=password name=pw2 required></label><button>Imposta password</button></form></div>'));
}
if (empty($_SESSION['u'])) {
    if (($_SERVER['REQUEST_METHOD'] ?? '')==='POST' && ($_POST['action'] ?? '')==='antidpi_sources' && ($_POST['source_async'] ?? '')==='1') {
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store, private');
        http_response_code(401);
        echo json_encode(['ok'=>false,'error'=>'Sessione IPTM scaduta: accedi nuovamente. Nessun download avviato.']);
        exit;
    }
    exit(shell_page('Accesso', '<div class=card><h2>🔥 iptables Manager</h2>' . flashes() . '<form method=post><input type=hidden name=csrf value="' . h($_SESSION['csrf']) . '"><input type=hidden name=action value=login><label class=fl><span>Utente</span><input name=user value=admin autocomplete=username></label><label class=fl><span>Password</span><input type=password name=pw autofocus required autocomplete=current-password></label><label class=fl><span>Codice 2FA (se attivo)</span><input name=otp inputmode=numeric autocomplete=one-time-code></label><button>Entra</button></form></div>'));
}
$iptmAccounts = users_get();
if (!isset($iptmAccounts[me()]) || !is_array($iptmAccounts[me()]) || empty($iptmAccounts[me()]['hash'])) {
    // Revoked accounts must not retain even read-only access via an old session.
    $_SESSION = [];
    session_regenerate_id(true);
    header('Location: ?p=status', true, 303);
    exit;
}
$_SESSION['role'] = in_array($iptmAccounts[me()]['role'] ?? '', ['admin','viewer'], true)
    ? $iptmAccounts[me()]['role'] : 'viewer';
unset($iptmAccounts);

/**
 * Import cleanup: discard comments and disabled (# -A ...) rules originating
 * from an old rules.v4. Never remove live rules, inline `--comment` match data,
 * or IPTM's paired managed-region boundaries needed for future regeneration.
 * Only invoked while importing, AFTER the portable bundle checksum is verified.
 * Does not change /etc/iptables/rules.v4 or the running kernel firewall.
 * @return array{draft:string,removed:int}
 */
function iptm_import_without_legacy_comments(string $draft): array {
    $removed = 0;
    $clean = preg_replace_callback('/^[ \t]*#[^\r\n]*(?:\r\n|\n|\r|$)/m',
        static function (array $match) use (&$removed): string {
            // IPTM uses these markers to locate, replace and remove managed blocks.
            if (preg_match('/^[ \t]*#[ \t]*(?:>>>|<<<)[ \t]+IPTM:/', $match[0])) return $match[0];
            $removed++;
            return '';
        }, $draft);
    if (!is_string($clean)) throw new RuntimeException('Pulizia commenti importati non riuscita');
    return ['draft' => $clean, 'removed' => $removed];
}

/** Single-file portable profile: secrets, session, credentials and privileged system files excluded. */
function iptm_export_config(): string {
    $S = S_get(); $blocked = '/(password|passwd|secret|private|api[_-]?key|^api_token$|^token$|^tg_token$|^tg_chat$|webhook|totp|virustotal|abuseipdb|greynoise|^otx$|urlscan|authorization)/i';
    $sanitize = function ($v) use (&$sanitize, $blocked) {
        if (!is_array($v)) return $v;
        $o = [];
        foreach ($v as $k => $x) if (!is_string($k) || !preg_match($blocked, $k)) $o[$k] = $sanitize($x);
        return $o;
    };
    $payload = ['settings' => $sanitize($S), 'draft_rules' => get_draft()];
    $encoded = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    return json_encode(['format'=>'iptm.config.v1', 'version'=>APP_VERSION, 'created'=>gmdate('c'),
       'sha256'=>hash('sha256', $encoded), 'payload'=>$payload,
       'notice'=>'Export portabile IPTM: token, utenti, CA private, WireGuard private key, database e configurazioni locali dei demoni NON inclusi. Non applica regole live.'],
       JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
}
function iptm_import_plan(string $raw): array {
    if (strlen($raw) > 5*1048576) throw new RuntimeException('Bundle oltre 5 MiB');
    $b = json_decode($raw, true, 64, JSON_THROW_ON_ERROR);
    if (!is_array($b) || ($b['format'] ?? '') !== 'iptm.config.v1' || !is_array($b['payload'] ?? null)) throw new RuntimeException('Formato importazione non riconosciuto');
    $p = $b['payload'];
    if (!is_array($p['settings'] ?? null) || !is_string($p['draft_rules'] ?? null)) throw new RuntimeException('Impostazioni/bozza mancanti');
    if (strlen($p['draft_rules']) > 3*1048576) throw new RuntimeException('Bozza troppo grande');
    $canonical = json_encode(['settings'=>$p['settings'], 'draft_rules'=>$p['draft_rules']], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    if (!preg_match('/^[a-f0-9]{64}$/D', (string)($b['sha256'] ?? '')) || !hash_equals($b['sha256'], hash('sha256',$canonical))) throw new RuntimeException('Checksum bundle non valido');
    $schema = S_def(); $current=S_get(); $new=$current;
    foreach ($p['settings'] as $key => $val) {
        if (!is_string($key) || !array_key_exists($key,$schema) || $key==='api_token') continue;
        if (in_array($key,['ti','notify'],true)) {
            if (!is_array($val)) throw new RuntimeException('Sezione settings non valida');
            // Never restore third-party secrets from untrusted portable files.
            $forbidden = ['tg_token','tg_chat','webhook','virustotal','abuseipdb','greynoise','otx','urlscan'];
            $safe=array_diff_key($val,array_flip($forbidden));
            $new[$key]=array_replace((array)($current[$key]??[]),$safe);
        } else $new[$key]=$val;
    }
    $new=settings_with_defaults($new);
    if (!in_array($new['iot_strategy'] ?? 'auto', ['auto','warden','iptm_zone','iptm_mac','none'], true)) $new['iot_strategy']='auto';
    // Never roll the on-disk schema version backward via a portable bundle.
    $new['settings_schema'] = max((int)($current['settings_schema'] ?? SETTINGS_SCHEMA),SETTINGS_SCHEMA);
    $clean = iptm_import_without_legacy_comments($p['draft_rules']);
    return ['settings'=>$new,'draft'=>$clean['draft'],'removed_comments'=>$clean['removed']];
}
/** Stream a root-generated DNS ZIP without storing it in PHP memory. CSRF and admin gate are outside. */
function iptm_dns_bundle_export_stream(string $passphrase): void {
    $tls = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
    $loopback = in_array((string)($_SERVER['REMOTE_ADDR']??''),['127.0.0.1','::1'],true);
    if (!$tls && !$loopback) { http_response_code(403); exit('Per esportare file DNS con credenziali usa HTTPS oppure la CLI SSH.'); }
    $cmd=[BIN_SUDO,'-n',HELPER,'dns-bundle','export-encrypted'];
    $proc=@proc_open($cmd,[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);
    if (!is_resource($proc)) { http_response_code(503); exit('Exporter DNS non disponibile'); }
    // Send the secret exclusively through a pipe; never include it in argv or log.
    fwrite($pipes[0], $passphrase . "\n"); fclose($pipes[0]); stream_set_timeout($pipes[1],600);
    // The root worker exports a complete encrypted OpenPGP file before stdout.
    $prefix='';
    while (strlen($prefix)<4 && !feof($pipes[1])) {
        $chunk=fread($pipes[1],4-strlen($prefix));
        if ($chunk===false) break;
        if ($chunk==='') { $meta=stream_get_meta_data($pipes[1]); if (!empty($meta['timed_out'])) break; continue; }
        $prefix.=$chunk;
    }
    if (strlen($prefix)!==4 || $prefix==="PK\x03\x04") {
        fclose($pipes[1]);$error=stream_get_contents($pipes[2],1200);fclose($pipes[2]);proc_close($proc);
        http_response_code(503);exit('Backup DNS non disponibile: '.h(substr((string)$error,0,200)));
    }
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="iptm-dns-config-'.APP_VERSION.'.zip.gpg"');
    header('Cache-Control: no-store, private');header('X-Content-Type-Options: nosniff');
    header('Content-Security-Policy: sandbox');
    if (function_exists('session_write_close')) session_write_close();
    echo $prefix;
    while (!feof($pipes[1]) && !connection_aborted()) {
        $chunk=fread($pipes[1],131072);
        if ($chunk===false) break;
        if ($chunk!=='') { echo $chunk; if (ob_get_level()>0) @ob_flush(); flush(); }
        else { $meta=stream_get_meta_data($pipes[1]); if (!empty($meta['timed_out'])) break; }
    }
    fclose($pipes[1]);fclose($pipes[2]);proc_close($proc);
    exit;
}

