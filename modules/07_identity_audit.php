<?php
// ===================== v2: UTENTI, 2FA, AUDIT, NOTIFICHE =====================
function me(): string { return (string)($_SESSION['u'] ?? 'sistema'); }
function audit(string $m): void {
    // Centralized rotation: iptm-retention.timer + logrotate (copytruncate).
    $f = DATA_DIR . '/audit.log';
    @file_put_contents($f, date('c') . "\t" . me() . "\t" . ($_SERVER['REMOTE_ADDR'] ?? '-') . "\t" . '[rid=' . iptm_request_id() . '] ' . str_replace(["\t", "\n", "\r", "\0"], ' ', $m) . "\n", FILE_APPEND | LOCK_EX);
}
function users_get(): array {
    $f = DATA_DIR . '/users.json';
    if (is_file($f)) {
        $raw = @file_get_contents($f);
        if (!is_string($raw)) throw new RuntimeException('Utenti non leggibili');
        $u = json_decode($raw, true);
        if (!is_array($u)) throw new RuntimeException('File utenti non valido: correzione manuale necessaria');
        $GLOBALS['_users_read_sha'] = hash('sha256', $raw);
        return $u;
    }
    $GLOBALS['_users_read_sha'] = hash('sha256', '');
    $a = DATA_DIR . '/auth.json';
    if (is_file($a)) {
        $h = (json_decode((string)file_get_contents($a), true)['hash'] ?? '');
        if ($h) { $u = ['admin' => ['hash' => $h, 'role' => 'admin', 'totp' => '']]; users_put($u); return $u; }
    }
    return [];
}
function users_put(array $u): void {
    if (!is_dir(DATA_DIR) && !@mkdir(DATA_DIR, 0700, true) && !is_dir(DATA_DIR)) throw new RuntimeException('Directory utenti non disponibile');
    $f = DATA_DIR . '/users.json';
    $data = json_encode($u, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR);
    $lock = @fopen(DATA_DIR . '/users.lock', 'c');
    if (!$lock || !@flock($lock, LOCK_EX)) throw new RuntimeException('Lock utenti non disponibile');
    try {
        $prev = @file_get_contents($f);
        if (!is_string($prev) && is_file($f)) throw new RuntimeException('Utenti non leggibili');
        if (!is_string($prev)) $prev = '';
        $expected = $GLOBALS['_users_read_sha'] ?? null;
        if ($expected !== null && !hash_equals($expected, hash('sha256', $prev)))
            throw new RuntimeException('Conflitto utenti: un altro amministratore ha modificato gli account. Ricarica.');
        if (!atomic_data_write($f, $data, 0600)) throw new RuntimeException('Scrittura utenti fallita');
        $GLOBALS['_users_read_sha'] = hash('sha256', $data);
    } finally { @flock($lock, LOCK_UN); @fclose($lock); }
}
function b32enc(string $b): string { $A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; $bits = ''; foreach (str_split($b) as $c) $bits .= str_pad(decbin(ord($c)), 8, '0', STR_PAD_LEFT); $o = ''; foreach (str_split($bits, 5) as $ch) $o .= $A[bindec(str_pad($ch, 5, '0'))]; return $o; }
function b32dec(string $s): string {
    $A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; $bits = ''; foreach (str_split(strtoupper(rtrim($s, '='))) as $c) { $p = strpos($A, $c); if ($p !== false) $bits .= str_pad(decbin($p), 5, '0', STR_PAD_LEFT); }
    $o = ''; foreach (str_split($bits, 8) as $b) if (strlen($b) === 8) $o .= chr(bindec($b)); return $o;
}
function totp_code(string $secret, ?int $t = null, int $off = 0): string {
    $c = intdiv($t ?? time(), 30) + $off; $h = hash_hmac('sha1', pack('J', $c), b32dec($secret), true); $o = ord($h[19]) & 15;
    $v = ((ord($h[$o]) & 0x7f) << 24) | (ord($h[$o + 1]) << 16) | (ord($h[$o + 2]) << 8) | ord($h[$o + 3]); return str_pad((string)($v % 1000000), 6, '0', STR_PAD_LEFT);
}
function totp_ok(string $secret, string $code): bool { if (!preg_match('/^[0-9]{6}$/D', $code)) return false; foreach ([-1, 0, 1] as $o) if (hash_equals(totp_code($secret, null, $o), $code)) return true; return false; }
function notify_cfg(): array { $n = S_get()['notify'] ?? []; return $n + ['tg_token' => '', 'tg_chat' => '', 'webhook' => '', 'ev' => [], 'rule_on' => 0, 'rule_min' => 20, 'rule_patterns' => 'DROP,REJECT,IPTM-DROP,IPTM-IN,IPTM-OUT,CROWDSEC']; }
function rule_alerts_write(array $n): void {
    $f = DATA_DIR . '/rule-alerts.conf';
    $on = !empty($n['rule_on']) ? 1 : 0;
    $min = max(1, min(1000000, (int)($n['rule_min'] ?? 20)));
    $pat = preg_replace('/[^A-Za-z0-9_,\-]/', '', (string)($n['rule_patterns'] ?? 'DROP,REJECT'));
    $txt = "RULE_ALERTS_ON=$on\nRULE_ALERT_MIN=$min\nRULE_ALERT_PATTERNS=$pat\n";
    if (!atomic_data_write($f, $txt, 0640)) throw new RuntimeException('Scrittura configurazione alert fallita');
}
function notify(string $ev, string $msg): void {
    $c = notify_cfg();
    if (!in_array($ev, $c['ev'], true) || !is_executable('/usr/bin/curl')) return;
    $title = '[' . gethostname() . '] ' . $msg;
    $requests = [];
    if ($c['tg_token'] !== '' && $c['tg_chat'] !== '') {
        $requests[] = ['https://api.telegram.org/bot' . $c['tg_token'] . '/sendMessage',
                       ['chat_id' => (string)$c['tg_chat'], 'text' => $title]];
    }
    if ($c['webhook'] !== '' && str_starts_with($c['webhook'], 'https://')) {
        $requests[] = [$c['webhook'], ['message' => $title]];
    }
    foreach ($requests as [$url, $fields]) {
        // Private URL and bot token travel only over stdin (curl --config -), not process argv.
        $cmd = ['/usr/bin/curl', '--silent', '--show-error', '--max-time', '8',
                '--proto', '=https', '--proto-redir', '=https', '--output', '/dev/null',
                '--config', '-'];
        $descriptors = [0 => ['pipe','r'], 1 => ['file','/dev/null','w'], 2 => ['file','/dev/null','w']];
        $pipes = [];
        $proc = @proc_open($cmd, $descriptors, $pipes, null, null, ['bypass_shell' => true]);
        if (!is_resource($proc)) continue;
        // curl config strings understand only \\ \" \t \n \r \v: JSON \uXXXX escapes are NOT
        // decoded, so accented text («», è, à, —) must stay literal UTF-8. Other control
        // characters are dropped; an unencodable value skips this request instead of
        // sending a malformed config.
        $curlQuote = static function (string $text): ?string {
            $text = preg_replace('/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/', '', $text) ?? '';
            $q = json_encode($text, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
                | JSON_UNESCAPED_LINE_TERMINATORS | JSON_INVALID_UTF8_SUBSTITUTE);
            return is_string($q) ? $q : null;
        };
        $config = null;
        $quotedUrl = $curlQuote($url);
        if ($quotedUrl !== null) {
            $config = 'url = ' . $quotedUrl . "\n" . "request = \"POST\"\n";
            foreach ($fields as $key => $value) {
                $quotedField = $curlQuote($key . '=' . $value);
                if ($quotedField === null) { $config = null; break; }
                $config .= 'data-urlencode = ' . $quotedField . "\n";
            }
        }
        if ($config === null) { @fclose($pipes[0]); @proc_close($proc); continue; }
        @fwrite($pipes[0], $config);
        @fclose($pipes[0]);
        @proc_close($proc);
    }
}

function notify_env(array $c): void {   // letto da helper: rollback, watch, rule-alerts
    $f = DATA_DIR . '/notify.env';
    // credenziali sempre se configurate: servono a rollback, watch e alert regole
    $tok = (string)($c['tg_token'] ?? ''); $chat = (string)($c['tg_chat'] ?? ''); $wh = (string)($c['webhook'] ?? '');
    foreach ([$tok, $chat, $wh] as $value) if (preg_match('/[\x00-\x1f\x7f\x27]/', $value)) throw new InvalidArgumentException('Credenziale di notifica non valida');
    if (!atomic_data_write($f, "TG_TOKEN='" . $tok . "'\nTG_CHAT='" . $chat . "'\nWEBHOOK='" . $wh . "'\n", 0600)) throw new RuntimeException('Scrittura configurazione notifiche fallita');
}
function post_hooks(string $a): void {
    static $AUD = ['rule_save', 'rule_op', 'wizard_add', 'chain_op', 'raw_save', 'settings_save', 'apply', 'confirm', 'revert', 'save_file', 'import_apply', 'import_skip', 'settings_reset', 'backend_set', 'strip_managed', 'rules_cleanup_apply', 'custom_rules_integrate', 'custom_rules_delete', 'chpw',
        'user_add', 'user_del', 'user_role', 'user_reset2fa', 'totp_on', 'totp_off', 'restore_backup', 'settings_rollback', 'advise_apply', 'draft_reset', 'factory_reset', 'apps_save', 'reset_minimal', 'lists_apply', 'block_ip', 'conn_kill', 'speed_profile', 'sqm_save', 'sqm_safe_confirm', 'sqm_safe_revert', 'sqm_review_claim', 'sqm_sync', 'sqm_calibrate', 'sqm_autocal_on', 'sqm_autocal_off', 'sqm_auto', 'v6_save', 'v6_raw', 'v6_apply', 'v6_write', 'zero_apply', 'notify_save', 'forward_sysctl', 'api_token_save', 'api_token_gen', 'cs_bouncer_setup_rec', 'cs_bouncer_set_only', 'policy_export', 'wg_mgmt_nets', 'rules_compact_safe', 'dns_unbound_profile', 'dns_service', 'dnscrypt_config', 'dns_stack'];
    if (!in_array($a, $AUD, true)) return;
    $err = false; foreach ($_SESSION['flash'] ?? [] as [$t]) if ($t === 'err') $err = true;
    audit($a . ($err ? ' (errore)' : '')); if ($err) return;
    $N = ['apply' => ['apply', 'Regole applicate in prova (serve conferma)'], 'v6_apply' => ['apply', 'Regole IPv6 applicate in prova'], 'confirm' => ['confirm', 'Configurazione confermata e salvata'], 'revert' => ['revert', 'Applicazione annullata manualmente'],
        'save_file' => ['confirm', 'File regole salvato'], 'import_apply' => ['apply', 'Importazione regole eseguita'], 'zero_apply' => ['apply', 'Configurazione guidata creata'], 'backend_set' => ['apply', 'Backend iptables cambiato']];
    if (isset($N[$a])) notify($N[$a][0], $N[$a][1] . ' (utente ' . me() . ')');
}
