<?php
// ===================== UTILITA' =====================
function h($s) { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }
// HTTP downloads require an independently obtained SHA-256; HTTP(S) must not become a
// privileged SSRF route to loopback or link-local services. RFC1918 LAN servers
// are intentionally allowed; the resolved IP is pinned for the curl connection.
function iptm_update_safe_ip(string $ip): bool {
    $raw = @inet_pton($ip);
    if ($raw === false) return false;
    if (strlen($raw) === 4) {
        $oct = array_values(unpack('C4', $raw));
        return $oct[0] !== 0 && $oct[0] !== 127 && $oct[0] < 224
            && !($oct[0] === 169 && $oct[1] === 254)
            && !($oct[0] === 255);
    }
    if (strlen($raw) !== 16) return false;
    $oct = array_values(unpack('C16', $raw));
    // IPv4-mapped addresses share the same restrictions as their IPv4 target.
    if (substr($raw, 0, 10) === str_repeat("\0", 10) && substr($raw, 10, 2) === "\xff\xff") {
        return iptm_update_safe_ip(inet_ntop(substr($raw, 12, 4)));
    }
    // Reject unspecified, loopback, IPv4-compatible, link-local, multicast and
    // deprecated site-local destinations. ULA remains valid for local servers.
    if (substr($raw, 0, 12) === str_repeat("\0", 12)) return false;
    if ($oct[0] === 0xff || ($oct[0] === 0xfe && ($oct[1] & 0xc0) === 0x80)) return false;
    if ($oct[0] === 0xfe && ($oct[1] & 0xc0) === 0xc0) return false;
    return true;
}
function iptm_update_curl_pin(string $host, ?int $port): array {
    // Returns either no --resolve argument for literal IPs, or one pinned,
    // validated address. Refuse DNS results mixing safe and unsafe addresses.
    $host = trim($host, '[]');
    if (filter_var($host, FILTER_VALIDATE_IP)) {
        if (!iptm_update_safe_ip($host)) throw new InvalidArgumentException('IP riservato o locale non consentito');
        return [];
    }
    if (!preg_match('/^(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/iD', $host)
        || str_contains($host, '..') || str_contains($host, '--.')
        || !filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)
        || strtolower($host) === 'localhost' || str_ends_with(strtolower($host), '.localhost')
        || preg_match('/^(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+))*$/iD', $host)) {
        throw new InvalidArgumentException('Nome host non consentito');
    }
    $addresses = @gethostbynamel($host) ?: [];
    // AAAA records are checked as well: an unsafe IPv6 target must not bypass
    // the address policy when A and AAAA exist together.
    $records = @dns_get_record($host, DNS_AAAA);
    if (is_array($records)) foreach ($records as $r) {
        if (!empty($r['ipv6'])) $addresses[] = $r['ipv6'];
    }
    $addresses = array_values(array_unique($addresses));
    if (!$addresses) throw new InvalidArgumentException('Risoluzione DNS assente');
    foreach ($addresses as $address) {
        if (!iptm_update_safe_ip($address)) throw new InvalidArgumentException('DNS risolto verso un indirizzo non consentito');
    }
    // Prefer IPv4 on IPv6-disabled DietPi; curl still verifies the original TLS
    // hostname. --resolve blocks a DNS rebinding between preflight and connect.
    usort($addresses, fn($a, $b) => (int)(strpos($a, ':') !== false) <=> (int)(strpos($b, ':') !== false));
    $ip = $addresses[0];
    return ['--resolve', $host . ':' . $port . ':' . (str_contains($ip, ':') ? '[' . $ip . ']' : $ip)];
}
/** One vetted network hop. Do not use curl -L: every redirect must be revalidated. */
function iptm_update_url_parts(string $url, ?string $originScheme = null): array {
    if (strlen($url) > 6000 || preg_match('/[\x00-\x20\x7f\\\\]/', $url))
        throw new InvalidArgumentException('URL non valido o troppo lungo');
    $parts = parse_url($url);
    $scheme = is_array($parts) ? strtolower((string)($parts['scheme'] ?? '')) : '';
    $host = is_array($parts) ? (string)($parts['host'] ?? '') : '';
    if (!is_array($parts) || !in_array($scheme, ['http','https'], true)
        || $host === '' || !filter_var($url, FILTER_VALIDATE_URL)
        || isset($parts['user']) || isset($parts['pass']) || isset($parts['fragment'])
        || (isset($parts['port']) && ($parts['port'] < 1 || $parts['port'] > 65535)))
        throw new InvalidArgumentException('Aggiornamenti web via HTTP/HTTPS, senza credenziali nell’URL; HTTP richiede SHA-256 verificato');
    if ($originScheme === 'https' && $scheme !== 'https')
        throw new InvalidArgumentException('Redirect HTTPS verso HTTP rifiutato');
    $parts['scheme'] = $scheme;
    $parts['host'] = $host;
    return $parts;
}
/** Only absolute or same-origin relative paths; reject schemes, userinfo and //host shortcuts. */
function iptm_update_redirect_target(string $current, string $location): string {
    $location = trim($location);
    if ($location === '' || strlen($location) > 6000 || preg_match('/[\x00-\x1f\x7f\\\\]/', $location))
        throw new InvalidArgumentException('Header Location non valido');
    $base = iptm_update_url_parts($current);
    if (preg_match('~^https?://~i', $location)) {
        $next = $location;
    } else {
        if (str_starts_with($location, '//') || preg_match('~^[a-z][a-z0-9+.-]*:~i', $location))
            throw new InvalidArgumentException('Redirect con schema non autorizzato');
        $host = $base['host'];
        if (str_contains($host, ':') && !str_starts_with($host, '[')) $host = '['.$host.']';
        $origin = $base['scheme'].'://'.$host.(isset($base['port']) ? ':'.$base['port'] : '');
        if (str_starts_with($location, '/')) $next = $origin.$location;
        elseif (str_starts_with($location, '?')) $next = $origin.($base['path'] ?? '/').$location;
        else {
            $basePath = $base['path'] ?? '/';
            $next = $origin.substr($basePath, 0, (int)strrpos($basePath, '/') + 1).$location;
        }
    }
    iptm_update_url_parts($next, $base['scheme']);
    return $next;
}
/** Fetch one installer ZIP over HTTP(S), at most 3 redirects, with DNS pinning on *each* hop.
 * Reusing the original pinned address for a redirected host is NOT safe.
 * $dest must be a fresh, web-private random name, not a user-chosen path.
 */
function iptm_update_download_zip(string $url, string $dest): array {
    $curl = is_executable('/usr/bin/curl') ? '/usr/bin/curl' : '/usr/local/bin/curl';
    if (!is_executable($curl)) return [127, 'curl non installato'];
    $current = $url;
    $seen = [];
    $lastScheme = null;
    $headerPath = $dest.'.headers';
    try {
        for ($hop=0; $hop<=3; $hop++) {
            $parts = iptm_update_url_parts($current, $lastScheme);
            if (isset($seen[$current])) throw new InvalidArgumentException('Ciclo di redirect rilevato');
            $seen[$current] = true;
            $pin = iptm_update_curl_pin((string)$parts['host'], (int)($parts['port'] ?? ($parts['scheme']==='https'?443:80)));
            @unlink($headerPath); @unlink($dest);
            [$rc,$http,$error] = run(array_merge([$curl, '--disable', '--fail', '--silent', '--show-error',
                '--noproxy','*','--globoff','--proto','=http,https', '--max-time','90',
                '--connect-timeout','10', '--max-filesize','8388608', '--max-redirs','0',
                '--dump-header',$headerPath,'--write-out','%{http_code}'], $pin,
                ['--output',$dest,'--url',$current]), null, 100.0, 4096);
            $status = ctype_digit(trim($http)) ? (int)trim($http) : 0;
            if ($rc!==0) return [$rc, 'Download fallito (curl '.$rc.', HTTP '.$status.'): '.substr(trim($error),0,120)];
            if ($status===200) {
                $size = @filesize($dest);
                if (!is_int($size) || $size<100 || $size>8*1048576) return [65, 'Dimensioni ZIP non valide (max 8 MiB)'];
                $fh = @fopen($dest,'rb');
                $magic = is_resource($fh) ? fread($fh,4) : '';
                if (is_resource($fh)) fclose($fh);
                if ($magic!=="PK\x03\x04") return [65, 'La risposta HTTP non è uno ZIP installabile'];
                return [0, 'ok'];
            }
            if (!in_array($status,[301,302,303,307,308],true))
                return [65, 'Server aggiornamenti: risposta HTTP '.$status];
            if ($hop===3) return [65, 'Troppi redirect HTTP (max 3)'];
            if (!is_file($headerPath) || filesize($headerPath)>16384)
                return [65, 'Redirect senza header affidabili'];
            $headers = file_get_contents($headerPath);
            if (!is_string($headers) || !preg_match_all('/^Location:[ \t]*([^\r\n]+)\r?$/mi', $headers, $matches) || count($matches[1])!==1)
                return [65, 'Redirect senza Location univoco'];
            $lastScheme = $parts['scheme'];
            $current = iptm_update_redirect_target($current, $matches[1][0]);
        }
    } catch (InvalidArgumentException $e) {
        return [65, 'URL o redirect rifiutato: '.$e->getMessage()];
    } finally {
        @unlink($headerPath);
    }
    return [65, 'Download non completato'];
}
function iptm_request_id(): string {
    static $id = null;
    return $id ??= bin2hex(random_bytes(6));
}
function flash(string $m, string $t = 'ok') { $_SESSION['flash'][] = [$t, $m]; }
function go(string $q = '') {
    // In classic form mode, keep the current URL path. A rewritten/aliased
    // SCRIPT_NAME can point to a filename that the public web server does not serve.
    if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST' && in_array(($_POST['action'] ?? ''), ['update_apply', 'update_url_apply', 'ui_update_apply'], true)) {
        header('Location: ?p=update', true, 303);
        exit;
    }
    header('Location: ' . ($q ? '?' . $q : '?p=status'), true, 303);
    exit;
}
if (!ini_get('date.timezone')) {   // senza date.timezone PHP userebbe UTC: allineo al fuso del sistema
    $tz = trim((string)@file_get_contents('/etc/timezone'));
    if ($tz === '' && ($l = @readlink('/etc/localtime')) && preg_match('~zoneinfo/(.+)$~', $l, $m)) $tz = $m[1];
    if ($tz !== '' && in_array($tz, timezone_identifiers_list(), true)) date_default_timezone_set($tz);
}
/** Bound login history without resetting an active source's rate limit.
 * Repeated short-lived IPv6 client addresses previously accumulated forever.
 * The function is pure: the caller holds the stable fails.json.lock file.
 */
function iptm_login_failures_prune(array $entries, int $now, string $current, int $maxSources = 4096): array {
    $clean = [];
    foreach ($entries as $address => $times) {
        if (!is_string($address) || strlen($address) > 100 || !is_array($times)) continue;
        if ($address !== $current && filter_var($address, FILTER_VALIDATE_IP) === false) continue;
        $valid=[];
        // No source needs more than eight timestamps for a five-attempt limit.
        foreach (array_slice($times, -32) as $t) {
            if ((is_int($t) || is_float($t) || (is_string($t) && ctype_digit($t)))
                && (int)$t > $now - 600 && (int)$t <= $now + 60) $valid[]=(int)$t;
        }
        if ($valid) $clean[$address] = array_slice($valid, -8);
    }
    // Keep the most recent sources. An attacker cannot erase the current
    // source's lockout by creating many distinct IPv6 privacy addresses.
    $currentTimes = $clean[$current] ?? [];
    uasort($clean, fn($a,$b) => end($b) <=> end($a));
    if (count($clean) > $maxSources) $clean = array_slice($clean,0,$maxSources,true);
    if ($currentTimes && !isset($clean[$current]) && count($clean) >= $maxSources) array_pop($clean);
    if ($currentTimes) $clean[$current] = $currentTimes;
    return $clean;
}
/** A malformed ui_nets entry must never be interpreted as /0. */
function ip_in_nets(string $ip, string $nets): bool {
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) return false;
    $l = ip2long($ip);
    foreach (explode(',', $nets) as $entry) {
        $entry = trim($entry);
        if ($entry === '') continue;
        if (!preg_match('~^((?:[0-9]{1,3}\.){3}[0-9]{1,3})(?:/(3[0-2]|[12]?[0-9]))?$~D', $entry, $m)
            || filter_var($m[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) continue;
        $base = ip2long($m[1]);
        $prefix = isset($m[2]) ? (int)$m[2] : 32;
        $mask = $prefix === 0 ? 0 : (-1 << (32 - $prefix));
        if (($base & $mask) === ($l & $mask)) return true;
    }
    return false;
}
/** Compare packed IPv6 network prefixes, without relying on ip2long(). */
function iptm_ip6_in_nets(string $ip, array $nets): bool {
    $value = @inet_pton($ip);
    if (!is_string($value) || strlen($value) !== 16) return false;
    foreach ($nets as $net) {
        if (!is_string($net) || !preg_match('~^([^/]+)/([0-9]{1,3})$~D', $net, $parts)) continue;
        $base = @inet_pton($parts[1]);
        $bits = (int)$parts[2];
        if (!is_string($base) || strlen($base) !== 16 || $bits > 128) continue;
        $bytes = intdiv($bits, 8);
        if ($bytes && substr($value, 0, $bytes) !== substr($base, 0, $bytes)) continue;
        $rem = $bits % 8;
        if (!$rem || ((ord($value[$bytes]) ^ ord($base[$bytes])) & (0xff << (8 - $rem))) === 0) return true;
    }
    return false;
}
function herr(string $s): string { $s = trim($s); return 'Errore: ' . ($s !== '' ? $s : 'comando non riuscito (programma non installato o richiesta non valida)'); }
function tarpit_ok(): bool {   // TARPIT richiede xt_TARPIT (xtables-addons): assente di default su DietPi/Debian; senza modulo l'applicazione fallirebbe
    [$c, $o] = priv('compat', null, ['t:TARPIT']);
    if ($c === 0 && preg_match('/^target TARPIT ok$/m', $o)) return true;
    flash('TARPIT non attivato: il kernel non ha il modulo xt_TARPIT. Installa «xtables-addons» da Strumenti → Programmi e poi abilita TARPIT in Sicurezza.', 'err');
    return false;
}
function ip_ok(): bool {
    $ip = preg_replace('/^::ffff:/', '', $_SERVER['REMOTE_ADDR'] ?? '');
    if (str_contains($ip, ':')) {
        $b = @inet_pton($ip); if ($b === false) return false;
        // An explicit IPv4 management allowlist must not silently leave all
        // ULA/link-local IPv6 ranges authorized. Legacy defaults retain their
        // IPv6 scopes until the operator configures an explicit ACL.
        return iptm_ip6_in_nets($ip, ALLOWED_NETS6);
    }
    $l = ip2long($ip); if ($l === false) return false;
    foreach (ALLOWED_NETS as $n) {
        [$b, $m] = array_pad(explode('/', $n, 2), 2, '32'); $m = (int)$m; $bl = ip2long($b);
        if ($bl === false || $m < 0 || $m > 32) continue;   // difesa aggiuntiva: evita shift negativo con configurazioni non valide
        $mask = $m === 0 ? 0 : (-1 << (32 - $m));
        if (($l & $mask) === ($bl & $mask)) return true;
    }
    return false;
}
function run(array $cmd, ?string $in = null, float $timeout = 30.0, int $maxOutput = 8388608): array {
    // Bounded, multiplexed execution; stdin must not be written synchronously
    // before the timeout starts (large Pi-hole imports used to freeze workers).
    if (!$cmd || $timeout <= 0 || $maxOutput < 1024) return [2, '', 'parametri non validi'];
    $startedAt = microtime(true);
    $proc = @proc_open($cmd, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    if (!is_resource($proc)) return [127, '', 'proc_open non disponibile'];
    foreach ($pipes as $pipe) stream_set_blocking($pipe, false);
    $input = $in ?? ''; $total = strlen($input); $offset = 0;
    $stdinOpen = true; $stdoutOpen = true; $stderrOpen = true;
    if ($total === 0) { fclose($pipes[0]); $stdinOpen = false; }
    $out = ''; $err = ''; $truncated = false; $stdinOk = true; $timedOut = false;
    $exitCode = null; $deadline = microtime(true) + $timeout;
    while (true) {
        if (microtime(true) >= $deadline) { $timedOut = true; break; }
        $st = proc_get_status($proc);
        if (!$st['running'] && $exitCode === null && (int)$st['exitcode'] >= 0) $exitCode = (int)$st['exitcode'];
        if (!$st['running'] && $stdinOpen) { fclose($pipes[0]); $stdinOpen = false; $stdinOk = ($offset === $total); }
        $read = []; if ($stdoutOpen) $read[] = $pipes[1]; if ($stderrOpen) $read[] = $pipes[2];
        $write = ($stdinOpen && $offset < $total) ? [$pipes[0]] : [];
        if (!$st['running'] && !$stdoutOpen && !$stderrOpen) break;
        if (!$read && !$write) { usleep(10000); continue; }
        $except = null;
        $r = @stream_select($read, $write, $except, 0, 150000);
        if ($r === false) { $stdinOk = false; break; }
        foreach ($write as $pipe) {
            $n = @fwrite($pipe, substr($input, $offset, min(16384, $total - $offset)));
            if ($n === false) { $stdinOk = false; fclose($pipes[0]); $stdinOpen = false; }
            elseif ($n > 0) { $offset += $n; if ($offset >= $total) { fclose($pipes[0]); $stdinOpen = false; } }
        }
        foreach ($read as $pipe) {
            $isOut = ($pipe === $pipes[1]);
            $chunk = @fread($pipe, 65536);
            if ($chunk !== false && $chunk !== '') {
                $room = max(0, $maxOutput - strlen($out) - strlen($err));
                if ($room > 0) { if ($isOut) $out .= substr($chunk, 0, $room); else $err .= substr($chunk, 0, $room); }
                if (strlen($chunk) > $room) $truncated = true;
            }
            if (feof($pipe)) { fclose($pipe); if ($isOut) $stdoutOpen = false; else $stderrOpen = false; }
        }
    }
    if ($timedOut) {
        @proc_terminate($proc, 15); usleep(150000);
        $st = proc_get_status($proc); if ($st['running']) @proc_terminate($proc, 9);
    }
    if ($stdinOpen && is_resource($pipes[0])) fclose($pipes[0]);
    if ($stdoutOpen && is_resource($pipes[1])) fclose($pipes[1]);
    if ($stderrOpen && is_resource($pipes[2])) fclose($pipes[2]);
    $closed = proc_close($proc);
    $rc = $timedOut ? 124 : ($exitCode !== null ? $exitCode : $closed);
    if (!$stdinOk) { $rc = $rc === 0 ? 1 : $rc; $err .= "\nstdin incompleto"; }
    if ($timedOut) $err .= "\ntimeout (" . $timeout . "s)";
    if ($truncated) {
        $err .= "\noutput troncato";
        if ($rc === 0) $rc = 75; // Never report an incomplete command response as success.
    }
    if ($timedOut || $truncated || $rc === 127) {
        // Do not log the argument array: it may contain API passwords or keys.
        // sudo -n HELPER <operation> <subcommand>: the operation is argv[3], not the helper path.
        $operation = isset($cmd[3]) && is_string($cmd[3]) ? $cmd[3] : 'process';
        $subcommand = isset($cmd[4]) && is_string($cmd[4]) ? $cmd[4] : '';
        if (!preg_match('/^[a-z0-9_-]{1,36}$/i', $subcommand)) $subcommand='';
        error_log('IPTM request=' . iptm_request_id() . ' operation=' . preg_replace('/[^a-z0-9_-]/i', '', $operation)
            . ' exit=' . $rc . ' timed_out=' . ($timedOut ? 'yes' : 'no')
            . ' output_truncated=' . ($truncated ? 'yes' : 'no')
            . ' subcommand=' . $subcommand
            . ' elapsed_ms=' . (int)round((microtime(true) - $startedAt) * 1000)); 
    }
    return [$rc, $out, trim($err)];
}
const KC_RO = ['compat6-readiness', 'svc-state', 'cat', 'cat6', 'test', 'test6', 'rollback-prepare', 'v6cap', 'v6diag', 'save', 'save6', 'savec', 'journal', 'conf', 'ping', 'notice-status', 'ipset-info', 'ipset-test', 'ipset-hits', 'cs-status', 'conns', 'leases', 'suricata', 'selftest', 'backend', 'lists-status', 'sqm-status', 'sqm-v2-status', 'sqm-v3-status', 'security-integrations', 'suricata-eve-summary', 'sqm-probe', 'sqm-calibrate-status', 'sqm-safe-status', 'sqm-safe-preflight', 'version', 'post-suggest', 'compat', 'tool-status', 'tool-log', 'tool-logs', 'f2b-status', 'cs-decisions', 'vnstat-json', 'watch-status', 'capture', 'wg-status', 'wg-peer-conf', 'wg-peer-qr', 'cs-info', 'cs-collections', 'cs-log-discover', 'cs-scenarios', 'cs-metrics', 'cs-alerts', 'cs-bouncers', 'cs-allowlist', 'cs-acquis', 'su-info', 'su-alerts', 'su-stats', 'su-sources', 'su-config', 'su-test', 'su-rules-list', 'su-local-get', 'cs-parsers', 'cs-bouncer-get', 'cs-bouncer-status', 'cs-simulation', 'rules-check', 'ti-check', 'ti-summary', 'sec-audit', 'sysctl-audit', 'dns-status', 'dns-test'];
function kc(string $k, callable $f) { return $GLOBALS['_kc'][$k] ??= $f(); }   // cache per richiesta di letture del kernel; si azzera dopo ogni comando che modifica lo stato
function priv(string $cmd, ?string $in = null, array $args = []): array {
    $readonly = in_array($cmd, KC_RO, true) || (($cmd === 'qos-policy' && ($args[0]??'')==='status') || ($cmd === 'upgrade-cleanup' && in_array(($args[0]??''),['scan','report'],true)) || ($cmd === 'qos-engine' && in_array(($args[0]??''),['status','inspect','calibrate-status','auto-status'],true)) || ($cmd === 'security-stack' && in_array(($args[0]??''),['status','plan','suricata-sources'],true)) || ($cmd === 'nm-editor' && in_array(($args[0]??''),['inventory','preview','trial-status'],true))) || ($cmd === 'ipv6-control' && ($args[0] ?? '') === 'status') || ($cmd === 'dns-guard' && in_array(($args[0] ?? ''), ['status','events','preview'], true)) || ($cmd === 'multi-nic' && in_array(($args[0]??''), ['inventory','status'], true)) || ($cmd === 'anti-dpi-sources' && in_array(($args[0] ?? ''), ['status','catalog'], true));
    if (!$readonly) $GLOBALS['_kc'] = [];
    // Never abort an updater during file replacement merely because the generic
    // read-only status timeout (30 s) elapsed. Mutating jobs need separate budgets.
    $deadline = ($cmd==='security' && ($args[0]??'')==='mac-inventory') ? 15.0
        : (in_array($cmd, ['self-update','ui-update','dns-bundle'], true) ? 600.0
        : (in_array($cmd, ['save','save6','cat','cat6'], true) ? 40.0
        : ($cmd === 'tool-status' ? 25.0 // dpkg-query + apt-cache + systemctl are bounded individually
        : (($cmd === 'maintenance' && ($args[0] ?? '') === 'preflight') ? 45.0
        : (($cmd === 'maintenance' || $cmd === 'security') ? 300.0 : ($readonly ? 12.0 : 180.0))))));
    // Only small stable read-only status commands: avoid repeated sudo/systemctl
    // launches on old ARM hardware. Cache is request-local and invalidated by
    // every mutating priv() call; never cache stdin/output-heavy or failed jobs.
    $cacheable = $in === null && in_array($cmd, [
        'version','backend','svc-state','tool-status','wg-status','sqm-status',
        'dns-status','lists-status','cs-status'
    ], true);
    $cacheKey = $cacheable ? 'priv:' . $cmd . ':' . hash('sha256', json_encode($args, JSON_THROW_ON_ERROR)) : '';
    if ($cacheable && isset($GLOBALS['_kc'][$cacheKey])) return $GLOBALS['_kc'][$cacheKey];
    $result = run(array_merge([BIN_SUDO, '-n', HELPER, $cmd], $args), $in, $deadline);
    if ($cacheable && $result[0] === 0) $GLOBALS['_kc'][$cacheKey] = $result;
    return $result;
}
function sysctl_maintenance_apply_text(string $text): array { return priv('maintenance', $text, ['sysctl-apply', '--file', '-', '--apply']); }
function rules_live(): string {
    return kc('rules', function () { $t = @file_get_contents(RULES_FILE); if ($t === false) { [$code, $o] = priv('cat'); $t = $code === 0 ? $o : ''; } return (string)$t; });
}
function atomic_data_write(string $path, string $data, int $mode = 0600): bool {
    $dir = dirname($path);
    if (!is_dir($dir) && !@mkdir($dir, 0700, true)) return false;
    $tmp = @tempnam($dir, '.iptm-');
    if ($tmp === false) return false;
    $ok = false; $fp = @fopen($tmp, 'wb');
    if ($fp !== false) {
        @chmod($tmp, $mode);
        $len = strlen($data); $off = 0;
        while ($off < $len) {
            $n = @fwrite($fp, substr($data, $off, 65536));
            if ($n === false || $n === 0) break;
            $off += $n;
        }
        $ok = ($off === $len) && @fflush($fp);
        if ($ok && function_exists('fsync')) $ok = @fsync($fp);
        @fclose($fp);
    }
    if ($ok) $ok = @chmod($tmp, $mode) && @rename($tmp, $path);
    if (!$ok) @unlink($tmp);
    return $ok;
}
function get_draft(): string {
    // A rename atomically replaces the draft: readers need no advisory lock on
    // the replaced inode. Save the observed revision for a compare-and-swap.
    $f = DATA_DIR . '/draft.rules';
    $data = @file_get_contents($f);
    if (!is_string($data)) $data = rules_live();
    $GLOBALS['_draft_read_sha'] = hash('sha256', $data);
    return $data;
}
function put_draft(string $t): bool {
    // Lock a STABLE sidecar inode, not draft.rules (renamed on each write).
    // Compare while holding the lock: a POST revision check alone is racy.
    if (!is_dir(DATA_DIR) && !@mkdir(DATA_DIR, 0700, true) && !is_dir(DATA_DIR)) return false;
    $lock = @fopen(DATA_DIR . '/draft.lock', 'c');
    if (!$lock || !@flock($lock, LOCK_EX)) {
        if (is_resource($lock)) fclose($lock);
        throw new RuntimeException('Lock della bozza non disponibile');
    }
    try {
        $f = DATA_DIR . '/draft.rules';
        $cur = @file_get_contents($f);
        if (!is_string($cur) && is_file($f)) return false; // read error, never overwrite
        if (!is_string($cur)) $cur = rules_live();
        $expected = $GLOBALS['_draft_read_sha'] ?? null;
        if (is_string($expected) && !hash_equals($expected, hash('sha256', $cur))) {
            throw new RuntimeException('Conflitto: bozza modificata da un’altra richiesta. Ricarica prima di salvare.');
        }
        if (!atomic_data_write($f, $t, 0600)) return false;
        $GLOBALS['_draft_read_sha'] = hash('sha256', $t);
        return true;
    } finally {
        @flock($lock, LOCK_UN);
        @fclose($lock);
    }
}
/** Remove a draft only if the on-disk bytes still match the just-confirmed
 * snapshot. Reuse the same stable sidecar lock as put_draft()/v6_put(). */
function iptm_draft_remove_if_same(string $expected, string $fam='4'): bool {
    $is6=$fam==='6';
    $base=DATA_DIR . ($is6?'/draft6':'/draft');
    $file=$base.'.rules';
    $lock=@fopen($base.'.lock','c');
    if (!$lock || !@flock($lock,LOCK_EX)) {
        if (is_resource($lock)) @fclose($lock);
        throw new RuntimeException('Lock bozza non disponibile: mantenere la bozza');
    }
    try {
        if (is_link($file)) throw new RuntimeException('Percorso bozza non sicuro');
        if (!is_file($file)) return true;
        $current=@file_get_contents($file);
        if (!is_string($current)) return false;
        if (!hash_equals(hash('sha256',$expected),hash('sha256',$current))) return false;
        return @unlink($file);
    } finally { @flock($lock,LOCK_UN); @fclose($lock); }
}

function pending(): ?array {
    // Scadenza != completamento. Uno snapshot ancora presente dopo la scadenza
    // deve essere visibile e recuperabile, mai nascosto alla UI.
    $f = DATA_DIR . '/pending.json';
    $raw = @file_get_contents($f);
    if ($raw === false) return is_file($f) ? ['fam'=>'?', 'until'=>0, 'status'=>'recovery_required', 'invalid'=>true] : null;
    $p = json_decode($raw, true);
    if (!is_array($p) || !isset($p['until'], $p['fam']) || !is_numeric($p['until']) || !in_array($p['fam'], ['4','6'], true))
        return ['fam'=>'?', 'until'=>0, 'status'=>'recovery_required', 'invalid'=>true];
    $p['status'] = time() >= (int)$p['until'] ? 'recovery_required' : 'pending';
    return $p;
}
