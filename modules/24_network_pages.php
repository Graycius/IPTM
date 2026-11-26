<?php
// ===================== PAGINE "STILE DD-WRT" =====================
// dd / dd_radio / dd_in / s_form: definiti in 17_common_ui_ops.php
function wan_warn(array $S) { if (!wan_ready($S)) echo '<div class="msg err">⚠ WAN non definita: i filtri «dal WAN» non verranno generati. Impostala in <a href="?p=setup">Setup</a>.</div>'; }



function ti_cfg(): array {
    $t = S_get()['ti'] ?? [];
    return $t + ['abuseipdb' => '', 'greynoise' => '', 'otx' => '', 'virustotal' => '', 'urlscan' => '', 'ipapi' => 0, 'threatfox' => 1, 'urlhaus' => 1, 'cache_hours' => 24];
}
function ti_cache_read(): array {
    $f=DATA_DIR.'/ti-cache.json';
    if(is_link($f)||!is_file($f))return [];
    $raw=@file_get_contents($f,false,null,0,4194305);
    if(!is_string($raw)||strlen($raw)>4194304)return [];
    $j=json_decode($raw,true);return is_array($j)?$j:[];
}
function ti_cache_get(string $ip): ?array {
    $e=ti_cache_read()[$ip]??null;
    if(!is_array($e)||!is_int($e['exp']??null)||$e['exp']<=time()||!is_array($e['data']??null))return null;
    return $e['data'];
}
function ti_cache_put_seconds(string $ip,array $data,int $seconds): void {
    if(filter_var($ip,FILTER_VALIDATE_IP)===false)return;
    $lockPath=DATA_DIR.'/ti-cache.lock';
    if(is_link($lockPath)||(file_exists($lockPath)&&!is_file($lockPath)))return;
    $lock=@fopen($lockPath,'c');if(!$lock)return;
    try {
        if(!flock($lock,LOCK_EX))return;
        $j=array_filter(ti_cache_read(),fn($e)=>is_array($e)&&is_int($e['exp']??null)&&$e['exp']>time()&&is_array($e['data']??null));
        $j[$ip]=['exp'=>time()+max(60,min(2592000,$seconds)),'data'=>$data];
        uasort($j,fn($a,$b)=>$a['exp']<=>$b['exp']);
        $j=array_slice($j,-500,null,true);
        $encoded=json_encode($j,JSON_INVALID_UTF8_SUBSTITUTE);
        if(is_string($encoded)&&strlen($encoded)<=4194304)atomic_data_write(DATA_DIR.'/ti-cache.json',$encoded,0600);
    } finally {fclose($lock);}
}
function ti_cache_put(string $ip,array $data,int $hours=24): void {ti_cache_put_seconds($ip,$data,max(1,min(720,$hours))*3600);}
/** HTTPS-only HTTP client: API keys and submission fields never appear in ps argv. */
function iptm_https_curl(string $url, array $headers = [], int $timeout = 8,
                         array $fields = [], ?string $fileField = null, ?string $filePath = null,
                         bool $post = false, ?string $rawBody = null): ?string {
    $binary = is_executable('/usr/bin/curl') ? '/usr/bin/curl' : (is_executable('/usr/local/bin/curl') ? '/usr/local/bin/curl' : '');
    if ($binary === '' || !preg_match('~\Ahttps://[A-Za-z0-9.-]+(?::443)?(?:[/?#]|\z)~', $url) || strlen($url)>4096) return null;
    $timeout=max(2,min($timeout,120));
    // curl --config - parses double-quoted values from stdin; no secrets in process arguments.
    $quote = static function (string $value): string {
        if (preg_match('/[\x00-\x1f\x7f]/', $value)) throw new InvalidArgumentException('Dati HTTP non validi');
        return '"' . str_replace(['\\','"'],['\\\\','\\"'], $value) . '"';
    };
    try {
        $conf='url = '.$quote($url)."\n";
        foreach ($headers as $h) $conf.='header = '.$quote((string)$h)."\n";
        if ($post) {
            if ($rawBody !== null) {
                $conf.='data = '.$quote($rawBody)."\n";
            } elseif ($fileField !== null && $filePath !== null) {
                if (!is_file($filePath) || !is_readable($filePath) || !preg_match('/^[A-Za-z0-9_-]{1,40}$/D',$fileField)) return null;
                $conf.='form = '.$quote($fileField.'=@'.$filePath)."\n";
                foreach ($fields as $k=>$v) $conf.='form = '.$quote((string)$k.'='.(string)$v)."\n";
            } else {
                $conf.="request = \"POST\"\n";
                foreach ($fields as $k=>$v) $conf.='data-urlencode = '.$quote((string)$k.'='.(string)$v)."\n";
            }
        }
    } catch (InvalidArgumentException $e) { return null; }
    [$c,$o] = run([$binary, '-q', '--silent','--max-time',(string)$timeout,'--connect-timeout','5',
                    '--proto','=https','--proto-redir','=https','--config','-'],
                    $conf, $timeout+5, 2097152);
    return $c===0 && $o!=='' ? $o : null;
}
function ti_curl(string $url, array $headers = [], int $timeout = 4): ?string {
    return iptm_https_curl($url, $headers, $timeout);
}
/** Enrichment via API esterne (chiavi opzionali in Impostazioni TI). */
function ti_api_enrich(string $ip, array $cfg): array {
    $ext = ['apis' => [], 'score' => 0, 'labels' => [], 'raw' => []];
    if (filter_var($ip,FILTER_VALIDATE_IP,FILTER_FLAG_IPV4|FILTER_FLAG_NO_PRIV_RANGE|FILTER_FLAG_NO_RES_RANGE)===false) return $ext; // API free quasi tutte IPv4
    $cached = ti_cache_get($ip);
    if ($cached !== null) return $cached;

    // Historical ip-api.com free HTTP lookups are disabled: no plaintext client-IP disclosure.
    // 2) AbuseIPDB
    $key = trim((string)($cfg['abuseipdb'] ?? ''));
    if ($key !== '' && preg_match('/^[A-Za-z0-9]{20,80}$/D', $key)) {
        $body = ti_curl(
            'https://api.abuseipdb.com/api/v2/check?ipAddress=' . rawurlencode($ip) . '&maxAgeInDays=90&verbose',
            ['Key: ' . $key, 'Accept: application/json'],
            5
        );
        $j = $body ? json_decode($body, true) : null;
        $d = is_array($j) ? ($j['data'] ?? null) : null;
        if (is_array($d)) {
            $ext['apis'][] = 'abuseipdb';
            $ext['raw']['abuseipdb'] = ['score' => $d['abuseConfidenceScore'] ?? 0, 'reports' => $d['totalReports'] ?? 0, 'isp' => $d['isp'] ?? ''];
            $sc = (int)($d['abuseConfidenceScore'] ?? 0);
            $rep = (int)($d['totalReports'] ?? 0);
            if ($sc >= 80) { $ext['score'] += 6; $ext['labels'][] = "abuseipdb:$sc%"; }
            elseif ($sc >= 40) { $ext['score'] += 4; $ext['labels'][] = "abuseipdb:$sc%"; }
            elseif ($sc >= 15) { $ext['score'] += 2; $ext['labels'][] = "abuseipdb:$sc%"; }
            if ($rep > 0) $ext['labels'][] = "reports:$rep";
        }
    }
    // 3) GreyNoise community
    $gk = trim((string)($cfg['greynoise'] ?? ''));
    if ($gk !== '' && strlen($gk) >= 16) {
        $body = ti_curl('https://api.greynoise.io/v3/community/' . rawurlencode($ip), ['key: ' . $gk, 'Accept: application/json'], 5);
        $j = $body ? json_decode($body, true) : null;
        if (is_array($j) && empty($j['error'])) {
            $ext['apis'][] = 'greynoise';
            $cls = (string)($j['classification'] ?? ($j['noise'] ?? false ? 'noise' : ''));
            $ext['raw']['greynoise'] = ['classification' => $cls, 'name' => $j['name'] ?? ''];
            if ($cls === 'malicious') { $ext['score'] += 5; $ext['labels'][] = 'greynoise:malicious'; }
            elseif ($cls === 'suspicious') { $ext['score'] += 3; $ext['labels'][] = 'greynoise:suspicious'; }
            elseif (!empty($j['noise'])) { $ext['score'] += 2; $ext['labels'][] = 'greynoise:noise'; }
            elseif ($cls === 'benign') { $ext['labels'][] = 'greynoise:benign'; }
        }
    }
    // 4) AlienVault OTX passive DNS / general — indicator of compromise section via IPv4
    $otx = trim((string)($cfg['otx'] ?? ''));
    if ($otx !== '' && strlen($otx) >= 16) {
        $body = ti_curl('https://otx.alienvault.com/api/v1/indicators/IPv4/' . rawurlencode($ip) . '/general', ['X-OTX-API-KEY: ' . $otx, 'Accept: application/json'], 5);
        $j = $body ? json_decode($body, true) : null;
        if (is_array($j)) {
            $ext['apis'][] = 'otx';
            $pulse = (int)($j['pulse_info']['count'] ?? 0);
            $ext['raw']['otx'] = ['pulses' => $pulse];
            if ($pulse >= 10) { $ext['score'] += 5; $ext['labels'][] = "otx:pulses:$pulse"; }
            elseif ($pulse >= 3) { $ext['score'] += 3; $ext['labels'][] = "otx:pulses:$pulse"; }
            elseif ($pulse >= 1) { $ext['score'] += 1; $ext['labels'][] = "otx:pulses:$pulse"; }
        }
    }

    // 5) VirusTotal (free API key — report IP)
    $vt = trim((string)($cfg['virustotal'] ?? ''));
    if ($vt !== '' && preg_match('/^[A-Za-z0-9_\-]{32,128}$/D', $vt)) {
        $body = ti_curl('https://www.virustotal.com/api/v3/ip_addresses/' . rawurlencode($ip), ['x-apikey: ' . $vt, 'Accept: application/json'], 6);
        $j = $body ? json_decode($body, true) : null;
        $stats = is_array($j) ? ($j['data']['attributes']['last_analysis_stats'] ?? null) : null;
        if (is_array($stats)) {
            $ext['apis'][] = 'virustotal';
            $mal = (int)($stats['malicious'] ?? 0);
            $sus = (int)($stats['suspicious'] ?? 0);
            $ext['raw']['virustotal'] = $stats;
            if ($mal >= 5) { $ext['score'] += 6; $ext['labels'][] = "vt:malicious:$mal"; }
            elseif ($mal >= 1) { $ext['score'] += 4; $ext['labels'][] = "vt:malicious:$mal"; }
            elseif ($sus >= 3) { $ext['score'] += 2; $ext['labels'][] = "vt:suspicious:$sus"; }
            elseif ($mal === 0 && $sus === 0) { $ext['labels'][] = 'vt:clean'; }
        }
    }
    // 6) ThreatFox (abuse.ch) — IOC su IP, senza chiave
    if (!empty($cfg['threatfox'])) {
        $payload = json_encode(['query' => 'search_ioc', 'search_term' => $ip]);
        {
            // POST body through curl's private stdin config; no queried IP in ps argv.
            $body = iptm_https_curl('https://threatfox-api.abuse.ch/api/v1/',
                ['Content-Type: application/json'], 5, [], null, null, true, $payload);
            $j = $body ? json_decode($body, true) : null;
            if (is_array($j) && ($j['query_status'] ?? '') === 'ok' && !empty($j['data']) && is_array($j['data'])) {
                $ext['apis'][] = 'threatfox';
                $n = count($j['data']);
                $ext['raw']['threatfox'] = ['hits' => $n];
                if ($n >= 1) {
                    $ext['score'] += min(6, 2 + $n);
                    $mal = (string)($j['data'][0]['malware'] ?? 'ioc');
                    $ext['labels'][] = 'threatfox:' . substr(preg_replace('/\s+/', '_', $mal), 0, 30) . "×$n";
                }
            }
        }
    }
    // 7) URLhaus (abuse.ch) — host malevoli che puntano a questo IP / host
    if (!empty($cfg['urlhaus'])) {
        {
            $body = iptm_https_curl('https://urlhaus-api.abuse.ch/v1/host/',
                [], 5, ['host'=>$ip], null, null, true);
            $j = $body ? json_decode($body, true) : null;
            if (is_array($j) && ($j['query_status'] ?? '') === 'ok') {
                $ext['apis'][] = 'urlhaus';
                $urls = $j['urls'] ?? [];
                $n = is_array($urls) ? count($urls) : 0;
                $ext['raw']['urlhaus'] = ['urls' => $n];
                if ($n >= 1) {
                    $ext['score'] += min(5, 2 + intdiv($n, 3));
                    $ext['labels'][] = "urlhaus:urls:$n";
                }
            }
        }
    }
    // 8) urlscan.io search (API key opzionale — più quota)
    $us = trim((string)($cfg['urlscan'] ?? ''));
    if ($us !== '' && strlen($us) >= 8) {
        $body = ti_curl('https://urlscan.io/api/v1/search/?q=ip:' . rawurlencode($ip), ['API-Key: ' . $us, 'Content-Type: application/json'], 5);
        $j = $body ? json_decode($body, true) : null;
        if (is_array($j) && isset($j['total'])) {
            $ext['apis'][] = 'urlscan';
            $tot = (int)$j['total'];
            $ext['raw']['urlscan'] = ['total' => $tot];
            if ($tot >= 20) { $ext['score'] += 2; $ext['labels'][] = "urlscan:$tot"; }
            elseif ($tot >= 1) { $ext['labels'][] = "urlscan:$tot"; }
        }
    }
    $got = count($ext['apis'] ?? []);
    $hours = (int)($cfg['cache_hours'] ?? 24);
    if ($got === 0) {
        // nessuna risposta API: cache 15 minuti (evita ban su errori temporanei)
        ti_cache_put_seconds($ip,$ext,900);
    } else {
        ti_cache_put($ip, $ext, $hours);
    }
    return $ext;
}

function ti_lookup_ips(array $ips): array {
    $ips = array_values(array_unique(array_filter($ips, fn($x) => (bool)preg_match('/^(\d{1,3}\.){3}\d{1,3}$|^[0-9A-Fa-f:]+$/', $x))));
    $out = [];
    if (!$ips) return $out;
    $cfg = ti_cfg();
    $apiLeft = 10; // max lookup API esterne per richiesta (quota + timeout)
    foreach (array_chunk($ips, 12) as $chunk) {
        [$c, $o] = priv('ti-check', null, $chunk);
        if ($c !== 0) $o = '';
        foreach ($chunk as $ip) {
            $rec = [
                'sets' => [], 'dnsbl' => [], 'bogon' => 'none', 'asn' => '-', 'as' => '-', 'cc' => '-',
                'ptr' => '-', 'net24' => '-', 'score' => 0, 'labels' => [], 'confidence' => 'low', 'apis' => [],
            ];
            // parse local line if present
            foreach (explode("\n", trim($o)) as $l) {
                if (!str_starts_with($l, 'ip ' . $ip . ' ') && $l !== 'ip ' . $ip) {
                    if (!preg_match('/^ip ' . preg_quote($ip, '/') . '\s/', $l)) continue;
                }
                $p = preg_split('/\s+/', trim($l));
                foreach ($p as $tok) {
                    foreach (['sets', 'dnsbl', 'bogon', 'asn', 'as', 'cc', 'ptr', 'net24'] as $k) {
                        if (str_starts_with($tok, $k . ':')) { $rec[$k] = substr($tok, strlen($k) + 1); break; }
                    }
                }
            }
            if (is_string($rec['sets']) && $rec['sets'] !== '' && $rec['sets'] !== 'none') $rec['sets'] = array_values(array_filter(explode(',', $rec['sets'])));
            else $rec['sets'] = is_array($rec['sets']) ? $rec['sets'] : [];
            if (is_string($rec['dnsbl']) && $rec['dnsbl'] !== '' && $rec['dnsbl'] !== 'none') $rec['dnsbl'] = array_values(array_filter(explode(',', $rec['dnsbl'])));
            else $rec['dnsbl'] = is_array($rec['dnsbl']) ? $rec['dnsbl'] : [];
            if ($rec['sets']) {
                $rec['score'] += 4 * count($rec['sets']);
                $rec['labels'][] = 'ipset×' . count($rec['sets']) . ' (' . implode(',', array_slice($rec['sets'], 0, 3)) . ')';
            }
            if ($rec['dnsbl']) {
                $rec['score'] += 2 * count($rec['dnsbl']);
                $short = array_map(fn($z) => preg_replace('/\..*$/', '', $z), $rec['dnsbl']);
                $rec['labels'][] = 'dnsbl:' . implode(',', $short);
            }
            if (($rec['bogon'] ?? 'none') !== 'none') {
                $rec['score'] += 1;
                $rec['labels'][] = 'bogon:' . $rec['bogon'];
            }
            if (($rec['asn'] ?? '-') !== '-' && $rec['asn'] !== '') $rec['labels'][] = 'AS' . $rec['asn'] . (($rec['as'] ?? '-') !== '-' ? ' ' . $rec['as'] : '');
            if (($rec['cc'] ?? '-') !== '-' && $rec['cc'] !== '') $rec['labels'][] = 'cc:' . strtoupper($rec['cc']);
            $ptr = $rec['ptr'] ?? '-';
            if ($ptr !== '-' && $ptr !== '') {
                $rec['labels'][] = 'ptr:' . $ptr;
                if (preg_match('/(amazon|aws|google|cloud|azure|digitalocean|linode|ovh|hetzner|contabo|vps|hosting)/i', $ptr)) {
                    $rec['score'] += 1;
                    $rec['labels'][] = 'hosting-ptr';
                }
            }
            // --- API esterne (limitate per richiesta) ---
            if ($apiLeft > 0) {
                $ext = ti_api_enrich($ip, $cfg);
                $apiLeft--;
                if ($ext['score'] ?? 0) $rec['score'] += (int)$ext['score'];
                foreach ($ext['labels'] ?? [] as $lb) $rec['labels'][] = $lb;
                if (!empty($ext['apis'])) $rec['apis'] = $ext['apis'];
            }
            // confidenza
            $sources = 0;
            if ($rec['sets']) $sources++;
            if ($rec['dnsbl']) $sources++;
            if (!empty($ext['apis'])) $sources += count($ext['apis']);
            if ($rec['score'] >= 8 || $sources >= 3) $rec['confidence'] = 'high';
            elseif ($rec['score'] >= 3 || $sources >= 1) $rec['confidence'] = 'med';
            else $rec['confidence'] = 'low';
            $out[$ip] = $rec;
        }
    }
    // cluster /24
    $by24 = [];
    foreach ($out as $ip => $rec) {
        $n = $rec['net24'] ?? '-';
        if ($n !== '-' && $n !== '') $by24[$n][] = $ip;
    }
    foreach ($by24 as $net => $list) {
        if (count($list) < 3) continue;
        foreach ($list as $ip) {
            $out[$ip]['score'] += 2;
            $out[$ip]['labels'][] = 'cluster:' . $net . '×' . count($list);
            if ($out[$ip]['confidence'] === 'low') $out[$ip]['confidence'] = 'med';
            if (count($list) >= 5) $out[$ip]['confidence'] = 'high';
        }
    }
    return $out;
}

function attack_classify(array $rows): array {
    // $rows: list of [time, prefix, in, src, dst, proto, spt, dpt]
    $bySrc = []; $byPort = []; $byPrefix = []; $pairs = [];
    foreach ($rows as $r) {
        [, $pref, $in, $src, $dst, $proto, $spt, $dpt] = $r;
        if ($src === '') continue;
        $bySrc[$src] = $bySrc[$src] ?? ['n' => 0, 'ports' => [], 'protos' => [], 'prefs' => [], 'ins' => []];
        $bySrc[$src]['n']++;
        if ($dpt !== '') $bySrc[$src]['ports'][$dpt] = ($bySrc[$src]['ports'][$dpt] ?? 0) + 1;
        if ($proto !== '') $bySrc[$src]['protos'][$proto] = ($bySrc[$src]['protos'][$proto] ?? 0) + 1;
        $bySrc[$src]['prefs'][$pref] = ($bySrc[$src]['prefs'][$pref] ?? 0) + 1;
        if ($in !== '') $bySrc[$src]['ins'][$in] = true;
        $pk = strtolower($proto ?: '?') . '/' . ($dpt ?: '?');
        $byPort[$pk] = ($byPort[$pk] ?? 0) + 1;
        $byPrefix[$pref] = ($byPrefix[$pref] ?? 0) + 1;
        if ($dpt !== '') $pairs[$src . '|' . $dpt] = true;
    }
    arsort($byPort); arsort($byPrefix);

    // classic service ports for labeling
    $svc = [
        '22' => 'SSH', '23' => 'Telnet', '21' => 'FTP', '25' => 'SMTP', '53' => 'DNS',
        '80' => 'HTTP', '443' => 'HTTPS', '445' => 'SMB', '3389' => 'RDP', '5900' => 'VNC',
        '3306' => 'MySQL', '5432' => 'PostgreSQL', '6379' => 'Redis', '27017' => 'MongoDB',
        '8080' => 'HTTP-alt', '8443' => 'HTTPS-alt', '1433' => 'MSSQL', '1900' => 'SSDP',
        '11211' => 'Memcached', '5555' => 'ADB', '2323' => 'Telnet-alt', '81' => 'HTTP-alt',
    ];
    $patterns = [];

    foreach ($bySrc as $src => $info) {
        $nports = count($info['ports']);
        $n = $info['n'];
        $topPorts = $info['ports']; arsort($topPorts);
        $labels = [];
        // port scan: many distinct destination ports
        if ($nports >= 8) {
            $labels[] = ['port_scan', 'high', "Port scan: $nports porte distinte in $n eventi"];
        } elseif ($nports >= 4) {
            $labels[] = ['port_scan', 'med', "Possibile scan: $nports porte distinte"];
        }
        // brute / service probe: many hits on same sensitive port
        foreach (['22' => 'SSH brute/probe', '23' => 'Telnet probe', '3389' => 'RDP probe', '445' => 'SMB probe', '21' => 'FTP probe'] as $pt => $lab) {
            if (($info['ports'][$pt] ?? 0) >= 5) {
                $labels[] = ['brute', 'high', $lab . ' (' . $info['ports'][$pt] . ' hit)'];
            } elseif (($info['ports'][$pt] ?? 0) >= 3) {
                $labels[] = ['brute', 'med', $lab . ' (' . $info['ports'][$pt] . ' hit)'];
            }
        }
        // flood: high volume few ports
        if ($n >= 30 && $nports <= 2) {
            $labels[] = ['flood', 'high', "Flood/volume alto: $n eventi su $nports porte"];
        } elseif ($n >= 15 && $nports <= 3) {
            $labels[] = ['flood', 'med', "Traffico intenso: $n eventi"];
        }
        // amplification / odd UDP ports
        foreach (['1900', '11211', '19', '123', '389'] as $pt) {
            if (($info['ports'][$pt] ?? 0) >= 2) {
                $labels[] = ['amp', 'med', 'Possibile abuse UDP porta ' . $pt . ' (' . ($svc[$pt] ?? 'servizio') . ')'];
            }
        }
        // list/block prefix
        foreach ($info['prefs'] as $pref => $cnt) {
            if (str_contains($pref, 'BL') || str_contains($pref, 'CS') || str_contains($pref, 'CROWD')) {
                $labels[] = ['reputation', 'med', "Bloccato da lista/CrowdSec ($pref x$cnt)"];
            }
        }
        if (!$labels) continue;
        // severity = max
        $sev = 'low';
        foreach ($labels as $lb) if ($lb[1] === 'high') $sev = 'high'; elseif ($lb[1] === 'med' && $sev !== 'high') $sev = 'med';
        $portList = [];
        foreach (array_slice(array_keys($topPorts), 0, 8) as $pt) {
            $portList[] = $pt . (isset($svc[$pt]) ? ' (' . $svc[$pt] . ')' : '');
        }
        $patterns[] = [
            'src' => $src,
            'events' => $n,
            'sev' => $sev,
            'labels' => $labels,
            'ports' => $portList,
            'protos' => array_keys($info['protos']),
        ];
    }
    usort($patterns, function ($a, $b) {
        $o = ['high' => 0, 'med' => 1, 'low' => 2];
        return ($o[$a['sev']] <=> $o[$b['sev']]) ?: ($b['events'] <=> $a['events']);
    });

    // global signatures
    $global = [];
    $sshHits = $byPort['tcp/22'] ?? $byPort['TCP/22'] ?? 0;
    foreach ($byPort as $k => $v) if (preg_match('#^(tcp|TCP)/22$#', $k)) $sshHits = $v;
    if ($sshHits >= 10) $global[] = ['high', "Attività elevata su SSH (tcp/22): $sshHits eventi nei log recenti — valuta limiti SSH o CrowdSec sshd."];
    $scanSources = count(array_filter($patterns, fn($x) => $x['sev'] === 'high'));
    if ($scanSources >= 3) $global[] = ['high', "$scanSources sorgenti con pattern ad alta severità: possibile campagna di scan in corso."];
    if (($byPort['tcp/445'] ?? $byPort['TCP/445'] ?? 0) >= 5) $global[] = ['med', 'Probe SMB (445) rilevati: tipici di worm/botnet.'];
    if (($byPort['udp/1900'] ?? $byPort['UDP/1900'] ?? 0) >= 3) $global[] = ['med', 'Traffico SSDP/1900: possibile amplificazione o IoT rumoroso.'];

    return [
        'patterns' => array_slice($patterns, 0, 40),
        'top_ports' => array_slice($byPort, 0, 15, true),
        'top_prefix' => array_slice($byPrefix, 0, 10, true),
        'global' => $global,
        'total_events' => count($rows),
        'unique_src' => count($bySrc),
        'svc' => $svc,
    ];
}

function pg_attacks() {
    $S = S_get(); $ro = ($_SESSION['role'] ?? 'viewer') === 'viewer';
    [$c, $o, $e] = priv('journal');
    echo '<div class=card><h2>Analisi pattern di attacco</h2>';
    echo '<p class=mut>Classificazione automatica dai log del kernel (prefissi IPT…): port scan, brute force, flood, probe. Arricchita con threat intelligence locale (ipset blocklist/geo/crowdsec) e DNSBL pubbliche (Spamhaus zen, SORBS, Barracuda, SpamCop).</p>';
    if ($c) {
        echo '<div class="msg err">Impossibile leggere i log: ' . h($e) . '</div></div>';
        return;
    }
    $rows = [];
    foreach (array_reverse(explode("\n", trim($o))) as $l) {
        if (!preg_match('/(IPT[\w-]*):/', $l, $pm)) continue;
        preg_match_all('/\b([A-Z]+)=(\S*)/', $l, $kv);
        if (!$kv[1]) continue;
        $f = array_combine($kv[1], $kv[2]);
        $rows[] = [strtok($l, ' '), $pm[1], $f['IN'] ?? '', $f['SRC'] ?? '', $f['DST'] ?? '', $f['PROTO'] ?? '', $f['SPT'] ?? '', $f['DPT'] ?? ''];
    }
    $A = attack_classify($rows);
    $ips = array_map(fn($x) => $x['src'], $A['patterns']);
    // anche top sorgenti grezze dai log se pochi pattern
    if (count($ips) < 5) {
        $cnt = [];
        foreach ($rows as $r) if (($r[3] ?? '') !== '') $cnt[$r[3]] = ($cnt[$r[3]] ?? 0) + 1;
        arsort($cnt);
        $ips = array_slice(array_keys($cnt), 0, 25);
    } else {
        $ips = array_slice($ips, 0, 25);
    }
    $TI = ti_lookup_ips($ips);
    $tiHit = count(array_filter($TI, fn($x) => $x['score'] > 0));
    [, $tiSum] = priv('ti-summary');

    echo '<div class=row data-iptm-layout="ui-34311ab5e4">';
    $card = function ($lab, $val) {
        echo '<div data-iptm-layout="ui-ce44fa8a92"><div class=mut>' . h($lab) . '</div><div data-iptm-layout="ui-617aacb9fd">' . h((string)$val) . '</div></div>';
    };
    $card('Eventi log', number_format($A['total_events']));
    $card('Sorgenti uniche', number_format($A['unique_src']));
    $card('Pattern rilevati', number_format(count($A['patterns'])));
    $hi = count(array_filter($A['patterns'], fn($x) => $x['sev'] === 'high'));
    $card('Alta severità', $hi);
    $card('Threat intel hit', $tiHit);
    echo '</div>';

    if (trim($tiSum) !== '' || $TI) {
        echo '<details open><summary><b>Tecniche di enrichment</b></span></summary>';
        echo '<table><tr><th>Tecnica</th><th>Fonte</th><th>Peso</th><th>Note</th></tr>';
        echo '<tr><td><b>Membership ipset</b></td><td>Liste locali (Spamhaus, FireHOL, ET, CINS, geo, CrowdSec)</td><td>+4 / set</td><td>Alta affidabilità: dati già usati dal firewall</td></tr>';
        echo '<tr><td><b>DNSBL</b></td><td>zen.spamhaus.org, SORBS, Barracuda, SpamCop</td><td>+2 / lista</td><td>Query DNS reverse; possibili falsi positivi</td></tr>';
        echo '<tr><td><b>ASN / paese</b></td><td>Team Cymru (origin.asn.cymru.com)</td><td>contesto</td><td>Operatore e country code senza API key</td></tr>';
        echo '<tr><td><b>PTR</b></td><td>Reverse DNS</td><td>+1 se hosting</td><td>Riconosce VPS/cloud tipici degli scanner</td></tr>';
        echo '<tr><td><b>Bogon</b></td><td>RFC1918, CGNAT, link-local</td><td>+1</td><td>Utile se compaiono sul WAN</td></tr>';
        echo '<tr><td><b>Cluster /24</b></td><td>Aggregazione in UI</td><td>+2 se ≥3 IP</td><td>Campagne distribuite sulla stessa rete</td></tr>';
        echo '<tr><td><b>ip-api.com (legacy)</b></td><td>Non disponibile: solo HTTP non cifrato sul piano gratuito</td><td>—</td><td>Disabilitato per privacy</td></tr>';
        echo '<tr><td><b>AbuseIPDB</b></td><td>API key</td><td>+2–6 da score %</td><td>abuseipdb.com — confidenza abuso</td></tr>';
        echo '<tr><td><b>GreyNoise</b></td><td>API key community</td><td>+2–5</td><td>noise / malicious / benign</td></tr>';
        echo '<tr><td><b>OTX AlienVault</b></td><td>API key</td><td>+1–5 da pulse</td><td>Indicatori condivisi dalla community</td></tr>';
        echo '<tr><td><b>VirusTotal</b></td><td>API key free</td><td>+2–6</td><td>Motori AV: malicious/suspicious sull\'IP</td></tr>';
        echo '<tr><td><b>ThreatFox</b></td><td>abuse.ch (gratis)</td><td>+2–6</td><td>IOC malware / C2</td></tr>';
        echo '<tr><td><b>URLhaus</b></td><td>abuse.ch (gratis)</td><td>+2–5</td><td>URL malevoli associati all\'host</td></tr>';
        echo '<tr><td><b>urlscan.io</b></td><td>API key opz.</td><td>+0–2</td><td>Scan pubblici che citano l\'IP</td></tr>';


        echo '</table>';
        echo '<p class=mut><b>Confidenza</b>: high se score≥6 o ≥2 fonti indipendenti; med se score≥3. Le liste si gestiscono in <a href="?p=lists">Alias · Liste · GeoIP</a>.</p>';
        if (trim($tiSum) !== '') echo '<pre data-iptm-layout="ui-f8f4296401">' . h(trim($tiSum)) . '</pre>';
        
        echo '<h4>API esterne (opzionali)</h4>';
        $tc = ti_cfg();
        if (!$ro) {
            echo '<form method=post class=acc>' . fh('p=attacks') . '<input type=hidden name=action value=ti_save>';
            echo dd('AbuseIPDB API key', '<input name=abuseipdb type=password value="' . h($tc['abuseipdb']) . '" placeholder="chiave da abuseipdb.com" autocomplete=off>', 'Piano free: ~1000 check/giorno. Score di abuso 0–100.');
            echo dd('GreyNoise API key', '<input name=greynoise type=password value="' . h($tc['greynoise']) . '" placeholder="chiave community" autocomplete=off>', 'Classificazione noise/malicious/benign.');
            echo dd('AlienVault OTX key', '<input name=otx type=password value="' . h($tc['otx']) . '" placeholder="X-OTX-API-KEY" autocomplete=off>', 'Pulse count su indicatori IPv4.');
            echo '<div data-iptm-layout="ui-cc3e865af8"><b>VirusTotal</b> ';
            echo (!empty($tc['virustotal']) ? '<span class="b b-ACCEPT">chiave presente</span>' : '<span class=mut>chiave assente</span>');
            echo '<p class=mut data-iptm-layout="ui-5c2df38eed">Account free: <a href="https://www.virustotal.com/gui/join-us" target=_blank rel="noopener">registrati</a> → menu utente → <b>API key</b>. Quota tipica ~4 richieste/min.</p>';
            echo dd('VirusTotal API key', '<input name=virustotal type=password value="' . h($tc['virustotal'] ?? '') . '" placeholder="incolla la API key" autocomplete=off data-iptm-layout="mw420">');
            echo '<p class=ops><button type=submit class=s name=action value=ti_vt_test>Prova connessione VirusTotal</button></p></div>';
            echo dd('urlscan.io API key', '<input name=urlscan type=password value="' . h($tc['urlscan'] ?? '') . '" placeholder="opzionale" autocomplete=off>', 'Cerca scan pubblici che citano l\'IP.');
            echo dd('Scanner gratuiti abuse.ch', '<label><input type=checkbox name=threatfox value=1' . (!empty($tc['threatfox']) ? ' checked' : '') . '> ThreatFox IOC</label> · <label><input type=checkbox name=urlhaus value=1' . (!isset($tc['urlhaus']) || !empty($tc['urlhaus']) ? ' checked' : '') . '> URLhaus host</label>', 'Senza chiave. ThreatFox = malware C2/IOC; URLhaus = URL malevoli legati all\'IP.');
            echo dd('ip-api.com (legacy)', '<span class=mut>Disattivato: l’API free richiede HTTP non cifrato, quindi IPTM non invia gli IP dei client.</span>');
            echo dd('Cache ore', '<input name=cache_hours type=number min=1 max=168 value="' . h((string)($tc['cache_hours'] ?? 24)) . '" data-iptm-layout="ui-48a49aa0a8">');
            echo '<p><label><input type=checkbox name=clear_cache value=1> Svuota cache lookup</label></p>';
            echo '<p class=sticky><button class=g>Salva API threat intel</button></p></form>';
        } else {
            echo '<p class=mut>AbuseIPDB: ' . ($tc['abuseipdb'] ? 'configurata' : 'no') . ' · GreyNoise: ' . ($tc['greynoise'] ? 'configurata' : 'no') . ' · OTX: ' . ($tc['otx'] ? 'configurata' : 'no') . ' · VT: ' . (!empty($tc['virustotal']) ? 'si' : 'no') . ' · ip-api: disabilitato (HTTP)' . '</p>';
        }
echo '</details>';
    }

    if ($A['global']) {
        echo '<h3>Sintesi</h3><ul>';
        foreach ($A['global'] as [$sev, $msg]) {
            $b = $sev === 'high' ? 'b-DROP' : 'b-jump';
            echo '<li><span class="b ' . $b . '">' . h($sev) . '</span> ' . h($msg) . '</li>';
        }
        echo '</ul>';
    }

    // suggestions based on settings
    $sug = [];
    if ($tiHit > 0) $sug[] = $tiHit . ' indirizzi compaiono già in liste locali o DNSBL: verifica <a href="?p=lists">Liste / GeoIP</a> e CrowdSec.';
    if ($hi > 0 && empty($S['portscan'])) $sug[] = 'Abilita <a href="?p=security">Rilevamento port scan</a> in Sicurezza.';
    if ($hi > 0 && empty($S['crowdsec'])) $sug[] = 'Collega <a href="?p=crowdsec&t=firewall">CrowdSec bouncer iptables</a> per ban automatici.';
    if (($A['top_ports']['tcp/22'] ?? $A['top_ports']['TCP/22'] ?? 0) >= 5 && empty($S['ssh_limit']) && empty($S['ssh_acc'])) {
        $sug[] = 'Valuta <a href="?p=security">limiti SSH</a> o Fail2ban/CrowdSec sshd.';
    }
    if ($sug) {
        echo '<h3>Azioni consigliate</h3><ul>';
        foreach ($sug as $s) echo '<li>' . $s . '</li>';
        echo '</ul>';
    }

    echo '<h3>Sorgenti sospette</h3>';
    if (!$A['patterns']) {
        echo '<p class=mut>Nessun pattern evidente nei log recenti (pochi eventi o solo traffico sparso).</p>';
    } else {
        echo '<div data-iptm-layout="scroll"><table><tr><th>Sev.</th><th>Origine</th><th>Eventi</th><th>Pattern</th><th>Threat intel</th><th>Porte</th><th></th></tr>';
        foreach ($A['patterns'] as $x) {
            $b = $x['sev'] === 'high' ? 'b-DROP' : ($x['sev'] === 'med' ? 'b-jump' : 'b-ACCEPT');
            $labs = implode('; ', array_map(fn($l) => $l[2], $x['labels']));
            $ti = $TI[$x['src']] ?? null;
            $tiHtml = '<span class=mut>—</span>';
            if ($ti && $ti['score'] > 0) {
                $cb = ($ti['confidence'] ?? '') === 'high' ? 'b-DROP' : (($ti['confidence'] ?? '') === 'med' ? 'b-jump' : 'b-ACCEPT');
                $tiHtml = '<span class="b ' . $cb . '">score ' . (int)$ti['score'] . ' · ' . h($ti['confidence'] ?? '') . '</span>';
                $tiHtml .= '<br><span class=mut>' . h(implode(' · ', array_slice($ti['labels'], 0, 6))) . '</span>';
            } elseif ($ti) {
                $extra = [];
                if (($ti['cc'] ?? '-') !== '-') $extra[] = 'cc:' . $ti['cc'];
                if (($ti['asn'] ?? '-') !== '-') $extra[] = 'AS' . $ti['asn'];
                $tiHtml = '<span class="b b-ACCEPT">pulito</span>' . ($extra ? ' <span class=mut>' . h(implode(' ', $extra)) . '</span>' : '');
            }
            echo '<tr><td><span class="b ' . $b . '">' . h($x['sev']) . '</span></td>';
            echo '<td><code>' . h($x['src']) . '</code></td>';
            echo '<td>' . (int)$x['events'] . '</td>';
            echo '<td class=mut>' . h($labs) . '</td>';
            echo '<td>' . $tiHtml . '</td>';
            echo '<td class=mut>' . h(implode(', ', $x['ports'])) . '</td><td>';
            if (!$ro) echo blk_btn($x['src'], 'p=attacks');
            echo '</td></tr>';
        }
        echo '</table></div>';
    }

    echo '<div class=row><div data-iptm-layout="ui-83725d2c6e"><h3>Porte più colpite</h3><table>';
    foreach ($A['top_ports'] as $k => $v) {
        $pt = preg_replace('#^\w+/#', '', $k);
        $lab = $A['svc'][$pt] ?? '';
        echo '<tr><td>' . h($k) . ($lab ? ' <span class=mut>' . h($lab) . '</span>' : '') . '</td><td>' . $v . '</td></tr>';
    }
    echo '</table></div><div data-iptm-layout="ui-83725d2c6e"><h3>Prefissi log</h3><table>';
    foreach ($A['top_prefix'] as $k => $v) echo '<tr><td><code>' . h($k) . '</code></td><td>' . $v . '</td></tr>';
    echo '</table></div></div>';

    // CrowdSec / Suricata quick
    echo '<h3>Altre fonti</h3><div class=row>';
    try {
        $dec = function_exists('cs_decisions') ? cs_decisions() : [];
        if ($dec) {
            echo '<div data-iptm-layout="ui-83725d2c6e"><h4>CrowdSec (decisioni)</h4><table><tr><th>IP</th><th>Motivo</th><th>Azione</th></tr>';
            foreach (array_slice($dec, 0, 8) as $d) {
                echo '<tr><td>' . h($d['ip'] ?? '') . '</td><td class=mut>' . h($d['reason'] ?? '') . '</td><td>' . h($d['action'] ?? '') . '</td></tr>';
            }
            echo '</table><p class=mut><a href="?p=crowdsec&t=decisioni">Vedi tutte</a></p></div>';
        }
    } catch (Throwable $ex) {}
    try {
        [$c2, $al] = priv('su-alerts', null, ['30']);
        if (trim($al) !== '' && !str_contains($al, 'nessun log')) {
            echo '<div data-iptm-layout="ui-83725d2c6e"><h4>Suricata (ultimi alert)</h4><pre data-iptm-layout="ui-7c958bdca0">' . h(trim($al)) . '</pre><p class=mut><a href="?p=ips&t=avvisi">Vedi Suricata</a></p></div>';
        }
    } catch (Throwable $ex) {}
    echo '</div>';
    echo '<p class=ops data-iptm-layout="mt12"><a class="btn s" href="?p=log">Log completi</a> <a class="btn s" href="?p=impact">Impatto regole</a> <a class="btn s" href="?p=security">Sicurezza</a></p>';
    echo '</div>';
}

/** Interpret the bounded journal sample without assuming every packet has a protocol or port. */
function iptm_log_snapshot(string $journal): array {
    $rows=[];$sources=[];$ports=[];
    foreach(array_reverse(explode("\n",trim($journal))) as $line){
        if(!preg_match('/(IPT[\w-]*):/',$line,$prefix))continue;
        preg_match_all('/\b([A-Z]+)=(\S*)/',$line,$pairs);$fields=array_combine($pairs[1],$pairs[2]);
        $rows[]=[strtok($line,' '),$prefix[1],$fields['IN']??null,$fields['SRC']??null,$fields['DST']??null,$fields['PROTO']??null,$fields['SPT']??null,$fields['DPT']??null];
        if(!empty($fields['SRC']))$sources[$fields['SRC']]=($sources[$fields['SRC']]??0)+1;
        if(isset($fields['DPT'])&&ctype_digit($fields['DPT'])){$key=($fields['PROTO']??'?').'/'.$fields['DPT'];$ports[$key]=($ports[$key]??0)+1;}
    }
    arsort($sources);arsort($ports);return ['rows'=>$rows,'sources'=>$sources,'ports'=>$ports];
}
function pg_log() {
    [$rc,$out,$err]=priv('journal');
    iptm_view_start('Eventi del firewall','Campione del journal kernel con prefisso IPT; non rappresenta l’intero traffico.');
    if($rc!==0){iptm_view_error('Impossibile leggere il journal: '.$err);iptm_view_end();return;}
    $snapshot=iptm_log_snapshot($out);echo '<p>'.count($snapshot['rows']).' eventi nel campione.</p>';
    $top=static function(array $data):array{$rows=[];foreach(array_slice($data,0,10,true) as $k=>$v)$rows[]=[$k,$v];return $rows;};
    iptm_view_table(['Sorgente','Eventi'],$top($snapshot['sources']),'Sorgenti più frequenti');
    iptm_view_table(['Protocollo/porta','Eventi'],$top($snapshot['ports']),'Porte destinazione più frequenti');
    iptm_view_end();iptm_view_start('Dettaglio','Ultimi 100 eventi riconosciuti.');
    iptm_view_table(['Ora','Tipo','IN','Origine','Destinazione','Protocollo','Porta origine','Porta destinazione'],array_slice($snapshot['rows'],0,100),'Eventi kernel');iptm_view_end();
}

function pg_setup() {
    global $M; $S = S_get(); $if = sys_ifaces(); $fw = trim((string)@file_get_contents('/proc/sys/net/ipv4/ip_forward'));
    echo '<div class=card><h2>Setup di base</h2><p class=mut>Indica quali interfacce sono «WAN» (verso Internet/modem) e quali reti sono «LAN». Le sezioni Sicurezza e NAT usano questi dati.</p><p>Rilevate: ';
    foreach ($if as $n => $a) { echo '<a href="#" class=chip data-fill=wan_if data-v="' . h($n) . '">' . h($n) . '</a>'; foreach ($a as $ad) echo '<a href="#" class=chip data-fill=lan_nets data-v="' . h(net_of($ad)) . '" data-add=1 title="aggiungi alla LAN">' . h($ad) . ' → rete ' . h(net_of($ad)) . '</a>'; }
    echo '</p>';
    $b = dd_in($S, 'wan_if', 'Interfaccia WAN', 'eth0', 'Verso Internet/modem. Clic su un nome sopra per compilarla.', '200px') . dd_in($S, 'lan_if', 'Interfaccia LAN dedicata (facoltativa)', 'bond0', 'Usala solo quando gli accessi alle subnet LAN entrano realmente da questa interfaccia. Con più VLAN/interfacce LAN lascia vuoto e usa una WAN dedicata.', '220px') . dd_radio($S, 'wan_rfc1918_spoof', 'Blocca sorgenti RFC1918 sulla WAN pubblica verificata', 'Attivo solo con interfaccia WAN distinta, indirizzo pubblico verificato e nessun indirizzo privato sulla WAN. Disabilitato automaticamente su bond0 condivisa, doppio NAT, CGNAT o topologia sconosciuta.') . dd_in($S, 'external_ifs', 'Altre interfacce esterne non fidate (facoltative)', 'ppp0,eth1', 'Separale con virgole. I blocchi RFC1918 si generano solo se l’interfaccia ha un unico IPv4 pubblico, non ospita LAN e non è condivisa con VPN/VLAN. WAN dietro NAT privato: nessun blocco automatico.', '350px') .
        dd_in($S, 'lan_ingress_map', 'Associa rete LAN → ingresso (facoltativo)', '192.168.1.0/24=bond0,192.168.10.0/24=bond0.10,10.19.165.0/24=wg0', 'Per VLAN/VPN inoltrate che non hanno un indirizzo locale riconoscibile. La scheda deve esistere e non può essere WAN. L’associazione errata può bloccare SSH: verifica la bozza.', '100%') .
        dd_radio($S, 'single_nic', 'WAN e LAN sulla stessa interfaccia', 'Es. un solo cavo/bond: il «lato WAN» viene riconosciuto dalle subnet LAN invece che dall\'interfaccia.') .
        dd_in($S, 'lan_nets', 'Reti LAN', '192.168.1.0/24,192.168.10.0/24', 'CIDR separati da virgola.', '420px') .
        '<h3>NAT e routing</h3>' . dd_in($S, 'masq_ifs', 'Interfacce di uscita NAT (opz.)', 'bond0,wg0', 'Vuoto = WAN configurata. Se indicate, il NAT si applica esclusivamente alle subnet LAN indicate, mai a tutto il traffico dell’interfaccia.', '260px') . dd_in($S, 'drop_chain', 'Catena di scarto (opz.)', 'LOG-DROP', 'Le opzioni «scarta» saltano a questa catena (es. con log) invece di DROP. Vuoto = DROP.', '200px') .
        dd_radio($S, 'nat_masq', 'NAT / Masquerade verso la WAN', 'Condivide la connessione: la LAN esce con l\'IP della WAN.') . dd_radio($S, 'mss', 'Clamp MSS al PMTU', 'Evita blocchi su connessioni PPPoE/VPN.') .
        '<h3>Protezione DNS LAN</h3>' . dd_radio($S, 'dns_redirect', 'Forza DNS locale per la LAN (TCP/UDP 53)', 'Reindirizza soltanto le subnet LAN configurate; se l’ingresso non è verificato resta il vincolo per IP sorgente.') . dd_in($S, 'dns_ip', 'IP DNS locale', '192.168.1.165', 'Destinazione Pi-hole / Unbound / DNSCrypt. Nessuna modifica automatica del kernel.', '250px') . dd_radio($S, 'dot_block', 'Blocca DNS-over-TLS (TCP/UDP 853)', 'Mantiene i blocchi della LAN anche con ingresso non verificato. Non blocca automaticamente DoH/HTTPS.') . '<div class=msg><b>Gestione servizi DNS:</b> Pi-hole, Unbound e DNSCrypt restano in <a href="?p=dns"><b>DNS &amp; Privacy</b></a>. Le regole firewall DNS sono modificabili qui, nella stessa pagina del loro ambito LAN.</div>';
    $b.='<p><label><input type=checkbox name=confirm_dns_guard_removal value=1> Confermo la rimozione dei blocchi DoT/DNS esistenti se le relative opzioni sono disattivate (solo bozza, da verificare prima di applicare)</label></p>';
    if (!empty($S['nat_masq']) && !empty($S['single_nic'])) {
        $nets = array_values(array_filter(array_map('trim', explode(',', (string)($S['lan_nets'] ?? '')))));
        $outs = array_values(array_unique(array_filter(array_map('trim', explode(',',
            trim((string)($S['masq_ifs'] ?? '')) !== '' ? (string)$S['masq_ifs'] : (string)($S['wan_if'] ?? ''))))));
        if ($nets && $outs) {
            $b .= '<div class="msg" role="status"><strong>NAT Single-NIC: configurazione selettiva</strong>'
                . '<p>Origine: <code>' . h(implode(', ', $nets)) . '</code>. Uscita: <code>' . h(implode(', ', $outs))
                . '</code>. Le destinazioni LAN sono escluse. Nessun masquerade globale viene creato.</p></div>';
        } else {
            $b .= '<div class="msg err" role="alert"><strong>NAT incompleto.</strong> Indica almeno una subnet LAN e un’interfaccia di uscita per generare le regole.</div>';
        }
    }
    // Detect a saved-DNS-policy/draft mismatch before the operator applies it.
    try {
        $guardLoss=iptm_dns_guard_losses(rules_live(),ser($M));
    }catch(RuntimeException $e){$guardLoss=[];echo '<div class="msg err">Verifica protezioni DNS non disponibile: '.h($e->getMessage()).'</div>';}
    if($guardLoss){
        echo '<div class="msg warn" role="alert"><strong>Regole DNS/DoT presenti in rules.v4 ma mancanti nella bozza</strong><p>'.h(implode(', ',$guardLoss)).'. Non applicare una bozza che le elimina senza aver verificato le intenzioni. Ripristina dalla copia su disco con verifica delle tre subnet, senza toccare il firewall attivo.</p>';
        echo '<form method=post>'.fh('p=setup').'<input type=hidden name=action value=dns_guard_restore_disk><button class=g>Ripristina DoT/DNS dal file su disco (solo bozza)</button></form></div>';
    }
    $netRows=[];
    foreach(preg_split('/[\s,;]+/',trim((string)($S['lan_nets']??'')),-1,PREG_SPLIT_NO_EMPTY) as $subnet) {
        if(!v_ok('nets',$subnet) || !iptm_scope_within_lan($subnet,(string)($S['lan_nets']??'')))continue;
        $match=iptm_ingress_for_source($subnet,$S);
        $netRows[]='<tr><td><code>'.h($subnet).'</code></td><td>'.($match===''?'<span class="mut">ingresso non verificato</span>':'<code>'.h($match).'</code>').'</td></tr>';
    }
    $protected=iptm_external_spoof_ifaces($S);
    $b.='<div class="msg"><strong>Anteprima vincoli d’ingresso (senza applicare)</strong><p>INPUT, permessi FORWARD da LAN e reindirizzamento DNS vengono limitati a un ingresso attendibile quando verificabile. <b>Ingresso non verificato</b> non disattiva DoT o DNS: restano i vincoli per subnet sorgente, meno forti di un vincolo per interfaccia. Le policy IoT gestite dalla UI restano valide.</p>';
    if($netRows)$b.='<table><thead><tr><th>Rete autorizzata</th><th>Ingresso generato</th></tr></thead><tbody>'.implode('',$netRows).'</tbody></table>';
    $b.='<p>Anti-spoof RFC1918 attivabile su: <b>'.($protected?h(implode(', ',$protected)):'nessuna interfaccia esterna pubblica verificata').'</b>.</p>';
    if(!$protected && !empty($S['wan_rfc1918_spoof']))$b.='<p class="mut">In doppio NAT, su bond0 condivisa o con topologia incerta il blocco viene sospeso per non interrompere la rete.</p>';
    $b.='</div>';
    echo s_form('setup', $b, 'p=setup') . '</div>';
    echo '<div class=card><h3>IP forwarding del kernel</h3><p>Stato attuale: ' . ($fw === '1' ? '<span class="b b-ACCEPT">attivo</span>' : '<span class="b b-DROP">disattivo</span>') . ' — necessario per fare da router/NAT.</p>
<form method=post class=ops data-iptm-layout="ui-491198ddb7">' . fh('p=setup') . '<input type=hidden name=action value=forward_sysctl><button name=v value=1 class=g>Attiva (persistente)</button><button name=v value=0 class=d disabled title="Disponibile soltanto da console per sicurezza">Disattiva (solo console)</button></form></div>';
    $un = 0; foreach ($M as $bk) if ($bk['k'] === 'table') { $mg = false; foreach ($bk['items'] as $it) { if ($it['t'] === 'c') { if (str_starts_with($it['x'], '# >>> IPTM:')) $mg = true; elseif (str_starts_with($it['x'], '# <<< IPTM:')) $mg = false; } elseif ($it['t'] === 'rule' && $it['on'] && !$mg && $bk['name'] === 'nat' && preg_match('/-j (MASQUERADE|DNAT)/', $it['r'])) $un++; } }
    if ($un) echo '<div class=msg>ℹ Nel file ci sono già <b>' . $un . '</b> regole NAT scritte a mano (MASQUERADE/DNAT) non gestite da queste impostazioni. Se abiliti le stesse funzioni qui, valuta di disattivare le tue (⏸ nella pagina Regole) per non averle doppie.</div>';
}

function opt_rows(array $S, array $defs): string {   // [chiave, tipo(r|t), etichetta, aiuto, larghezza]
    $retired = array_merge(iptm_unsafe_flag_keys(), ['spoof_if','spoof_nets','sp_ports']);
    $o = ''; foreach ($defs as $d) { [$k, $t, $l] = $d; if (in_array($k, $retired, true)) continue; $o .= $t === 'r' ? dd_radio($S, $k, $l, $d[3] ?? '') : dd_in($S, $k, $l, '', $d[3] ?? '', $d[4] ?? '110px'); } return $o;
}
function pg_security() {
    $S = S_get(); wan_warn($S);
    echo '<div class="msg"><b>Preflight &amp; Commit sicurezza:</b> la procedura guidata interattiva è in <a href="?p=health#health-policy"><b>Sistema → Salute DietPi</b></a>. In questa pagina puoi gestire singole opzioni della policy; QoS rimane indipendente.</div>';
    global $M; echo iptm_policy_review_ui(ser($M),$S);
    echo '<div class="msg"><b>Modalità anti-disconnessione:</b> disabilitate nel backend le regole raw rpfilter, SYNPROXY, NOTRACK loopback e altre protezioni non sicure sulla WAN condivisa. Le vecchie bozze contenenti tali regole vengono rifiutate da Applica, anche con Forza. <a href="?p=apply">Controlla e rigenera la bozza</a>.</div>';
    echo '<div class="card"><strong>SSH instabile?</strong> ' . 'Ripristina l’accesso dal PC che usa questa console. Non riavvia né sostituisce le regole firewall.'
        . '<form method="post">'.fh('p=security')
        . '<button type="submit" class="s" name="action" value="ssh_continuity_recover">Recupera SSH da questo PC</button></form></div>';
    $b = '<div class="card" style="margin-bottom:12px"><h3>Continuità rete</h3>'
       . '<p>Privilegia navigazione, DNS, risposte e accesso amministratore. Evita rate-limit generici nella bozza.</p>'
       . dd_radio($S, 'continuity_priority', 'Proteggi la connettività', 'Consigliato: attivo. Non annulla blocchi IoT, DoT/QUIC esplicitamente selezionati.')
       . '<p class="mut">Per modifiche al firewall resta obbligatorio il ripristino automatico. Test completi offline, non nella console.</p></div>';
    $b .= '<div class=fw-policy-tools><label for=fw-policy-search><b>Trova un\'opzione</b></label><input type=search id=fw-policy-search placeholder="Es. SYN flood, DHCP, MAC, anti-lockout…" autocomplete=off><div class=fw-policy-actions><button type=button class=s id=fw-policy-open>Apri tutte le sezioni</button><button type=button class=s id=fw-policy-close>Chiudi tutte le sezioni</button><span class=mut>Le opzioni restano tutte disponibili; cerca per nome o descrizione.</span></div></div><div class=fw-policy-sections><details class=fw-acc open><summary><span>Protezione firewall</span><small>Base, SPI e anti-spoofing</small></summary><div class=fw-acc-body>' . opt_rows($S, [
        ['spi', 'r', 'Firewall SPI', 'Accetta le connessioni già stabilite e il loopback; imposta le policy INPUT/FORWARD su DROP.'],
        ['antispoof', 'r', 'Anti-spoofing (loopback)', 'Scarta sorgenti 127.0.0.0/8 che non arrivano da «lo».'], ['antispoof_mc', 'r', '… e multicast come sorgente'],
        ['spoof_on', 'r', 'Sorgenti impossibili su un\'interfaccia', 'Scarta (verso la catena di scarto) le subnet indicate se arrivano da quell\'interfaccia: sono falsificate.'],
        ['spoof_if', 't', 'Interfaccia', '', '140px'], ['spoof_nets', 't', 'Subnet che non possono arrivare da lì', 'CIDR separati da virgola.', '420px'],
        ['invalid', 'r', 'Scarta pacchetti non validi e scansioni', 'INVALID, NEW senza SYN, flag TCP anomali (NULL, XMAS, SYN+FIN…).'],
        ['crowdsec', 'r', 'CrowdSec: il bouncer protegge questo firewall', 'Non aggiunge regole: indica al bouncer su quali catene agganciarsi (INPUT, FORWARD se router, DOCKER-USER) e lo riavvia dopo ogni «Applica» (il caricamento delle regole svuota la sua catena). I set li crea e li aggiorna lui.'], ['cs_docker', 'r', 'Applica anche a DOCKER-USER']]) .
        '</div></details><details class=fw-acc><summary><span>Perimetro WAN e rate limit</span><small>Filtri, connessioni e traffico anomalo</small></summary><div class=fw-acc-body>' . opt_rows($S, [['multicast', 'r', 'Filtra multicast dal WAN'], ['ident', 'r', 'Filtra IDENT (porta 113)', 'Risponde con reset: evita ritardi con posta/IRC.'], ['blockping', 'r', 'Blocca richieste anonime (ping dal WAN)']]) .
        '' . opt_rows($S, [['conn_limit', 'r', 'Limite connessioni simultanee per IP', 'Scarta i nuovi SYN verso il router oltre la soglia (connlimit).'], ['cl_max', 't', 'Massimo connessioni per IP'], ['bad_mss', 'r', 'Scarta SYN con MSS anomalo', 'MSS inferiore a 536: tipico di scansioni e attacchi.'], ['udp_rl', 'r', 'Limite nuovi flussi UDP per sorgente', 'Verso il router, con hashlimit.'], ['ul_rate', 't', 'Soglia UDP al secondo'], ['ul_burst', 't', 'Burst UDP'], ['web_rl', 'r', 'Limite nuove connessioni web dal WAN', 'Per sorgente, verso il router e i server in port forwarding.'], ['wl_ports', 't', 'Porte web', '', '160px'], ['wl_rate', 't', 'Soglia connessioni al secondo'], ['wl_burst', 't', 'Burst web'], ['amp_block', 'r', 'Blocco amplificazione UDP dal WAN', 'Scarta risposte NON richieste da porte 19, 53, 111, 123, 137, 161, 389, 1900, 5353, 11211.'], ['bl_log', 'r', 'Registra i pacchetti scartati dalle liste IP', 'Log con limite (prefisso IPTM-BL) visibile nella pagina Log.'], ['rpfilter', 'r', 'Reverse path filter (raw)', 'Scarta sorgenti incoerenti con il routing. Non usare con routing asimmetrico, VPN o Docker; richiede il modulo xt_rpfilter.']]) .
        '</div></details><details class=fw-acc><summary><span>LAN, segmentazione e dispositivi</span><small>Reti ospiti, isolamento, MAC e quarantena</small></summary><div class=fw-acc-body>' . opt_rows($S, [
        ['iso_on', 'r', 'Isola tra loro le reti indicate', 'Nessun traffico tra le reti elencate (es. IoT, telecamere, ufficio), in entrambe le direzioni.'], ['iso_nets', 't', 'Reti da isolare', 'Almeno due CIDR separati da virgola.', '420px'],
        ['guest_on', 'r', 'Rete ospiti', 'Internet sì; reti private (10/8, 172.16/12, 192.168/16) no; al router solo le porte indicate.'], ['guest_nets', 't', 'Reti ospiti', 'CIDR separati da virgola.', '420px'], ['guest_ports', 't', 'Porte consentite verso il router', 'Predefinite: DNS e DHCP.', '160px'], ['guest_allow', 't', 'Destinazioni private consentite agli ospiti', 'Es. il tuo DNS locale (IP o CIDR, virgola).', '420px'],
        ['mac_block', 't', 'Quarantena: MAC bloccati', 'Indirizzi MAC separati da virgola (aa:bb:cc:dd:ee:ff). Scartati in INPUT e FORWARD.', '520px'],
        ['quic_block', 'r', 'Blocca QUIC / HTTP3 (UDP 443) dalla LAN', 'Utile per filtri e statistiche: i browser tornano su HTTPS/TCP.'],
        ['lan_cl', 'r', 'Limite connessioni simultanee per client LAN', 'Contiene malware, torrent e scansioni che aprono migliaia di connessioni.'], ['lan_cl_max', 't', 'Massimo connessioni per client'],
        ['svc_ban', 'r', 'Ban automatico dei servizi esposti', 'Troppe nuove connessioni verso le porte indicate dal WAN: la sorgente viene bannata (tutte le porte) per il tempo indicato.'], ['sb_ports', 't', 'Porte sorvegliate', '', '240px'], ['sb_hits', 't', 'Tentativi (max 20)'], ['sb_secs', 't', 'Nel periodo (secondi)'], ['sb_ban', 't', 'Durata del ban (secondi)']]) .
        '</div></details><details class=fw-acc><summary><span>Controllo avanzato e ALG</span><small>Policer, MAC autorizzati e helper NAT</small></summary><div class=fw-acc-body>' . opt_rows($S, [
        ['bw_on', 'r', 'Limite di banda per host (policer)', 'Scarta i pacchetti oltre la soglia, per ogni host LAN (solo con interfacce WAN/LAN separate).'], ['bw_up', 't', 'Uscita massima per host (KB/s)'], ['bw_down', 't', 'Ingresso massimo per host (KB/s)'],
        ['mac_only', 'r', 'LAN solo per dispositivi autorizzati (MAC)', 'Il traffico in transito dall\'interfaccia LAN è consentito solo ai MAC elencati (max 40). L\'accesso al router non cambia.'], ['mac_allow', 't', 'MAC autorizzati', 'aa:bb:cc:dd:ee:ff separati da virgola. Obbligatorio se attivi la funzione.', '520px'],
        ['alg_ftp', 'r', 'ALG FTP', 'Helper conntrack per le connessioni dati FTP attraverso il NAT.'], ['alg_tftp', 'r', 'ALG TFTP'], ['alg_sip', 'r', 'ALG SIP', 'Per telefonia VoIP dietro NAT.']]) .
        '</div></details><details class=fw-acc><summary><span>Accesso alla gestione web</span><small>Reti autorizzate alla dashboard</small></summary><div class=fw-acc-body>' . opt_rows($S, [['ui_nets', 't', 'Reti autorizzate (opzionale)', 'Restringe ulteriormente ALLOWED_NETS. Vuoto = nessuna restrizione aggiuntiva. Il tuo indirizzo deve esserne incluso. La sessione scade dopo 30 minuti di inattività.', '420px']]) . '<p class=ops><button class=s type=submit name=action value=wg_mgmt_nets formnovalidate title="Imposta ui_nets a LAN + rete WireGuard + localhost">Suggerisci LAN+WireGuard</button></p>' .
        '</div></details><details class=fw-acc><summary><span>ICMP, flood e servizi LAN</span><small>DHCP, Docker, broadcast e DoS</small></summary><div class=fw-acc-body>' . opt_rows($S, [
        ['icmp_limit', 'r', 'ICMP con limite per sorgente', 'Ping accettato entro soglia, scartato oltre.'], ['icmp_echo_rate', 't', 'Soglia echo-request', 'es. 2/sec'], ['icmp_echo_burst', 't', 'Burst echo'],
        ['icmp_other_rate', 't', 'Soglia altri ICMP', 'es. 5/sec'], ['icmp_other_burst', 't', 'Burst altri'], ['igmp_accept', 'r', 'Accetta IGMP multicast', 'Le query del modem a 224.0.0.1.'],
        ['lan_tcp_accept', 'r', 'Tutto il TCP dalla LAN', 'Se attiva, la LAN raggiunge tutte le porte TCP dell\'host. Le regole SSH sopra restano attive (connlimit/recent).'],
        ['docker_accept', 'r', 'Accetta reti Docker', 'INPUT da docker_nets + risposte FORWARD RELATED/ESTABLISHED verso i container.'],
        ['docker_nets', 't', 'Reti Docker', 'es. 172.16.0.0/12', '220px'],
        ['dhcp_accept', 'r', 'Server DHCP: accetta richieste dei client', 'UDP 68→67 (sorgente 0.0.0.0) su tutte le interfacce tranne il WAN, più le risposte 67→68. Senza, i client non ricevono l\'IP con policy DROP/SPI.'],
        ['bcast_accept', 'r', 'Broadcast UDP dalla LAN', 'Accetta traffico verso 255.255.255.255 dalle reti LAN (discovery).'],
        ['coap_accept', 'r', 'mDNS e CoAP (Shelly)', 'UDP 5353 multicast e CoAP 5683 sulla interfaccia WAN/LAN bridge.'],
        ['lan_out_fwd', 'r', 'FORWARD LAN → uscita', 'Permette alle reti LAN di uscire sulle interfacce di MASQUERADE/WAN.'],
        ['cs_set_match', 'r', 'Match-set CrowdSec classico', 'Oltre al bouncer, scarta con -m set crowdsec-blacklists (compatibilità iptables legacy).'],

        ['dos', 'r', 'Anti SYN flood per sorgente', 'hashlimit sui nuovi SYN.'], ['dos_syn', 't', 'Soglia SYN al secondo'], ['dos_burst', 't', 'Burst']]) .
        '</div></details><details class=fw-acc><summary><span>Accesso servizi e anti brute-force</span><small>SSH, Telnet e port knocking</small></summary><div class=fw-acc-body>' . opt_rows($S, [
        ['ssh_acc', 'r', 'Limiti SSH per rete (connlimit + recent)', 'Per ogni rete: max connessioni simultanee e max nuovi tentativi nel periodo.'], ['ssh_nets', 't', 'Reti', 'CIDR separati da virgola.', '420px'],
        ['ssh_acc_port', 't', 'Porta SSH'], ['ssh_conn', 't', 'Max connessioni simultanee'], ['ssh_hits', 't', 'Max tentativi nel periodo'], ['ssh_secs', 't', 'Periodo (secondi)'], ['ssh_name', 't', 'Nome lista «recent»', '', '160px'],
        ['ssh_limit', 'r', 'Limita SSH dal WAN', 'Dopo N nuove connessioni nel periodo, scarta.'], ['ssh_port', 't', 'Porta SSH (WAN)'], 
        ['lim_hits', 't', 'Max connessioni nel periodo (WAN)'], ['lim_secs', 't', 'Periodo (WAN, secondi)'],
        ['knock_on', 'r', 'Port knocking', 'La porta resta chiusa finché non «bussi» in ordine sulle porte indicate.'], ['knock_ports', 't', 'Sequenza di porte TCP', '2 o più, es. 7000,8000,9000', '260px'], ['knock_target', 't', 'Porta da aprire'], ['knock_secs', 't', 'Secondi di apertura'], ['knock_nets', 't', 'Solo da queste reti (opz.)', 'CIDR separati da virgola.', '300px']]) .
        '</div></details><details class=fw-acc><summary><span>Chiusura e policy finale</span><small>Porte non autorizzate e DROP finale</small></summary><div class=fw-acc-body>' . opt_rows($S, [
        ['closeports', 'r', 'Scarta le porte privilegiate non autorizzate', 'Vale per le porte che nessuna regola sopra ha accettato.'], ['close_range', 't', 'Intervallo', 'es. 1:1023'],
        ['final_drop', 'r', 'Scarta tutto il resto (INPUT e FORWARD)', 'Regola catch-all finale verso la catena di scarto.'],
        ['logdrop_on', 'r', 'Gestisci la catena di scarto con log', 'Crea il log con limiti per sorgente (utile a CrowdSec). Il nome della catena è in Setup.'],
        ['ld_src_rate', 't', 'Log: soglia per sorgente'], ['ld_src_burst', 't', 'Log: burst per sorgente'], ['ld_glob_rate', 't', 'Log: tetto globale'], ['ld_glob_burst', 't', 'Log: burst globale'], ['ld_prefix', 't', 'Prefisso nel log', '', '200px']]) .
        '</div></details><details class=fw-acc><summary><span>Anti-lockout e hardening avanzato</span><small>Port scan, SYNPROXY, stealth e protezioni host</small></summary><div class=fw-acc-body><p class=mut>Ispirate a pfSense/OPNsense, alle guide CIS e a iptables-essentials. Le opzioni «dal WAN» richiedono la WAN definita in Setup.</p>' . opt_rows($S, [
        ['lockout_on', 'r', 'Anti-lockout (gestione sempre raggiungibile)', 'Mantiene aperte le porte solo dalle reti amministrative; SSH protetto mantiene i propri limiti.'], ['mgmt_nets', 't', 'Reti amministrative', 'CIDR separati da virgola. Necessarie con più LAN o VLAN; non includere reti ospiti.', '300px'], ['mgmt_ports', 't', 'Porte di gestione', 'es. 22,80,443', '200px'],
        ['drop_frag', 'r', 'Scarta i frammenti IP', 'Raro nel traffico legittimo; usato in alcuni attacchi.'],
        ['portscan', 'r', 'Rilevamento port scan', 'Chi tocca troppe porte chiuse viene bannato. Le reti locali sono escluse. Parametri configurabili sotto.'],
        ['ps_hits', 't', 'Port scan: tentativi (hitcount)', 'Soglia di porte diverse toccate (default 14)', '120px'],
        ['ps_secs', 't', 'Port scan: finestra (secondi)', 'Periodo di osservazione (default 60)', '120px'],
        ['ps_ban', 't', 'Port scan: durata ban (secondi)', 'Quanto resta bloccata la sorgente (default 3600)', '140px'],
        ['bogon_wan', 'r', 'Scarta reti private/bogon dal WAN', 'Solo con WAN su interfaccia dedicata e IP pubblico: NON usarlo con modem in doppio NAT.'],
        ['stealth', 'r', 'Modalità stealth', 'Preferisce DROP silenzioso (niente TCP-reset / ICMP unreachable). Riduce la visibilità del firewall, ispirato alle opzioni stealth di firewall commerciali.'],
        ['synproxy', 'r', 'SYNPROXY (anti SYN flood avanzato)', 'Usa il target SYNPROXY del kernel (richiede modulo nf_synproxy_core). Più efficace del solo hashlimit contro flood massicci.'],
        ['sp_ports', 't', 'SYNPROXY: solo queste porte (opz.)', 'Vuoto = tutti i SYN in ingresso. Es. 80,443,22 per limitare l\'overhead.', '260px'],
        ['tarpit', 'r', 'TARPIT su porte privilegiate chiuse', 'Rallenta drasticamente gli scanner che toccano le porte chiuse (richiede modulo xt_TARPIT / ipt_TARPIT). Si combina con «Scarta porte privilegiate».'],
        ['dns_rebind', 'r', 'Promemoria DNS rebinding (resolver)', 'Segnala che la protezione rebinding va configurata su Pi-hole, Unbound o DNSCrypt. Non genera regole iptables: bloccare la destinazione RFC1918 delle risposte DNS interromperebbe i client LAN.'],
        ['raw_invalid', 'r', 'Scarta INVALID in tabella raw', 'Elimina i pacchetti non validi prima del connection tracking: riduce carico e attacchi su conntrack.'],
        ['glob_new_limit', 'r', 'Limite globale nuove connessioni TCP', 'Soglia complessiva di SYN/sec verso il router (oltre al limite per sorgente). Utile contro flood distribuiti.'],
        ['gn_rate', 't', 'Soglia globale SYN/sec', '', '100px'], ['gn_burst', 't', 'Burst globale', '', '100px'],
        ['arp_protect', 'r', 'Protezione ARP (sysctl)', 'Attiva filtri ARP del kernel (arp_ignore/arp_announce) contro spoofing banale. Per monitoraggio attivo installa arpwatch da Programmi.'],
        ['tcp_fastopen_off', 'r', 'Disabilita TCP Fast Open', 'Riduce la superficie di attacco su stack TCP (alcuni exploit storici sfruttavano TFO).'],
        ['lan_flood', 'r', 'Limita le nuove connessioni per client LAN', 'Contiene un dispositivo infetto che apre migliaia di connessioni.'], ['lf_rate', 't', 'Soglia al secondo'], ['lf_burst', 't', 'Burst'],
        ['egress_smtp', 'r', 'Blocca SMTP (porta 25) in uscita dalla LAN', 'Impedisce lo spam da dispositivi compromessi.'], ['egress_allow', 't', 'Eccezioni (server di posta)', 'IP o reti, separati da virgola.', '300px'], ['egress_ports', 't', 'Altre porte da bloccare in uscita', 'es. 6667,6697 (TCP e UDP)', '260px']]) .
        '</div></details><details class=fw-acc><summary><span>Conntrack e tabella raw</span><small>Regole pre-connection tracking</small></summary><div class=fw-acc-body>' . opt_rows($S, [['raw_lo', 'r', 'Loopback senza connection tracking'], ['raw_drop', 'r', 'Scarta porte Windows/SSDP prima del tracking'], ['raw_tcp', 't', 'Porte TCP', '', '300px'], ['raw_udp', 't', 'Porte UDP', '', '300px']]) .
        '<p class=mut>Gestione log del kernel (Stato → Log).</p>' . opt_rows($S, [['log_in', 'r', 'Log connessioni in ingresso dal WAN'], ['log_out', 'r', 'Log connessioni verso il WAN'], ['log_drop', 'r', 'Log pacchetti scartati'], ['log_rate', 't', 'Limite di log', 'n/sec|min|hour|day', '140px']]) . '</div></details></div>';

    $presets = '<div class="card"><h2>Configurazione protetta</h2>'
        . '<p class=mut>Per la tua rete con LAN e gateway su <code>bond0</code>, i profili Rigoroso e Paranoico sono stati ritirati. Il profilo di base non applica sysctl o regole attive.</p>'
        . '<form method=post>' . fh('p=security')
        . '<input type=hidden name=action value=sec_preset><button class=g name=level value=standard>Prepara profilo consigliato (solo bozza)</button></form></div>';
    echo '<div class="iptm-security-hub"><div><span class="iptm-eyebrow">Centro protezione firewall</span><h2>Impostazioni e policy</h2><p>Le opzioni sono organizzate per perimetro, LAN, servizi e protezioni avanzate. Il salvataggio aggiorna soltanto la bozza.</p></div><nav aria-label="Funzioni firewall"><a href="?p=rules">Regole</a><a href="?p=chains">Catene</a><a href="?p=safeplan">Calibrazione</a><a href="?p=apply">Applica con rollback</a></nav></div>';
    echo $presets . '<section class="card iptm-security-settings" aria-label="Impostazioni di protezione"><h2>Policy e contromisure</h2>' . s_form('security', $b, 'p=security') . '</section>';
}
function svc_table(string $pk, array $rows, bool $fwd): string {
    $row = function ($i, $r) use ($pk, $fwd) {
        $n = fn($k) => $pk . '[' . $i . '][' . $k . ']'; $in = fn($k, $ph = '', $w = '110px') => '<td><input name="' . $n($k) . '" value="' . h($r[$k] ?? '') . '" placeholder="' . h($ph) . '" style="min-width:' . $w . '"></td>';
        return '<tr><td><input type=checkbox name="' . $n('on') . '" value=1' . (!empty($r['on']) ? ' checked' : '') . '></td>' . $in('name', 'Nome', '130px') . $in('iif', 'ingresso') . ($fwd ? $in('oif', 'uscita') : '') . $in('src', 'sorgente', '140px') . $in('dst', 'destinazione', '140px') .
            '<td><select name="' . $n('proto') . '">' . opts(['', 'tcp', 'udp', 'icmp', 'igmp'], $r['proto'] ?? '') . '</select></td>' . $in('ports', '22 o 80,443') . ($fwd ? $in('ct', 'RELATED,ESTABLISHED', '140px') : '<td><label><input type=checkbox name="' . $n('after') . '" value=1' . (!empty($r['after']) ? ' checked' : '') . '> dopo SSH</label></td>') .
            '<td><label><input type=checkbox name="' . $n('del') . '" value=1> elimina</label></td></tr>';
    };
    $t = '<div data-iptm-layout="scroll"><table id=' . $pk . 'tab><tr><th>On</th><th>Nome</th><th>Interf. ingresso</th>' . ($fwd ? '<th>Interf. uscita</th>' : '') . '<th>Sorgente</th><th>Destinazione</th><th>Proto</th><th>Porte</th><th>' . ($fwd ? 'Stato conn.' : 'Ordine') . '</th><th></th></tr>';
    foreach ($rows as $i => $r) $t .= $row($i, $r);
    return $t . '</table></div><template id=' . $pk . 'tpl>' . $row('__i__', ['on' => 1]) . '</template><p><button type=button class=s data-tpl="#' . $pk . 'tpl" data-into="#' . $pk . 'tab">＋ Aggiungi riga</button></p>';
}
function pg_router(): void {
    global $M; $S=S_get();
    echo iptm_policy_review_ui(ser($M),$S);
    iptm_view_start('Accesso al router e transito','Distingui i servizi locali dalle connessioni tra LAN, VPN e WAN. Una subnet da sola non identifica l’interfaccia di ingresso.');
    echo '<p>'.iptm_view_link('setup','Controlla interfacce').' '.iptm_view_link('rulesaudit','Analizza bozza').'</p>';
    $body='<h3>Servizi locali (INPUT)</h3><p>Traffico verso questo host. Le regole dopo SSH rispettano la precedenza dei limiti SSH.</p>'.svc_table('s_in',$S['svc_in'],false).'<h3>Transito (FORWARD)</h3><p>Traffico tra interfacce, VPN, LAN e WAN.</p>'.svc_table('s_fw',$S['svc_fwd'],true);
    echo s_form('router',$body,'p=router');iptm_view_end();
}
function pg_import() {
    global $M;$admin=($_SESSION['role']??'viewer')==='admin';
    iptm_view_start('Importazione delle regole','Analizza le regole esistenti e prepara opzioni gestite da IPTM. Il firewall attivo non cambia.');
    if(is_file(DATA_DIR.'/settings.json')){echo '<p>Le impostazioni sono già presenti. Esporta un backup prima di ripetere l’importazione.</p>'.iptm_view_link('config','Esporta configurazione');
        if($admin){iptm_view_form('import','settings_reset');iptm_view_submit('Azzera impostazioni','d');}iptm_view_end();return;}
    try{$plan=import_plan_safe($M);$settings=$plan['S'];$removed=iptm_import_without_legacy_comments(ser($M))['removed'];}catch(Throwable $e){iptm_view_error($e->getMessage());iptm_view_end();return;}
    iptm_view_table(['Indicatore','Valore'],[['Livello',$plan['level']],['Regole attive',$plan['total']],['Opzioni riconosciute',count($plan['on'])],['Servizi INPUT',$plan['svc'][0]],['Servizi FORWARD',$plan['svc'][1]],['Interfacce NAT',$settings['masq_ifs']],['Reti LAN',$settings['lan_nets']],['DNS',$settings['dns_ip']],['Catena scarto',$settings['drop_chain']??'DROP'],['Regole rimosse',count($plan['removed'])],['Regole unite',$plan['merged']],['Commenti legacy da eliminare',$removed]],'Riepilogo importazione');
    if((int)$plan['level_n']!==0)echo '<p class="msg warn">Importazione parziale: le regole non assorbite restano manuali.</p>';iptm_view_end();
    iptm_view_start('Opzioni riconosciute');$rows=[];foreach(OPT_LABEL as $key=>$label)$rows[]=[$label,!empty($settings[$key])?'Attiva':'Non attiva'];iptm_view_table(['Opzione','Stato'],$rows,'Riconoscimento delle opzioni');iptm_view_end();
    iptm_view_start('Anteprima e decisione','Le equivalenze vengono valutate dal modello IPTM; controlla comunque le differenze prima di applicare.');
    foreach(['removed'=>'Regole rimosse','left'=>'Regole non riconosciute e conservate'] as $key=>$label)if(!empty($plan[$key]))echo '<details><summary>'.iptm_view_text($label).' ('.count($plan[$key]).')</summary><pre>'.iptm_view_text(implode("\n",$plan[$key])).'</pre></details>';
    if($admin){iptm_view_form('import','import_apply');iptm_view_submit('Importa nella bozza');iptm_view_form('import','import_skip');iptm_view_submit('Salta importazione','s');}iptm_view_end();
}


function iptm_forward_row($index,array $row): string {
    $key='f['.$index.']';
    $cells=[iptm_edit_check($key.'[on]','Attiva',!empty($row['on'])),
        iptm_edit_text($key.'[name]','Applicazione',$row['name']??''),
        '<select name="'.h($key.'[proto]').'" aria-label="Protocollo">'.opts(['both','tcp','udp'],$row['proto']??'both').'</select>',
        iptm_edit_text($key.'[src]','Sorgente',$row['src']??'','Qualsiasi'),
        iptm_edit_text($key.'[eport]','Porta esterna',$row['eport']??'','8080'),
        iptm_edit_text($key.'[ip]','Destinazione',$row['ip']??'','192.168.1.50'),
        iptm_edit_text($key.'[tport]','Porta interna',$row['tport']??'','Uguale'),
        iptm_edit_check($key.'[del]','Elimina')];
    return '<tr><td>'.implode('</td><td>',$cells).'</td></tr>';
}
function pg_forward(): void {
    $S=S_get();wan_warn($S);
    iptm_view_start('NAT e inoltro porte','Configura i servizi raggiungibili dalla WAN. Le modifiche vengono salvate nella bozza; verifica prima di applicare.');
    $body='<h3>Inoltri configurati</h3><div class="iptm-table-scroll" role="region" aria-label="Inoltri" tabindex="0"><table id="ftab"><thead><tr>';
    foreach(['Stato','Applicazione','Protocollo','Sorgente','Porta esterna','IP interno','Porta interna','Rimozione'] as $head)$body.='<th scope="col">'.h($head).'</th>';
    $body.='</tr></thead><tbody>';
    foreach(iptm_view_rows($S['fwd']??[]) as $i=>$row)$body.=iptm_forward_row($i,$row);
    $body.='</tbody></table></div><template id="ftpl">'.iptm_forward_row('__i__',['on'=>1]).'</template><p><button type="button" class="s" id="fadd">Aggiungi inoltro</button></p>';
    $body.='<h3>Accesso LAN al nome pubblico</h3>'.dd_radio($S,'loopback','NAT loopback','Consente l’accesso ai servizi inoltrati anche dalla LAN.');
    $body.='<h3>DMZ</h3><p class="msg warn">La DMZ può esporre servizi interni non protetti. Preferisci inoltri selettivi.</p>'.dd_radio($S,'dmz_on','Abilita DMZ').dd_in($S,'dmz_ip','IP host DMZ','192.168.1.50').dd_in($S,'dmz_excl','Porte escluse','22,80','Massimo 15 porte separate da virgola.');
    echo s_form('forward',$body,'p=forward');iptm_view_end();
}
function iptm_access_card($index,array $policy): string {
    $key='a['.$index.']';
    $body='<section class="card iptm-policy-editor"><h3>Criterio di accesso</h3><div class="ops">'.iptm_edit_check($key.'[on]','Attivo',!empty($policy['on'])).iptm_edit_check($key.'[del]','Elimina').'</div>';
    $body.='<label class="fl">Nome'.iptm_edit_text($key.'[name]','Nome',$policy['name']??'').'</label><label class="fl">Client (IP, rete, intervallo, MAC)'.iptm_edit_text($key.'[clients]','Client',$policy['clients']??'','Uno per riga; vuoto = tutta la LAN',true).'</label><fieldset><legend>Giorni</legend>';
    $days=(array)($policy['days']??[]);foreach(DAYS as $id=>$day)$body.=iptm_edit_check($key.'[days][]',(string)$day,!$days||in_array($id,$days,true),(string)$id);
    $body.='</fieldset><div class="row"><label class="fl">Dalle'.iptm_edit_text($key.'[from]','Dalle',($policy['from']??'')?:'00:00').'</label><label class="fl">Alle'.iptm_edit_text($key.'[to]','Alle',($policy['to']??'')?:'24:00').'</label></div><fieldset><legend>Servizi da bloccare</legend>';
    foreach(SVC as $id=>[$label])$body.=iptm_edit_check($key.'[svc][]',(string)$label,in_array($id,(array)($policy['svc']??[]),true),(string)$id);
    return $body.'</fieldset><label class="fl">Altre porte'.iptm_edit_text($key.'[custom]','Altre porte',$policy['custom']??'','tcp:8080,9000 udp:5000:5100').'</label><label class="fl">Siti e parole chiave'.iptm_edit_text($key.'[urls]','Siti',$policy['urls']??'','Una voce per riga',true).'</label><p class="mut">Il filtro HTTP/SNI non equivale a un filtro web completo; DoH, VPN e QUIC possono limitarne l’efficacia.</p></section>';
}
function pg_access(): void {
    $S=S_get();$rows=iptm_view_rows($S['acl']??[]);
    $add=$_GET['add']??'';if(is_string($add)&&preg_match('/^[0-9A-Fa-f:.\-]{7,20}$/D',$add))$rows[]=['on'=>1,'name'=>'Nuovo criterio','clients'=>$add];
    iptm_view_start('Restrizioni di accesso','Definisci quali client possono utilizzare determinati servizi e in quali orari. Agisce sul traffico inoltrato dal router.');
    $body='<div id="plist">';foreach($rows as $i=>$row)$body.=iptm_access_card($i,$row);
    $body.='</div><template id="ptpl">'.iptm_access_card('__i__',['on'=>1]).'</template><p><button type="button" class="s" id="padd">Nuovo criterio</button></p>';
    echo s_form('access',$body,'p=access');iptm_view_end();
}
