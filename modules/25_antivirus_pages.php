<?php
// ===================== SCANNER ANTIVIRUS CLOUD (VirusTotal free + ClamAV locale) =====================
function vt_key(): string {
    $k = trim((string)(ti_cfg()['virustotal'] ?? ''));
    return preg_match('/^[A-Za-z0-9_\-]{32,128}$/D', $k) ? $k : '';
}
/** POST multipart o form-urlencoded verso VirusTotal; restituisce body o null. */
function vt_curl_post(string $url, array $headers, array $fields = [], ?string $fileField = null, ?string $filePath = null, int $timeout = 60): ?string {
    return iptm_https_curl($url,$headers,$timeout,$fields,$fileField,$filePath,true);
}
function vt_stats_label(array $st): array {
    $count=static fn($v)=>is_int($v)&&$v>=0?min($v,1000000):0;
    $mal = $count($st['malicious'] ?? 0);
    $sus = $count($st['suspicious'] ?? 0);
    $harm = $count($st['harmless'] ?? 0);
    $und = $count($st['undetected'] ?? 0);
    $tot = max(1, $mal + $sus + $harm + $und + $count($st['timeout'] ?? 0) + $count($st['failure'] ?? 0) + $count($st['type-unsupported'] ?? 0) + $count($st['confirmed-timeout']??0));
    if ($mal > 0) $ver = 'malicious';
    elseif ($sus > 0) $ver = 'suspicious';
    elseif ($harm > 0) $ver = 'clean';
    else $ver = 'unknown';
    return [$ver, $mal, $sus, $harm, $und, $tot];
}
/** Lookup report file per hash (md5/sha1/sha256). */
function vt_file_report(string $hash): array {
    $key = vt_key();
    if ($key === '') return ['ok' => false, 'err' => 'Configura la API key VirusTotal in Pattern attacco o in questa pagina.'];
    $hash = strtolower(trim($hash));
    if (!preg_match('/^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/', $hash)) return ['ok' => false, 'err' => 'Hash non valido (MD5 32, SHA1 40 o SHA256 64 caratteri esadecimali).'];
    $body = ti_curl('https://www.virustotal.com/api/v3/files/' . $hash, ['x-apikey: ' . $key, 'Accept: application/json'], 12);
    if ($body === null || $body === '') return ['ok' => false, 'err' => 'Nessuna risposta da VirusTotal (rete/DNS/firewall in uscita?).'];
    $j = json_decode($body, true);
    if (!is_array($j)) return ['ok' => false, 'err' => 'Risposta non JSON.'];
    if (isset($j['error'])) {
        $code = (int)($j['error']['code'] ?? 0);
        $msg = (string)($j['error']['message'] ?? 'errore');
        if ($code === 404 || stripos($msg, 'not found') !== false) return ['ok' => true, 'found' => false, 'hash' => $hash, 'msg' => 'Hash sconosciuto a VirusTotal: nessun report pubblico.'];
        return ['ok' => false, 'err' => 'VirusTotal: ' . $msg];
    }
    $attr = $j['data']['attributes'] ?? [];
    $st = $attr['last_analysis_stats'] ?? [];
    [$ver, $mal, $sus, $harm, $und, $tot] = vt_stats_label($st);
    $engines = [];
    foreach (($attr['last_analysis_results'] ?? []) as $eng => $r) {
        $cat = (string)($r['category'] ?? '');
        if (in_array($cat, ['malicious', 'suspicious'], true)) $engines[] = $eng . ': ' . (($r['result'] ?? $cat) ?: $cat);
    }
    usort($engines, 'strnatcasecmp');
    return [
        'ok' => true, 'found' => true, 'hash' => $hash, 'verdict' => $ver,
        'malicious' => $mal, 'suspicious' => $sus, 'harmless' => $harm, 'undetected' => $und, 'total' => $tot,
        'engines' => array_slice($engines, 0, 40),
        'type' => (string)($attr['type_description'] ?? ($attr['type_tag'] ?? '')),
        'name' => (string)(($attr['meaningful_name'] ?? '') ?: (($attr['names'][0] ?? '') ?: '')),
        'size' => (int)($attr['size'] ?? 0),
        'link' => 'https://www.virustotal.com/gui/file/' . ($j['data']['id'] ?? $hash),
        'date' => (int)($attr['last_analysis_date'] ?? 0),
    ];
}
/** Invia URL a scan / recupera report. */
function vt_url_scan(string $url): array {
    $key = vt_key();
    if ($key === '') return ['ok' => false, 'err' => 'Configura la API key VirusTotal.'];
    $url = trim($url);
    if (!preg_match('~^https?://[A-Za-z0-9._\~:/?#\[\]@!$&\'()*+,;=%-]+$~D', $url) || strlen($url) > 2048) return ['ok' => false, 'err' => 'URL non valido (solo http/https, max 2048 caratteri).'];
    // prima prova lookup (id = base64url senza padding)
    $id = rtrim(strtr(base64_encode($url), '+/', '-_'), '=');
    $body = ti_curl('https://www.virustotal.com/api/v3/urls/' . $id, ['x-apikey: ' . $key, 'Accept: application/json'], 12);
    $j = $body ? json_decode($body, true) : null;
    if (!is_array($j) || isset($j['error'])) {
        // submit nuovo scan
        $body2 = vt_curl_post('https://www.virustotal.com/api/v3/urls', ['x-apikey: ' . $key, 'Accept: application/json'], ['url' => $url], null, null, 20);
        $j2 = $body2 ? json_decode($body2, true) : null;
        if (!is_array($j2) || empty($j2['data']['id'])) {
            $msg = is_array($j2) && isset($j2['error']['message']) ? $j2['error']['message'] : 'invio scan fallito';
            return ['ok' => false, 'err' => 'VirusTotal URL: ' . $msg];
        }
        // attendi un attimo e rileggi via analysis → url
        usleep(1500000);
        $aid = $j2['data']['id'];
        $body3 = ti_curl('https://www.virustotal.com/api/v3/analyses/' . rawurlencode($aid), ['x-apikey: ' . $key, 'Accept: application/json'], 15);
        $j3 = $body3 ? json_decode($body3, true) : null;
        $st = $j3['data']['attributes']['stats'] ?? [];
        if (!$st) {
            // fallback: rileggi url object
            $body = ti_curl('https://www.virustotal.com/api/v3/urls/' . $id, ['x-apikey: ' . $key, 'Accept: application/json'], 12);
            $j = $body ? json_decode($body, true) : null;
            $st = $j['data']['attributes']['last_analysis_stats'] ?? [];
        }
        [$ver, $mal, $sus, $harm, $und, $tot] = vt_stats_label($st ?: []);
        return [
            'ok' => true, 'found' => true, 'url' => $url, 'verdict' => $ver,
            'malicious' => $mal, 'suspicious' => $sus, 'harmless' => $harm, 'undetected' => $und, 'total' => $tot,
            'link' => 'https://www.virustotal.com/gui/url/' . $id,
            'queued' => empty($st),
        ];
    }
    $attr = $j['data']['attributes'] ?? [];
    $st = $attr['last_analysis_stats'] ?? [];
    [$ver, $mal, $sus, $harm, $und, $tot] = vt_stats_label($st);
    $engines = [];
    foreach (($attr['last_analysis_results'] ?? []) as $eng => $r) {
        $cat = (string)($r['category'] ?? '');
        if (in_array($cat, ['malicious', 'suspicious'], true)) $engines[] = $eng . ': ' . (($r['result'] ?? $cat) ?: $cat);
    }
    return [
        'ok' => true, 'found' => true, 'url' => $url, 'verdict' => $ver,
        'malicious' => $mal, 'suspicious' => $sus, 'harmless' => $harm, 'undetected' => $und, 'total' => $tot,
        'engines' => array_slice($engines, 0, 40),
        'link' => 'https://www.virustotal.com/gui/url/' . ($j['data']['id'] ?? $id),
        'queued' => false,
    ];
}
/** Upload file ≤32MB a VirusTotal; poi report per hash. */
function vt_file_upload(string $tmpPath, string $origName): array {
    $key = vt_key();
    if ($key === '') return ['ok' => false, 'err' => 'Configura la API key VirusTotal.'];
    if (!is_file($tmpPath) || !is_readable($tmpPath)) return ['ok' => false, 'err' => 'File temporaneo non leggibile.'];
    $size = filesize($tmpPath);
    if ($size === false || $size < 1) return ['ok' => false, 'err' => 'File vuoto.'];
    if ($size > 32 * 1024 * 1024) return ['ok' => false, 'err' => 'Piano free VirusTotal: max 32 MB per upload diretto.'];
    $sha = hash_file('sha256', $tmpPath);
    // se già noto, evita upload (privacy + quota)
    $rep = vt_file_report($sha);
    if (!empty($rep['ok']) && !empty($rep['found'])) {
        $rep['name'] = $rep['name'] ?: $origName;
        $rep['skipped_upload'] = true;
        return $rep;
    }
    $body = vt_curl_post('https://www.virustotal.com/api/v3/files', ['x-apikey: ' . $key, 'Accept: application/json'], [], 'file', $tmpPath, 90);
    $j = $body ? json_decode($body, true) : null;
    if (!is_array($j) || empty($j['data']['id'])) {
        $msg = is_array($j) && isset($j['error']['message']) ? $j['error']['message'] : 'upload fallito';
        return ['ok' => false, 'err' => 'Upload VirusTotal: ' . $msg];
    }
    // attesa breve poi report
    usleep(2000000);
    $rep = vt_file_report($sha);
    if (!empty($rep['ok'])) {
        $rep['name'] = $rep['name'] ?: $origName;
        $rep['uploaded'] = true;
        if (empty($rep['found'])) $rep['msg'] = 'File inviato: analisi in coda su VirusTotal (riprova tra 30–60 s con l\'hash).';
        return $rep;
    }
    return ['ok' => true, 'found' => false, 'hash' => $sha, 'uploaded' => true, 'name' => $origName, 'msg' => 'Upload ok, report non ancora pronto. Hash: ' . $sha];
}
/** ClamAV locale se installato (clamscan). */
function clam_scan_file(string $path): array {
    $bin = '';
    foreach (['/usr/bin/clamscan', '/usr/local/bin/clamscan'] as $c) if (is_executable($c)) { $bin = $c; break; }
    if ($bin === '') return ['ok' => false, 'err' => 'ClamAV non installato (pacchetto clamav).'];
    if (!is_file($path)||is_link($path)||!is_readable($path)) return ['ok'=>false,'err'=>'File non leggibile o non regolare.'];
    [$c,$stdout,$stderr]=run([$bin,'--no-summary','--infected','--',$path],null,120.0,1048576);
    $out=trim($stdout."\n".$stderr);
    // exit 0 = clean, 1 = infected, 2 = error
    if ($c === 0) return ['ok' => true, 'infected' => false, 'detail' => 'pulito'];
    if ($c === 1) return ['ok' => true, 'infected' => true, 'detail' => $out !== '' ? $out : 'infetto'];
    return ['ok' => false, 'err' => $out !== '' ? $out : 'clamscan exit ' . $c];
}

function pg_avscan() {
    $ro = ($_SESSION['role'] ?? 'viewer') === 'viewer';
    $key = vt_key();
    $res = $_SESSION['av_result'] ?? null;
    unset($_SESSION['av_result']);
    $clam = is_executable('/usr/bin/clamscan') || is_executable('/usr/local/bin/clamscan');

    echo '<div class=card><h2>Scanner antivirus cloud</h2>';
    echo '<p class=mut>Analisi file, hash e URL tramite <b>VirusTotal</b> (70+ motori AV, piano free) e, se presente, <b>ClamAV</b> in locale. '
        . 'Ideale per verificare un allegato sospetto, un binario scaricato o un link prima di aprirlo sulla LAN.</p></div>';

    // stato chiave
    echo '<div class=card><h3>Stato</h3><ul class=kv>';
    echo '<li><span>VirusTotal API</span><span>' . ($key !== '' ? '<span class="b b-ACCEPT">configurata</span>' : '<span class="b b-DROP">mancante</span>') . '</span></li>';
    echo '<li><span>Quota tipica free</span><span>~4 richieste/min · ~500/giorno · upload max 32&nbsp;MB</span></li>';
    echo '<li><span>ClamAV locale</span><span>' . ($clam ? '<span class="b b-ACCEPT">clamscan disponibile</span>' : '<span class=mut>non installato</span>') . '</span></li>';
    echo '</ul>';
    if ($key === '') {
        echo '<p class=mut>Ottieni una chiave gratuita: <a href="https://www.virustotal.com/gui/join-us" target=_blank rel="noopener">registrati su VirusTotal</a> → menu utente → <b>API key</b>. '
            . 'Puoi incollarla anche in <a href="?p=attacks">Pattern attacco</a> (stessa impostazione).</p>';
        if (!$ro) {
            echo '<form method=post class=acc>' . fh('p=avscan') . '<input type=hidden name=action value=av_save_key>';
            echo dd('API key VirusTotal', '<input name=virustotal type=password autocomplete=off placeholder="incolla la chiave" data-iptm-layout="mw420">');
            echo '<p class=ops><button type=submit>Salva chiave</button></p></form>';
        }
    }
    echo '</div>';

    if ($res) {
        $ok = !empty($res['ok']);
        $ver = $res['verdict'] ?? '';
        $cls = !$ok ? 'err' : ($ver === 'malicious' ? 'err' : ($ver === 'suspicious' ? 'warn' : 'ok'));
        echo '<div class="msg ' . $cls . '"><b>Esito scansione</b><br>';
        if (!$ok) {
            echo h($res['err'] ?? 'errore');
        } else {
            if (isset($res['hash'])) echo 'Hash: <code>' . h($res['hash']) . '</code><br>';
            if (!empty($res['name'])) echo 'Nome: ' . h($res['name']) . '<br>';
            if (!empty($res['url'])) echo 'URL: ' . h($res['url']) . '<br>';
            if (!empty($res['type'])) echo 'Tipo: ' . h($res['type']) . '<br>';
            if (!empty($res['found'])) {
                $badge = ['malicious' => 'MALEVOLO', 'suspicious' => 'SOSPETTO', 'clean' => 'PULITO', 'unknown' => 'SCONOSCIUTO'][$ver] ?? strtoupper($ver);
                echo 'Verdetto: <b>' . h($badge) . '</b> — '
                    . (int)($res['malicious'] ?? 0) . ' malicious / '
                    . (int)($res['suspicious'] ?? 0) . ' suspicious su ~'
                    . (int)($res['total'] ?? 0) . ' motori<br>';
                if (!empty($res['engines'])) {
                    echo '<details data-iptm-layout="ui-301647f506"><summary>Motori che hanno segnalato</summary><pre data-iptm-layout="ui-7c958bdca0">'
                        . h(implode("\n", $res['engines'])) . '</pre></details>';
                }
                if (!empty($res['link'])) echo '<p class=ops data-iptm-layout="mt8"><a class=btn href="' . h($res['link']) . '" target=_blank rel="noopener">Apri report VirusTotal</a></p>';
            } else {
                echo h($res['msg'] ?? 'Nessun report trovato.');
                if (!empty($res['hash'])) echo ' Puoi riprovare tra poco con lo stesso hash.';
            }
            if (!empty($res['skipped_upload'])) echo '<p class=mut>Upload saltato: hash già presente su VirusTotal (nessun file inviato).</p>';
            if (!empty($res['uploaded'])) echo '<p class=mut>File caricato su VirusTotal (condiviso con i partner AV — vedi avviso privacy).</p>';
            if (isset($res['clam'])) {
                $cl = $res['clam'];
                if (!empty($cl['ok'])) echo '<p>ClamAV locale: <b>' . (!empty($cl['infected']) ? 'INFETTO' : 'pulito') . '</b>' . (!empty($cl['detail']) && !empty($cl['infected']) ? ' — ' . h($cl['detail']) : '') . '</p>';
                elseif (!empty($cl['err'])) echo '<p class=mut>ClamAV: ' . h($cl['err']) . '</p>';
            }
        }
        echo '</div>';
    }

    if ($ro) { echo '<div class=card><p class=mut>Account in sola lettura.</p></div>'; return; }

    // Hash
    echo '<div class=card><h3>1. Controlla hash (consigliato)</h3>';
    echo '<p class=mut>Nessun file viene inviato: si interroga solo il database pubblico di VirusTotal (MD5 / SHA1 / SHA256).</p>';
    echo '<form method=post>' . fh('p=avscan') . '<input type=hidden name=action value=av_hash>';
    echo dd('Hash', '<input name=hash placeholder="es. e3b0c44298fc1c149afbf4c8996fb924..." data-iptm-layout="ui-980418c5ad" autocomplete=off>');
    echo '<p class=ops><button type=submit>Cerca su VirusTotal</button></p></form></div>';

    // URL
    echo '<div class=card><h3>2. Scansiona URL</h3>';
    echo '<p class=mut>Verifica un link sospetto (phishing, download). Se non esiste un report, viene richiesta una nuova analisi (può richiedere qualche secondo).</p>';
    echo '<form method=post>' . fh('p=avscan') . '<input type=hidden name=action value=av_url>';
    echo dd('URL', '<input name=url placeholder="https://..." data-iptm-layout="ui-980418c5ad" autocomplete=off>');
    echo '<p class=ops><button type=submit>Analizza URL</button></p></form></div>';

    // Upload
    echo '<div class=card><h3>3. Carica file</h3>';
    echo '<p class=mut><b>Privacy:</b> il file viene inviato a VirusTotal e può essere condiviso con oltre 70 vendor antivirus e con la community. '
        . 'Non caricare documenti riservati o con dati personali. Se l\'hash è già noto, l\'upload viene saltato automaticamente.</p>';
    echo '<form method=post enctype="multipart/form-data" class="iptm-classic-form">' . fh('p=avscan') . '<input type=hidden name=action value=av_file>';
    echo '<p class=mut>Scegli il metodo. «Solo hash» invia al cloud esclusivamente l’impronta SHA-256 del file; «caricamento cloud» condivide il file e richiede conferma esplicita.</p>';
    echo '<label><input type=radio name=av_mode value=local> Solo ClamAV locale (nessun invio)</label> '
        . '<label><input type=radio name=av_mode value=hash checked> VirusTotal gratuito: solo hash SHA-256</label> '
        . '<label><input type=radio name=av_mode value=upload> VirusTotal: carica file (solo se autorizzato)</label>';

    echo dd('File (max 32 MB)', '<input type=file name=sample>');
    if ($clam) echo '<label><input type=checkbox name=also_clam value=1 checked> Esegui anche ClamAV in locale prima dell\'upload</label>';
    echo '<p class=ops><button type=submit>Scansiona file</button><progress class=iptm-progress hidden></progress><span role=status class=mut></span></p></form></div>';

    echo '<div class=card><h3>Note</h3><ul class=mut>';
    echo '<li>Il piano pubblico VirusTotal non è destinato a prodotti commerciali ad alto volume; resta nei limiti free.</li>';
    echo '<li>Un esito «pulito» non è garanzia assoluta: i motori possono discordare o non avere ancora firme.</li>';
    echo '<li>Per bloccare IP malevoli in automatico usa <a href="?p=lists">Liste / GeoIP</a>, CrowdSec e le regole in Sicurezza.</li>';
    echo '</ul></div>';
}

function pg_traffic(): void {
    $ro = ($_SESSION['role'] ?? 'viewer') === 'viewer';
    [$c, $o] = priv('traffic-status');
    $state = [];
    if ($c === 0) foreach (preg_split('/\R/', trim($o)) as $line) {
        $bits = explode(' ', trim($line), 2);
        if (count($bits) === 2) $state[$bits[0]] = $bits[1];
    }
    echo '<div class=hero><div><h2>Ispezione HTTPS e antivirus locale</h2><p>mitmproxy + ClamAV, gratuiti. Solo per client e reti che autorizzi esplicitamente.</p></div></div>';
    $saved=priv('traffic-policy',null,['show']); $mitmState=$saved[0]===0?json_decode($saved[1],true):null;
    $mitmProfile=is_array($mitmState)?($mitmState['policy']??[]):[];
    $rd=iptm_security_read('mac-inventory');
    $rows=iptm_devices_unified(!empty($rd['ok'])?(array)($rd['devices']??[]):[],devices(),(array)(S_get()['iot_devices']??[]));
    echo '<div class=card><h3>Seleziona dispositivi e traffico autorizzato</h3><p>Solo proxy <b>esplicito locale</b>, nessuna intercettazione automatica. Nessun contenuto viene inviato a servizi cloud; non possiamo garantire che un provider esterno non registri il traffico. Il certificato CA va installato volontariamente sul client.</p>';
    echo '<form method=post>'.fh('p=traffic').'<input type=hidden name=action value=traffic_policy_save>';
    echo '<h4>Client autorizzati</h4><div class=iptm-https-clients>';
    $eligible=0;
    foreach($rows as $row)foreach((array)($row['ips']??[]) as $ip) {
        if($eligible>=32||!filter_var($ip,FILTER_VALIDATE_IP,FILTER_FLAG_IPV4))continue;
        $eligible++;
        echo '<label><input type=checkbox name="mitm_clients[]" value="'.h($ip).'"'.(in_array($ip,(array)($mitmProfile['clients']??[]),true)?' checked':'').'><span><b>'.h($ip).'</b><small>'.h(implode(', ',(array)($row['names']??[])) ?: (($row['vendor']??'') ?: 'Dispositivo non identificato')).'</small></span></label>'; 
    }
    echo '</div><p class=mut>Se non compaiono client, verifica l’inventario DHCP/ARP. Le policy richiedono indirizzi IP stabili.</p>';
    echo '<label class=fl>Domini consentiti (uno per riga, inclusi sottodomini)<textarea name=mitm_hosts rows=3 placeholder="example.org">'.h(implode("\n",(array)($mitmProfile['hosts']??[]))).'</textarea></label>';
    foreach([80=>'HTTP · porta 80',443=>'HTTPS · porta 443'] as $port=>$label)echo '<label class=iptm-iot-flag><input type=checkbox name="mitm_ports[]" value="'.$port.'"'.(in_array($port,(array)($mitmProfile['ports']??[]),true)?' checked':'').'> '.h($label).'</label> ';
    echo '<p class=mut>Il profilo configura solo un proxy esplicito: ogni client deve scegliere autonomamente di usarlo.</p>';
    echo '<button class=g '.($ro?'disabled':'').'>Salva policy locale</button></form></div>';
    echo '<div class=card><h3>Stato del servizio</h3><ul class=kv>';
    foreach (['proxy' => 'Proxy', 'clamav' => 'Antivirus', 'mitmdump' => 'mitmdump', 'listen' => 'Ascolto LAN'] as $k => $v) {
        echo '<li><span>' . h($v) . '</span><span>' . h($state[$k] ?? 'non disponibile') . '</span></li>';
    }
    echo '</ul>';
    if (!$ro) {
        echo '<div class=ops><form method=post>' . fh('p=traffic') . '<input type=hidden name=action value=traffic_start><button class=g>Avvia proxy</button></form>';
        echo '<form method=post>' . fh('p=traffic') . '<input type=hidden name=action value=traffic_stop><button class=d>Ferma proxy</button></form></div>';
    }
    if (($state['ca'] ?? 'no') === 'yes') echo '<p><a class=btn href="?dl=traffic-ca">Scarica certificato CA pubblico</a></p>';
    echo '</div>';
    echo '<div class=card><h3>Attivazione controllata</h3><p>Su DietPi/Debian, come root, esegui <code>bash setup-traffic-proxy.sh IP_LAN_DEL_ROUTER</code>. '
        . 'Lo script installa mitmproxy e ClamAV, configura il servizio ma lo lascia disabilitato. '
        . 'Apri la porta TCP 8899 <b>solo dalle reti LAN autorizzate</b> con una regola iptables gestita da IPTM, '
        . 'poi configura manualmente il proxy sui dispositivi che possiedi o amministri.</p>'
        . '<p>Per decifrare HTTPS è necessario che ogni client autorizzato installi volontariamente la CA di mitmproxy. '
        . 'Le applicazioni con certificate pinning possono non funzionare. Non aggira il pinning né intercetta di nascosto.</p>'
        . '<p class=mut>Scansione locale ClamAV in transito per le risposte HTTP(S) che attraversano questo proxy. '
        . 'Risposte oltre 16 MiB, codifiche non verificabili o scanner indisponibile sono bloccati: '
        . 'nessun traffico viene dichiarato “pulito” senza scansione. Non copre QUIC/UDP, flussi non proxy, '
        . 'traffico end-to-end con pinning o altri protocolli.</p></div>';
}

