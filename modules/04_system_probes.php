<?php
// ---- informazioni di sistema
function sys_ifaces(): array { return $GLOBALS['_if'] ??= sys_ifaces_raw(); }
function sys_ifaces_raw(): array {
    $r = [];
    [$rc, $o] = run([BIN_IP, '-o', 'link', 'show']);
    if ($rc !== 0) return [];
    foreach (explode("\n", $o) as $l) if (preg_match('/^\d+:\s+([^:@\s]+)/', $l, $m) && $m[1] !== 'lo' && !preg_match('/^(veth|br-|docker)/', $m[1])) $r[$m[1]] = [];
    [$rc, $o] = run([BIN_IP, '-o', '-4', 'addr', 'show']);
    if ($rc !== 0) return [];
    foreach (explode("\n", $o) as $l) if (preg_match('/^\d+:\s+(\S+)\s+inet\s+(\S+)/', $l, $m) && isset($r[$m[1]]) && preg_match('/^([0-9.]+)\/(\d{1,2})$/D', $m[2], $cidr) && filter_var($cidr[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) && (int)$cidr[2]<=32) $r[$m[1]][] = $m[2];
    return $r;
}
function net_of(string $cidr): string {
    [$ip, $p] = array_pad(explode('/', $cidr), 2, '32');
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) || !ctype_digit($p) || (int)$p > 32) throw new InvalidArgumentException('CIDR IPv4 non valido');
    $m = (int)$p === 0 ? 0 : (-1 << (32 - (int)$p)) & 0xFFFFFFFF;
    return long2ip(ip2long($ip) & $m) . '/' . $p;
}
function live_state(?float $shortBudget = null): array {
    [$c, $o] = $shortBudget === null ? priv('savec') : run([BIN_SUDO, '-n', HELPER, 'savec'], null, $shortBudget, 2097152); $st = ['ok' => $c === 0, 'pol' => [], 'rules' => []]; if ($c) return $st; $tb = '';
    foreach (explode("\n", $o) as $l) {
        if (preg_match('/^\*(\w+)/', $l, $m)) $tb = $m[1];
        elseif (preg_match('/^:(\S+)\s+(\S+)\s+\[(\d+):(\d+)\]/', $l, $m) && $tb === 'filter') $st['pol'][$m[1]] = $m[2];
        elseif (preg_match('/^\[(\d+):(\d+)\]\s+(-A\s.+)$/', $l, $m)) $st['rules'][] = ['t' => $tb, 'p' => (int)$m[1], 'b' => (int)$m[2], 'r' => $m[3]];
    }
    return $st;
}
function hb(int $n): string { foreach (['B', 'KB', 'MB', 'GB', 'TB'] as $u) { if ($n < 1024) return round($n, 1) . ' ' . $u; $n /= 1024; } return round($n, 1) . ' PB'; }



/** Marche DSCP per prioritizzazione CAKE (stile cFosSpeed / diffserv). */
function sqm_prio_rules(array $S): array {
    $q = $S['sqm'] ?? [];
    if (empty($q['on'])) return [];
    $out = [];
    $mark = function (string $chain, string $spec, string $cls) use (&$out) {
        $out[] = "-A $chain $spec -j DSCP --set-dscp-class $cls";
    };
    if (!empty($q['prio_interactive'])) {
        foreach (['OUTPUT', 'FORWARD'] as $c) {
            $mark($c, '-p icmp', 'CS6');
            $mark($c, '-p udp --dport 53', 'CS6');
            $mark($c, '-p udp --sport 53', 'CS6');
            $mark($c, '-p tcp --dport 53', 'CS6');
            $mark($c, '-p tcp --dport 22', 'AF41');
            $mark($c, '-p tcp --tcp-flags ACK ACK -m length --length 40:100', 'CS6');
        }
    }
    if (!empty($q['prio_voip'])) {
        $vp = preg_replace('/[^0-9,:]/', '', (string)($q['voip_ports'] ?? '5060,5061'));
        if ($vp !== '') {
            foreach (['OUTPUT', 'FORWARD'] as $c) {
                $mark($c, "-p udp -m multiport --dports $vp", 'EF');
                $mark($c, "-p udp -m multiport --sports $vp", 'EF');
            }
        }
    }
    if (!empty($q['prio_games'])) {
        // porte gioco tipiche: range singoli via -m multiport se lista corta
        $gp = preg_replace('/[^0-9,:]/', '', (string)($q['game_ports'] ?? '3074,7777,25565'));
        $ports = [];
        foreach (explode(',', $gp) as $p) {
            $p = trim($p);
            if ($p === '') continue;
            if (preg_match('/^\d+:\d+$/', $p)) {
                // range: regola dedicata
                foreach (['OUTPUT', 'FORWARD'] as $c) {
                    $mark($c, "-p udp --dport $p", 'AF41');
                    $mark($c, "-p tcp --dport $p", 'AF41');
                }
            } elseif (preg_match('/^\d+$/', $p)) {
                $ports[] = $p;
            }
        }
        if ($ports) {
            $list = implode(',', array_slice($ports, 0, 15));
            foreach (['OUTPUT', 'FORWARD'] as $c) {
                $mark($c, "-p udp -m multiport --dports $list", 'AF41');
                $mark($c, "-p tcp -m multiport --dports $list", 'AF41');
            }
        }
    }
    if (!empty($q['prio_bulk_low'])) {
        $bp = preg_replace('/[^0-9,:]/', '', (string)($q['bulk_ports'] ?? '6881:6999'));
        foreach (explode(',', $bp) as $p) {
            $p = trim($p);
            if ($p === '') continue;
            foreach (['OUTPUT', 'FORWARD'] as $c) {
                if (preg_match('/^\d+:\d+$/', $p) || preg_match('/^\d+$/', $p)) {
                    $mark($c, "-p tcp --dport $p", 'CS1');
                    $mark($c, "-p udp --dport $p", 'CS1');
                }
            }
        }
    }
    return $out;
}

/** Safe, opt-in application priorities for CAKE DiffServ4. Port = remote service port.
 * Download uses remote source port before IFB; upload uses destination port.
 * No global high-priority 443, no privileged CS6/CS7 traffic markings.
 */
function iptm_qos_dscp_recommendations(): array {
    return [
        'dns_udp' => ['label'=>'DNS UDP · AF41','reason'=>'Risoluzione dei nomi, tipicamente sulla porta 53','protocol'=>'udp','port'=>53,'priority'=>'interactive','direction'=>'both','group'=>'base','essential'=>true],
        'dns_tcp' => ['label'=>'DNS TCP · AF41','reason'=>'Risposte DNS di grandi dimensioni e fallback TCP','protocol'=>'tcp','port'=>53,'priority'=>'interactive','direction'=>'both','group'=>'base','essential'=>true],
        'ssh' => ['label'=>'SSH / SFTP · AF41','reason'=>'Terminale interattivo; SFTP usa la stessa porta','protocol'=>'tcp','port'=>22,'priority'=>'interactive','direction'=>'both','group'=>'base','essential'=>true],
        'ntp' => ['label'=>'NTP · AF41','reason'=>'Sincronizzazione dell’orologio','protocol'=>'udp','port'=>123,'priority'=>'interactive','direction'=>'both','group'=>'base','essential'=>true],
        'teams_stun' => ['label'=>'Teams · STUN · AF41','reason'=>'UDP 3478: negoziazione media, non tutta la chiamata','protocol'=>'udp','port'=>3478,'priority'=>'interactive','direction'=>'both','group'=>'meeting','essential'=>false],
        'teams_audio' => ['label'=>'Teams · audio · EF','reason'=>'UDP 3479: audio tramite relay Microsoft','protocol'=>'udp','port'=>3479,'priority'=>'realtime','direction'=>'both','group'=>'meeting','essential'=>false],
        'teams_video' => ['label'=>'Teams · video · AF41','reason'=>'UDP 3480: video tramite relay Microsoft','protocol'=>'udp','port'=>3480,'priority'=>'interactive','direction'=>'both','group'=>'meeting','essential'=>false],
        'teams_share' => ['label'=>'Teams · schermo · AF41','reason'=>'UDP 3481: condivisione / VBSS','protocol'=>'udp','port'=>3481,'priority'=>'interactive','direction'=>'both','group'=>'meeting','essential'=>false],
        'zoom_media' => ['label'=>'Zoom · media principale · EF','reason'=>'UDP 8801: una delle porte Zoom; usare solo con traffico Zoom','protocol'=>'udp','port'=>8801,'priority'=>'realtime','direction'=>'both','group'=>'meeting','essential'=>false],
        'zoom_media_alt' => ['label'=>'Zoom · media aggiuntiva · AF41','reason'=>'UDP 8802: porta aggiuntiva Zoom; altre porte non incluse','protocol'=>'udp','port'=>8802,'priority'=>'interactive','direction'=>'both','group'=>'meeting','essential'=>false],
        'sip_signaling' => ['label'=>'VoIP · SIP UDP · AF41','reason'=>'Segnalazione SIP, non voce RTP','protocol'=>'udp','port'=>5060,'priority'=>'interactive','direction'=>'both','group'=>'meeting','essential'=>false],
        'sip_tls' => ['label'=>'VoIP · SIP TLS · AF41','reason'=>'Segnalazione SIP protetta, non media RTP','protocol'=>'tcp','port'=>5061,'priority'=>'interactive','direction'=>'both','group'=>'meeting','essential'=>false],
        'rtp_known' => ['label'=>'VoIP · RTP 10000 · EF','reason'=>'Voce EF solo se il centralino usa questa porta','protocol'=>'udp','port'=>10000,'priority'=>'realtime','direction'=>'both','group'=>'meeting','essential'=>false],
        'rdp_tcp' => ['label'=>'Desktop remoto · RDP TCP · AF41','reason'=>'Desktop Windows remoto tramite TCP 3389','protocol'=>'tcp','port'=>3389,'priority'=>'interactive','direction'=>'both','group'=>'remote','essential'=>false],
        'rdp_udp' => ['label'=>'Desktop remoto · RDP UDP · AF41','reason'=>'Desktop Windows remoto tramite UDP 3389','protocol'=>'udp','port'=>3389,'priority'=>'interactive','direction'=>'both','group'=>'remote','essential'=>false],
        'vnc' => ['label'=>'Desktop remoto · VNC · AF41','reason'=>'Sessioni VNC sulla porta standard 5900','protocol'=>'tcp','port'=>5900,'priority'=>'interactive','direction'=>'both','group'=>'remote','essential'=>false],
        'game_udp' => ['label'=>'Gaming · Xbox / giochi · AF41','reason'=>'UDP 3074: usata da alcuni giochi e console','protocol'=>'udp','port'=>3074,'priority'=>'interactive','direction'=>'both','group'=>'gaming','essential'=>false],
        'steam_udp' => ['label'=>'Gaming · Steam UDP · AF41','reason'=>'UDP 27015: giochi/servizi che adottano questa porta','protocol'=>'udp','port'=>27015,'priority'=>'interactive','direction'=>'both','group'=>'gaming','essential'=>false],
        'steam_tcp' => ['label'=>'Gaming · Steam TCP · AF41','reason'=>'TCP 27015: alcuni server di gioco','protocol'=>'tcp','port'=>27015,'priority'=>'interactive','direction'=>'both','group'=>'gaming','essential'=>false],
        'minecraft' => ['label'=>'Gaming · Minecraft Java · AF41','reason'=>'TCP 25565, se il server usa la porta predefinita','protocol'=>'tcp','port'=>25565,'priority'=>'interactive','direction'=>'both','group'=>'gaming','essential'=>false],
        'mqtt' => ['label'=>'IoT · MQTT · AF41','reason'=>'Broker MQTT su TCP 1883: telemetria/domotica','protocol'=>'tcp','port'=>1883,'priority'=>'interactive','direction'=>'both','group'=>'iot','essential'=>false],
        'mqtt_tls' => ['label'=>'IoT · MQTT TLS · AF41','reason'=>'Broker MQTT su TCP 8883','protocol'=>'tcp','port'=>8883,'priority'=>'interactive','direction'=>'both','group'=>'iot','essential'=>false],
        'coap' => ['label'=>'IoT · CoAP · AF41','reason'=>'UDP 5683 su dispositivi che lo utilizzano','protocol'=>'udp','port'=>5683,'priority'=>'interactive','direction'=>'both','group'=>'iot','essential'=>false],
        'homeassistant' => ['label'=>'Domotica · Home Assistant · AF41','reason'=>'TCP 8123, soltanto per quell’applicazione','protocol'=>'tcp','port'=>8123,'priority'=>'interactive','direction'=>'both','group'=>'iot','essential'=>false],
        'p2p_tcp' => ['label'=>'P2P · BitTorrent TCP · CS1','reason'=>'TCP 6881: traffico di trasferimento in background','protocol'=>'tcp','port'=>6881,'priority'=>'background','direction'=>'both','group'=>'background','essential'=>false],
        'p2p_udp' => ['label'=>'P2P · BitTorrent UDP · CS1','reason'=>'UDP 6881: traffico di trasferimento in background','protocol'=>'udp','port'=>6881,'priority'=>'background','direction'=>'both','group'=>'background','essential'=>false],
        'rsync' => ['label'=>'Backup · rsync · CS1','reason'=>'TCP 873: sincronizzazione dati non interattiva','protocol'=>'tcp','port'=>873,'priority'=>'background','direction'=>'both','group'=>'background','essential'=>false],
    ];
}
