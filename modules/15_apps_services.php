<?php
// ===================== SOFTWARE INSTALLATO → APERTURA PORTE =====================
// Catalogo di programmi comuni (NAS, IoT, backup, stampa, media…) con porte tipiche.
// Rileva binari, unità systemd e porte in ascolto; in «Porte software» scegli quali aprire (di solito dalla LAN).

/** @return array<string, array{name:string,cat:string,ports:string,bins:string[],units:string[],pkgs:string[],scope:string,note:string}> */
function app_catalog(): array {
    // ports: "tcp:80,443 udp:53"  scope: lan|any
    $e = fn(string $name, string $cat, string $ports, array $bins = [], array $units = [], array $pkgs = [], string $scope = 'lan', string $note = '') =>
        compact('name', 'cat', 'ports', 'bins', 'units', 'pkgs', 'scope', 'note');
    return [
        // --- Backup ---
        'urbackup' => $e('UrBackup', 'Backup', 'tcp:35621,35622,35623,55413,55414,55415,35622 udp:35622,35623',
            ['/usr/bin/urbackupsrv', '/usr/bin/urbackupclientbackend'], ['urbackup-server.service', 'urbackupclientbackend.service'], ['urbackup-server', 'urbackup-client'], 'lan',
            'Porte client/server UrBackup (web 55414, sync 35621–35623).'),
        'borgmatic' => $e('Borg / Borgmatic', 'Backup', 'tcp:22',
            ['/usr/bin/borg', '/usr/bin/borgmatic'], [], ['borgbackup', 'borgmatic'], 'lan', 'SSH già coperto se abiliti SSH; utile solo se il server riceve backup in ingresso.'),
        // --- Stampa / scanner ---
        'cups' => $e('CUPS (stampa IPP)', 'Stampa', 'tcp:631 udp:631',
            ['/usr/sbin/cupsd'], ['cups.service', 'cups-browsed.service'], ['cups'], 'lan', 'Server di stampa locale.'),
        'ipp_usb' => $e('ipp-usb (stampanti USB via IPP)', 'Stampa', 'tcp:60000,60001',
            ['/usr/sbin/ipp-usb', '/usr/bin/ipp-usb'], ['ipp-usb.service'], ['ipp-usb'], 'lan',
            'Espone stampanti USB come IPP sulla LAN (porte tipiche 60000+).'),
        'avahi' => $e('Avahi (mDNS / Bonjour)', 'Rete', 'udp:5353',
            ['/usr/sbin/avahi-daemon'], ['avahi-daemon.service'], ['avahi-daemon'], 'lan', 'Scoperta servizi (stampanti, Shelly, Home Assistant…).'),
        // --- IoT / casa ---
        'mosquitto' => $e('Mosquitto (MQTT)', 'IoT', 'tcp:1883,8883',
            ['/usr/sbin/mosquitto'], ['mosquitto.service'], ['mosquitto'], 'lan', 'Broker MQTT (Shelly, Zigbee2MQTT, Node-RED…).'),
        'homeassistant' => $e('Home Assistant', 'IoT', 'tcp:8123',
            ['/usr/bin/hass', '/srv/homeassistant/bin/hass'], ['home-assistant.service', 'homeassistant.service'], ['homeassistant'], 'lan'),
        'zigbee2mqtt' => $e('Zigbee2MQTT', 'IoT', 'tcp:8080',
            [], ['zigbee2mqtt.service'], ['zigbee2mqtt'], 'lan'),
        'node_red' => $e('Node-RED', 'IoT', 'tcp:1880',
            ['/usr/bin/node-red'], ['nodered.service', 'node-red.service'], ['nodered'], 'lan'),
        'deconz' => $e('deCONZ / Phoscon', 'IoT', 'tcp:80,443,8081',
            ['/usr/bin/deCONZ'], ['deconz.service'], ['deconz'], 'lan'),
        'shelly' => $e('Shelly (MQTT / CoAP / HTTP locale)', 'IoT', 'udp:5683 tcp:80',
            [], [], [], 'lan',
            'Non è un pacchetto host: apri se questo dispositivo fa da proxy/MQTT per dispositivi Shelly (CoAP 5683 + HTTP).'),
        // --- Media ---
        'plex' => $e('Plex Media Server', 'Media', 'tcp:32400',
            ['/usr/lib/plexmediaserver/Plex Media Server', '/usr/bin/plexmediaserver'], ['plexmediaserver.service'], ['plexmediaserver'], 'lan'),
        'jellyfin' => $e('Jellyfin', 'Media', 'tcp:8096,8920',
            ['/usr/bin/jellyfin'], ['jellyfin.service'], ['jellyfin'], 'lan'),
        'minidlna' => $e('ReadyMedia / MiniDLNA', 'Media', 'tcp:8200 udp:1900',
            ['/usr/sbin/minidlnad'], ['minidlna.service'], ['minidlna'], 'lan'),
        'snapcast' => $e('Snapcast', 'Media', 'tcp:1704,1705,1780',
            ['/usr/bin/snapserver'], ['snapserver.service'], ['snapserver'], 'lan'),
        // --- File / sync ---
        'samba' => $e('Samba (SMB/CIFS)', 'File', 'tcp:139,445 udp:137,138',
            ['/usr/sbin/smbd'], ['smbd.service', 'nmbd.service'], ['samba'], 'lan'),
        'nfs' => $e('NFS server', 'File', 'tcp:2049 udp:2049',
            ['/usr/sbin/rpc.nfsd'], ['nfs-server.service'], ['nfs-kernel-server'], 'lan'),
        'syncthing' => $e('Syncthing', 'File', 'tcp:22000 udp:22000,21027',
            ['/usr/bin/syncthing'], ['syncthing.service'], ['syncthing'], 'lan'),
        'nextcloud' => $e('Nextcloud (Apache/Nginx già web)', 'File', 'tcp:80,443',
            [], ['nextcloud.service'], ['nextcloud-server'], 'lan', 'Di solito usa le porte del web server; abilita se chiudi le 80/443 generiche.'),
        // --- DNS / adblock ---
        'pihole' => $e('Pi-hole', 'DNS', 'tcp:53,80,443 udp:53',
            ['/usr/local/bin/pihole'], ['pihole-FTL.service'], [], 'lan'),
        'adguard' => $e('AdGuard Home', 'DNS', 'tcp:53,80,443,3000 udp:53',
            ['/opt/AdGuardHome/AdGuardHome', '/usr/bin/AdGuardHome'], ['AdGuardHome.service'], [], 'lan'),
        'unbound' => $e('Unbound', 'DNS', 'tcp:53 udp:53',
            ['/usr/sbin/unbound'], ['unbound.service'], ['unbound'], 'lan'),
        'dnsmasq' => $e('dnsmasq', 'DNS', 'tcp:53 udp:53,67',
            ['/usr/sbin/dnsmasq'], ['dnsmasq.service'], ['dnsmasq'], 'lan', 'DNS + spesso DHCP.'),
        // --- Monitoraggio ---
        'netdata' => $e('Netdata', 'Monitor', 'tcp:19999',
            ['/usr/sbin/netdata'], ['netdata.service'], ['netdata'], 'lan'),
        'grafana' => $e('Grafana', 'Monitor', 'tcp:3000',
            ['/usr/sbin/grafana-server'], ['grafana-server.service'], ['grafana'], 'lan'),
        'prometheus' => $e('Prometheus', 'Monitor', 'tcp:9090',
            ['/usr/bin/prometheus'], ['prometheus.service'], ['prometheus'], 'lan'),
        'cockpit' => $e('Cockpit', 'Admin', 'tcp:9090',
            ['/usr/bin/cockpit-ws'], ['cockpit.socket', 'cockpit.service'], ['cockpit'], 'lan'),
        'webmin' => $e('Webmin', 'Admin', 'tcp:10000',
            ['/usr/bin/webmin', '/usr/share/webmin/miniserv.pl'], ['webmin.service'], ['webmin'], 'lan'),
        'portainer' => $e('Portainer', 'Admin', 'tcp:9000,9443',
            [], ['portainer.service'], [], 'lan', 'Rilevato se in ascolto o unità presente (spesso in Docker).'),
        // --- VPN / remoto (oltre al modulo VPN) ---
        'openvpn' => $e('OpenVPN', 'VPN', 'udp:1194 tcp:1194',
            ['/usr/sbin/openvpn'], ['openvpn.service', 'openvpn@server.service'], ['openvpn'], 'any'),
        'wireguard' => $e('WireGuard', 'VPN', 'udp:51820',
            ['/usr/bin/wg'], ['wg-quick@wg0.service'], ['wireguard'], 'any', 'Preferisci la pagina VPN dedicata se usi la configurazione IPTM.'),
        'wg_easy' => $e('wg-easy (UI WireGuard)', 'VPN', 'udp:51820 tcp:51821',
            [], [], [], 'lan',
            'Container tipico: UI su 51821/tcp (solo LAN), tunnel 51820/udp. Non sostituisce le regole IPTM VPN.'),
        'node_exporter' => $e('Prometheus node_exporter', 'Monitor', 'tcp:9100',
            ['/usr/bin/node_exporter', '/usr/local/bin/node_exporter'], ['node_exporter.service', 'prometheus-node-exporter.service'], ['prometheus-node-exporter'], 'lan',
            'Metriche host; per IPTM usa anche ?api=metrics.'),
        'tailscale' => $e('Tailscale', 'VPN', 'udp:41641',
            ['/usr/bin/tailscale'], ['tailscaled.service'], ['tailscale'], 'any'),
        // --- Download ---
        'transmission' => $e('Transmission', 'Download', 'tcp:9091,51413 udp:51413',
            ['/usr/bin/transmission-daemon'], ['transmission-daemon.service'], ['transmission-daemon'], 'lan'),
        'qbittorrent' => $e('qBittorrent', 'Download', 'tcp:8080,6881 udp:6881',
            ['/usr/bin/qbittorrent-nox'], ['qbittorrent-nox.service'], ['qbittorrent-nox'], 'lan'),
        // --- DB / app ---
        'postgresql' => $e('PostgreSQL', 'Database', 'tcp:5432',
            ['/usr/lib/postgresql'], ['postgresql.service'], ['postgresql'], 'lan'),
        'mysql' => $e('MySQL / MariaDB', 'Database', 'tcp:3306',
            ['/usr/sbin/mysqld'], ['mysql.service', 'mariadb.service'], ['mariadb', 'mysql-server'], 'lan'),
        'redis' => $e('Redis', 'Database', 'tcp:6379',
            ['/usr/bin/redis-server'], ['redis-server.service'], ['redis-server'], 'lan'),
        // --- Virtualizzazione ---
        'libvirt' => $e('libvirt / KVM', 'Virt', 'tcp:16509',
            ['/usr/sbin/libvirtd'], ['libvirtd.service'], ['libvirt-daemon'], 'lan'),
        'docker' => $e('Docker API (non i container) — apertura manuale soltanto', 'Virt', 'tcp:2375,2376',
            ['/usr/bin/docker'], ['docker.service'], ['docker.io', 'docker-ce'], 'lan',
            'Attenzione: esporre l\'API Docker è rischioso; di solito resta solo su localhost.'),
    ];
}

/** Porte in ascolto non-loopback: ['tcp' => ['80'=>1,...], 'udp'=>...] */
function apps_listen_map(): array {
    $map = ['tcp' => [], 'udp' => []];
    [$c, $o] = priv('listen-ports');
    if ($c === 0 && trim($o) !== '') {
        foreach (preg_split('/\s+/', trim($o)) as $x) {
            if (!preg_match('/^(tcp|udp)\/(\d+)$/i', $x, $m)) continue;
            $map[strtolower($m[1])][(string)(int)$m[2]] = 1;
        }
        return $map;
    }
    // fallback: /proc/net/tcp e udp (solo IPv4)
    foreach (['tcp' => '/proc/net/tcp', 'udp' => '/proc/net/udp'] as $proto => $f) {
        if (!is_readable($f)) continue;
        $lines = file($f, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
        array_shift($lines);
        foreach ($lines as $ln) {
            $p = preg_split('/\s+/', trim($ln));
            if (count($p) < 2) continue;
            [$ipHex, $portHex] = array_pad(explode(':', $p[1]), 2, '0');
            if (strtolower($ipHex) === '0100007f') continue; // 127.0.0.1
            $port = hexdec($portHex);
            if ($port > 0 && $port < 65536) $map[$proto][(string)$port] = 1;
        }
    }
    return $map;
}

function apps_unit_exists(string $u): bool {
    $u = basename($u);
    foreach (['/etc/systemd/system/', '/lib/systemd/system/', '/usr/lib/systemd/system/'] as $d) {
        if (is_file($d . $u) || is_file($d . $u . '.service')) return true;
    }
    return false;
}

function apps_bin_exists(array $bins): bool {
    foreach ($bins as $b) {
        if ($b !== '' && (is_file($b) || is_executable($b))) return true;
        // PATH
        if ($b !== '' && $b[0] !== '/' && ($w = shell_exec('command -v ' . escapeshellarg($b) . ' 2>/dev/null'))) {
            if (trim($w) !== '') return true;
        }
    }
    return false;
}

/** true se almeno una porta del catalogo risulta in ascolto */
function apps_ports_listening(string $ports, array $listen): bool {
    foreach (apps_parse_ports($ports) as [$proto, $plist]) {
        foreach ($plist as $p) if (!empty($listen[$proto][(string)$p])) return true;
    }
    return false;
}

/** @return list<array{0:string,1:list<int>}> */
function apps_parse_ports(string $spec): array {
    $out = [];
    foreach (preg_split('/\s+/', trim($spec)) as $chunk) {
        if (!preg_match('/^(tcp|udp):(.+)$/i', $chunk, $m)) continue;
        $proto = strtolower($m[1]); $ports = [];
        foreach (explode(',', $m[2]) as $x) {
            $x = trim($x);
            if (preg_match('/^(\d+)-(\d+)$/', $x, $r)) {
                $a = (int)$r[1]; $b = (int)$r[2];
                if ($a > 0 && $b >= $a && $b - $a < 50) for ($i = $a; $i <= $b; $i++) $ports[] = $i;
            } elseif (ctype_digit($x) && (int)$x > 0 && (int)$x < 65536) $ports[] = (int)$x;
        }
        if ($ports) $out[] = [$proto, array_values(array_unique($ports))];
    }
    return $out;
}

/**
 * @return array<string, array{id:string,name:string,cat:string,ports:string,scope:string,note:string,installed:bool,listening:bool,enabled:bool,why:string}>
 */
function apps_detect(?array $S = null): array {
    $S ??= S_get();
    $en = array_fill_keys(array_map('strval', (array)($S['apps'] ?? [])), 1);
    $listen = apps_listen_map();
    $out = [];
    foreach (app_catalog() as $id => $a) {
        $byBin = apps_bin_exists($a['bins']);
        $byUnit = false;
        foreach ($a['units'] as $u) if (apps_unit_exists($u)) { $byUnit = true; break; }
        $byListen = apps_ports_listening($a['ports'], $listen);
        // shelly: "soft" — suggerito se c'è mosquitto o porte CoAP
        if ($id === 'shelly' && !$byBin && !$byUnit) {
            $byListen = !empty($listen['udp']['5683']) || !empty($en[$id]);
        }
        $installed = $byBin || $byUnit || $byListen;
        $why = [];
        if ($byBin) $why[] = 'binario';
        if ($byUnit) $why[] = 'servizio systemd';
        if ($byListen) $why[] = 'in ascolto';
        if (!$why && !empty($en[$id])) $why[] = 'abilitato manualmente';
        $out[$id] = [
            'id' => $id, 'name' => $a['name'], 'cat' => $a['cat'], 'ports' => $a['ports'],
            'scope' => $a['scope'], 'note' => $a['note'],
            'installed' => $installed, 'listening' => $byListen,
            'enabled' => !empty($en[$id]),
            'why' => implode(', ', $why),
        ];
    }
    return $out;
}

/** LAN application ports: fold identical IP/proto/port opens while retaining a
 * traceable first owner. Does not merge across scopes, interfaces or protocols.
 * Explicit router services and lockout openings take precedence. */
function apps_rules(array $S): array {
    $en=array_fill_keys(array_map('strval',(array)($S['apps']??[])),1);
    if(!$en)return [];
    $lan=iptm_trusted_lan_nets((string)($S['lan_nets']??''));
    $nets=$lan!==''?explode(',',$lan):[];
    $cat=app_catalog();$seen=[];$groups=[];
    // Only count assured same-semantics managed accepts. Do not infer a port
    // allowed by a source/target/conntrack-filtered user service.
    foreach((array)($S['svc_in']??[]) as $row){
        if(!is_array($row)||empty($row['on']) || ($row['act']??'ACCEPT')!=='ACCEPT' ||
           !empty($row['iif']) || !empty($row['dst']) || !empty($row['ct']) || !empty($row['after']))continue;
        $proto=(string)($row['proto']??'');$src=(string)($row['src']??'');
        if(!in_array($proto,['tcp','udp'],true) || !in_array($src,$nets,true))continue;
        foreach(explode(',',(string)($row['ports']??'')) as $part){
            if(ctype_digit($part) && (int)$part>0 && (int)$part<65536)
                $seen[$proto.'|'.$src][(string)(int)$part]=true;
        }
    }
    if(!empty($S['lockout_on'])){
        foreach($nets as $src)foreach(explode(',',(string)($S['mgmt_ports']??'')) as $part){
            if(!ctype_digit($part))continue;
            $p=(int)$part;
            if($p>=1&&$p<=65535 && !(empty($S['ssh_acc'])===false && $p===(int)($S['ssh_acc_port']??22)))
                $seen['tcp|'.$src][(string)$p]=true;
        }
    }
    foreach(array_keys($en) as $id){
        if($id==='docker'||!isset($cat[$id]))continue;
        $app=$cat[$id];
        if($app['scope']!=='any'&&!$nets)continue;
        $srcList=$app['scope']==='any'?['']:$nets;
        foreach(apps_parse_ports($app['ports']) as [$proto,$ports]){
            foreach($srcList as $src){
                $key=$proto.'|'.$src;
                foreach($ports as $port){
                    $port=(int)$port;
                    if(($proto==='tcp') && $port===(int)($S['ssh_acc_port']??22) &&
                        !empty($S['ssh_acc']) && ($src!=='' || !empty($S['ssh_nets'])))continue;
                    if(isset($seen[$key][(string)$port]))continue;
                    $seen[$key][(string)$port]=true;
                    $groups[$key.'|'.$id]['proto']=$proto;
                    $groups[$key.'|'.$id]['src']=$src;
                    $groups[$key.'|'.$id]['id']=$id;
                    $groups[$key.'|'.$id]['ports'][]=$port;
                }
            }
        }
    }
    $out=[];
    foreach($groups as $group){
        $proto=$group['proto'];$src=$group['src'];$id=$group['id'];
        $ports=array_values(array_unique($group['ports']));sort($ports,SORT_NUMERIC);
        foreach(array_chunk($ports,15) as $chunk){
            $arg=count($chunk)>1?'-m multiport --dports '.implode(',',$chunk):'--dport '.$chunk[0];
            $s=$src!==''?'-s '.$src.' ':'';
            $out[]='-A INPUT '.$s.'-p '.$proto.' '.$arg.' -m conntrack --ctstate NEW -j ACCEPT -m comment --comment "IPTM-app:'.$id.'"';
        }
    }
    return $out;
}

function pg_apps() {
    $S = S_get(); $ro = ($_SESSION['role'] ?? 'viewer') === 'viewer';
    $det = apps_detect($S);
    $found = array_filter($det, fn($x) => $x['installed'] || $x['enabled']);
    $other = array_filter($det, fn($x) => !$x['installed'] && !$x['enabled']);
    // ordina per categoria + nome
    $sort = function (array $a, array $b) {
        return [$a['cat'], $a['name']] <=> [$b['cat'], $b['name']];
    };
    uasort($found, $sort);
    uasort($other, $sort);

    echo '<div class=card><h2>Porte software</h2>';
    echo '<p class=mut>Rileva programmi installati o in ascolto (UrBackup, ipp-usb, CUPS, MQTT, Plex, Samba…) e ti fa scegliere <b>quali porte aprire</b> sul firewall. '
        . 'Di solito dalla <b>LAN</b>: le porte comuni (DNS 53, web 80/443) vengono compattate senza riaprirle più volte. Il provider DNS in esecuzione si sceglie nel resolver, non tramite queste aperture. Dopo «Salva» usa <b>Applica</b>.</p>';
    $nInst = count(array_filter($det, fn($x) => $x['installed']));
    $nEn = count(array_filter($det, fn($x) => $x['enabled']));
    $nIdle = count(array_filter($det, fn($x) => $x['enabled'] && !$x['listening']));
    echo '<p>Rilevati: <b>' . $nInst . '</b> · Abilitati: <b>' . $nEn . '</b> · Senza listener verificato: <b>'.$nIdle.'</b> · LAN: <code>' . h(trim((string)($S['lan_nets'] ?? '')) ?: 'non impostata — nessuna apertura LAN generata') . '</code></p>';
    if($nIdle){
        $candidates=array_values(array_filter($det,fn($x)=>$x['enabled']&&!$x['listening']));
        $labels=array_map(fn($x)=>$x['name'],array_slice($candidates,0,8));
        echo '<p class="msg warn">Profili abilitati senza listener rilevato: <b>'.h(implode(', ',$labels)).'</b>'.($nIdle>8?' e altri '.($nIdle-8):'').'. Il rilevamento non copre tutte le installazioni/container: verifica prima di disabilitare.</p>';
    }
    if (trim((string)($S['lan_nets'] ?? '')) === '') {
        echo '<div class="msg err">⚠ Nessuna rete LAN in Setup: le aperture «solo LAN» non vengono generate. Imposta la LAN in <a href="?p=setup">Setup</a>.</div>';
    }
    echo '</div>';

    if ($ro) {
        echo '<div class=card><p class=mut>Solo lettura (viewer).</p></div>';
        return;
    }

    $row = function (array $x, bool $checkedDefault) {
        $id = $x['id'];
        $badge = $x['listening'] ? '<span class="b b-ACCEPT">in ascolto</span>' : ($x['installed'] ? '<span class="b b-jump">installato</span>' : '<span class=mut>catalogo</span>');
        $scope = $x['scope'] === 'any' ? 'WAN+LAN' : 'solo LAN';
        echo '<tr><td><label><input type=checkbox class=acb name="apps[]" data-iptm-no-listener="' . (!empty($x['enabled'])&&!$x['listening']?'1':'0') . '" value="' . h($id) . '"'
            . (!empty($x['enabled']) ? ' checked' : '')
            . '> <b>' . h($x['name']) . '</b></label></td>'
            . '<td>' . h($x['cat']) . '</td>'
            . '<td><code>' . h($x['ports']) . '</code></td>'
            . '<td>' . h($scope) . '</td>'
            . '<td>' . $badge . ($x['why'] ? ' <small class=mut>' . h($x['why']) . '</small>' : '')
            . ($x['note'] ? '<br><small class=mut>' . h($x['note']) . '</small>' : '') . '</td></tr>';
    };

    echo '<form method=post>' . fh('p=apps') . '<input type=hidden name=action value=apps_save>';
    echo '<div class=card><h3>Rilevati o già abilitati</h3>';
    if (!$found) {
        echo '<p class=mut>Nessun software del catalogo risulta installato o in ascolto. Puoi comunque abilitare voci dal catalogo completo sotto (es. Shelly/MQTT).</p>';
    } else {
        echo '<p><button type=button class=s onclick="document.querySelectorAll(\'.acb\').forEach(c=>c.checked=true)">Seleziona tutto</button> '
            . '<button type=button class=s onclick="document.querySelectorAll(\'.acb\').forEach(c=>c.checked=false)">Nessuna</button></p>';
        echo '<p><button type=button class=s onclick="document.querySelectorAll(\'.acb[data-iptm-no-listener=1]\').forEach(c=>c.checked=false)">Deseleziona servizi senza listener (solo modulo)</button></p>';
        echo '<p class=mut>Verifica le voci prima di salvare: container e porte personalizzate potrebbero non essere rilevati.</p>';
        echo '<table><tr><th>Software</th><th>Categoria</th><th>Porte</th><th>Ambito</th><th>Stato</th></tr>';
        foreach ($found as $x) $row($x, true);
        echo '</table>';
    }
    echo '</div>';

    echo '<details class=card><summary><b>Catalogo completo</b> <span class=mut>abilita anche software non ancora rilevato</span></summary>';
    echo '<table><tr><th>Software</th><th>Categoria</th><th>Porte</th><th>Ambito</th><th>Stato</th></tr>';
    foreach ($other as $x) $row($x, false);
    echo '</table></details>';

    echo '<p class=sticky><button>💾 Salva selezione (bozza)</button> '
        . '<button class=g name=apply value=1>🚀 Salva e applica</button> '
        . '<span class=mut>Le regole finiscono nei blocchi gestiti «Porte software»; restano modificabili anche da Accesso router.</span></p>';
    echo '</form>';
}
