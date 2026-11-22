<?php
// ===================== v3: EQUIVALENZA SEMANTICA, PREFLIGHT, IMPATTO, HARDENING =====================
function sem_atoms(string $raw): array {   // espande liste come fa iptables (-s a,b) e multiport, per confrontare regole "uguali nel significato"
    $f = rule_parse($raw); $lst = fn($v) => ($v !== '' && $v[0] !== '!' && str_contains($v, ',')) ? explode(',', $v) : [$v];
    $o = [];
    foreach ($lst($f['s']) as $s) foreach ($lst($f['d']) as $d) foreach ($lst($f['dports']) as $dp) foreach ($lst($f['sports']) as $sp) {
        $g = $f; $g['s'] = $s; $g['d'] = $d; $g['dports'] = ''; $g['sports'] = ''; $g['dport'] = $dp !== '' ? $dp : $f['dport']; $g['sport'] = $sp !== '' ? $sp : $f['sport']; $o[] = rkey(rule_build($g));
    }
    return $o;
}
function sem_model(array $M): array {   // forma normale: stesso comportamento = stessa forma (ignora commenti, duplicati, regole irraggiungibili e ordine fra regole con lo stesso verdetto)
    $o = []; $TERM = ['ACCEPT', 'DROP', 'REJECT'];
    foreach ($M as $b) if ($b['k'] === 'table') {
        $pol = []; foreach (BUILTIN[$b['name']] ?? [] as $c) $pol[$c] = 'ACCEPT'; $by = [];
        foreach ($b['items'] as $it) { if ($it['t'] === 'chain' && isset($pol[$it['n']])) $pol[$it['n']] = $it['p']; elseif ($it['t'] === 'rule' && $it['on']) $by[rchain($it['r'])][] = $it['r']; }
        $termCh = []; foreach ($by as $c => $rs) { $f = rule_parse(end($rs)); if (catchall($f) && in_array($f['target'], $TERM, true)) $termCh[$c] = 1; }
        $rl = [];
        foreach ($by as $c => $rs) {
            $seq = [];
            foreach ($rs as $raw) { $f = rule_parse($raw); foreach (sem_atoms($raw) as $k) $seq[] = [$k, $f['target'] . '|' . trim($f['targs'])]; if (catchall($f) && (in_array($f['target'], $TERM, true) || isset($termCh[$f['target']]))) break; }
            $out = []; $run = []; $rt = null;
            foreach ($seq as [$k, $t]) {
                $tt = explode('|', $t)[0];
                if ($t === $rt && in_array($tt, $TERM, true)) { $run[$k] = 1; continue; }
                if ($run) { ksort($run); foreach (array_keys($run) as $x) $out[] = $x; $run = []; }
                if (in_array($tt, $TERM, true)) { $run = [$k => 1]; $rt = $t; } else { $out[] = $k; $rt = null; }
            }
            if ($run) { ksort($run); foreach (array_keys($run) as $x) $out[] = $x; }
            $rl[$c] = $out;
        }
        ksort($pol); ksort($rl); if ($rl || array_filter($pol, fn($p) => $p !== 'ACCEPT')) $o[$b['name']] = ['pol' => $pol, 'rules' => $rl];
    }
    ksort($o); return $o;
}
function model_delta(string $a, string $b): array {   // [regole aggiunte, regole rimosse] fra due testi
    $f = function ($t) { $c = []; foreach (sem_model(parse_rules($t)) as $tb => $x) foreach ($x['rules'] as $ch => $l) foreach ($l as $k) { $k2 = "$tb|$ch|$k"; $c[$k2] = ($c[$k2] ?? 0) + 1; } return $c; };
    $A = $f($a); $B = $f($b); $ad = 0; $rm = 0; foreach ($B as $k => $n) $ad += max(0, $n - ($A[$k] ?? 0)); foreach ($A as $k => $n) $rm += max(0, $n - ($B[$k] ?? 0)); return [$ad, $rm];
}
function delta_msg(string $a, string $b): string { [$ad, $rm] = model_delta($a, $b); return ($ad || $rm) ? "ℹ Variazioni nella bozza: +$ad / −$rm regole." : 'ℹ Nessuna variazione effettiva delle regole.'; }
function rules_equiv(string $a, string $b): bool { return sem_model(parse_rules($a)) == sem_model(parse_rules($b)); }
/** Riconosce catene create da servizi runtime (Docker, CrowdSec, fail2ban, IOT_*, …). */
function runtime_chain(string $n): bool {
    static $exact = null;
    if ($exact === null) $exact = array_flip([
        'DOCKER', 'DOCKER-USER', 'DOCKER-ISOLATION-STAGE-1', 'DOCKER-ISOLATION-STAGE-2', 'DOCKER-FORWARD',
        'DOCKER-BRIDGE', 'DOCKER-CT', 'DOCKER-INGRESS', 'DOCKER-INTERNAL',
        'LIBVIRT_INP', 'LIBVIRT_OUT', 'LIBVIRT_FWO', 'LIBVIRT_FWI', 'LIBVIRT_FWX', 'LIBVIRT_PRT',
        'f2b-sshd', 'f2b-sshd-ddos',
    ]);
    if (isset($exact[$n])) return true;
    if (str_starts_with($n, 'DOCKER')) return true;
    if (str_starts_with($n, 'fail2ban-') || str_starts_with($n, 'f2b-')) return true;
    if (str_starts_with($n, 'CROWDSEC') || str_starts_with($n, 'crowdsec')) return true;
    if (str_starts_with($n, 'LIBVIRT_')) return true;
    if (str_starts_with($n, 'ufw-')) return true;
    if (str_starts_with($n, 'cali') || str_starts_with($n, 'KUBE-') || str_starts_with($n, 'CNI-')) return true;
    if (str_starts_with($n, 'IOT_') || str_starts_with($n, 'IOT-')) return true;
    if (function_exists('runtime_chain_conf_prefixes')) {
        foreach (runtime_chain_conf_prefixes() as $px) {
            if ($px !== '' && str_starts_with($n, $px)) return true;
        }
    }
    return false;
}

/** Regola solo-runtime (salto a catena runtime, docker0, MASQUERADE docker, …). */
function runtime_rule(string $r): bool {
    if (preg_match('/\s-j\s+(\S+)/', $r, $m) && runtime_chain($m[1])) return true;
    if (preg_match('/\s-[io]\s+docker\d*\b/', $r)) return true;
    if (preg_match('/\s-[io]\s+br-[0-9a-f]+\b/', $r)) return true;
    if (preg_match('/--dst-type\s+LOCAL\s+-j\s+DOCKER/', $r)) return true;
    // hairpin NAT docker (stesso IP src/dst container)
    if (preg_match('/-s\s+172\.1[6-9]\.\d+\.\d+.*-d\s+172\.1[6-9]\.\d+\.\d+.*MASQUERADE/', $r)) return true;
    if (preg_match('/-s\s+172\.1[6-9]\.\d+\.\d+\/\d+\s+!\s+-o\s+docker/', $r)) return true;
    return false;
}

/** Normalizza una riga -A per confronto semantico robusto. */
function rules_normalize_line(string $r): string {
    $r = preg_replace('/\s-m\s+comment\s+--comment\s+(?:"[^"]*"|\S+)/', '', $r) ?? $r;
    $r = preg_replace('/\s-m\s+(tcp|udp|icmp)(?=\s)/', '', $r) ?? $r;
    $r = str_replace(' --tcp-flags FIN,SYN,RST,ACK SYN', ' --syn', $r);
    $r = str_replace('--tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE', '--tcp-flags ALL NONE', $r);
    $r = str_replace('--tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,RST,PSH,ACK,URG', '--tcp-flags ALL ALL', $r);
    $r = str_replace('--tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,PSH,URG', '--tcp-flags ALL FIN,URG,PSH', $r);
    $r = str_replace('--tcp-flags FIN,SYN FIN,SYN', '--tcp-flags SYN,FIN SYN,FIN', $r);
    $r = str_replace('--icmp-type 8', '--icmp-type echo-request', $r);
    $r = preg_replace('/\s-p\s+2\b/', ' -p igmp', $r) ?? $r;
    $r = preg_replace('/\s--mask\s+255\.255\.255\.255\b/', '', $r) ?? $r;
    $r = preg_replace('/\s--rsource\b/', '', $r) ?? $r;
    $r = preg_replace('/\s--rdest\b/', '', $r) ?? $r;
    $r = preg_replace('/\s--log-level\s+4\b/', '', $r) ?? $r;
    $r = preg_replace('/\s--connlimit-saddr\b/', '', $r) ?? $r;
    $r = preg_replace('/\s-j\s+TARPIT(?:\s+--tarpit)?/', ' -j TARPIT', $r) ?? $r;
    $r = preg_replace('/\/32\b/', '', $r) ?? $r;
    $r = preg_replace('/\s+/', ' ', trim($r)) ?? $r;
    return $r;
}

function live_dump(): array { return kc('dump', 'live_dump_raw'); }
function live_dump_raw(): array {
    [$c, $o] = priv('save'); $d = ['ok' => $c === 0, 'chains' => [], 'rules' => []]; if ($c) return $d; $t = '';
    foreach (explode("\n", $o) as $l) {
        if (preg_match('/^\*(\w+)/', $l, $m)) $t = $m[1]; elseif (preg_match('/^:(\S+)/', $l, $m)) $d['chains'][$t][$m[1]] = 1;
        elseif (str_starts_with($l, '-A ')) foreach (sem_atoms($l) as $k) $d['rules'][] = ['t' => $t, 'c' => rchain($l), 'raw' => $l, 'k' => $k];
    }
    return $d;
}
function dyn_owner(string $c): string {
    foreach (['DOCKER' => 'docker', 'f2b-' => 'fail2ban', 'crowdsec' => 'crowdsec-firewall-bouncer', 'ts-' => 'tailscaled', 'LIBVIRT' => 'libvirtd', 'ufw' => 'ufw', 'KUBE' => 'k3s', 'cali-' => 'calico'] as $p => $s) if (stripos($c, $p) === 0) return $s;
    return '';
}
function dyn_report(array $M): array {   // cosa c'è nel kernel ma non nella bozza (creato da altri programmi) e andrà perso al caricamento
    $L = live_dump(); if (!$L['ok']) return ['ok' => false]; $dc = []; $dr = [];
    foreach ($M as $b) if ($b['k'] === 'table') foreach ($b['items'] as $it) { if ($it['t'] === 'chain') $dc[$b['name']][$it['n']] = 1; elseif ($it['t'] === 'rule' && $it['on']) foreach (sem_atoms($it['r']) as $k) $dr[$b['name'] . '|' . rchain($it['r'])][$k] = 1; }
    $chains = []; foreach ($L['chains'] as $t => $cs) foreach (array_keys($cs) as $c) if (!in_array($c, BUILTIN[$t] ?? [], true) && empty($dc[$t][$c])) $chains[$c] = ['t' => $t, 'n' => 0, 'owner' => dyn_owner($c)];
    $hooks = 0;
    foreach ($L['rules'] as $r) { if (isset($chains[$r['c']])) { $chains[$r['c']]['n']++; continue; } if (!isset($dr[$r['t'] . '|' . $r['c']][$r['k']]) && in_array($r['c'], BUILTIN[$r['t']] ?? [], true)) $hooks++; }
    return ['ok' => true, 'chains' => $chains, 'hooks' => $hooks];
}
function post_conf(): array {
    [, $c] = priv('conf'); $o = ['services' => '', 'script' => ''];
    if (preg_match('/^POST_SERVICES="([^"]*)"/m', $c, $m)) $o['services'] = $m[1]; if (preg_match('/^POST_SCRIPT="([^"]*)"/m', $c, $m)) $o['script'] = $m[1]; return $o;
}
/**
 * Conservative LAN connectivity gate.  Uses the proposed restore document, not
 * the lan_out_fwd switch: manual FORWARD rules are valid too.  The packet model
 * is a preflight aid, not a replacement for a network/route test on DietPi.
 * No firewall, sysctl or NetworkManager changes are made here.
 */
function iptm_client_navigation_gate(string $txt, array $S, ?array $inputIfaces = null): array {
    $warnings = []; $block = '';
    $nets = array_values(array_filter(array_map('trim', explode(',', (string)($S['lan_nets'] ?? '')))));
    if (!$nets) return ['block'=>'', 'warn'=>[]];
    $ifaces = $inputIfaces ?? (function_exists('sys_ifaces') ? array_keys(sys_ifaces()) : []);
    $wan = trim((string)($S['wan_if'] ?? ''));
    $lanIf = trim((string)($S['lan_if'] ?? ''));
    $outs = array_values(array_filter(array_map('trim', explode(',', (string)($S['masq_ifs'] ?? '')))));
    if (!$outs && $wan !== '') $outs = [$wan];
    if (!$outs) {
        $warnings[] = 'LAN→WAN: interfaccia di uscita non determinata; verifica routing e topologia, non applicare alla cieca.';
        return ['block'=>'', 'warn'=>$warnings];
    }
    // An unscoped masquerade on the shared WAN changes the semantics of
    // modem-side, VPN and container flows. Require cleanup in the draft;
    // never mutate the live firewall from this preflight.
    if (!empty($S['single_nic']) && $outs) {
        // Come in IPTM 6.11.3, ogni egress deve essere legato a una sorgente
        // LAN esplicita. Verificare tutte le uscite, anche quando diverse da WAN.
        foreach (explode("\n", $txt) as $line) {
            if (!preg_match('/^-A\s+POSTROUTING\b/', $line)
                || !preg_match('/(?:^|\s)-j\s+MASQUERADE(?:\s|$)/', $line)
                || preg_match('/(?:^|\s)-s\s+\S+/', $line)) continue;
            foreach ($outs as $out) {
                if (preg_match('/(?:^|\s)-o\s+' . preg_quote($out, '/') . '(?:\s|$)/', $line)) {
                    return ['block'=>'LAN→WAN: masquerade globale su ' . $out .
                        ' incompatibile con Single-NIC. Elimina la regola manuale non selettiva dalla bozza; il NAT automatico resta limitato alle subnet LAN.', 'warn'=>$warnings];
                }
            }
        }
    }
    $model = parse_rules($txt);
    $forwardingGuarded = (bool)preg_match('/^:FORWARD\s+DROP\b/m', $txt)
        || (bool)preg_match('/^-A\s+FORWARD\s+-j\s+(?:DROP|REJECT|IPTM-[A-Za-z0-9_-]*DROP)\b/m', $txt)
        || !empty($S['final_drop']);
    $candidates = array_values(array_unique(array_filter(array_merge([$lanIf], $ifaces))));
    if (!$candidates) $candidates = [''];
    $seen = [];
    foreach ($nets as $cidr) {
        if (!preg_match('~^((?:\d{1,3}\.){3}\d{1,3})/(\d|[12]\d|3[0-2])$~D', $cidr, $m)
            || filter_var($m[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
            $warnings[] = 'LAN→WAN: subnet non interpretabile (' . substr($cidr, 0, 70) . ').';
            continue;
        }
        $prefix = (int)$m[2];
        $mask = $prefix === 0 ? 0 : ((0xffffffff << (32-$prefix)) & 0xffffffff);
        $base = (ip2long($m[1]) & $mask) & 0xffffffff;
        $src = long2ip($base | ($prefix < 31 ? 1 : 0));
        foreach ($outs as $out) {
            $forwardAccepted = false; $returnAccepted = false;
            foreach ($candidates as $iface) {
                // A candidate LAN interface may equal WAN on a single-NIC gateway.
                $packet = ['flow'=>'forward','in'=>$iface,'out'=>$out,'src'=>$src,
                           'dst'=>'1.1.1.1','proto'=>'tcp','sport'=>'55000',
                           'dport'=>'443','state'=>'NEW','local_ips'=>[]];
                $fwd = trace_packet($model, $packet);
                if ($fwd['verdict'] !== 'ACCEPT') continue;
                $forwardAccepted = true;
                $back = trace_packet($model, array_merge($packet, [
                    'in'=>$out,'out'=>$iface,'src'=>'1.1.1.1','dst'=>$src,
                    'sport'=>'443','dport'=>'55000','state'=>'ESTABLISHED']));
                if ($back['verdict'] === 'ACCEPT') { $returnAccepted = true; break; }
            }
            $key = $cidr . '|' . $out;
            if ($forwardingGuarded && (!$forwardAccepted || !$returnAccepted)) {
                $seen[$key] = 1;
                $block = 'LAN→WAN: bozza non sicura per ' . $cidr . ' → ' . $out .
                    (!$forwardAccepted ? ': traffico NEW non consentito in FORWARD.' : ': risposte ESTABLISHED non consentite in FORWARD.') .
                    ' Aggiungi regole esplicite in entrambi i versi e rigenera la bozza. Nessuna applicazione consentita, anche con Forza.';
                break 2;
            }
        }
    }
    if (empty($S['nat_masq'])) {
        $warnings[] = 'LAN→WAN: NAT non abilitato; è necessaria una rotta di ritorno sul router a monte per ogni subnet LAN.';
    } elseif (!preg_match('/^-A\s+(?:POSTROUTING|IPTM-MASQ)\b[^\n]*-j\s+(?:MASQUERADE|SNAT)\b/m', $txt)) {
        $warnings[] = 'LAN→WAN: NAT previsto nelle impostazioni ma non presente nelle regole IPv4 proposte.';
    }
    $ipForwardFile = '/proc/sys/net/ipv4/ip_forward';
    if (is_readable($ipForwardFile) && trim((string)@file_get_contents($ipForwardFile)) === '0')
        $warnings[] = 'LAN→WAN: net.ipv4.ip_forward=0 sul sistema che esegue il preflight; il traffico non verrà inoltrato.';
    return ['block'=>$block,'warn'=>$warnings];
}
function apply_preflight(string $txt): array {   // controlli prima di caricare: ti chiudi fuori? gli ipset contengono il tuo IP?
    $M = parse_rules($txt); $w = []; $block = ''; $S = S_get(); $ifs = array_keys(sys_ifaces()); $loc = []; foreach (sys_ifaces() as $a) foreach ($a as $x) $loc[] = explode('/', $x)[0];
    $me = preg_replace('/^::ffff:/', '', $_SERVER['REMOTE_ADDR'] ?? ''); $srv = $_SERVER['SERVER_ADDR'] ?? ($loc[0] ?? ''); $port = (string)($_SERVER['SERVER_PORT'] ?? '80');
    if (v_ok('ip', $me) && $me !== '' && v_ok('ip', $srv) && $srv !== '' && !str_starts_with($me, '127.')) {
        $ok = false; $note = [];
        foreach ($ifs ?: [''] as $i) { $r = trace_packet($M, ['flow' => 'local', 'in' => $i, 'out' => '', 'src' => $me, 'dst' => $srv, 'proto' => 'tcp', 'sport' => '50000', 'dport' => $port, 'state' => 'NEW', 'local_ips' => $loc, 'local_ip' => $srv]); if ($r['verdict'] === 'ACCEPT') { $ok = true; break; } $note[] = $r['where']; }
        if (!$ok) $block = "Con queste regole il tuo indirizzo ($me) non potrebbe più raggiungere questa pagina (porta $port): scarta " . ($note[0] ?? '') . ". Abilita «Anti-lockout» in Sicurezza o aggiungi una regola per la tua rete.";
    }
    $navigation = iptm_client_navigation_gate($txt, $S);
    if ($navigation['block'] !== '') $block = $navigation['block'];
    array_push($w, ...$navigation['warn']);
    $lsets = array_keys(list_sets($S));
    if ($lsets) foreach (array_unique(array_filter([$me, $S['dns_ip'], $loc[0] ?? ''])) as $ip) if (v_ok('ip', $ip)) { [, $hit] = priv('ipset-hits', null, array_merge([$ip], $lsets)); foreach (array_filter(explode("\n", trim($hit))) as $set) $w[] = "L'indirizzo $ip è presente nella lista $set (le reti private sono comunque escluse dalle regole)."; }
    if ($txt !== '') { $cr = compat_report($txt); if ($cr['ok']) {
        foreach (['matches' => 'match', 'targets' => 'target'] as $k => $lbl) foreach ($cr[$k] as $n => $okx) if (!$okx) {
            if ($n === 'recent') $w[] = "Il kernel non espone il match «recent» (modulo xt_recent). Opzioni che lo usano (port-scan, anti brute-force SSH, port knocking, ban automatico servizi) non funzioneranno finché non carichi il modulo (`modprobe xt_recent`) o usi un kernel che lo include.";
            elseif ($n === 'TARPIT') $w[] = "Il kernel non espone il target «TARPIT». Installa «xtables-addons» da Strumenti → Programmi.";
            else $w[] = "Il kernel non espone $lbl «{$n}» usato dalla bozza (modulo mancante?): il caricamento potrebbe fallire.";
        }
    } }
    return ['block' => $block, 'warn' => $w];
}
function apply_result(string $e): bool {   // true = applicato
    if ($e === '@skip') { flash('ℹ Nessuna modifica effettiva rispetto al file attivo: il firewall in esecuzione NON è stato toccato (nessuna interruzione). «Forza ricarica» in Applica & Backup lo ricarica comunque.'); return false; }
    if ($e !== '') { flash($e, 'err'); return false; }
    foreach ($GLOBALS['apply_notes'] ?? [] as [$t, $m]) flash($m, $t); return true;
}
const HARDEN = ['syncookies' => ['SYN cookies', 'Protegge dal SYN flood quando la coda si riempie.', ['net.ipv4.tcp_syncookies' => '1']],
    'bcast' => ['Ignora il ping broadcast', 'Evita di partecipare ad attacchi «smurf».', ['net.ipv4.icmp_echo_ignore_broadcasts' => '1']],
    'bogus' => ['Ignora risposte ICMP malformate', '', ['net.ipv4.icmp_ignore_bogus_error_responses' => '1']],
    'srcroute' => ['Rifiuta il source routing', 'Il mittente non può imporre il percorso.', ['net.ipv4.conf.all.accept_source_route' => '0', 'net.ipv4.conf.default.accept_source_route' => '0', 'net.ipv6.conf.all.accept_source_route' => '0', 'net.ipv6.conf.default.accept_source_route' => '0']],
    'redirects' => ['Ignora i redirect ICMP', 'Impedisce di cambiare le rotte con pacchetti falsi.', ['net.ipv4.conf.all.accept_redirects' => '0', 'net.ipv4.conf.default.accept_redirects' => '0', 'net.ipv4.conf.all.secure_redirects' => '0', 'net.ipv4.conf.default.secure_redirects' => '0', 'net.ipv6.conf.all.accept_redirects' => '0', 'net.ipv6.conf.default.accept_redirects' => '0']],
    'sendredir' => ['Non inviare redirect ICMP', '', ['net.ipv4.conf.all.send_redirects' => '0', 'net.ipv4.conf.default.send_redirects' => '0']],
    'rfc1337' => ['Protezione TIME-WAIT (RFC 1337)', '', ['net.ipv4.tcp_rfc1337' => '1']],
    'ctloose' => ['Conntrack rigoroso', 'Non crea voci di tracking per pacchetti TCP a metà connessione (nf_conntrack_tcp_loose=0). Dopo un flush del tracking le connessioni aperte vanno riaperte.', ['net.netfilter.nf_conntrack_tcp_loose' => '0']],
    'ctacct' => ['Contabilità conntrack', 'Conta i byte per connessione: serve per ordinare le connessioni per traffico e vedere i maggiori consumatori.', ['net.netfilter.nf_conntrack_acct' => '1']],
    'cttimeout' => ['Timeout conntrack ridotto', 'Connessioni TCP stabilite: 2 ore di inattività invece di 5 giorni. Libera la tabella su router molto usati.', ['net.netfilter.nf_conntrack_tcp_timeout_established' => '7200']],
    'martians' => ['Registra i pacchetti «marziani»', 'Sorgenti impossibili nel log del kernel (può essere verboso).', ['net.ipv4.conf.all.log_martians' => '1', 'net.ipv4.conf.default.log_martians' => '1']],
    'arp_protect' => ['Protezione ARP', 'Filtra risposte ARP non attese (anti-spoofing base).', ['net.ipv4.conf.all.arp_ignore' => '1', 'net.ipv4.conf.default.arp_ignore' => '1', 'net.ipv4.conf.all.arp_announce' => '2', 'net.ipv4.conf.default.arp_announce' => '2']],
    'tcp_fastopen_off' => ['Disabilita TCP Fast Open', 'Riduce superficie di attacco sullo stack TCP.', ['net.ipv4.tcp_fastopen' => '0']],
    'synack' => ['Meno tentativi SYN-ACK', 'Riduce da 5 a 2 i tentativi di risposta a connessioni mai completate: la coda si libera prima durante un SYN flood.', ['net.ipv4.tcp_synack_retries' => '2']],
    'k_dmesg' => ['Log del kernel riservato a root', 'Impedisce agli utenti normali di leggere dmesg (indirizzi e dettagli utili a chi prepara un exploit).', ['kernel.dmesg_restrict' => '1']],
    'k_kptr' => ['Nascondi gli indirizzi del kernel', 'Gli indirizzi di memoria del kernel non vengono più mostrati agli utenti (rende più difficili gli exploit locali).', ['kernel.kptr_restrict' => '2']],
    'k_sysrq' => ['Disabilita Magic SysRq', 'Chiude la tastiera di emergenza del kernel: utile contro chi ha accesso fisico o a una console.', ['kernel.sysrq' => '0']],
    'k_aslr' => ['ASLR completo', 'Randomizza gli indirizzi di memoria dei programmi (stack, librerie, heap).', ['kernel.randomize_va_space' => '2']],
    'fs_links' => ['Protezione link simbolici e hard link', 'Impedisce attacchi che sfruttano link in cartelle condivise come /tmp.', ['fs.protected_hardlinks' => '1', 'fs.protected_symlinks' => '1']],
    'fs_suid' => ['Niente core dump dei programmi privilegiati', 'I programmi con permessi speciali non scrivono core dump che potrebbero contenere password o chiavi.', ['fs.suid_dumpable' => '0']],
    'bpf_jit' => ['Hardening del JIT BPF', 'Rende più difficile sfruttare il compilatore BPF del kernel (se presente).', ['net.core.bpf_jit_harden' => '2']],
    // --- prestazioni / velocità (non solo sicurezza) ---
    'bbr' => ['TCP BBR', 'Congestion control moderno: migliore throughput e latenza su reti/Wi‑Fi (richiede modulo tcp_bbr).', ['net.ipv4.tcp_congestion_control' => 'bbr']],
    'fq' => ['Coda FQ di default', 'Fair Queueing a livello di socket (ottimo con BBR).', ['net.core.default_qdisc' => 'fq']],
    'tcp_fastopen_on' => ['TCP Fast Open', 'Riduce un RTT all\'apertura connessione (client+server).', ['net.ipv4.tcp_fastopen' => '3']],
    'tcp_tune' => ['TCP tuning velocità', 'Niente slow-start dopo idle, MTU probing, window scaling.', [
        'net.ipv4.tcp_slow_start_after_idle' => '0',
        'net.ipv4.tcp_mtu_probing' => '1',
        'net.ipv4.tcp_window_scaling' => '1',
        'net.ipv4.tcp_timestamps' => '1',
        'net.ipv4.tcp_no_metrics_save' => '1',
    ]],
    'buf_large' => ['Buffer di rete ampi', 'rmem/wmem fino a 16 MB per flussi ad alta velocità.', [
        'net.core.rmem_max' => '16777216',
        'net.core.wmem_max' => '16777216',
        'net.core.optmem_max' => '65536',
        'net.ipv4.tcp_rmem' => '4096 87380 16777216',
        'net.ipv4.tcp_wmem' => '4096 65536 16777216',
    ]],
    'netdev_backlog' => ['Backlog netdev alto', 'Meno drop sotto burst di pacchetti.', ['net.core.netdev_max_backlog' => '5000', 'net.core.somaxconn' => '4096']],
    'ct_max' => ['Conntrack ampio', 'Più sessioni contemporanee su router trafficati.', ['net.netfilter.nf_conntrack_max' => '262144']],
];
function harden_conflicts(array $H): array {
    $seen = []; $errors = [];
    foreach (HARDEN as $id => [, , $kv]) {
        if (empty($H[$id])) continue;
        foreach ($kv as $key => $value) {
            $value = (string)$value;
            if (isset($seen[$key]) && $seen[$key]['value'] !== $value) {
                $errors[] = 'Impostazioni sysctl incompatibili per ' . $key . ' (' . $seen[$key]['id'] . ' e ' . $id . '): scegli un solo profilo.';
            } else $seen[$key] = ['value' => $value, 'id' => $id];
        }
    }
    return array_values(array_unique($errors));
}
function harden_lines(array $H): string {
    // Un solo valore per chiave: evita che opzioni diverse generino assegnazioni sysctl duplicate.
    $kvOut = [];
    foreach (HARDEN as $id => [, , $kv]) if (!empty($H[$id])) foreach ($kv as $k => $v) $kvOut[$k] = (string)$v;
    $r = $H['rpf'] ?? '2';
    if (in_array($r, ['0', '1', '2'], true)) { $kvOut['net.ipv4.conf.all.rp_filter'] = $r; $kvOut['net.ipv4.conf.default.rp_filter'] = $r; }
    $o = []; foreach ($kvOut as $k => $v) $o[] = "$k=$v";
    return implode("\n", $o) . "\n";
}


/** Profilo prestazioni consigliato (BBR + buffer + FQ). */
function speed_profile_keys(): array {
    return ['bbr', 'fq', 'tcp_fastopen_on', 'tcp_tune', 'buf_large', 'netdev_backlog', 'ct_max'];
}

function speed_profile_apply(): array {
    $S = S_get();
    $H = $S['harden'] ?? [];
    foreach (speed_profile_keys() as $k) $H[$k] = 1;
    // non forzare tcp_fastopen_off se stiamo abilitando fastopen
    $H['tcp_fastopen_off'] = 0;
    if (!isset($H['rpf'])) $H['rpf'] = '2';
    $S['harden'] = $H;
    // MSS clamp utile con SQM/VPN
    if (isset($S['mss'])) $S['mss'] = 1;
    S_put($S);
    $lines = harden_lines($H);
    [$c, $o, $e] = sysctl_maintenance_apply_text($lines);
    return [$c, $c === 0 ? 'Profilo velocità applicato (BBR, FQ, buffer, Fast Open, conntrack).' : trim($o . "\n" . $e), $H];
}

function harden_state(array $kv): array {   // confronta i valori in /proc/sys; le chiavi inesistenti (es. IPv6 disattivato, modulo non caricato) NON contano come «non attivo»
    $diff = []; $na = 0;
    foreach ($kv as $k => $v) { $f = '/proc/sys/' . str_replace('.', '/', $k); if (!file_exists($f)) { $na++; continue; } $c = trim((string)@file_get_contents($f)); if ($c !== (string)$v) $diff[] = "$k = $c (atteso $v)"; }
    return ['on' => !$diff && $na < count($kv), 'na' => $na === count($kv), 'diff' => $diff, 'skipped' => $na];
}
function zero_prefill(array $S): array {   // risposte del wizard dedotte da una configurazione esistente
    $a = []; $in = $S['svc_in'] ?? []; $fw = $S['svc_fwd'] ?? [];
    $a['mode'] = !empty($S['single_nic']) ? 'single' : (($S['nat_masq'] || $S['masq_ifs'] !== '' || $fw) ? 'router' : 'host');
    $a['wan_if'] = $S['wan_if']; $a['lan_nets'] = $S['lan_nets']; $a['dhcp_server'] = !empty($S['dhcp_accept']) ? '1' : '0'; $a['pihole_web'] = '1'; $a['pihole_ports'] = '8089,8489'; $a['nat'] = $S['nat_masq'] ? '1' : '0'; $a['dns_local'] = $S['dns_redirect'] ? '1' : '0'; $a['dns_ip'] = $S['dns_ip']; $a['dot'] = $S['dot_block'] ? '1' : '0';
    $a['level'] = (!empty($S['stealth']) || !empty($S['synproxy']) || !empty($S['tarpit'])) ? 'paranoid' : (($S['ident'] || $S['multicast'] || $S['blockping'] || $S['portscan']) ? 'strict' : (($S['icmp_limit'] && $S['dos'] && $S['closeports']) ? 'standard' : 'base'));
    $a['logging'] = ($S['log_in'] || $S['log_out']) ? 'all' : (($S['logdrop_on'] || $S['log_drop']) ? 'drops' : 'none'); $a['crowdsec'] = $S['crowdsec'] ? '1' : '0'; $a['docker'] = ($S['cs_docker'] && $S['crowdsec']) ? '1' : '0';
    $a['v6'] = !empty($S['v6']['on']) ? '1' : '0'; $a['lists'] = array_values(array_map(fn($b) => $b['id'], array_filter($S['blocklists'] ?? [], fn($b) => !empty($b['on']) && isset(BL_PRESETS[$b['id']])))); $a['geo_codes'] = $S['geo_on'] ? $S['geo_codes'] : '';
    $a['ssh_limit'] = ($S['ssh_acc'] || $S['ssh_limit']) ? '1' : '0'; if ($S['ssh_acc']) $a['ssh_port'] = (string)$S['ssh_acc_port'];
    $known = []; foreach (ZSVC as $id => [$n, $pp, $ports]) foreach (explode(',', $pp) as $pr) $known[$pr . '|' . $ports] = $id;
    $sv = []; $cp = []; $sshFrom = []; $vpn = 'none'; $web = null;
    foreach ($in as $r) {
        if (empty($r['on'])) continue; $pr = $r['proto'] ?? ''; $po = $r['ports'] ?? '';
        if ($pr === 'udp' && $po === '51820') { $vpn = 'wireguard'; $a['vpn_port'] = $po; continue; } if ($pr === 'udp' && $po === '1194') { $vpn = 'openvpn'; $a['vpn_port'] = $po; continue; }
        if (($r['iif'] ?? '') !== '' && $po === '' && $pr === '') { $a['vpn_if'] = $r['iif']; continue; } if (($r['src'] ?? '') === '172.16.0.0/12') { $a['docker'] = '1'; continue; }
        if ($pr === 'tcp' && preg_match('/^22$|^2222$/', $po)) { $a['ssh_port'] = $po; $sshFrom[($r['src'] ?? '') === '' ? 'wan' : (($r['src'] === $S['lan_nets']) ? 'lan' : 'vpn')] = 1; continue; }
        if ($pr === 'tcp' && in_array($po, ['80,443', '443,80', '80', '443'], true) && $web === null) { $web = $po; continue; }
        if (isset($known[$pr . '|' . $po])) { $sv[$known[$pr . '|' . $po]] = 1; continue; } if ($po !== '' && in_array($pr, ['tcp', 'udp'], true)) $cp[$pr . ':' . $po] = 1;
    }
    if ($S['ssh_acc']) $sshFrom['lan'] = 1; $a['vpn'] = $vpn; if ($web !== null) $a['web_ports'] = $web; $a['ssh_from'] = array_keys($sshFrom) ?: ['lan']; $a['svcs'] = array_keys($sv); $a['custom_ports'] = implode(' ', array_keys($cp));
    $a['fwd'] = array_map(fn($f) => ['name' => $f['name'], 'proto' => $f['proto'], 'eport' => $f['eport'], 'ip' => $f['ip'], 'tport' => $f['tport']], array_values(array_filter($S['fwd'] ?? [], fn($f) => !empty($f['on']))));
    return array_filter($a, fn($v) => $v !== '' && $v !== null);
}
function row_name(array $r): string {
    static $K = ['22' => 'SSH', '53' => 'DNS', '67' => 'DHCP', '68' => 'DHCP', '67,68' => 'DHCP', '80' => 'HTTP', '443' => 'HTTPS', '123' => 'NTP', '5353' => 'mDNS', '51820' => 'WireGuard', '1194' => 'OpenVPN', '139' => 'SMB', '445' => 'SMB', '3389' => 'RDP', '1883' => 'MQTT', '8883' => 'MQTT', '8123' => 'Home Assistant', '32400' => 'Plex', '2049' => 'NFS', '161' => 'SNMP', '1900' => 'SSDP', '5683' => 'CoAP'];
    $sv = []; foreach (explode(',', $r['ports'] ?? '') as $p) if ($p !== '') $sv[$K[$p] ?? $p] = 1;
    $pr = $r['proto'] ?? ''; $w = $sv ? implode('/', array_slice(array_keys($sv), 0, 3)) : ((($r['dst'] ?? '') === '255.255.255.255') ? 'broadcast' : (($r['iif'] ?? '') !== '' ? 'traffico da ' . $r['iif'] : (($r['oif'] ?? '') !== '' ? 'traffico verso ' . $r['oif'] : (($r['ct'] ?? '') !== '' ? 'risposte ' . strtolower($r['ct']) : ($pr !== '' ? 'tutte le porte' : 'tutto il traffico')))));
    return cut40(trim((($r['proto'] ?? '') !== '' ? strtoupper($r['proto']) . ' ' : '') . $w . (($r['src'] ?? '') !== '' ? ' da ' . $r['src'] : '') . (($r['dst'] ?? '') !== '' ? ' verso ' . $r['dst'] : '')));
}
function merge_rows(array $rows): array {   // unisce righe ADIACENTI che differiscono per una sola dimensione (porte o sorgenti): stesso comportamento, meno righe
    $o = []; $n = 0;
    foreach ($rows as $r) {
        $p = $o ? $o[count($o) - 1] : null; $merged = false;
        if ($p && $p['_c'] === $r['_c'] && $p['_n'] + 1 === $r['_n'] && ($p['after'] ?? 0) === ($r['after'] ?? 0)) {
            $same = function ($ks) use ($p, $r) { foreach ($ks as $k) if (($p[$k] ?? '') !== ($r[$k] ?? '')) return false; return true; };
            $plain = fn($v) => $v !== '' && $v[0] !== '!' && $v[0] !== '@';
            if ($same(['iif', 'oif', 'src', 'dst', 'proto', 'ct', 'act']) && in_array($p['proto'], ['tcp', 'udp'], true) && $p['ports'] !== '' && $r['ports'] !== '' && !str_contains($p['ports'] . $r['ports'], ':')) {
                $ports = array_values(array_unique(array_merge(explode(',', $p['ports']), explode(',', $r['ports']))));
                if (count($ports) <= 15) { $o[count($o) - 1]['ports'] = implode(',', $ports); $o[count($o) - 1]['_n'] = $r['_n']; $merged = true; $n++; }
            } elseif ($same(['iif', 'oif', 'dst', 'proto', 'ports', 'ct', 'act']) && $plain($p['src']) && $plain($r['src'])) {
                $o[count($o) - 1]['src'] = implode(',', array_values(array_unique(array_merge(explode(',', $p['src']), explode(',', $r['src']))))); $o[count($o) - 1]['_n'] = $r['_n']; $merged = true; $n++;
            }
        }
        if (!$merged) $o[] = $r;
    }
    $GLOBALS['merged_rows'] = ($GLOBALS['merged_rows'] ?? 0) + $n; return $o;
}

