<?php
/**
 * iptables Manager - gestione guidata di /etc/iptables/rules.v4 (file unico).
 * Distribuzione modulare nativa: moduli della release in sola lettura.
 * Aggiornare tramite archivio Native Update verificato.
 */

// ===================== CONFIGURAZIONE =====================
// Valori predefiniti. Per personalizzarli SENZA perderli negli aggiornamenti crea /etc/iptables-manager.web.json, es.:
//   {"ALLOWED_NETS":["192.168.1.0/24"],"ROLLBACK_SECS":120,"IDLE_SECS":3600}
// (gli aggiornamenti sostituiscono questo file PHP ma non toccano quello JSON; i valori già modificati qui vengono migrati in automatico)
const WEB_CONF = '/etc/iptables-manager.web.json';
$__wc=[];
if (file_exists(WEB_CONF)||is_link(WEB_CONF)) {
    $__raw=is_file(WEB_CONF)&&!is_link(WEB_CONF)?@file_get_contents(WEB_CONF,false,null,0,65537):false;
    if(!is_string($__raw)||strlen($__raw)>65536||!(json_decode($__raw) instanceof stdClass)){http_response_code(503);exit('IPTM: configurazione web non valida o non leggibile. Verificare da console.');}
    $__wc=json_decode($__raw,true);unset($__raw);
}
$__wp = fn(string $k, string $d): string => (isset($__wc[$k]) && is_string($__wc[$k]) && preg_match('~^/[A-Za-z0-9._/-]{1,200}$~D', $__wc[$k])) ? $__wc[$k] : $d;
$__wi = fn(string $k, int $d, int $lo, int $hi): int => (isset($__wc[$k]) && is_int($__wc[$k]) && $__wc[$k] >= $lo && $__wc[$k] <= $hi) ? $__wc[$k] : $d;
define('RULES_FILE', $__wp('RULES_FILE', '/etc/iptables/rules.v4'));
define('DATA_DIR', $__wp('DATA_DIR', '/var/lib/iptables-manager'));   // fuori dalla web-root: mkdir + chown utente-web
define('ALLOWED_NETS', (isset($__wc['ALLOWED_NETS']) && is_array($__wc['ALLOWED_NETS']) && $__wc['ALLOWED_NETS'] && !array_filter($__wc['ALLOWED_NETS'], fn($n) =>
    !is_string($n)
    || !preg_match('~^(?:\d{1,3}\.){3}\d{1,3}/(?:0|[1-9]|[12][0-9]|3[0-2])$~D', $n)
    || filter_var(substr($n, 0, strrpos($n, '/')), FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false))
    ? array_values($__wc['ALLOWED_NETS']) : (array_key_exists('ALLOWED_NETS',$__wc)?['127.0.0.0/8']:['127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']));   // predefinito: solo reti private; CIDR IPv4 validi
// Configurable IPv6 management scopes. If ALLOWED_NETS is explicitly
// restricted to specific IPv4 networks, default IPv6 access becomes loopback
// only. Add ALLOWED_NETS6 explicitly to authorize private IPv6 clients.
$__v6 = ['::1/128'];
if (!array_key_exists('ALLOWED_NETS', $__wc)) $__v6 = ['::1/128','fc00::/7','fe80::/10'];
if (isset($__wc['ALLOWED_NETS6']) && is_array($__wc['ALLOWED_NETS6'])) {
    $__provided = $__wc['ALLOWED_NETS6'];
    $__valid = count($__provided) <= 64;
    foreach ($__provided as $__net) {
        if (!is_string($__net) || !preg_match('~^([^/]+)/([0-9]{1,3})$~D', $__net, $__match)
            || filter_var($__match[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) === false
            || (int)$__match[2] > 128) { $__valid = false; break; }
    }
    // Invalid configuration cannot expand privileges by falling back to ULA.
    $__v6 = $__valid ? array_values($__provided) : ['::1/128'];
}
define('ALLOWED_NETS6', $__v6);
unset($__v6, $__provided, $__valid, $__net, $__match);
define('ROLLBACK_SECS', $__wi('ROLLBACK_SECS', 60, 10, 3600));      // secondi per confermare dopo "Applica"
define('MIN_PW', $__wi('MIN_PW', 10, 8, 128));
define('IDLE_SECS', $__wi('IDLE_SECS', 1800, 60, 86400));           // scadenza della sessione per inattivita'
const APP_VERSION = '6.0.9';
const APP_BUILD = '20261126.2.iptm-6.0.9';
const SETTINGS_SCHEMA = 46;   // versione schema settings.json (migrazioni in S_load)
define('HELPER', $__wp('HELPER', '/usr/local/sbin/iptm-helper'));   // creato da install-dietpi.sh (operazioni root)
define('BIN_IP', $__wp('BIN_IP', '/usr/sbin/ip'));
define('BIN_SUDO', $__wp('BIN_SUDO', '/usr/bin/sudo'));
unset($__wc, $__wp, $__wi);
// CrowdSec firewall bouncer (modo iptables, >= 0.0.34): set ipset NUMERATI, uno per origine della decisione
//   IPv4: crowdsec-blacklists-0 .. -N     IPv6: crowdsec6-blacklists-0 .. -N     catena: CROWDSEC_CHAIN (+ CROWDSEC_LOG)
// Il nome semplice «crowdsec-blacklists» NON esiste piu'. In modo nftables i set hanno il nome dell'origine (-CAPI, -crowdsec, -cscli).
const CS_V4 = 'crowdsec-blacklists'; const CS_V6 = 'crowdsec6-blacklists'; const CS_CHAIN = 'CROWDSEC_CHAIN'; const CS_NSETS = 4;
const SVC = ['web' => ['Web (HTTP/HTTPS)', 'tcp:80,443'], 'dns' => ['DNS', 'tcp,udp:53'], 'ssh' => ['SSH', 'tcp:22'], 'ftp' => ['FTP', 'tcp:20,21'],
    'mail' => ['Posta (SMTP/POP3/IMAP)', 'tcp:25,110,143,465,587,993,995'], 'telnet' => ['Telnet', 'tcp:23'], 'rdp' => ['Desktop remoto (RDP)', 'tcp,udp:3389'],
    'p2p' => ['BitTorrent (porte comuni)', 'tcp,udp:6881:6999'], 'ntp' => ['NTP', 'udp:123'], 'vpn' => ['VPN (OpenVPN/WireGuard/IPsec)', 'udp:1194,51820,500,4500'], 'all' => ['TUTTO il traffico', '']];
const DAYS = ['Mon' => 'Lun', 'Tue' => 'Mar', 'Wed' => 'Mer', 'Thu' => 'Gio', 'Fri' => 'Ven', 'Sat' => 'Sab', 'Sun' => 'Dom'];
const SEC_FIELDS = [
    'setup' => ['wan_if' => 'if', 'lan_if' => 'if', 'wan_rfc1918_spoof' => 'b', 'external_ifs' => 'ifs', 'lan_ingress_map' => 'lanmap', 'single_nic' => 'b', 'lan_nets' => 'nets', 'masq_ifs' => 'ifs', 'drop_chain' => 'chain', 'nat_masq' => 'b', 'mss' => 'b', 'dns_redirect' => 'b', 'dns_ip' => 'ip', 'dot_block' => 'b'],
    'security' => ['continuity_priority' => 'b', 'spi' => 'b', 'antispoof' => 'b', 'antispoof_mc' => 'b', 'spoof_on' => 'b', 'spoof_if' => 'if', 'spoof_nets' => 'nets', 'invalid' => 'b', 'blockping' => 'b', 'ident' => 'b', 'multicast' => 'b',
        'crowdsec' => 'b', 'cs_docker' => 'b', 'conn_limit' => 'b', 'cl_max' => 'n:1:100000', 'rpfilter' => 'b', 'bw_on' => 'b', 'bw_up' => 'n:1:10000000', 'bw_down' => 'n:1:10000000', 'mac_only' => 'b', 'mac_allow' => 'macs', 'alg_ftp' => 'b', 'alg_tftp' => 'b', 'alg_sip' => 'b', 'iso_on' => 'b', 'iso_nets' => 'nets', 'guest_on' => 'b', 'guest_nets' => 'nets', 'guest_ports' => 'ports', 'guest_allow' => 'nets', 'mac_block' => 'macs', 'quic_block' => 'b', 'lan_cl' => 'b', 'lan_cl_max' => 'n:10:1000000', 'svc_ban' => 'b', 'sb_ports' => 'ports', 'sb_hits' => 'n:1:20', 'sb_secs' => 'n:1:3600', 'sb_ban' => 'n:60:86400', 'ui_nets' => 'nets', 'bad_mss' => 'b', 'udp_rl' => 'b', 'ul_rate' => 'n:1:100000', 'ul_burst' => 'n:1:100000', 'web_rl' => 'b', 'wl_rate' => 'n:1:100000', 'wl_burst' => 'n:1:100000', 'wl_ports' => 'ports', 'amp_block' => 'b', 'bl_log' => 'b',
        'icmp_limit' => 'b', 'icmp_echo_rate' => 'rate', 'icmp_echo_burst' => 'n:1:100000', 'icmp_other_rate' => 'rate', 'icmp_other_burst' => 'n:1:100000', 'igmp_accept' => 'b', 'lan_tcp_accept' => 'b', 'docker_accept' => 'b', 'docker_nets' => 'nets', 'bcast_accept' => 'b', 'dhcp_accept' => 'b', 'coap_accept' => 'b', 'lan_out_fwd' => 'b', 'cs_set_match' => 'b',
        'dos' => 'b', 'dos_syn' => 'n:1:100000', 'dos_burst' => 'n:1:100000', 'ssh_acc' => 'b', 'ssh_nets' => 'nets', 'ssh_acc_port' => 'port', 'ssh_conn' => 'n:1:1000', 'ssh_hits' => 'n:1:20', 'ssh_secs' => 'n:1:3600', 'ssh_name' => 'setname',
        'ssh_limit' => 'b', 'ssh_port' => 'port', 'telnet_limit' => 'b', 'telnet_port' => 'port', 'lim_hits' => 'n:1:20', 'lim_secs' => 'n:1:3600',
        'closeports' => 'b', 'close_range' => 'ports', 'final_drop' => 'b', 'logdrop_on' => 'b', 'ld_src_rate' => 'rate', 'ld_src_burst' => 'n:1:100000', 'ld_glob_rate' => 'lrate', 'ld_glob_burst' => 'n:1:10000', 'ld_prefix' => 'prefix',
        'raw_lo' => 'b', 'raw_drop' => 'b', 'raw_tcp' => 'ports', 'raw_udp' => 'ports', 'log_in' => 'b', 'log_out' => 'b', 'log_drop' => 'b', 'log_rate' => 'lrate',
        'knock_on' => 'b', 'knock_ports' => 'ports', 'knock_target' => 'port', 'knock_secs' => 'n:5:3600', 'knock_nets' => 'nets',
        'lockout_on' => 'b', 'mgmt_nets' => 'nets', 'mgmt_ports' => 'ports', 'drop_frag' => 'b', 'portscan' => 'b', 'ps_hits' => 'n:5:50', 'ps_secs' => 'n:10:600', 'ps_ban' => 'n:60:86400', 'bogon_wan' => 'b', 'lan_flood' => 'b', 'lf_rate' => 'n:1:100000', 'lf_burst' => 'n:1:100000', 'egress_smtp' => 'b', 'egress_allow' => 'nets', 'egress_ports' => 'ports',
        'stealth' => 'b', 'synproxy' => 'b', 'sp_ports' => 'ports', 'tarpit' => 'b', 'dns_rebind' => 'b', 'raw_invalid' => 'b', 'arp_protect' => 'b', 'tcp_fastopen_off' => 'b', 'glob_new_limit' => 'b', 'gn_rate' => 'n:1:100000', 'gn_burst' => 'n:1:100000'],
    'forward' => ['loopback' => 'b', 'dmz_on' => 'b', 'dmz_ip' => 'ip', 'dmz_excl' => 'ports'],
    'access' => [], 'fwdtable' => [], 'router' => [],
    'vpn' => ['wg_on' => 'b', 'wg_port' => 'port', 'wg_if' => 'if', 'wg_input' => 'b', 'wg_lan' => 'b', 'wg_internet' => 'b', 'wg_lan_to_vpn' => 'b', 'wg_local_tcp' => 'ports', 'wg_local_udp' => 'ports', 'wg_net' => 'nets', 'wg_fwd_nets' => 'nets', 'wg_fwd_tcp' => 'ports', 'wg_fwd_udp' => 'ports'],
];
const BUILTIN = ['filter' => ['INPUT', 'FORWARD', 'OUTPUT'], 'nat' => ['PREROUTING', 'INPUT', 'OUTPUT', 'POSTROUTING'],
    'mangle' => ['PREROUTING', 'INPUT', 'FORWARD', 'OUTPUT', 'POSTROUTING'], 'raw' => ['PREROUTING', 'OUTPUT'],
    'security' => ['INPUT', 'FORWARD', 'OUTPUT']];

