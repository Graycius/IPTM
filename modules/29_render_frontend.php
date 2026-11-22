<?php
// ===================== RENDER =====================
function iptm_page_description(string $page): string {
    static $descriptions = [
        'status'=>'Stato del firewall, rete e servizi.',
        'stats'=>'Traffico, regole e andamento della rete.',
        'conns'=>'Connessioni attive e azioni disponibili.',
        'devices'=>'Dispositivi riconosciuti e relative policy.',
        'monitor'=>'Controlli del traffico e degli eventi.',
        'zones'=>'Accesso e isolamento dei dispositivi.',
        'topology'=>'Mappa interattiva delle reti e dei dispositivi.',
        'dns'=>'Impostazioni dei resolver DNS locali.',
        'unbound'=>'Configurazione e controlli di Unbound.',
        'piholelists'=>'Liste di blocco e autorizzazioni DNS.',
        'piholehealth'=>'Stato e raggiungibilità di Pi-hole.',
        'dnsaudit'=>'Verifica delle impostazioni di privacy DNS.',
        'dnsguard'=>'Configura DNSCrypt, Unbound e Anti-DPI.',
        'security'=>'Opzioni di protezione del firewall.',
        'rules'=>'Elenco delle regole e relativo ordine.',
        'rule'=>'Aggiungi o modifica una regola.',
        'wizard'=>'Crea una configurazione firewall guidata.',
        'chains'=>'Gestisci le catene del firewall.',
        'access'=>'Permessi di accesso a dispositivi e servizi.',
        'raw'=>'Modifica manuale delle regole in bozza.',
        'setup'=>'Indirizzi, routing e NAT.',
        'forward'=>'Inoltra porte verso i servizi della LAN.',
        'router'=>'Configurazione dei servizi di rete.',
        'vpn'=>'Stato e impostazioni della VPN.',
        'multinic'=>'Gestisci schede, indirizzi, VLAN e DHCP.',
        'v6convert'=>'Converti le regole IPv4 in IPv6.',
        'sqm'=>'Velocità, priorità e calibrazione CAKE.',
        'v6'=>'Regole e filtri IPv6.',
        'crowdsec'=>'Rilevamento e blocco delle minacce.',
        'ips'=>'Controlli del motore Suricata.',
        'lists'=>'Liste degli indirizzi da filtrare.',
        'harden'=>'Parametri di protezione del kernel.',
        'avscan'=>'Strumenti e scansioni antivirus.',
        'traffic'=>'Analisi del traffico cifrato.',
        'operations'=>'Stato dei processi e controlli principali.',
        'deviceinsights'=>'Attività dei dispositivi della rete.',
        'log'=>'Eventi rilevati dal firewall.',
        'diag'=>'Errori, controlli e risultati dei test.',
        'impact'=>'Confronta gli effetti delle regole.',
        'postcheck'=>'Verifica lo stato dopo un’applicazione.',
        'health'=>'Controlla salute e accessibilità del sistema.',
        'apply'=>'Verifica e applica la configurazione.',
        'config'=>'Esporta, importa o ripristina un backup.',
        'update'=>'Installa e verifica gli aggiornamenti.',
        'upgrade-wizard'=>'Configura le funzioni introdotte dagli aggiornamenti, senza attivazione automatica.',
    ];
    return $descriptions[$page]??'Impostazioni e informazioni disponibili.';
}

// Navigation follows the network: uplink -> local segments -> resolution -> policy -> operations.
// Stable ?p= routes and POST action names stay unchanged to preserve bookmarks and forms.
$MENU = [
    'overview' => ['Panoramica', ['status'=>'Stato generale', 'topology'=>'Mappa della rete', 'stats'=>'Statistiche', 'conns'=>'Connessioni', 'monitor'=>'Monitoraggio']],
    'uplink' => ['Connessione e rete', ['multinic'=>'Interfacce e VLAN', 'setup'=>'Indirizzamento e NAT', 'router'=>'Routing e servizi', 'sqm'=>'Qualità del traffico', 'performance'=>'Prestazioni e cache', 'vpn'=>'VPN e tunnel', 'forward'=>'Porte inoltrate', 'v6'=>'IPv6', 'v6convert'=>'Conversione IPv6']],
    'clients' => ['Rete locale', ['devices'=>'Dispositivi', 'zones'=>'Zone e isolamento', 'access'=>'Permessi di accesso', 'deviceinsights'=>'Attività dispositivi', 'apps'=>'Servizi e porte']],
    'dns' => ['DNS e privacy', ['dns'=>'Resolver DNS', 'piholelists'=>'Filtri Pi-hole', 'dnsguard'=>'DNS protetto', 'piholehealth'=>'Salute Pi-hole', 'unbound'=>'Unbound', 'dnsaudit'=>'Audit DNS']],
    'firewall' => ['Protezione', ['security'=>'Firewall', 'rules'=>'Regole', 'rulesaudit'=>'Analizza rules.v4', 'rule'=>'Nuova regola', 'wizard'=>'Procedura guidata', 'chains'=>'Catene', 'crowdsec'=>'CrowdSec', 'ips'=>'Suricata', 'lists'=>'Liste e GeoIP', 'harden'=>'Hardening', 'avscan'=>'Antivirus', 'traffic'=>'Analisi HTTPS', 'attacks'=>'Attacchi', 'raw'=>'Editor regole', 'manual'=>'Conversione manuale']],
    'system' => ['Sistema e strumenti', ['apply'=>'Applica configurazione', 'operations'=>'Operazioni', 'diag'=>'Diagnostica', 'log'=>'Log', 'health'=>'Salute sistema', 'update'=>'Aggiornamenti', 'config'=>'Backup e ripristino', 'postcheck'=>'Controllo dopo apply', 'tracer'=>'Analisi pacchetti', 'impact'=>'Impatto regole', 'advise'=>'Consigli', 'system'=>'Servizi', 'history'=>'Cronologia', 'search'=>'Ricerca avanzata', 'zero'=>'Configurazione iniziale', 'retention'=>'Pulizia', 'import'=>'Importa regole', 'progs'=>'Programmi', 'admin'=>'Utenti', 'upgrade-wizard'=>'Nuove opzioni', 'guide'=>'Guida']]
];
$MENU_PRIMARY = [
    'overview'=>['status','topology','stats'],
    'uplink'=>['multinic','setup','sqm','performance','vpn','forward'],
    'clients'=>['devices','zones','access'],
    'dns'=>['dns','piholelists','dnsguard','piholehealth'],
    'firewall'=>['security','rules','rulesaudit','crowdsec','ips'],
    'system'=>['apply','operations','diag','update','config'],
];
$MENU_LABELS = [
    'multinic'=>'Interfacce, VLAN e DHCP',
    'setup'=>'WAN, LAN e NAT',
    'rules'=>'Regole firewall',
    'dnsguard'=>'DNS, TLS e Anti-DPI',
    'config'=>'Backup, importazione e ripristino',
    'operations'=>'Centro operativo',
];
// These are navigation-only shortcuts. They do not introduce new POST
// actions or alternate versions of existing workflows.
$MENU_WORKFLOWS = [
    'status'=>['multinic','devices','dns','security'],
    'multinic'=>['setup','zones','dns','sqm'],
    'setup'=>['multinic','forward','vpn','apply'],
    'devices'=>['zones','access','dns','topology'],
    'zones'=>['devices','access','rules'],
    'dns'=>['piholelists','dnsguard','piholehealth'],
    'security'=>['rules','crowdsec','ips','apply'],
    'rules'=>['rule','security','apply'],
    'operations'=>['diag','log','health'],
    'zero'=>['multinic','dns','security'],
];
// Search synonyms are for discovery only, not separate actions or routes.
$MENU_ALIASES = [
    'multinic' => 'network fabric dual lan wan bridge bonding vlan switch rete interfacce secondo dhcp',
    'setup' => 'nat interfacce legacy route router lan wan',
    'sqm' => 'cake traffic shaping qos bandwidth upload download speedtest calibrazione velocità',
    'performance'=>'proxy caching squid http performance velocita CDN CDN DNS regole firewall iptables sicurezza',
    'dnsguard' => 'antidpi anti-dpi zapret dnscrypt tls dot doh privacy',
    'dns' => 'pihole pi-hole ftl dhcp dnscrypt unbound',
    'piholelists' => 'adlist whitelist regex rethinkdns importazione',
    'piholehealth' => 'pihole ftl diagnostica salute web 8089',
    'rules' => 'iptables nat firewall catene regole ipv4',
    'rule' => 'nuova regola iptables',
    'ips' => 'suricata intrusion detection ips ids',
    'crowdsec' => 'bouncer firewall log eventi blocchi',
    'vpn' => 'wireguard wg0 openvpn tunnel',
    'update' => 'versione release zip web aggiornamento rollback',
    'config' => 'backup export import ripristino impostazioni',
    'health' => 'iptm guard systemd dietpi servizi salute',
    'diag' => 'errori http 500 timeout log helper',
];
/* Stable in-package line icons: no CDN, no font requests, accessible text stays in links. */
function iptm_svg_icon(string $name): string {
    static $icons = [
        'overview'=>'<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>',
        'network'=>'<rect x="2" y="3" width="20" height="7" rx="2"/><rect x="2" y="14" width="20" height="7" rx="2"/><path d="M6 6.5h.01M6 17.5h.01M10 6.5h8M10 17.5h8"/>',
        'clients'=>'<rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/>',
        'dns'=>'<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a17 17 0 0 1 0 18M12 3a17 17 0 0 0 0 18"/>',
        'shield'=>'<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"/><path d="m9 12 2 2 4-4"/>',
        'settings'=>'<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.8 1.8 0 0 0 .4 2l-2.8 2.8a1.8 1.8 0 0 0-2-.4 1.8 1.8 0 0 0-1 1.7h-4A1.8 1.8 0 0 0 9 19.4a1.8 1.8 0 0 0-2 .4l-2.8-2.8a1.8 1.8 0 0 0 .4-2A1.8 1.8 0 0 0 3 14H2v-4h1a1.8 1.8 0 0 0 1.6-1 1.8 1.8 0 0 0-.4-2L7 4.2a1.8 1.8 0 0 0 2 .4A1.8 1.8 0 0 0 10 3V2h4v1a1.8 1.8 0 0 0 1 1.6 1.8 1.8 0 0 0 2-.4L19.8 7a1.8 1.8 0 0 0-.4 2 1.8 1.8 0 0 0 1.6 1h1v4h-1a1.8 1.8 0 0 0-1.6 1Z"/>',
        'chart'=>'<path d="M3 3v18h18M7 16v-5M12 16V7M17 16V4"/>',
        'search'=>'<circle cx="11" cy="11" r="7"/><path d="m16 16 5 5"/>',
        'connections'=>'<circle cx="6" cy="7" r="3"/><circle cx="18" cy="17" r="3"/><path d="M8.5 9.5 15 15M14 7h7v7"/>',
        'wifi'=>'<path d="M3 9a14 14 0 0 1 18 0M6 12a9 9 0 0 1 12 0M9 15a5 5 0 0 1 6 0"/><circle cx="12" cy="19" r="1"/>',
        'devices'=>'<rect x="4" y="3" width="16" height="18" rx="2"/><path d="M8 7h8M8 12h8M8 17h8"/>',
        'zones'=>'<rect x="3" y="3" width="8" height="8" rx="1"/><rect x="13" y="3" width="8" height="8" rx="1"/><rect x="3" y="13" width="8" height="8" rx="1"/><rect x="13" y="13" width="8" height="8" rx="1"/>',
        'access'=>'<circle cx="9" cy="7" r="4"/><path d="M2 21v-3a7 7 0 0 1 14 0v3M18 7v8m-3-3h6"/>',
        'lock'=>'<rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3M12 15v2"/>',
        'rule'=>'<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>',
        'tools'=>'<path d="M14 4a6 6 0 0 0-6 7l-5 5a3 3 0 0 0 4 4l5-5a6 6 0 0 0 8-8l-4 4-4-4 4-4Z"/>',
        'activity'=>'<path d="M2 12h4l3-8 6 16 3-8h4"/>',
        'check'=>'<path d="m4 12 5 5L20 6"/>',
        'download'=>'<path d="M12 3v13m-5-5 5 5 5-5M4 17v4h16v-4"/>',
        'swap'=>'<path d="M3 7h18m-5-4 5 4-5 4M21 17H3m5-4-5 4 5 4"/>',
        'layers'=>'<path d="m12 2 10 6-10 6L2 8l10-6Zm-10 10 10 6 10-6M2 16l10 6 10-6"/>',
        'pulse'=>'<path d="M3 12h4l3-7 4 14 3-7h4"/>',
        'arrow'=>'<path d="M5 12h14m-6-6 6 6-6 6"/>',
        'circle'=>'<circle cx="12" cy="12" r="9"/>',
    ];
    $path=$icons[$name] ?? $icons['circle'];
    return '<svg class="iptm-svg-icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false">'.$path.'</svg>';
}
$IPTM_NAV_ICONS = [
    'status'=>'overview','topology'=>'network','stats'=>'chart','conns'=>'connections','monitor'=>'activity',
    'multinic'=>'network','setup'=>'connections','router'=>'network','sqm'=>'activity','vpn'=>'lock',
    'forward'=>'arrow','v6'=>'dns','v6convert'=>'swap','devices'=>'clients','zones'=>'zones',
    'access'=>'access','deviceinsights'=>'activity','apps'=>'devices','dns'=>'dns','piholelists'=>'rule',
    'dnsguard'=>'lock','piholehealth'=>'pulse','unbound'=>'dns','dnsaudit'=>'check','security'=>'shield',
    'rules'=>'rule','rule'=>'rule','wizard'=>'tools','chains'=>'layers','crowdsec'=>'shield',
    'ips'=>'shield','apply'=>'check','operations'=>'settings','diag'=>'pulse','update'=>'download',
    'config'=>'download','log'=>'rule','health'=>'pulse','retention'=>'tools','admin'=>'access',
];
$menu_link = static function (string $route, string $label, bool $active=false) use ($MENU_ALIASES, $IPTM_NAV_ICONS): string {
    return '<a class="iptm-nav-link'.($active?' on':'').'" href="?p='.rawurlencode($route).'"'.
           ($active?' aria-current="page"':'').' title="'.h(iptm_page_description($route)).'"'.
           ' data-route="'.h($route).'" data-label="'.h(strtolower($label.' '.($MENU_ALIASES[$route] ?? ''))).'">'.
           '<span class="iptm-nav-icon" aria-hidden="true">'.iptm_svg_icon($IPTM_NAV_ICONS[$route] ?? 'circle').'</span>'.
           '<span>'.h($label).'</span></a>';
};
$pages = []; $pageLabel = 'Dashboard';
foreach ($MENU as $g => [$gl, $sb]) foreach ($sb as $k => $l) {
    $pages[$k] = $g;
    if ($k === ($_GET['p'] ?? 'status')) $pageLabel = $MENU_LABELS[$k] ?? $l;
}
$p = $_GET['p'] ?? 'status'; if (!isset($pages[$p])) { $p = 'status'; $pageLabel = 'Dashboard'; } $grp = $pages[$p];
if ($_SERVER['REQUEST_METHOD'] === 'GET' && !is_file(DATA_DIR . '/settings.json') && !in_array($p, ['import', 'guide', 'zero'], true)) go(trim($draftTxt) !== '' ? 'p=import' : 'p=zero');
$mod = $draftTxt !== rules_live();
if ($_SERVER['REQUEST_METHOD'] === 'GET' && ($_GET['fragment'] ?? '') === $p && in_array($p, ['status','stats','dnsaudit','health','zones','topology','piholehealth'],true)) {
    header('Cache-Control: private, no-store'); header('X-Content-Type-Options: nosniff');
    // The session was released before draft parsing; keep compatibility with
    // clients that reached this route without the earlier fast path.
    if (session_status() === PHP_SESSION_ACTIVE) session_write_close();
    if ($p === 'status') pg_status(); elseif ($p === 'stats') pg_stats(); elseif ($p === 'dnsaudit') pg_dnsaudit(); elseif ($p === 'zones') pg_zones(); elseif ($p === 'topology') pg_topology(); elseif ($p === 'piholehealth') pg_piholehealth(); else pg_health();
    exit;
}
echo '<!doctype html><html lang="it" data-theme="auto"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark"><title>'.h($pageLabel).' · IPTM</title><script>document.documentElement.classList.add("js");</script><link rel="stylesheet" href="?iptm_asset=app.css&amp;v=' . APP_VERSION . '"></head><body class="iptm-console">';
echo '<a class="skip-link" href="#main-content">Vai al contenuto</a><a class="skip-link skip-navigation" href="#primary-menu">Vai alla navigazione</a>';
echo '<header class="top iptm-masthead" role="banner">';
echo '<div class="iptm-masthead-left"><button id="burger" class="s sm nav-toggle iptm-icon-button" type="button" aria-controls="side" aria-expanded="false" aria-label="Apri il menu di navigazione">☰</button>';
echo '<a href="?p=status" class="iptm-logo" aria-label="IPTM · Panoramica"><span class="iptm-logo-glyph" aria-hidden="true">'.iptm_svg_icon('shield').'</span><span class="iptm-logo-word">IPTM<small>NETWORK CONTROL</small></span></a>';
echo '<span class="iptm-version">'.h(APP_VERSION).'</span></div>';
echo '<div class="iptm-masthead-center"><button class="iptm-command-open" type="button" id="iptm-open-search" aria-haspopup="dialog" aria-controls="iptm-command"><span class="iptm-command-icon" aria-hidden="true">'.iptm_svg_icon('search').'</span><span>Cerca…</span><kbd>Ctrl K</kbd></button></div>';
echo '<div class="iptm-masthead-actions">';
echo $mod ? '<a href="?p=apply" class="iptm-config-state iptm-config-pending"><span class="iptm-status-led"></span><span>Da applicare</span></a>' : '<span class="iptm-config-state"><span class="iptm-status-led"></span><span>Salvato</span></span>';
echo '<button id="theme" class="s sm iptm-theme-button iptm-icon-button" type="button" aria-label="Cambia tema" title="Cambia tema">🌗</button>';
echo '<div class="iptm-account" title="Sessione attiva"><span aria-hidden="true">◉</span><span>'.h(me()).(($_SESSION['role']??'')==='viewer'?' · lettura':'').'</span></div>';
echo '<form method="post" class="iptm-logout"><input type="hidden" name="csrf" value="'.h($_SESSION['csrf']).'"><input type="hidden" name="action" value="logout"><button class="s sm iptm-logout-button" aria-label="Esci dall’applicazione">Esci</button></form>';
echo '</div></header>';
echo '<div id="iptm-global-wait" role="status" aria-live="polite" aria-atomic="true" hidden class="iptm-global-wait"><span class="iptm-wait-spinner" aria-hidden="true"></span> Applicazione delle modifiche…</div>';
echo '<div class="layout" id="app-layout"><aside id="side" aria-label="Navigazione principale">';
echo '';
echo '';
echo '<div class="side-search"><label class="sr-only" for="ms">Filtra le pagine</label><span class="iptm-side-search-symbol" aria-hidden="true">⌕</span><input type="search" id="ms" placeholder="Cerca…" autocomplete="off" aria-controls="primary-menu" aria-describedby="msResults"><output id="msResults" class="iptm-nav-results" role="status" aria-live="polite"></output></div>';
echo '<nav class="primary-nav" aria-label="Sezioni di IPTM"><div id="primary-menu" tabindex="-1">';
$GROUP_ICONS = ['overview'=>'overview', 'uplink'=>'network', 'clients'=>'clients', 'dns'=>'dns', 'firewall'=>'shield', 'system'=>'settings'];
foreach ($MENU as $g => [$gl, $sub]) {
    $main = array_flip($MENU_PRIMARY[$g] ?? []);
    echo '<details class="mg mg-'.h($g).'"'.($grp===$g?' open':'').' data-iptm-nav-group="'.h($g).'">';
    echo '<summary class="gt"><span class="iptm-group-icon" aria-hidden="true">'.iptm_svg_icon($GROUP_ICONS[$g]??'circle').'</span><span>'.h($gl).'</span></summary>';
    foreach ($MENU_PRIMARY[$g] ?? [] as $k) if (isset($sub[$k])) echo $menu_link($k, $MENU_LABELS[$k]??$sub[$k], $p===$k);
    foreach (array_diff_key($sub,$main) as $k=>$label) {
      echo '<div class="iptm-nav-extra"'.($p===$k?' data-current="1"':'').'>'.$menu_link($k,$MENU_LABELS[$k]??$label,$p===$k).'</div>';
    }
    echo '</details>';
}
echo '<button type="button" id="iptm-nav-advanced" class="iptm-nav-toggle-extra" aria-controls="primary-menu" aria-expanded="false">Altre funzioni <span aria-hidden="true">+</span></button>';
echo '</div></nav>';
echo '<div class="iptm-sidebar-footer"><a href="?p=guide">? Guida</a><a href="?p=health">♡ Salute sistema</a></div></aside>';
echo '<button type="button" id="navBackdrop" class="nav-backdrop" aria-label="Chiudi navigazione" hidden></button>';
echo '<main id="main-content" class="wrap2" tabindex="-1" aria-label="Contenuto principale">';
echo '<div class="iptm-content-topline"><div class="iptm-page-path"><a href="?p=status">IPTM</a><span aria-hidden="true">/</span><span>'.h($MENU[$grp][0]??'Rete').'</span><span aria-hidden="true">/</span><b>'.h($pageLabel).'</b></div></div>';
// Direct area switching on small screens: one tap, no sidebar expansion required.
$IPTM_AREA_TARGETS=['overview'=>'status','uplink'=>'multinic','clients'=>'devices','dns'=>'dns','firewall'=>'security','system'=>'operations'];
echo '<nav class="iptm-area-nav" aria-label="Aree della rete">';
foreach ($IPTM_AREA_TARGETS as $group=>$route) {
    echo '<a href="?p='.rawurlencode($route).'"'.($grp===$group?' class="active" aria-current="location"':'').'>'.iptm_svg_icon($GROUP_ICONS[$group]).'<span>'.h($MENU[$group][0]).'</span></a>';
}
echo '</nav>';
echo '<div class="iptm-section-heading"><div class="iptm-heading-copy"><h1>'.h($pageLabel).'</h1></div><div class="iptm-heading-actions">';
if ($mod && $p!=='apply') echo '<a class="iptm-apply-shortcut" href="?p=apply">'.iptm_svg_icon('check').' Applica</a>';
echo '<button class="iptm-heading-search" type="button" data-open-command="1" aria-label="Cerca">'.iptm_svg_icon('search').'<span>Cerca</span></button><a class="iptm-help-link" href="?p=guide">Guida <span aria-hidden="true">↗</span></a></div></div>';
echo flashes();
// The authenticated GET has already consumed flash messages. Release its
// session lock before expensive rendering/privileged read-only operations.
// Keep it for pages intentionally staging a session-backed preview.
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'GET'
    && !in_array($p, ['zones','zero','wizard'], true)
    && empty($_SESSION['settings_migrated'])
    && session_status() === PHP_SESSION_ACTIVE) session_write_close();
$rf = DATA_DIR . '/post-update-reset.flag';
if (is_file($rf) && !reset_notice_is_dismissed()) {
    echo '<div class="msg ok" data-iptm-layout="ui-95a2fb7219"><b>Aggiornamento con reset da zero</b><br>'
        . 'Impostazioni e bozza sono state azzerate (backup in <code>data/backups/</code>). '
        . 'Le regole attualmente in kernel non sono cambiate.<br>'
        . 'Prossimo passo: <a href="?p=zero"><b>Wizard da zero</b></a> per ricostruire la configurazione.'
        . '<form method=post style="display:inline;margin-left:12px">' . fh('p=status') . '<input type=hidden name=action value=dismiss_reset_flag><button class="s sm">Nascondi</button></form></div>';
}
if ($pd = pending()) {
    $recover = ($pd['status'] ?? '') === 'recovery_required';
    echo '<div class=banner style="position:sticky;top:0;z-index:50;display:flex;flex-wrap:wrap;gap:8px;align-items:center">';
    if ($recover) echo '<b>⚠ Ripristino firewall necessario.</b> Il watchdog è scaduto o lo stato è incompleto. Non applicare nuove regole finché il recupero non è verificato.';
    else echo '<b>⏳ Regole in prova (anti-lockout).</b> Ripristino tra <b id=cd data-until=' . (int)$pd['until'] . '>…</b> s.';
    if (!$recover && iptm_health_policy_marker_read() === null) echo '<form method=post data-iptm-layout="ui-ab79ea2b85">' . fh('p=apply') . '<input type=hidden name=action value=confirm><button class=g>✔ Conferma e salva</button></form>';
    elseif (!$recover && iptm_health_policy_marker_read() !== null) echo '<a class="btn g" href="?p=health#health-policy">Conferma nella pagina Salute</a>';
    if (iptm_health_policy_marker_read() === null) echo '<form method=post data-iptm-layout="ui-ab79ea2b85">' . fh('p=apply') . '<input type=hidden name=action value=revert><button class=d>↩ Ripristina regole precedenti</button></form>';
    else echo '<a class="btn d" href="?p=health#health-policy">Ripristina da Salute</a>';
    echo '</div>';
}
// Contextual workflow shortcuts keep related operations in one place without
// duplicating the full sidebar or changing legacy deep links.
// Every view has relevant cross-page operations. Read-only navigation
// reuses the canonical route registry, never duplicates privileged POST logic.
$IPTM_GROUP_RELATED = [
    'overview'=>['multinic','devices','diag'],
    'dns'=>['piholehealth','dnsaudit','multinic','diag'],
    'uplink'=>['multinic','sqm','diag'],
    'clients'=>['devices','zones','access'],
    'firewall'=>['security','rules','apply'],
    'system'=>['health','config','update','retention'],
];
$IPTM_RELATED = $MENU_WORKFLOWS[$p] ?? $IPTM_GROUP_RELATED[$grp] ?? ['status','diag'];
$IPTM_RELATED = array_values(array_unique(array_filter($IPTM_RELATED,
    static fn($target)=>$target!==$p && isset($pages[$target]))));
if ($p !== 'status' && $IPTM_RELATED) {
    echo '<nav class="iptm-workflows" aria-label="Funzioni correlate">';
    foreach (array_slice($IPTM_RELATED,0,3) as $target) {
        $label = $MENU_LABELS[$target] ?? ($MENU[$pages[$target]][1][$target] ?? $target);
        echo '<a href="?p='.rawurlencode($target).'">'.h($label).'</a>';
    }
    echo '</nav>';
}
echo '<section class="iptm-page-body iptm-view-' . h($p) . '" id="iptm-page-body" aria-label="Funzioni ' . h($pageLabel) . '">';
// Explicit registry keeps legacy ?p= routes stable while consolidating dispatch.
// Only listed handlers are callable; request parameters never become PHP callables.
$IPTM_PAGE_HANDLERS = [
    'manual' => 'pg_manual',
    'update' => 'iptm_page_update',
    'upgrade-wizard' => 'pg_upgrade_wizard',
    'status' => 'pg_status',
    'zones' => 'pg_zones', 'topology' => 'pg_topology',
    'config' => 'pg_config', 'retention' => 'pg_retention',
    'stats' => 'pg_stats',
    'search' => 'pg_search',
    'postcheck' => 'pg_postcheck',
    'impact' => 'pg_impact',
    'operations' => 'pg_security_operations',
    'deviceinsights' => 'pg_device_insights',
    'attacks' => 'pg_attacks',
    'log' => 'pg_log', 'diag' => 'pg_diag',
    'setup' => 'pg_setup',
    'dns' => 'pg_dns', 'dnsguard' => 'pg_dns_guard', 'unbound' => 'pg_unbound_hardening',
    'piholelists' => 'pg_pihole_lists',
    'security' => 'pg_security',
    'crowdsec' => 'pg_crowdsec',
    'forward' => 'pg_forward',
    'access' => 'pg_access',
    'admin' => 'pg_admin',
    'router' => 'pg_router',
    'import' => 'pg_import',
    'conns' => 'pg_conns',
    'devices' => 'pg_devices',
    'ips' => 'pg_ips',
    'history' => 'pg_history',
    'tracer' => 'pg_tracer',
    'lists' => 'pg_lists',
    'sqm' => 'pg_sqm', 'performance' => 'pg_performance',
    'v6' => 'pg_v6', 'v6convert' => 'pg_v6convert',
    'zero' => 'pg_zero',
    'safeplan' => 'pg_safeplan',
    'harden' => 'pg_harden',
    'advise' => 'pg_advise',
    'system' => 'pg_system',
    'progs' => 'pg_progs',
    'apps' => 'pg_apps',
    'vpn' => 'pg_vpn',
    'multinic' => 'pg_multinic',
    'monitor' => 'pg_monitor',
    'avscan' => 'pg_avscan',
    'traffic' => 'pg_traffic',
    'rule' => 'pg_rule',
    'wizard' => 'pg_wizard',
    'chains' => 'pg_chains',
    'raw' => 'pg_raw',
    'apply' => 'pg_apply',
    'guide' => 'pg_guide',
    'rules' => 'pg_rules',
    'rulesaudit' => 'pg_rulesaudit',
];
$IPTM_ASYNC_PAGES = [
    'dnsaudit' => 'Analisi DNS in corso…',
    'piholehealth' => 'Verifica Pi-hole in corso…',
    'health' => 'Verifica DietPi/Lynis in corso…',
];
if (isset($IPTM_ASYNC_PAGES[$p])) {
    echo '<div data-iptm-fragment="' . h($p) . '" role="status">' . h($IPTM_ASYNC_PAGES[$p]) . '</div>';
} else {
    $handler = $IPTM_PAGE_HANDLERS[$p] ?? 'pg_status';
    $handler();
}
echo '</section></main></div><dialog id="iptm-command" class="iptm-command" aria-label="Ricerca rapida"><div class="iptm-command-top"><span aria-hidden="true">⌕</span><input id="iptm-command-input" type="search" autocomplete="off" placeholder="Cerca funzione o pagina…" aria-label="Cerca"><button type="button" id="iptm-command-close" class="iptm-icon-button" aria-label="Chiudi ricerca">✕</button></div><div class="iptm-command-caption">Seleziona una funzione per aprirla direttamente</div><div id="iptm-command-results" class="iptm-command-results" role="listbox" aria-label="Risultati ricerca"></div><div class="iptm-command-bottom"><span>↑ ↓ naviga</span><span>Invio apri</span><span>Esc chiudi</span></div></dialog><script>window.MODEL=' . (in_array($p, ['rules','rule','chains','wizard','raw','tracer','search','apply'], true) ? model_json() : '{}') . ';window.FH=' . json_encode(fh('p=rules'), JSON_HEX_TAG | JSON_HEX_AMP) . ';</script><script src="?iptm_asset=firewall.js&amp;v=' . APP_VERSION . '"></script><script src="?iptm_asset=rules.js&amp;v=' . APP_VERSION . '"></script><script src="?iptm_asset=wizard.js&amp;v=' . APP_VERSION . '"></script><script src="?iptm_asset=forms.js&amp;v=' . APP_VERSION . '"></script><script src="?iptm_asset=interface.js&amp;v=' . APP_VERSION . '"></script><script src="?iptm_asset=diagnostics.js&amp;v=' . APP_VERSION . '"></script><script src="?iptm_asset=domains.js&amp;v=' . APP_VERSION . '"></script><script src="?iptm_asset=topology.js&amp;v=' . APP_VERSION . '"></script><script src="?iptm_asset=charts.js&amp;v=' . APP_VERSION . '"></script><script src="?iptm_asset=console.js&amp;v=' . APP_VERSION . '"></script><script src="?iptm_asset=networkui.js&amp;v=' . APP_VERSION . '"></script><script src="?iptm_asset=preferences.js&amp;v=' . APP_VERSION . '"></script></body></html>';
