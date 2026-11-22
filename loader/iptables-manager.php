<?php
// APP_VERSION = '5.20.25';
// Physical modules: no executable code in a web-writable directory.
define('IPTM_RELEASE_DIR', '/usr/local/lib/iptables-manager/web/releases/5.20.25');
// Small, public, version-pinned static resource endpoint. It reads ONLY known
// CSS/JS files shipped in the root-owned, immutable native release directory.
// No session, helper, network probe or config is needed to serve UI resources.
if (isset($_GET['iptm_asset'])) {
  $name = $_GET['iptm_asset'];
  $allowed = ['app.css','firewall.js','rules.js','wizard.js','forms.js',
    'interface.js','diagnostics.js','domains.js','topology.js',
    'console.js','networkui.js','preferences.js','charts.js'];
  if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'GET' && ($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'HEAD') {
    header('Allow: GET, HEAD'); http_response_code(405); exit;
  }
  if (!is_string($name) || !in_array($name, $allowed, true)) {
    http_response_code(404); header('Cache-Control: no-store'); exit;
  }
  $file = IPTM_RELEASE_DIR . '/assets/' . $name;
  if (!is_file($file) || is_link($file) || !is_readable($file)) {
    http_response_code(503); header('Cache-Control: no-store'); exit;
  }
  $mime = str_ends_with($name, '.css') ? 'text/css' : 'text/javascript';
  $size = filesize($file);
  if (!is_int($size) || $size < 1 || $size > 1048576) {
    http_response_code(503); header('Cache-Control: no-store'); exit;
  }
  $etag = '"iptm-5.20.25-' . $name . '-' . $size . '"';
  header('Content-Type: ' . $mime . '; charset=utf-8');
  header('X-Content-Type-Options: nosniff');
  header('Cross-Origin-Resource-Policy: same-origin');
  header('Referrer-Policy: no-referrer');
  header("Content-Security-Policy: default-src 'none'; frame-ancestors 'none'");
  header('Cache-Control: public, max-age=31536000, immutable');
  header('ETag: ' . $etag);
  if (trim((string)($_SERVER['HTTP_IF_NONE_MATCH'] ?? '')) === $etag) {
    http_response_code(304); exit;
  }
  header('Content-Length: ' . $size);
  if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'HEAD') readfile($file);
  exit;
}
$iptm_modules=['modules/00_bootstrap.php', 'modules/01_core_utilities.php', 'modules/02_rule_model.php', 'modules/03_rule_generation.php', 'modules/04_system_probes.php', 'modules/05_rule_import.php', 'modules/06_manual_rules.php', 'modules/07_identity_audit.php', 'modules/08_alias_ipsets.php', 'modules/09_packet_tracer.php', 'modules/10_net_devices_ips.php', 'modules/11_firewall_transaction.php', 'modules/12_policy_analysis.php', 'modules/13_runtime_diagnostics.php', 'modules/14_system_advice.php', 'modules/15_apps_services.php', 'modules/38_visual_engine.php', 'modules/16_statistics.php', 'modules/17_common_ui_ops.php', 'modules/18_integrations.php', 'modules/19_http_boot_auth.php', 'modules/20_download_backup.php', 'modules/21_application_state.php', 'modules/30_features_core.php', 'modules/23_firewall_pages.php', 'modules/24_network_pages.php', 'modules/25_antivirus_pages.php', 'modules/26_health_dns_qos_pages.php', 'modules/27_more_system_pages.php', 'modules/28_system_monitoring.php', 'modules/31_features_pages.php', 'modules/32_diagnostics_pages.php', 'modules/33_dns_wizard.php', 'modules/34_qos_pages.php', 'modules/35_iot_zones_pages.php', 'modules/36_health_pages.php', 'modules/37_topology_page.php', 'modules/39_retention_pages.php', 'modules/40_multinic_pages.php', 'modules/22_actions_controller.php', 'modules/29_render_frontend.php'];
foreach ($iptm_modules as $iptm_module) {
  $iptm_file = IPTM_RELEASE_DIR . '/' . $iptm_module;
  if (!is_file($iptm_file) || !is_readable($iptm_file)) {
    http_response_code(503); header('Content-Type: text/plain; charset=utf-8');
    exit('IPTM: moduli non installati. Eseguire sudo /usr/local/sbin/iptm-helper modules-deploy.');
  }
  require $iptm_file;
}
