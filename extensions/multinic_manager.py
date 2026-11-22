#!/usr/bin/env python3
"""IPTM multi-NIC planner, release 4.9.0.

Read-only device inventory and root-only draft persistence. There is deliberately
NO runtime network-manager migration or iproute/iptables mutation from HTTP:
those require a separately audited, watchdog-protected console transaction.
"""
from __future__ import annotations

import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fabric_manager import FabricError, validate_fabric, plan_fabric
from traffic_fabric import propose as propose_traffic

VERSION = '5.30.2'
CONFIG_DIR = Path('/etc/iptables-manager')
PROFILE_PATH = CONFIG_DIR / 'multinic-draft.json'
IF_RX = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,14}$')
ROLES = {'wan', 'lan', 'iot', 'guest', 'management', 'vpn-underlay', 'spare'}
BACKENDS = {'dietpi', 'networkmanager'}
STRATEGIES = {'single', 'failover', 'balanced'}
MAX_NICS = 16
MAX_INPUT = 65536


class ValidationError(ValueError):
    pass


def read_str(path: Path, default: str = '') -> str:
    try:
        return path.read_text(encoding='utf-8', errors='replace').strip()[:240]
    except (OSError, UnicodeError):
        return default


def command(argv: list[str], timeout: float = 2.0) -> str:
    if not shutil.which(argv[0]):
        return ''
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
        return r.stdout[:65536] if r.returncode == 0 else ''
    except (OSError, subprocess.TimeoutExpired):
        return ''


def json_command(argv: list[str], fallback: Any) -> Any:
    try:
        obj = json.loads(command(argv))
        return obj if isinstance(obj, type(fallback)) else fallback
    except (ValueError, TypeError):
        return fallback


def service_state(name: str) -> dict:
    active = command(['systemctl', 'is-active', name]).strip()
    enabled = command(['systemctl', 'is-enabled', name]).strip()
    return {'active': active == 'active', 'enabled': enabled == 'enabled'}


def inventory(*, sys_base: Path = Path('/sys/class/net'), data: dict | None = None) -> dict:
    """Inventory physical and logical interfaces, current routes and manager ownership.

    `data` is an injectable fixture for tests, never read from external HTTP.
    """
    data = data or {}
    links = data.get('links', json_command(['ip', '-j', 'link', 'show'], []))
    addresses = data.get('addresses', json_command(['ip', '-j', '-4', 'addr', 'show'], []))
    routes = data.get('routes', json_command(['ip', '-j', '-4', 'route', 'show', 'table', 'main'], []))
    addr_by_name = {x.get('ifname'): x for x in addresses if isinstance(x, dict)}
    list_by_name = {x.get('ifname'): x for x in links if isinstance(x, dict)}
    interfaces = []
    names = set(list_by_name)
    try:
        names.update(p.name for p in sys_base.iterdir())
    except OSError:
        pass
    for name in sorted(n for n in names if isinstance(n, str) and IF_RX.fullmatch(n) and n != 'lo'):
        d = list_by_name.get(name) or {}
        p = sys_base / name
        physical = (p / 'device').exists() or (p / 'device').is_symlink()
        # A fixture without a sysfs device uses explicit metadata: no guessed physical NICs.
        if 'physical' in d:
            physical = d['physical'] is True
        infos = addr_by_name.get(name, {}).get('addr_info') or []
        addrs = [f"{x['local']}/{x.get('prefixlen', 32)}" for x in infos
                 if isinstance(x, dict) and x.get('family') == 'inet' and isinstance(x.get('local'), str)]
        stats = d.get('stats64') or d.get('stats') or {}
        entry = {'name': name, 'physical': physical, 'kind': (d.get('linkinfo') or {}).get('info_kind') or ('ethernet' if physical else 'virtual'),
                 'state': d.get('operstate') or read_str(p / 'operstate', '?'),
                 'mtu': d.get('mtu'), 'master': d.get('master') or ((p/'master').resolve().name if (p/'master').exists() else ''), 'mac': read_str(p / 'address'),
                 'carrier': read_str(p / 'carrier', '?'), 'speed_mbps': 0,
                 'ipv4': addrs[:12],
                 'rx_bytes': int((stats.get('rx') or {}).get('bytes', 0)),
                 'tx_bytes': int((stats.get('tx') or {}).get('bytes', 0)),
                 'rx_errors': int((stats.get('rx') or {}).get('errors', 0)),
                 'tx_errors': int((stats.get('tx') or {}).get('errors', 0))}
        try:
            speed = int(read_str(p / 'speed', '0'))
            if 0 < speed <= 1000000:
                entry['speed_mbps'] = speed
        except ValueError:
            pass
        interfaces.append(entry)
    defaults = []
    for row in routes:
        if isinstance(row, dict) and row.get('dst') == 'default':
            defaults.append({'dev': row.get('dev', ''), 'gateway': row.get('gateway', ''),
                             'metric': row.get('metric', 0), 'protocol': row.get('protocol', '')})
    if 'managers' in data:
        managers = data['managers']
    else:
        managers = {
            'networkmanager': {'installed': bool(shutil.which('nmcli')), **service_state('NetworkManager')},
            'systemd-networkd': service_state('systemd-networkd'),
            'ifupdown': {'installed': Path('/etc/network/interfaces').exists() or bool(shutil.which('ifup'))},
            'dietpi-network': {'installed': bool(shutil.which('dietpi-network'))},
            'dietpi': Path('/boot/dietpi').exists() or Path('/boot/dietpi.txt').exists(),
        }
    warnings = []
    if managers.get('networkmanager', {}).get('active') and managers.get('ifupdown', {}).get('installed'):
        warnings.append('NetworkManager e configurazioni ifupdown presenti: verificare il proprietario di ogni NIC prima di cambiare gestore.')
    if managers.get('systemd-networkd', {}).get('active') and managers.get('networkmanager', {}).get('active'):
        warnings.append('NetworkManager e systemd-networkd attivi: rischio configurazioni concorrenti.')
    if len([x for x in interfaces if x['physical']]) < 2:
        warnings.append('Modalità monointerfaccia compatibile: nessuna seconda NIC necessaria per aggiornare IPTM. Funzioni di bilanciamento, doppio DHCP e bonding richiedono interfacce aggiuntive.')
    return {'version': VERSION, 'interfaces': interfaces[:64], 'default_routes': defaults[:16],
            'managers': managers, 'warnings': warnings, 'observation_only': True}


def _integer(value: Any, label: str, lo: int, hi: int) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, str)) or not str(value).isdigit():
        raise ValidationError(f'{label}: numero intero richiesto')
    n = int(value)
    if not lo <= n <= hi:
        raise ValidationError(f'{label}: fuori intervallo ({lo}-{hi})')
    return n


def _ipv4_address(value: str, label: str) -> str:
    try:
        addr = ipaddress.ip_address(value)
        if addr.version != 4 or addr.is_multicast or addr.is_unspecified or addr.is_loopback:
            raise ValueError()
        return str(addr)
    except ValueError as e:
        raise ValidationError(f'{label}: IPv4 non valido') from e


def validate(profile: Any, live: dict) -> dict:
    if not isinstance(profile, dict) or set(profile) - {'backend', 'strategy', 'nics', 'fabric'}:
        raise ValidationError('Schema piano multi-NIC non riconosciuto')
    backend = profile.get('backend')
    strategy = profile.get('strategy')
    if backend not in BACKENDS or strategy not in STRATEGIES:
        raise ValidationError('Backend o strategia non validi')
    nics = profile.get('nics')
    if not isinstance(nics, list) or len(nics) < 1 or len(nics) > MAX_NICS:
        raise ValidationError('Occorrono tra 1 e 16 NIC con ruolo assegnato')
    if len(nics) == 1 and strategy != 'single':
        raise ValidationError('Una sola NIC richiede strategia WAN singola: failover e bilanciamento non disponibili')
    physical = {x['name']: x for x in live.get('interfaces', []) if x.get('physical') is True}
    all_nics = {x['name']: x for x in live.get('interfaces', [])}
    eligible = {**physical, **{n:x for n,x in all_nics.items() if x.get('kind') in ('bond','bridge') and (x.get('ipv4') or n in {r.get('dev') for r in live.get('default_routes', [])})}}
    chosen = []
    names = set()
    networks = []
    for row in nics:
        if not isinstance(row, dict) or set(row) - {'name', 'role', 'address', 'gateway', 'capacity_mbps', 'priority', 'dhcp', 'alias_address'}:
            raise ValidationError('Campo NIC non riconosciuto')
        name, role = row.get('name'), row.get('role')
        if not isinstance(name, str) or not IF_RX.fullmatch(name) or name not in all_nics:
            raise ValidationError('Interfaccia inesistente o nome non valido')
        if name not in eligible:
            raise ValidationError(f'{name}: non è una NIC fisica o un bond/bridge L3 esistente')
        if name in names or role not in ROLES:
            raise ValidationError(f'{name}: ruolo non valido o duplicazione')
        names.add(name)
        address = row.get('address', '')
        gateway = row.get('gateway', '')
        if not isinstance(address, str) or not isinstance(gateway, str):
            raise ValidationError(f'{name}: indirizzo o gateway non validi')
        address, gateway = address.strip(), gateway.strip()
        alias = row.get('alias_address', '')
        if not isinstance(alias, str) or len(alias) > 32:
            raise ValidationError(f'{name}: alias IPv4 non valido')
        alias = alias.strip()
        dhcp = row.get('dhcp') is True
        if dhcp and (address or gateway):
            raise ValidationError(f'{name}: DHCP non compatibile con IPv4/gateway manuale')
        if role != 'wan' and gateway:
            raise ValidationError(f'{name}: il gateway predefinito è consentito solo alle WAN')
        if role == 'wan' and not dhcp and (not address or not gateway):
            raise ValidationError(f'{name}: WAN statica richiede indirizzo CIDR e gateway')
        if not dhcp and not address and role not in {'spare', 'vpn-underlay'}:
            # L3 can belong to a bridge/VLAN; the validated fabric must supply
            # an IPv4 on that L2 parent, never on a bridged slave port.
            fabric_raw = profile.get('fabric', {})
            bridge_defs = fabric_raw.get('bridges', []) if isinstance(fabric_raw, dict) else []
            vlan_defs = fabric_raw.get('vlans', []) if isinstance(fabric_raw, dict) else []
            bridge_l3 = any(isinstance(b, dict) and name in b.get('ports', [])
                            and b.get('zone', 'lan') == role and b.get('address') for b in bridge_defs)
            vlan_l3 = any(isinstance(v, dict) and v.get('parent') == name
                          and v.get('zone') == role and v.get('address') for v in vlan_defs)
            if not bridge_l3 and not vlan_l3:
                raise ValidationError(f'{name}: configurare IPv4/DHCP su NIC o su bridge/VLAN')
        if address:
            try:
                iface = ipaddress.ip_interface(address)
                if iface.version != 4 or iface.ip.is_loopback or iface.ip.is_multicast or iface.ip.is_unspecified:
                    raise ValueError()
            except ValueError as e:
                raise ValidationError(f'{name}: CIDR IPv4 non valido') from e
            network = iface.network
            for other, other_net in networks:
                if other_net.overlaps(network):
                    raise ValidationError(f'{name}: sottorete {network} sovrapposta a {other} ({other_net})')
            networks.append((name, network))
            address = str(iface)
            if gateway:
                g = _ipv4_address(gateway, name + ' gateway')
                if ipaddress.ip_address(g) not in network or g == str(iface.ip):
                    raise ValidationError(f'{name}: gateway fuori dalla sottorete o uguale all’indirizzo host')
                gateway = g
        if alias:
            try:
                alias_iface = ipaddress.ip_interface(alias)
                if (not isinstance(alias_iface, ipaddress.IPv4Interface) or
                        alias_iface.ip.is_loopback or alias_iface.ip.is_multicast or
                        alias_iface.ip.is_unspecified or alias_iface.ip.is_link_local or
                        (alias_iface.network.prefixlen < 31 and alias_iface.ip == alias_iface.network.network_address) or
                        (alias_iface.network.prefixlen < 31 and alias_iface.ip == alias_iface.network.broadcast_address)):
                    raise ValueError()
            except ValueError as exc:
                raise ValidationError(f'{name}: indirizzo IPv4 aggiuntivo CIDR non valido') from exc
            if address and alias_iface.ip == ipaddress.ip_interface(address).ip:
                raise ValidationError(f'{name}: alias uguale all’IP primario')
            if gateway and str(alias_iface.ip) == gateway:
                raise ValidationError(f'{name}: alias uguale al gateway WAN')
            for other, other_net in networks:
                if other != name and alias_iface.network.overlaps(other_net):
                    raise ValidationError(f'{name}: alias sovrapposto alla rete {other}')
            networks.append((name, alias_iface.network))
            alias = str(alias_iface)
        speed = _integer(row.get('capacity_mbps', 0), name + ' capacità Mbit/s', 0, 100000)
        priority = _integer(row.get('priority', 100), name + ' priorità', 1, 9999)
        chosen.append({'name': name, 'role': role, 'address': address, 'gateway': gateway,
                       'dhcp': dhcp, 'alias_address': alias, 'capacity_mbps': speed, 'priority': priority})
    wans = sorted((x for x in chosen if x['role'] == 'wan'), key=lambda x: (x['priority'], x['name']))
    if len(wans) == 0:
        raise ValidationError('Almeno una WAN obbligatoria')
    if strategy in {'failover', 'balanced'} and len(wans) < 2:
        raise ValidationError('Per failover o bilanciamento servono almeno due WAN')
    if strategy == 'balanced' and any(not x['capacity_mbps'] for x in wans):
        raise ValidationError('Per bilanciamento occorre indicare la capacità di ogni WAN')
    warnings = list(live.get('warnings', []))
    if len(chosen) == 1:
        warnings.append('Compatibilità monointerfaccia: nessuna configurazione di rete applicata durante l’aggiornamento.')
    if backend == 'dietpi' and not live.get('managers', {}).get('dietpi-network', {}).get('installed'):
        warnings.append('dietpi-network non disponibile: controlla la versione DietPi; non usare comandi per versioni incompatibili.')
    if backend == 'networkmanager' and not live.get('managers', {}).get('networkmanager', {}).get('installed'):
        warnings.append('NetworkManager non installato: prima prevedere installazione e migrazione via console.')
    active = [x for x in live.get('default_routes', []) if x.get('dev')]
    if active and active[0]['dev'] not in names:
        warnings.append('La route predefinita attuale usa una NIC non inclusa: non cambiare il piano di accesso senza console.')
    if len(wans) > 1 and any(x['dhcp'] for x in wans):
        warnings.append('Multi-WAN con DHCP: i gateway effettivi vanno ricontrollati ad ogni rinnovo lease.')
    if strategy == 'balanced':
        warnings.append('Bilanciamento per flusso (non per pacchetto): richiede source routing, conntrack e SNAT coerenti per ogni WAN.')
    if any(x['capacity_mbps'] and eligible[x['name']].get('speed_mbps') and x['capacity_mbps'] > eligible[x['name']]['speed_mbps'] for x in chosen):
        warnings.append('Una capacità richiesta supera la velocità negoziata della scheda: ricontrolla link e cablaggio.')
    # A single network model owns physical ports, bridge/bond, VLAN and zone definitions.
    # Existing drafts without fabric remain valid for non-disruptive migrations.
    physical_roles = {x['name']: x['role'] for x in chosen}
    reserved = [x['address'] for x in chosen if x['address']]
    for row in chosen:
        a = row['alias_address']
        if a and not any(ipaddress.ip_interface(a).network.overlaps(ipaddress.ip_interface(b).network) for b in reserved):
            reserved.append(a)
        if a:
            warnings.append(f"{row['name']}: alias IPv4 progettato, nessun secondo gateway automatico. Richiede routing per sorgente e conferma della raggiungibilità WAN.")
    try:
        fabric = validate_fabric(profile.get('fabric', {}), set(physical), reserved_networks=reserved)
        slaves = {port for b in fabric['bridges'] for port in b['ports']}
        slaves.update(port for b in fabric['bonds'] for port in b['ports'])
        for nic in chosen:
            if nic['name'] in slaves and (nic['address'] or nic['dhcp'] or nic['gateway'] or nic['alias_address']):
                raise FabricError(f"{nic['name']}: IP/DHCP/gateway su porta slave; assegnare indirizzo al bridge/bond")
        fabric_plan = plan_fabric(fabric, nic_roles=physical_roles)
    except FabricError as exc:
        raise ValidationError(str(exc)) from exc
    warnings.extend(fabric_plan['warnings'])
    normalized = {'backend': backend, 'strategy': strategy, 'nics': chosen, 'fabric': fabric}
    weights = {}
    if strategy == 'balanced':
        low = min(x['capacity_mbps'] for x in wans)
        weights = {x['name']: max(1, min(8, round(x['capacity_mbps'] / low))) for x in wans}
        if sum(weights.values()) > 16:
            warnings.append('Molte WAN/pesi: ridurre i pesi per non creare squilibri eccessivi.')
    commands = []
    for nic in chosen:
        if nic['name'] not in physical:
            commands.append({'iface':nic['name'],'display_only':'# Bond/bridge L3 già gestito dal sistema: non ricrearlo; verifica i profili NetworkManager prima di modificare IP o alias'})
            continue
        if backend == 'dietpi':
            args = ['dietpi-network', 'apply', nic['name']]
            if nic['dhcp']:
                args.append('--dhcp')
            elif nic['address']:
                args += ['--static', '--ip', nic['address']]
                if nic['gateway']:
                    args += ['--gateway', nic['gateway']]
            else:
                continue
            args.append('--no-restart')
        else:
            args = ['nmcli', 'connection', 'add', 'type', 'ethernet', 'ifname', nic['name'],
                    'con-name', f'iptm-{nic["name"]}', 'connection.autoconnect', 'no']
            if nic['dhcp']:
                args += ['ipv4.method', 'auto']
            elif nic['address']:
                args += ['ipv4.method', 'manual', 'ipv4.addresses', nic['address']]
                if nic['gateway']:
                    args += ['ipv4.gateway', nic['gateway']]
                else:
                    args += ['ipv4.never-default', 'yes']
        commands.append({'iface': nic['name'], 'display_only': shlex.join(args)})
        if nic['alias_address']:
            commands.append({'iface':nic['name'], 'display_only':
                '# Solo anteprima alias: ip -4 address add '+nic['alias_address']+' dev '+nic['name']})
    if backend == 'networkmanager':
        warnings.append('Una migrazione NetworkManager richiede la rimozione controllata del precedente proprietario di interfaccia: non disattivare ifupdown da web.')
    elif len(wans) > 1:
        warnings.append('DietPi può configurare le NIC, ma non il multi-WAN dinamico: serve routing IPTM separato.')
    # Explicitly no application from browser, even if a POST is forged.
    return {'ok': True, 'profile': normalized,
            'plan': {'primary_wan': wans[0]['name'], 'wan_count': len(wans),
                     'weights': weights, 'routing_tables': {x['name']: 210 + i for i, x in enumerate(wans)},
                     'commands_preview_only': commands, 'fabric_plan': fabric_plan,
                     'traffic_plan': propose_traffic(wans, strategy, weights),
                     'requires': ['iproute2', 'iptables', 'conntrack', 'safe-rollback', 'live-checks'],
                     'zone_simulation_only': True, 'external_switch_configuration_enabled': False,
                     'execution_enabled': False,
                     'console_vlan_trial_available': True,
                     'impact': 'Solo bozza: nessun cambio link, route, DNS, iptables, CAKE o NetworkManager.'},
            'warnings': warnings}


def read_profile(path: Path = PROFILE_PATH) -> dict | None:
    try:
        if path.is_symlink():
            return None
        doc = json.loads(path.read_text())
        return doc if isinstance(doc, dict) and doc.get('schema') == 1 else None
    except (OSError, ValueError):
        return None


def save_profile(profile: dict, path: Path = PROFILE_PATH) -> dict:
    """Write a root-owned, versioned DRAFT atomically. No networking commands."""
    if path.is_symlink():
        raise ValidationError('Percorso bozza non sicuro')
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if (path.parent.is_symlink() or path.parent.stat().st_uid != os.geteuid()
            or path.parent.stat().st_mode & 0o022):
        raise ValidationError('Directory configurazione non sicura: permessi o proprietario errati')
    lock_path = path.parent / '.multinic.lock'
    with open(lock_path, 'a+', encoding='utf-8') as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        current = read_profile(path)
        if current:
            backup = path.with_suffix('.previous.json')
            if backup.is_symlink():
                raise ValidationError('Percorso backup non sicuro')
            tmp_prev = path.parent / ('.multinic-prev-' + str(os.getpid()))
            try:
                tmp_prev.write_text(json.dumps(current, ensure_ascii=False), encoding='utf-8')
                os.chmod(tmp_prev, 0o600)
                os.replace(tmp_prev, backup)
            finally:
                tmp_prev.unlink(missing_ok=True)
        doc = {'schema': 1, 'version': VERSION, 'created': int(time.time()), 'profile': profile,
               'status': 'draft', 'applied': False}
        fd, temp = tempfile.mkstemp(prefix='.multinic-', dir=path.parent)
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as file:
                json.dump(doc, file, ensure_ascii=False, sort_keys=True)
                file.flush()
                os.fsync(file.fileno())
            os.chmod(temp, 0o600)
            os.replace(temp, path)
        finally:
            if os.path.exists(temp):
                os.unlink(temp)
    return doc


def clear_profile(path: Path = PROFILE_PATH) -> dict:
    if path.is_symlink() or path.parent.is_symlink():
        raise ValidationError('Percorso bozza non sicuro')
    if not path.parent.is_dir():
        return {'ok': True, 'cleared': True, 'applied': False}
    if path.parent.stat().st_uid != os.geteuid() or path.parent.stat().st_mode & 0o022:
        raise ValidationError('Directory configurazione non sicura')
    with open(path.parent / '.multinic.lock', 'a+', encoding='utf-8') as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        path.unlink(missing_ok=True)
    return {'ok': True, 'cleared': True, 'applied': False}




def legacy_wan_status() -> dict:
    """Read-only migration report. Old cron/service may survive package upgrades."""
    conf = Path('/etc/iptables-manager.d/wanfo.conf')
    timer = service_state('iptm-wanfo.timer')
    service = service_state('iptm-wanfo.service')
    return {'legacy_config_present': conf.is_file() and not conf.is_symlink(),
            'legacy_timer_active': timer['active'], 'legacy_timer_enabled': timer['enabled'],
            'legacy_service_active': service['active'],
            'migration': 'Use root console: iptm-helper multi-nic legacy-retire; never flush conntrack'}


def retire_legacy_wan() -> dict:
    """Explicit root-console retirement, without touching kernel routes/conntrack.

    Disable the timer first; keep the historical config in place for auditing and
    never delete it. Run only from an independent console. A malicious POST cannot
    reach this through the web handler (no action registered).
    """
    if os.geteuid() != 0:
        raise ValidationError('Ritiro legacy richiede root')
    if not shutil.which('systemctl'):
        raise ValidationError('systemd non disponibile')
    unit = ['iptm-wanfo.timer', 'iptm-wanfo.service']
    proc = subprocess.run(['systemctl', 'disable', '--now', *unit], timeout=20,
                          capture_output=True, text=True, check=False)
    if proc.returncode:
        # A system may not have these units; still stop timer if it exists.
        retry = subprocess.run(['systemctl', 'disable', '--now', 'iptm-wanfo.timer'],
                               timeout=20, capture_output=True, text=True, check=False)
        if retry.returncode and 'does not exist' not in (retry.stderr + proc.stderr):
            raise ValidationError('Impossibile disabilitare timer legacy: ' + retry.stderr[:200])
    return {'ok': True, 'legacy_retired': True, 'routes_modified': False,
            'conntrack_flushed': False, 'config_preserved': True}


def run_cli(argv: list[str], *, live: dict | None = None, path: Path = PROFILE_PATH) -> dict:
    operation = argv[0] if len(argv) == 1 else ''
    if operation not in {'status', 'inventory', 'preview', 'save', 'clear', 'legacy-retire'}:
        raise ValidationError('Operazione non autorizzata')
    if operation in {'save', 'clear', 'legacy-retire'} and os.geteuid() != 0 and path == PROFILE_PATH:
        raise ValidationError('Richiesti privilegi di root')
    if operation == 'clear':
        return clear_profile(path)
    if operation == 'legacy-retire':
        return retire_legacy_wan()
    live = live if live is not None else inventory()
    if operation == 'inventory':
        return {'ok': True, 'inventory': live}
    if operation == 'status':
        return {'ok': True, 'inventory': live, 'draft': read_profile(path), 'legacy': legacy_wan_status()}
    raw = sys.stdin.buffer.read(MAX_INPUT + 1)
    if len(raw) > MAX_INPUT:
        raise ValidationError('Payload oltre 64 KiB')
    try:
        doc = json.loads(raw)
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValidationError('JSON non valido') from exc
    result = validate(doc, live)
    if operation == 'save':
        doc = save_profile(result['profile'], path)
        return {'ok': True, 'draft': doc, 'warnings': result['warnings'], 'applied': False}
    return result


if __name__ == '__main__':
    try:
        print(json.dumps(run_cli(sys.argv[1:]), ensure_ascii=False, separators=(',', ':')))
    except (ValidationError, OSError) as exc:
        print(json.dumps({'ok': False, 'error': str(exc)}, ensure_ascii=False))
        sys.exit(2)
