#!/usr/bin/env python3
"""IPTM fabric: console-only, transactional *isolated VLAN* trial.

This is intentionally NOT a generic network-configuration executor. No physical
port enslaving, interface down/up, default route, firewall, DNS, DHCP, WAN or
NetworkManager mutations. Pending trials are reverted by a transient systemd
timer and an early-boot service. The latter also labels confirmed ephemeral
trials as absent after a reboot. Never run from the HTTP dispatcher.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time

from multinic_manager import inventory, read_profile, validate, ValidationError

VERSION = '5.30.1'
STATE_DIR = Path('/var/lib/iptm-fabric-runtime')
STATE = STATE_DIR / 'fabric-trial.json'
LOCK = STATE_DIR / 'fabric-trial.lock'
UNIT = Path('/etc/systemd/system/iptm-fabric-boot-recover.service')
SCRIPT = f'/usr/local/lib/iptables-manager/web/releases/{VERSION}/extensions/fabric_runtime.py'
TIMER = 'iptm-fabric-trial-revert'
TTL = 120
IF_RX = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$')

class TrialError(ValueError):
    pass


def call(argv, *, runner=None, timeout=12, check=True):
    """Argv only, no shell. Inject runner in tests."""
    result = (runner or subprocess.run)(argv, capture_output=True, text=True, timeout=timeout, check=False)
    if check and result.returncode:
        raise TrialError(f'Comando {argv[0]} non riuscito (exit {result.returncode}): {result.stderr[:180]}')
    return result


def secure_dir(path: Path):
    if path.is_symlink():
        raise TrialError('Directory di stato è un symlink')
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    st = path.stat()
    if st.st_uid != 0 or (st.st_mode & 0o077):
        raise TrialError('Directory di stato non protetta, serve root:0700')


def atomic_state(doc: dict, path: Path | None = None):
    path = path or STATE
    secure_dir(path.parent)
    if path.is_symlink():
        raise TrialError('File di stato è un symlink')
    fd, name = tempfile.mkstemp(prefix='.fabric-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(doc, stream, ensure_ascii=False, sort_keys=True)
            stream.flush(); os.fsync(stream.fileno())
        os.replace(name, path)
        directory_fd = os.open(path.parent, os.O_DIRECTORY)
        try: os.fsync(directory_fd)
        finally: os.close(directory_fd)
    finally:
        if os.path.exists(name): os.unlink(name)


def state_read(path: Path | None = None):
    path = path or STATE
    if path.is_symlink(): raise TrialError('File di stato non sicuro')
    try:
        raw = path.read_bytes()
        if len(raw) > 65536: raise TrialError('Stato oltre 64 KiB')
        obj = json.loads(raw)
        if not isinstance(obj, dict) or obj.get('schema') != 1:
            raise TrialError('Stato transazione non valido')
        return obj
    except FileNotFoundError:
        return None


def locking(path: Path | None = None):
    path = path or LOCK
    secure_dir(path.parent)
    if path.is_symlink(): raise TrialError('Lock symlink non sicuro')
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    st = os.fstat(fd)
    if st.st_uid != 0 or st.st_mode & 0o077:
        os.close(fd); raise TrialError('Lock non protetto')
    fcntl.flock(fd, fcntl.LOCK_EX)
    return fd


def _links(*, runner=None):
    result = call(['ip', '-j', 'link', 'show'], runner=runner)
    try:
        rows = json.loads(result.stdout)
        return {x['ifname']: x for x in rows if isinstance(x, dict) and isinstance(x.get('ifname'), str)}
    except (ValueError, KeyError, TypeError) as exc:
        raise TrialError('Inventario link iproute2 non leggibile') from exc


def plan(doc: dict, live: dict, links: dict) -> dict:
    """Reject any non-additive topology; produce a stable, signed-by-content trial plan."""
    if not isinstance(doc, dict) or doc.get('status') != 'draft' or doc.get('applied') is not False:
        raise TrialError('Salvare prima una bozza IPTM non applicata')
    try:
        valid = validate(doc['profile'], live)
    except (ValidationError, KeyError, TypeError) as exc:
        raise TrialError(f'Bozza non valida rispetto alle NIC presenti: {exc}') from exc
    fabric = valid['profile']['fabric']
    if fabric['bonds'] or fabric['bridges']:
        raise TrialError('Trial VLAN: bond e bridge con porte fisiche sono esclusi. Nessuna modifica a interfacce attive.')
    if fabric['switches']:
        raise TrialError('Switch esterni da configurare separatamente, non inclusi nel trial.')
    rows = fabric['vlans']
    if not rows or len(rows) > 8:
        raise TrialError('Trial: scegliere da 1 a 8 VLAN; non configurare bridge, bond o switch')
    physical = {x['name']: x for x in live.get('interfaces', []) if x.get('physical') is True}
    roles = {x['name']: x['role'] for x in valid['profile']['nics']}
    results = []
    for v in rows:
        parent, name = v['parent'], v['name']
        if (parent not in physical or parent not in links or name in links
                or not IF_RX.fullmatch(name) or not IF_RX.fullmatch(parent)):
            raise TrialError(f'{name}: parent assente o interfaccia già esistente')
        if roles.get(parent) in {'wan', 'vpn-underlay'}:
            raise TrialError(f'{parent}: la prova non usa porte WAN o underlay VPN')
        if v['dhcp_server'] or v['address']:
            raise TrialError(f'{name}: trial solo Layer 2; rimuovere IPv4 e DHCP dalla VLAN')
        if v['zone'] == 'wan':
            raise TrialError(f'{name}: la VLAN WAN non è attivabile in questa fase')
        if links[parent].get('master') or links[parent].get('linkinfo', {}).get('info_kind') in {'bond','bridge','vlan'}:
            raise TrialError(f'{parent}: parent già controllato da un bridge/bond/VLAN')
        if not v['vid'] in range(1,4095): raise TrialError('VLAN ID non valido')
        results.append({'name': name, 'parent': parent, 'vid': v['vid'], 'zone': v['zone']})
    if len({x['name'] for x in results}) != len(results):
        raise TrialError('VLAN duplicate')
    signature = hashlib.sha256(json.dumps({'vlans': results, 'nics': valid['profile']['nics'],
                                     'backend': valid['profile']['backend']},
                                     sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return {'schema': 1, 'version': VERSION, 'hash': signature, 'vlans': results,
            'mode': 'trial-l2', 'live_changes': ['creazione esclusiva di nuove interfacce VLAN'],
            'unchanged': ['porte fisiche', 'gateway default', 'DNS', 'DHCP', 'iptables', 'CAKE', 'NetworkManager'],
            'timeout_seconds': TTL, 'persistence': 'no; VLAN non persistenti dopo riavvio'}


def boot_guard_install(*, unit: Path | None = None, script: str = SCRIPT, runner=None):
    unit = unit or UNIT
    if not Path(script).is_file() and runner is None:
        raise TrialError('Modulo non installato nel percorso della release')
    content = (f'[Unit]\nDescription=IPTM Fabric boot trial recovery\n'
               'DefaultDependencies=no\nAfter=local-fs.target\nBefore=network-pre.target\n'
               'Wants=network-pre.target\n[Service]\nType=oneshot\n'
               f'ExecStart=/usr/bin/python3 -B {script} boot-recover\n'
               '[Install]\nWantedBy=sysinit.target\n')
    if unit.is_symlink(): raise TrialError('Unità di boot symlink non valida')
    if unit.exists() and 'Description=IPTM Fabric boot trial recovery' not in unit.read_text():
        raise TrialError('Unità preesistente non riconosciuta')
    if unit.parent.is_symlink(): raise TrialError('Unità in directory symlink')
    fd, tmp = tempfile.mkstemp(prefix='.iptm-fabric-', dir=unit.parent)
    try:
        with os.fdopen(fd, 'w') as file:
            file.write(content);file.flush();os.fsync(file.fileno());os.fchmod(file.fileno(), 0o644)
        os.replace(tmp, unit)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)
    call(['systemctl', 'daemon-reload'], runner=runner)
    call(['systemctl', 'enable', unit.name], runner=runner)
    return {'ok':True, 'boot_guard':str(unit)}


def _guard_verified(*, runner=None, unit: Path | None = None):
    unit = unit or UNIT
    if unit.is_symlink() or not unit.is_file() or SCRIPT not in unit.read_text():
        raise TrialError('Installare prima il boot guard della release dalla console')
    r=call(['systemctl','is-enabled',unit.name],runner=runner,check=False)
    if r.returncode or r.stdout.strip() not in {'enabled','static'}:
        raise TrialError('Servizio recupero boot non abilitato')
    if not shutil.which('systemd-run') and runner is None:
        raise TrialError('systemd-run necessario per rollback temporizzato')


def _timer_arm(*, runner=None):
    call(['systemd-run', f'--unit={TIMER}', f'--on-active={TTL}s', '--collect',
          '/usr/bin/python3', '-B', SCRIPT, 'expire'], runner=runner)


def _timer_cancel(*, runner=None):
    call(['systemctl', 'stop', TIMER + '.timer'], runner=runner, check=False)


def _remove_owned(doc: dict, *, runner=None):
    removed=[]; failed=[]
    links=_links(runner=runner)
    for item in reversed(doc.get('vlans', [])):
        name=item['name']; marker=f"iptm-fabric-{doc['token']}"
        if name not in links:continue
        # Ignore names which may have been recreated by an external manager.
        r=call(['ip','-j','-d','link','show','dev',name],runner=runner,check=False)
        try:
            details=json.loads(r.stdout)[0]
            alias=details.get('ifalias', '')
        except (ValueError, IndexError, KeyError, TypeError):
            alias=''
        if r.returncode or alias != marker:
            failed.append(f'{name}: alias transazione non corrispondente; intervento manuale necessario')
            continue
        try:
            call(['ip','link','delete','dev',name], runner=runner)
            removed.append(name)
        except TrialError as exc:failed.append(str(exc))
    return removed,failed


def rollback(doc: dict, *, runner=None):
    removed,failed=_remove_owned(doc,runner=runner)
    doc['status']='rollback-incomplete' if failed else 'rolled-back'
    doc['removed']=removed;doc['errors']=failed
    atomic_state(doc)
    return {'ok':not failed,'status':doc['status'],'removed':removed,'errors':failed}


def apply(expected_hash: str, *, runner=None, live=None, links=None, draft=None):
    if not re.fullmatch(r'[0-9a-f]{64}', expected_hash): raise TrialError('Hash anteprima non valido')
    _guard_verified(runner=runner)
    old=state_read()
    if old and old.get('status') in {'pending','confirmed','rollback-incomplete'}:
        raise TrialError('Trial precedente non chiuso; controllare status e usare rollback')
    live=live if live is not None else inventory()
    links=links if links is not None else _links(runner=runner)
    draft=draft if draft is not None else read_profile()
    trial=plan(draft,live,links)
    if trial['hash']!=expected_hash:raise TrialError('Bozza modificata: rigenerare anteprima')
    token=secrets.token_hex(12)
    doc={'schema':1,'version':VERSION,'token':token,'status':'pending',
         'started':int(time.time()),'deadline':int(time.time())+TTL,
         'hash':trial['hash'],'vlans':trial['vlans'],'errors':[]}
    atomic_state(doc)
    # Arm timeout BEFORE touching any networking state.
    try:
        _timer_arm(runner=runner)
    except Exception:
        doc['status']='rolled-back';atomic_state(doc)
        raise
    try:
        for item in doc['vlans']:
            name=item['name']
            # Re-check against a concurrent manager creating the same interface.
            if name in _links(runner=runner):raise TrialError(name+': interfaccia comparsa durante attivazione')
            call(['ip','link','add','link',item['parent'],'name',name,'type','vlan','id',str(item['vid'])],runner=runner)
            try:
                call(['ip','link','set','dev',name,'alias',f'iptm-fabric-{token}'],runner=runner)
            except TrialError:
                # This invocation has just created the name; do not leave an
                # alias-less orphan which the conservative rollback can't own.
                call(['ip','link','delete','dev',name],runner=runner,check=False)
                raise
            call(['ip','link','set','dev',name,'up'],runner=runner)
        return {'ok':True,'status':'pending','token':token,'expires':doc['deadline'],
                'changes':[v['name'] for v in doc['vlans']], 'confirm':'console-only; no persistence after reboot'}
    except Exception as exc:
        response=rollback(doc,runner=runner)
        if response['ok']:
            _timer_cancel(runner=runner)
        # If rollback is incomplete, leave the independent timer armed to retry.
        raise TrialError('Attivazione fallita, rollback: '+str(response)+'; causa: '+str(exc)) from exc


def action(op: str, token: str='', *, runner=None):
    if op not in {'status','preview','install-guard','apply','confirm','rollback','expire','boot-recover'}:
        raise TrialError('Operazione non ammessa')
    if os.geteuid()!=0:raise TrialError('Richiesto root')
    if op in {'apply','confirm','rollback','install-guard'} and not sys.stdin.isatty() and runner is None:
        raise TrialError('Operazione disponibile solo da terminale TTY root, non da HTTP')
    if op == 'preview':
        return {'ok':True,'plan':plan(read_profile(),inventory(),_links(runner=runner))}
    if op == 'status':
        return {'ok':True,'trial':state_read(),'boot_guard_installed':UNIT.exists() and not UNIT.is_symlink()}
    if op == 'install-guard':return boot_guard_install(runner=runner)
    fd=locking()
    try:
        if op == 'apply':return apply(token,runner=runner)
        doc=state_read()
        if not doc:return {'ok':True,'status':'absent'}
        if op == 'boot-recover' and doc['status']=='confirmed':
            doc['status']='rebooted-not-persistent';atomic_state(doc)
            return {'ok':True,'status':doc['status']}
        if op in {'confirm','rollback'} and (not re.fullmatch(r'[0-9a-f]{24}',token) or token!=doc['token']):
            raise TrialError('Token non corrispondente')
        if op == 'confirm':
            if doc['status']!='pending' or int(time.time())>=doc['deadline']:
                raise TrialError('Trial non confermabile, scaduto o non pendente')
            links=_links(runner=runner)
            for row in doc['vlans']:
                if row['name'] not in links: raise TrialError('VLAN sparita: '+row['name'])
                item=call(['ip','-j','-d','link','show','dev',row['name']],runner=runner)
                if json.loads(item.stdout)[0].get('ifalias')!=f"iptm-fabric-{doc['token']}":
                    raise TrialError('VLAN non posseduta da IPTM: '+row['name'])
            doc['status']='confirmed';atomic_state(doc)
            _timer_cancel(runner=runner)
            return {'ok':True,'status':'confirmed','persistent':False}
        if op in {'expire','boot-recover'} and doc['status']!='pending':
            return {'ok':True,'status':doc['status']}
        if op == 'rollback' and doc['status'] not in {'pending','confirmed','rollback-incomplete'}:
            return {'ok':True,'status':doc['status']}
        result=rollback(doc,runner=runner)
        if op == 'rollback' and result['ok']:_timer_cancel(runner=runner)
        return result
    finally:
        fcntl.flock(fd,fcntl.LOCK_UN);os.close(fd)


def main(argv: list[str]):
    op = argv[0] if argv else ''
    if op in {'apply','confirm','rollback'} and len(argv)==2:
        return action(op,argv[1])
    if op in {'status','preview','install-guard','expire','boot-recover'} and len(argv)==1:
        return action(op)
    raise TrialError('Uso: fabric-runtime status|preview|install-guard|apply HASH|confirm TOKEN|rollback TOKEN|expire|boot-recover')


if __name__=='__main__':
    try:
        print(json.dumps(main(sys.argv[1:]), ensure_ascii=False, separators=(',',':')))
    except (TrialError, OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({'ok':False,'error':str(exc)},ensure_ascii=False))
        sys.exit(2)
