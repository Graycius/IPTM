#!/usr/bin/env python3
"""IPTM post-commit systemd reconciliation and verified, reversible QoS ownership handoff.

The updater's smoke test MUST NOT mutate qdisc ownership or restart services.
A transient systemd timer may run this worker after an older updater commits;
newer native updaters also call `ensure` after committing their recovery journal.
Only confirmed, fully verified IPTM CAKE/IFB topologies are transferable.
No tc, iptables, NetworkManager or DNS configuration writes are performed here.
"""
from __future__ import annotations
from command_transport import capture
import base64, fcntl, importlib.util, json, os, pathlib, re, subprocess, sys, tempfile, time
VERSION='6.0.8'
ROOT=pathlib.Path('/usr/local/lib/iptables-manager')
ENGINE=ROOT/f'web/releases/{VERSION}/extensions/qos_engine.py'
UNIT=pathlib.Path('/etc/systemd/system/iptm-qos-watchdog.service')
STATE=pathlib.Path('/var/lib/iptm-qos-engine/active.json')
LOCK=STATE.parent/'lock'
JOURNAL=STATE.parent/'handoff.json'
PENDING=pathlib.Path('/var/lib/iptm-update-recovery/pending.json')
HELPER=pathlib.Path('/usr/local/sbin/iptm-helper')
VER_RX=re.compile(r'^\d+\.\d+\.\d+(?:\.\d+)?$')
COMPANIONS={
    'iptm-qos-adaptive.service':'Description=IPTM QoS adaptive RTT controller',
    'iptm-qos-auto-calibration.service':'Description=IPTM QoS hourly independent calibration',
    'iptm-qos-policy-restore.service':'Description=IPTM QoS DSCP boot restore',
}
class PostinstallError(Exception):pass

def call(*args,timeout=20,check=True):
    try:r=capture(args,timeout=timeout,stdout_limit=1048576,stderr_limit=262144)
    except (OSError,subprocess.TimeoutExpired) as exc:raise PostinstallError('Esito comando non verificabile: '+type(exc).__name__) from exc
    if check and r.returncode:raise PostinstallError(' '.join(args[:2])+': '+(r.stderr or r.stdout)[-500:])
    return r

def protected(path):
    if path.is_symlink() or not path.is_file():raise PostinstallError('Percorso non sicuro: '+str(path))
    st=path.stat()
    if st.st_uid or st.st_mode&0o077:raise PostinstallError('Stato non protetto: '+str(path))

def atomic(path,data,mode=0o600):
    from command_transport import durable_replace
    try: durable_replace(path,data,mode=mode)
    except (OSError,ValueError) as exc: raise PostinstallError(str(exc)) from exc


def owner():
    if not STATE.exists() and not STATE.is_symlink():return None
    protected(STATE)
    obj=json.loads(STATE.read_text())
    if not isinstance(obj,dict):raise PostinstallError('Journal CAKE invalido')
    return obj

def preflight():
    if os.geteuid():raise PostinstallError('root richiesto')
    if not ENGINE.is_file() or ENGINE.is_symlink():raise PostinstallError('Motore della nuova release assente')
    if UNIT.is_symlink():raise PostinstallError('Watchdog systemd simbolico')
    if UNIT.exists():
        content=UNIT.read_text()
        if 'Description=IPTM QoS independent rollback watchdog' not in content or 'qos_engine.py watchdog' not in content:
            raise PostinstallError('Watchdog non riconosciuto')
    pending_unshape=STATE.parent/'unshaped-calibration.json'
    if pending_unshape.exists() or pending_unshape.is_symlink():
        protected(pending_unshape)
        doc=json.loads(pending_unshape.read_text())
        if not isinstance(doc,dict) or doc.get('state')=='pending':
            raise PostinstallError('Prova CAKE unlimited pendente: handoff rinviato')
    data=owner()
    if data and data.get('state') in ('pending','applying','rollback-failed','reconciling'):
        raise PostinstallError('Transazione QoS pendente o rollback fallito: handoff sospeso')
    if data and data.get('state')=='confirmed' and data.get('version')!=VERSION:
        check_confirmed(data)
    return data

def guard_is_current():
    shown=call('systemctl','show',UNIT.name,'--property=ExecStart','--value',timeout=10,check=False)
    if shown.returncode or str(ENGINE)+' watchdog' not in shown.stdout:return False
    return all(call('systemctl',op,UNIT.name,timeout=10,check=False).stdout.strip()==wanted
               for op,wanted in [('is-active','active'),('is-enabled','enabled')])

def check_confirmed(data):
    old=data.get('version')
    if not isinstance(old,str) or not VER_RX.fullmatch(old) or old==VERSION:
        raise PostinstallError('Proprietario CAKE non riconosciuto')
    if not UNIT.exists() or f'/web/releases/{old}/extensions/qos_engine.py watchdog' not in UNIT.read_text():
        raise PostinstallError('Watchdog precedente non corrisponde al proprietario CAKE')
    if call('systemctl','is-active',UNIT.name,check=False).stdout.strip()!='active':
        raise PostinstallError('Il watchdog precedente non è attivo')
    engine=ROOT/f'web/releases/{old}/extensions/qos_engine.py'
    if not engine.is_file() or engine.is_symlink() or engine.stat().st_uid:
        raise PostinstallError('Motore precedente non verificabile')
    result=call('/usr/bin/python3','-B',str(engine),'status',timeout=15)
    try:status=json.loads(result.stdout)
    except json.JSONDecodeError as e:raise PostinstallError('Stato motore precedente non JSON') from e
    if status.get('state')!='confirmed' or status.get('verified') is not True or status.get('interface')!=data.get('interface'):
        raise PostinstallError('Proprietà CAKE/IFB non completamente verificata; nessuna migrazione')
    adaptive=STATE.parent/'adaptive.json'
    if adaptive.exists():
        protected(adaptive)
        config=json.loads(adaptive.read_text())
        if config.get('trial') is not None:
            raise PostinstallError('Regolazione RTT in prova: attendere approvazione/rollback')
    return old

def companion_changes(old):
    originals={}
    for name,marker in COMPANIONS.items():
        path=UNIT.parent/name
        if path.is_symlink():raise PostinstallError('Unità accessoria simbolica: '+name)
        if not path.exists():continue
        content=path.read_text()
        if f'/web/releases/{old}/extensions/' not in content:continue
        if marker not in content or path.stat().st_uid or path.stat().st_mode&0o022:
            raise PostinstallError('Unità accessoria personalizzata o non protetta: '+name)
        originals[str(path)]=content.encode()
    return originals

def save_journal(state_bytes, original_units):
    record={'version':VERSION,'created':int(time.time()),
            'state':base64.b64encode(state_bytes).decode(),
            'units':{name:base64.b64encode(blob).decode() for name,blob in original_units.items()}}
    atomic(JOURNAL,json.dumps(record,sort_keys=True).encode())

def recover_journal():
    if not JOURNAL.exists():return False
    protected(JOURNAL)
    record=json.loads(JOURNAL.read_text())
    if record.get('version')!=VERSION:raise PostinstallError('Handoff pendente di altra release')
    raw=base64.b64decode(record['state'],validate=True)
    obj=json.loads(raw)
    old=obj.get('version')
    if not isinstance(old,str) or not VER_RX.fullmatch(old):raise PostinstallError('Vecchio proprietario non valido')
    for name,encoded in record.get('units',{}).items():
        path=pathlib.Path(name)
        if path.parent!=UNIT.parent or path.name not in set(COMPANIONS)|{UNIT.name}:
            raise PostinstallError('Percorso nel journal non ammesso')
        atomic(path,base64.b64decode(encoded,validate=True),0o644)
    atomic(STATE,raw)
    call('systemctl','daemon-reload')
    call('systemctl','restart',UNIT.name)
    if call('systemctl','is-active',UNIT.name,check=False).stdout.strip()!='active':
        raise PostinstallError('Rollback watchdog non operativo: mantenuto journal')
    JOURNAL.unlink()
    return True

def handoff(previous):
    old=check_confirmed(previous)
    old_bytes=STATE.read_bytes()
    units={str(UNIT):UNIT.read_bytes()}
    units.update(companion_changes(old))
    adaptive_timer='iptm-qos-adaptive.timer'
    was_adaptive=call('systemctl','is-active',adaptive_timer,check=False).stdout.strip()=='active'
    if was_adaptive:
        try:
            call('systemctl','stop',adaptive_timer,timeout=25)
            # Do not lock the QoS state until the currently running one-shot exits.
            call('systemctl','stop','iptm-qos-adaptive.service',timeout=25)
        except Exception:
            call('systemctl','start',adaptive_timer,check=False)
            raise
    LOCK.parent.mkdir(parents=True,exist_ok=True)
    from command_transport import domain_lock
    with domain_lock(LOCK):
        if STATE.read_bytes()!=old_bytes:
            if was_adaptive:call('systemctl','start',adaptive_timer,check=False)
            raise PostinstallError('Stato QoS modificato durante la migrazione')
        if JOURNAL.exists():raise PostinstallError('Journal di handoff già presente')
        save_journal(old_bytes,units)
        try:
            transformed=dict(previous,version=VERSION,migrated_from=old,migrated_at=time.time())
            atomic(STATE,json.dumps(transformed,sort_keys=True).encode())
            for name,blob in units.items():
                if name==str(UNIT):continue
                updated=blob.decode().replace(f'/web/releases/{old}/extensions/',
                                               f'/web/releases/{VERSION}/extensions/')
                atomic(pathlib.Path(name),updated.encode(),0o644)
            # Replace only a verified IPTM unit; no qdisc/firewall writes.
            unit=(f'[Unit]\nDescription=IPTM QoS independent rollback watchdog\nAfter=network.target\n'
                  f'[Service]\nType=simple\nExecStart=/usr/bin/python3 -B {ENGINE} watchdog\n'
                  f'Restart=always\nRestartSec=2\nNoNewPrivileges=true\n'
                  f'[Install]\nWantedBy=multi-user.target\n')
            atomic(UNIT,unit.encode(),0o644)
            call('systemctl','daemon-reload')
            call('systemctl','enable',UNIT.name)
            call('systemctl','restart',UNIT.name)
            if not guard_is_current():raise PostinstallError('Nuovo watchdog non pronto')
            # Inspect the live topology with the *new* engine, without touching it.
            # Lock already held by handoff(): a subprocess status would wait
            # for the same flock forever (reproduced on 5.19.0).
            spec=importlib.util.spec_from_file_location('iptm_qos_handoff_verify',str(ENGINE))
            module=importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            current=module.status()
            if current.get('state')!='confirmed' or current.get('verified') is not True:
                raise PostinstallError('Proprietà CAKE dopo handoff non verificata')
            if was_adaptive:
                call('systemctl','start',adaptive_timer)
            JOURNAL.unlink()
        except Exception:
            # Fail closed: restore the original owner, not a half-swapped guard.
            recover_journal()
            if was_adaptive:
                call('systemctl','start',adaptive_timer,check=False)
            raise
    return {'ok':True,'version':VERSION,'handoff_from':old,'watchdog':'active',
            'qdisc_changed':False,'ifb_changed':False}

def _ensure_locked():
    if JOURNAL.exists() or JOURNAL.is_symlink():recover_journal()
    data=preflight()
    if data and data.get('state')=='confirmed' and data.get('version')!=VERSION:
        return handoff(data)
    if guard_is_current():
        return {'ok':True,'version':VERSION,'watchdog':'active','already_current':True}
    result=call('/usr/bin/python3','-B',str(ENGINE),'install-guard',timeout=75)
    if not json.loads(result.stdout).get('ok') or not guard_is_current():
        raise PostinstallError('Nuovo watchdog non operativo: conservare release precedente')
    return {'ok':True,'version':VERSION,'watchdog':'active'}

def cleanup_postcommit():
    """Best-effort, non-disruptive retirement after the updater committed.

    Report failures separately; cleanup must never undo a successful software
    install, a confirmed watchdog handoff or restore incomplete transactions.
    """
    target=ENGINE.with_name('upgrade_cleanup.py')
    if not target.is_file() or target.is_symlink():
        return {'ok':False,'error':'Motore pulizia non disponibile'}
    try:
        result=call('/usr/bin/python3','-B',str(target),'apply',timeout=45,check=False)
        if result.returncode:
            return {'ok':False,'error':(result.stderr or result.stdout)[-450:]}
        value=json.loads(result.stdout)
        return value if isinstance(value,dict) else {'ok':False,'error':'Risposta pulizia non valida'}
    except (OSError,ValueError,subprocess.TimeoutExpired) as exc:
        return {'ok':False,'error':str(exc)[:240]}

def ensure_retention():
    """Install conservative daily retention after verified update, no deletion."""
    worker=ENGINE.with_name('retention_manager.py')
    if not worker.is_file() or worker.is_symlink():return {'ok':False,'error':'retention non disponibile'}
    try:
        r=call('/usr/bin/python3','-B',str(worker),'install',timeout=45,check=False)
        if r.returncode:return {'ok':False,'error':(r.stderr or r.stdout)[-250:]}
        result=json.loads(r.stdout)
        return result if isinstance(result,dict) else {'ok':False,'error':'risposta retention invalida'}
    except (OSError,ValueError,subprocess.TimeoutExpired) as exc:
        return {'ok':False,'error':str(exc)[:220]}


def ensure():
    if PENDING.exists() or PENDING.is_symlink():
        raise PostinstallError('Aggiornamento ancora in transazione: handoff rimandato')
    if os.geteuid():raise PostinstallError('root richiesto')
    directory=STATE.parent
    if directory.is_symlink():raise PostinstallError('Directory handoff simbolica')
    directory.mkdir(mode=0o700,parents=True,exist_ok=True)
    stat=directory.stat()
    if stat.st_uid or stat.st_mode&0o077:raise PostinstallError('Directory handoff non root:0700')
    from command_transport import domain_lock
    with domain_lock(directory/'postinstall.lock'):
        cleanup=cleanup_postcommit()
        result=_ensure_locked()
        result['cleanup']=cleanup
        from native_update import cleanup_after_legacy_commit
        result['release_cleanup']=cleanup_after_legacy_commit(VERSION)
        result['retention']=ensure_retention()
        return result

def schedule():
    """Called by older updater's helper ping; never blocks its commit."""
    if os.geteuid():raise PostinstallError('root richiesto')
    if not PENDING.exists():return {'ok':True,'scheduled':False,'reason':'nessun aggiornamento in corso'}
    unit='iptm-qos-handoff-'+VERSION.replace('.','-')
    run=['systemd-run','--quiet','--unit='+unit,'--on-active=20s',
         '--property=Type=oneshot','--property=TimeoutStartSec=240',
         '/usr/bin/python3','-B',str(ENGINE.with_name('postinstall.py')),'after-commit']
    result=call(*run,timeout=20,check=False)
    if result.returncode:
        raise PostinstallError('Pianificazione non riuscita: '+(result.stderr or result.stdout)[-350:])
    return {'ok':True,'scheduled':True,'unit':unit}

def after_commit():
    for _ in range(72):
        if not PENDING.exists():break
        time.sleep(3)
    else:raise PostinstallError('Aggiornamento non concluso entro 216 secondi')
    result=call(str(HELPER),'version',check=False)
    if result.stdout.splitlines()[:1]!=[VERSION]:
        return {'ok':True,'skipped':'aggiornamento annullato o release cambiata'}
    # A one-minute RTT experiment can be in flight when the delayed worker runs.
    # Retry only transient, specifically identified races; do not bypass ownership checks.
    for attempt in range(7):
        try:return ensure()
        except PostinstallError as exc:
            if not any(term in str(exc) for term in ('Regolazione RTT in prova','Stato QoS modificato durante la migrazione')) or attempt==6:
                raise
            time.sleep(12)

def main():
    if sys.argv[1:]==['check']:preflight();return {'ok':True,'can_install':True}
    if sys.argv[1:]==['ensure']:return ensure()
    if sys.argv[1:]==['schedule']:return schedule()
    if sys.argv[1:]==['after-commit']:return after_commit()
    raise PostinstallError('comando sconosciuto')

if __name__=='__main__':
    try:print(json.dumps(main(),ensure_ascii=False))
    except (PostinstallError,OSError,ValueError,KeyError,json.JSONDecodeError,subprocess.TimeoutExpired) as e:
        print('IPTM post-install: '+str(e),file=sys.stderr);sys.exit(1)
