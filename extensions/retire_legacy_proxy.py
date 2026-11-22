#!/usr/bin/env python3
"""One-time retirement of legacy IPTM-owned HTTP interception components.

Called only by a validated native update, before switching the privileged
helper. Does NOT touch the distribution's independent proxy service or APT.
Never flushes a firewall table or guesses a missing NAT journal.
"""
from __future__ import annotations
import json, os, pathlib, pwd, re, shutil, subprocess, sys

ROOT=pathlib.Path('/usr/local/lib/iptables-manager/web/releases')
BASE=pathlib.Path('/var/lib/iptm-cache-proxy')
REDIRECT=BASE/'redirect.json'
UNITS={
 pathlib.Path('/etc/systemd/system/iptm-cache-proxy.service'):'Description=IPTM isolated LAN HTTP caching proxy',
 pathlib.Path('/etc/systemd/system/iptm-cache-redirect.service'):'Description=IPTM HTTP cache redirect reconciliation',
 pathlib.Path('/etc/systemd/system/iptm-cache-redirect.timer'):'# IPTM HTTP redirect timer',
}
CONFIG=pathlib.Path('/etc/iptm-cache-proxy/squid.conf')
LEGACY_LOG=pathlib.Path('/var/lib/iptm/tool-squid.log')
DIRECTORIES=(pathlib.Path('/etc/iptm-cache-proxy'), BASE,
             pathlib.Path('/var/cache/iptm-cache-proxy'),pathlib.Path('/var/log/iptm-cache-proxy'))
VERSION=re.compile(r'\d+\.\d+\.\d+\Z')
TAG='IPTM_HTTP_CACHE_V1'; CHAIN='IPTM_HTTP_CACHE'
class RetireError(ValueError):pass


def execute(*argv, timeout=20, check=True):
    try:r=subprocess.run(list(argv),capture_output=True,text=True,stdin=subprocess.DEVNULL,timeout=timeout)
    except (OSError,subprocess.TimeoutExpired) as exc:raise RetireError('Comando non eseguibile: '+str(exc)[:160]) from exc
    if check and r.returncode:raise RetireError('Operazione negata: '+(r.stderr or r.stdout)[-350:])
    return r


def owned_file(path,marker):
    if path.is_symlink():raise RetireError('File simbolico non gestibile: '+str(path))
    if not path.exists():return False
    st=path.stat()
    if not path.is_file() or st.st_uid or st.st_mode & 0o022 or st.st_size>16384:
        raise RetireError('File non attribuibile a IPTM: '+str(path))
    if marker not in path.read_text():raise RetireError('Marcatore proprietario assente: '+str(path))
    return True


def safe_dir(path):
    if path.is_symlink():raise RetireError('Directory simbolica: '+str(path))
    if path.exists():
        st=path.stat()
        uid_ok={0}
        if path in DIRECTORIES[2:]:
            try:uid_ok.add(pwd.getpwnam('proxy').pw_uid)
            except KeyError:pass
        if not path.is_dir() or st.st_mode & 0o002 or st.st_uid not in uid_ok:
            raise RetireError('Directory non attribuibile a IPTM: '+str(path))


def service_state(unit):
    result=execute('systemctl','is-active',unit,check=False,timeout=8)
    state=result.stdout.strip()
    if state not in ('active','activating','reloading','inactive','failed','unknown','deactivating'):
        raise RetireError('Stato servizio non verificabile: '+unit)
    return state


def nat_residue():
    """Read only; both backend families checked so changing alternatives cannot hide hooks."""
    found=[]
    for binpath in ('/usr/sbin/iptables-legacy','/usr/sbin/iptables-nft'):
        if not pathlib.Path(binpath).is_file():continue
        for table,chain in (('nat','PREROUTING'),('filter','INPUT'),('nat',CHAIN)):
            r=execute(binpath,'-w','5','-t',table,'-S',chain,timeout=10,check=False)
            if r.returncode not in (0,1):
                raise RetireError('Verifica residue netfilter non riuscita per '+binpath+' '+chain)
            if r.returncode == 1:
                diagnostic=(r.stderr or '').lower()
                if not any(known in diagnostic for known in ('no chain/target/match',
                       'does not exist', 'table `nat` is incompatible', 'table not found',
                       'chain not found')):
                    raise RetireError('Netfilter non leggibile: '+binpath+' '+chain)
            if TAG in r.stdout or (chain=='PREROUTING' and CHAIN in r.stdout):
                found.append(binpath+':'+chain)
            if chain==CHAIN and r.returncode==0 and ('-N '+CHAIN) in r.stdout:
                found.append(binpath+':'+CHAIN)
    return found


def retire(old_version):
    if os.geteuid():raise RetireError('root richiesto')
    if not VERSION.fullmatch(old_version):raise RetireError('Versione precedente non valida')
    # A transient APT worker from an older release must never reinstall the
    # component concurrently with this migration.
    if service_state('iptm-tool-squid.service') in ('active','activating','reloading'):
        raise RetireError('Installazione precedente ancora attiva: iptm-tool-squid.service')
    for d in DIRECTORIES:safe_dir(d)
    if LEGACY_LOG.is_symlink():raise RetireError('Log installazione simbolico')
    if LEGACY_LOG.exists():
        st=LEGACY_LOG.stat()
        if not LEGACY_LOG.is_file() or st.st_uid or st.st_mode & 0o022:
            raise RetireError('Log installazione non riconosciuto: '+str(LEGACY_LOG))
    present_units=[p for p,m in UNITS.items() if owned_file(p,m)]
    if CONFIG.parent.exists():owned_file(CONFIG,'# IPTM cache proxy')
    if REDIRECT.exists() and REDIRECT.is_symlink():raise RetireError('Journal NAT simbolico')
    # Missing managed files can still leave an orphan redirect; verify both backends.
    artifacts=bool(present_units or any(d.exists() for d in DIRECTORIES))
    if not artifacts:
        remain=nat_residue()
        if remain:raise RetireError('Redirect residuo senza journal: '+','.join(remain))
        if LEGACY_LOG.exists():LEGACY_LOG.unlink()
        return {'ok':True,'retired':False,'reason':'nessuna installazione IPTM precedente'}
    script=ROOT/old_version/'extensions/cache_proxy.py'
    if script.is_symlink() or not script.is_file() or script.stat().st_uid or script.stat().st_mode&0o022:
        raise RetireError('Motore legacy non verificato: interruzione prima di qualsiasi modifica')
    # Existing code uses an exact per-profile NAT journal and refuses foreign rules.
    result=execute('/usr/bin/python3','-B',str(script),'disable',timeout=65)
    try:report=json.loads(result.stdout)
    except ValueError as exc:raise RetireError('Risposta disattivazione legacy non valida') from exc
    if report.get('ok') is not True or report.get('redirect') is not False:
        raise RetireError('Disattivazione non verificata')
    # Stop an outstanding oneshot after its timer has been disabled.
    execute('systemctl','stop','iptm-cache-redirect.service',timeout=20,check=False)
    for unit in ('iptm-cache-proxy.service','iptm-cache-redirect.timer','iptm-cache-redirect.service'):
        if service_state(unit) in ('active','activating','reloading'):
            raise RetireError('Unità ancora attiva: '+unit)
    remain=nat_residue()
    if remain:raise RetireError('Rimozione NAT incompleta; nessuna cancellazione di file: '+','.join(remain))
    if REDIRECT.exists():raise RetireError('Journal redirect rimasto: non posso dichiarare disattivazione')
    # Remove ONLY files with the IPTM marker, and only IPTM-namespaced paths.
    for path in present_units:path.unlink()
    if present_units:execute('systemctl','daemon-reload',timeout=20)
    for d in DIRECTORIES:
        if d.exists():shutil.rmtree(d)
    if LEGACY_LOG.exists():LEGACY_LOG.unlink()
    return {'ok':True,'retired':True,'removed_units':[p.name for p in present_units],
            'packages_removed':False,'firewall_other_rules_changed':False}


def main(args):
    if len(args)!=2 or args[0]!='apply':raise RetireError('Uso: apply <versione-precedente>')
    return retire(args[1])

if __name__=='__main__':
    try:print(json.dumps(main(sys.argv[1:]),ensure_ascii=False))
    except (RetireError,OSError,ValueError) as exc:
        print(json.dumps({'ok':False,'error':str(exc)[:450]},ensure_ascii=False));sys.exit(1)
