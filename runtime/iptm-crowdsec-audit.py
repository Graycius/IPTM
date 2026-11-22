#!/usr/bin/env python3
"""Read-only CrowdSec acquisition inventory. Never guesses that a parser is installed."""
import argparse
import json
import os
import pathlib
import shutil
import subprocess
import sys
import ipaddress

# Names below are real CrowdSec Hub collections; use local cscli to verify
# availability/installation rather than creating an imaginary parser.
SOURCES = (
    ('SSH', 'crowdsecurity/linux', ('/var/log/auth.log', '/var/log/secure'), 'syslog', 'journalctl -u ssh'),
    ('Kernel iptables', 'crowdsecurity/iptables', ('/var/log/kern.log', '/var/log/syslog'), 'syslog', 'journalctl -k'),
    ('Nginx', 'crowdsecurity/nginx', ('/var/log/nginx/access.log',), 'nginx', ''),
    ('Apache', 'crowdsecurity/apache2', ('/var/log/apache2/access.log',), 'apache2', ''),
    ('Suricata', 'crowdsecurity/suricata', ('/var/log/suricata/eve.json',), 'suricata', ''),
    ('Traefik', 'crowdsecurity/traefik', ('/var/log/traefik/access.log',), 'traefik', ''),
    ('Caddy', 'crowdsecurity/caddy', ('/var/log/caddy/access.log',), 'caddy', ''),
    ('Nextcloud', 'crowdsecurity/nextcloud', ('/var/www/nextcloud/data/nextcloud.log', '/var/lib/nextcloud/data/nextcloud.log'), 'nextcloud', ''),
)

def command(args, timeout=3):
    try:
        p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           text=True, timeout=timeout, check=False)
        return p.returncode, p.stdout[:300000]
    except (OSError, subprocess.TimeoutExpired):
        return 124, ''

def inspect():
    cs = shutil.which('cscli')
    local_installed = set()
    local_available = set()
    status = 'unavailable'
    if cs:
        rc, raw = command([cs, 'collections', 'list', '-o', 'json'], 5)
        if rc == 0:
            try:
                values = json.loads(raw)
                if isinstance(values, dict):
                    values = values.get('collections') or values.get('items') or []
                if isinstance(values, list):
                    for item in values:
                        if isinstance(item, dict):
                            name = str(item.get('name', item.get('Name', '')))
                            if name and (item.get('installed') or item.get('enabled') or str(item.get('status', '')).lower() in ('enabled', 'installed')):
                                local_installed.add(name)
                    status = 'ok'
            except (ValueError, TypeError):
                status = 'unparsed'
        rc, raw = command([cs, 'collections', 'list', '-a', '-o', 'json'], 5)
        if rc == 0:
            try:
                values = json.loads(raw)
                if isinstance(values, dict):
                    values = values.get('collections') or values.get('items') or []
                if isinstance(values, list):
                    for item in values:
                        if isinstance(item, dict):
                            name = str(item.get('name', item.get('Name', '')))
                            if name:
                                local_available.add(name)
                            if name and (item.get('installed') or item.get('enabled') or str(item.get('status', '')).lower() in ('enabled', 'installed')):
                                local_installed.add(name)
                    status = 'ok'
            except (ValueError, TypeError):
                pass
    rows = []
    for title, collection, paths, label, journal in SOURCES:
        existing = []
        for name in paths:
            try:
                p = pathlib.Path(name)
                if p.is_file() and not p.is_symlink():
                    existing.append(name)
            except OSError:
                pass
        rows.append({
            'service': title, 'collection': collection, 'label': label,
            'paths': existing, 'journal_hint': journal,
            'collection_installed': collection in local_installed,
            'collection_available_locally': collection in local_available,
            'state': 'candidate' if existing else ('journal-check' if journal else 'no-log'),
        })
    return {'ok': True, 'cscli': bool(cs), 'hub_status': status, 'sources': rows,
            'note': 'Inventario in sola lettura. I parser sono verificati solo se cscli restituisce metadati validi. Non installa collezioni né acquisizioni.'}

def integration_status():
    """Inventory of locally installed tools; never launches third-party stacks."""
    capabilities = {'crowdsec':bool(shutil.which('cscli')),
                    'suricata':bool(shutil.which('suricata')),
                    'suricata_update':bool(shutil.which('suricata-update')),
                    'networkmanager':bool(shutil.which('nmcli')),
                    'evebox':bool(shutil.which('evebox')),
                    'crowdsec_manager':bool(shutil.which('crowdsec-manager')),
                    'crowdsec_blocklist_import':bool(shutil.which('crowdsec-blocklist-import'))}
    services={}
    for name in ('crowdsec','suricata','NetworkManager','evebox'):
        if shutil.which('systemctl'):
            rc,output=command(['systemctl','is-active',name+'.service'],2)
            services[name]=output.strip() if rc==0 and output.strip()=='active' else 'not-active-or-unavailable'
        else: services[name]='unknown'
    return {'mode':'read-only','capabilities':capabilities,'services':services,
            'sources':['https://github.com/hhftechnology/crowdsec_manager',
                       'https://github.com/wolffcatskyy/crowdsec-blocklist-import',
                       'https://github.com/StamusNetworks/scirius',
                       'https://github.com/jasonish/evebox',
                       'https://github.com/cockpit-project/cockpit'],
            'no_remote_install':True,'no_implicit_firewall_changes':True}


def preview_blocklist(lines, protected=()):
    """Normalize public IPv4/IPv6 candidates. Refuse any management overlap.

    No reserved/private/global-unroutable ranges are returned. This is staging,
    not an import into CrowdSec or a firewall.
    """
    keep=set(); discarded=0
    protected_networks=[ipaddress.ip_network(x,strict=False) for x in protected]
    for line in lines:
        value=line.split('#',1)[0].strip()
        if not value:continue
        try:net=ipaddress.ip_network(value,strict=False)
        except ValueError:
            discarded+=1;continue
        if not net.is_global or any(net.overlaps(n) for n in protected_networks):
            discarded+=1;continue
        if len(keep)>=200000:raise ValueError('too-many-entries')
        keep.add(str(net))
    return {'mode':'preview-only','entries':sorted(keep),
            'accepted':len(keep),'discarded':discarded,'applied':False}


# IPTM integrated local-only security orchestration (5.4.8)

import hashlib
import tempfile
import re
from pathlib import Path
MAX_BYTES = 3_000_000
MAX_ITEMS = 10000  # Conservative limit on resource constrained gateways
STATE_DIR = Path('/var/lib/iptm-integrations')
IFACE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,31}$')

class IntegrationError(ValueError): pass

def ic_command(args, *, timeout=7):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                           stdin=subprocess.DEVNULL, check=False)
        return p.returncode, p.stdout[:256000]
    except (OSError, subprocess.TimeoutExpired):
        return 124, ''

def parse_feed(text, protected=()):
    if len(text.encode('utf-8'))>MAX_BYTES:raise IntegrationError('feed-too-large')
    guards=[ipaddress.ip_network(n, strict=False) for n in protected]
    accepted=set(); rejected=0
    for line in text.splitlines():
        line=line.split('#',1)[0].strip()
        if not line:continue
        try: network=ipaddress.ip_network(line,strict=False)
        except ValueError:
            rejected+=1;continue
        if not network.is_global or any(network.overlaps(g) for g in guards):
            rejected+=1;continue
        accepted.add(str(network))
        if len(accepted)>MAX_ITEMS:raise IntegrationError('too-many-entries')
    return {'accepted':sorted(accepted), 'count':len(accepted), 'rejected':rejected}

def nm_inventory():
    """Never requires root or modifies a connection."""
    result={'installed':bool(shutil.which('nmcli')),'devices':[], 'profiles':[], 'mode':'read-only'}
    if not result['installed']:return result
    for field,cmd in [('devices',['nmcli','-t','-f','DEVICE,TYPE,STATE,CONNECTION','device','status']),
                      ('profiles',['nmcli','-t','-f','NAME,UUID,TYPE,DEVICE','connection','show'])]:
        rc,out=ic_command(cmd)
        result[field+'_verified']=rc==0
        if rc==0:
            # Escape sequences and credentials are never exposed to the UI.
            result[field]=[re.sub(r'[\x00-\x1f\x7f]', '',line)[:256] for line in out.splitlines()[:128]]
    return result

def suricata_inventory():
    result={'suricata':bool(shutil.which('suricata')),
            'suricata_update':bool(shutil.which('suricata-update')),
            'evebox':bool(shutil.which('evebox')),
            'mode':'read-only'}
    for name,cmd in [('engine',['suricata','--build-info']),
                     ('rules',['suricata-update','list-enabled-sources'])]:
        if not shutil.which(cmd[0]):continue
        rc,out=ic_command(cmd,timeout=6)
        result[name+'_available']=rc==0
        # No unbounded logs or absolute paths in the frontend.
        if name=='rules' and rc==0:result['enabled_sources']=out.splitlines()[:64]
    for fname in ('/var/log/suricata/eve.json','/var/lib/suricata/rules/suricata.rules'):
        p=Path(fname)
        result['eve_present' if fname.endswith('.json') else 'rules_present']=p.is_file() and not p.is_symlink()
    return result

def crowdsec_inventory():
    result={'cscli':bool(shutil.which('cscli')),'mode':'read-only'}
    if not result['cscli']:return result
    for field,args in [('decisions',['cscli','decisions','list','-o','json']),
                       ('collections',['cscli','collections','list','-o','json'])]:
        rc,out=ic_command(args)
        result[field+'_available']=rc==0
        if rc==0:
            try:
                parsed=json.loads(out)
                result[field+'_count']=len(parsed) if isinstance(parsed,list) else None
            except (ValueError,TypeError):result[field+'_count']=None
    return result

def inventory():return {'version':1,'networkmanager':nm_inventory(),
                        'suricata':suricata_inventory(),'crowdsec':crowdsec_inventory(),
                        'mutations_enabled':False}

def secure_state():
    if STATE_DIR.is_symlink():raise IntegrationError('unsafe-state-directory')
    STATE_DIR.mkdir(mode=0o700,parents=True,exist_ok=True)
    s=STATE_DIR.stat()
    if s.st_uid!=0 or s.st_mode&0o077:raise IntegrationError('unsafe-state-permissions')

def stage(source, guards):
    if os.geteuid()!=0:raise IntegrationError('root-required')
    if not source.is_absolute() or source.is_symlink() or not source.is_file():
        raise IntegrationError('regular-absolute-source-required')
    st=source.stat()
    if st.st_uid!=0 or st.st_mode&0o022 or st.st_size>MAX_BYTES:
        raise IntegrationError('unsafe-feed-file')
    secure_state()
    data=parse_feed(source.read_text(encoding='utf-8'), guards)
    if not data['count']:raise IntegrationError('empty-valid-feed')
    payload='\n'.join(data['accepted'])+'\n'
    digest=hashlib.sha256(payload.encode()).hexdigest()
    tmpfd, tmpname=tempfile.mkstemp(prefix='.stage-',dir=STATE_DIR)
    try:
        with os.fdopen(tmpfd,'w') as f:
            os.fchmod(f.fileno(),0o600)
            f.write(payload);f.flush();os.fsync(f.fileno())
        os.replace(tmpname,STATE_DIR/'staged.txt')
    finally:
        if os.path.exists(tmpname):os.unlink(tmpname)
    return {'state':'staged','sha256':digest,'accepted':data['count'],
            'rejected':data['rejected'],'applied':False}

def import_stage(digest, duration):
    """Explicit root console import; never tries to delete existing decisions."""
    if os.geteuid()!=0 or not os.isatty(0):raise IntegrationError('interactive-root-console-required')
    if not re.fullmatch(r'[0-9a-f]{64}',digest):raise IntegrationError('invalid-sha256')
    if duration not in ('1h','4h','12h','24h'):raise IntegrationError('invalid-duration')
    secure_state()
    staged=STATE_DIR/'staged.txt'
    if staged.is_symlink() or not staged.is_file() or staged.stat().st_uid!=0 or staged.stat().st_mode&0o077:
        raise IntegrationError('unsafe-stage')
    raw=staged.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=digest:raise IntegrationError('stage-changed')
    if not shutil.which('cscli'):raise IntegrationError('cscli-missing')
    # Explicit --format values, as documented by the CrowdSec CLI.
    rc,out=ic_command(['cscli','decisions','import','-i',str(staged),'--format','values',
                    '--duration',duration],timeout=45)
    if rc!=0:raise IntegrationError('cscli-import-failed')
    return {'state':'imported','count':len(raw.splitlines()),'duration':duration,
            'note':'Decisions expire via CrowdSec; inspect cscli for effective entries'}

def main(argv=None):
    p=argparse.ArgumentParser()
    p.add_argument('action',choices=['status','stage','import'])
    p.add_argument('arg',nargs='?')
    p.add_argument('--protect',action='append',default=[])
    p.add_argument('--duration',choices=['1h','4h','12h','24h'],default='4h')
    args=p.parse_args(argv)
    try:
        if args.action=='status':res=inventory()
        elif args.action=='stage':
            if not args.arg:raise IntegrationError('source-missing')
            res=stage(Path(args.arg),args.protect)
        else:
            if not args.arg:raise IntegrationError('digest-missing')
            res=import_stage(args.arg,args.duration)
        print(json.dumps(res,ensure_ascii=False));return 0
    except (IntegrationError,UnicodeError,OSError,ValueError) as exc:
        print(json.dumps({'error':str(exc)}));return 2



def eve_summary(path=Path('/var/log/suricata/eve.json'), max_bytes=524288):
    """Bounded tail reader; alert aggregation only, no stored packet payloads/IPs."""
    if path.is_symlink() or not path.is_file():
        return {'available':False,'alerts':0,'reason':'eve-unavailable'}
    st=path.stat()
    if st.st_size<0 or st.st_size>2**42:raise IntegrationError('eve-size-invalid')
    with path.open('rb') as stream:
        size=st.st_size
        stream.seek(max(0,size-max_bytes))
        payload=stream.read(max_bytes)
    lines=payload.split(b'\n')
    if size>max_bytes:lines=lines[1:]
    aggregate={}; parsed=0; alerts=0
    for raw in lines[:10000]:
        if not raw or len(raw)>65536:continue
        try:ev=json.loads(raw)
        except (ValueError,UnicodeError):continue
        if not isinstance(ev,dict) or ev.get('event_type')!='alert':continue
        parsed+=1
        alert=ev.get('alert') or {}
        if not isinstance(alert,dict):continue
        try:severity=int(alert.get('severity',0))
        except (ValueError,TypeError):severity=0
        sid=alert.get('signature_id')
        if not isinstance(sid,int) or sid<0 or sid>2**31:continue
        alerts+=1
        key=(sid,severity)
        aggregate[key]=aggregate.get(key,0)+1
    top=sorted(aggregate.items(),key=lambda x:(-x[1],x[0]))[:15]
    return {'available':True,'source':'eve-json-bounded-tail', 'alerts':alerts,
            'sample_bytes':min(size,max_bytes),'top_signatures':[
            {'sid':sid,'severity':sev,'count':n} for ((sid,sev),n) in top],
            'privacy':'no-src-or-dst-addresses-returned'}


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--json', action='store_true')
    ap.add_argument('--integration-status', action='store_true')
    ap.add_argument('--eve-summary', action='store_true')
    ap.add_argument('--stage-file')
    ap.add_argument('--import-stage')
    ap.add_argument('--duration', choices=['1h','4h','12h','24h'], default='4h')
    ap.add_argument('--integrations', action='store_true')
    ap.add_argument('--preview-feed', action='store_true')
    ap.add_argument('--protect', action='append', default=[])
    args=ap.parse_args()
    if args.eve_summary:
        try:print(json.dumps(eve_summary(),ensure_ascii=False))
        except (IntegrationError,OSError) as exc:
            print(json.dumps({'error':str(exc)}));sys.exit(2)
    elif args.integration_status:
        print(json.dumps(inventory(), ensure_ascii=False))
    elif args.stage_file or args.import_stage:
        try:
            result = stage(Path(args.stage_file),args.protect) if args.stage_file else import_stage(args.import_stage,args.duration)
            print(json.dumps(result,ensure_ascii=False))
        except (IntegrationError,UnicodeError,OSError,ValueError) as exc:
            print(json.dumps({'error':str(exc)}));sys.exit(2)
    elif args.preview_feed:
        try:
            # Local stdin only; no arbitrary URL fetch from privileged web process.
            data=sys.stdin.read(3*1024*1024+1)
            if len(data)>3*1024*1024:raise ValueError('input-too-large')
            print(json.dumps(preview_blocklist(data.splitlines(),args.protect),ensure_ascii=False))
        except ValueError as exc:
            print(json.dumps({'error':str(exc)}));sys.exit(2)
    else:print(json.dumps(integration_status() if args.integrations else inspect(), ensure_ascii=False))
