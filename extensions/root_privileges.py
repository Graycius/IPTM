#!/usr/bin/env python3
"""Read-only privileged access assessment for staged sudoers migration.

This deliberately does not rewrite sudoers. Retiring the existing helper's
sudo grant before an on-device command-by-command validation can lock admins
out of their gateway. See migration roadmap in MIGRATION.md.
"""
from __future__ import annotations
import json, os, pathlib, sys, stat, shutil
from command_transport import capture

HELPER='/usr/local/sbin/iptm-helper'
SUDOERS=pathlib.Path('/etc/sudoers')
DROPIN=pathlib.Path('/etc/sudoers.d')

class AuditError(Exception):pass

def find_rules():
    if os.geteuid()!=0:raise AuditError('Verifica sudoers riservata a root')
    files=[SUDOERS]
    if DROPIN.is_dir() and not DROPIN.is_symlink():
        files.extend(sorted(p for p in DROPIN.iterdir() if '.' not in p.name and not p.name.endswith('~')))
    warnings=[];matches=[]
    for path in files:
        if path.is_symlink() or not path.is_file():warnings.append('non regular: '+path.name);continue
        st=path.stat()
        if st.st_uid!=0 or st.st_mode & 0o022 or st.st_nlink!=1:
            warnings.append('unsafe permissions: '+path.name);continue
        try:
            fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            with os.fdopen(fd,'rb') as handle:
                meta=os.fstat(handle.fileno())
                if not stat.S_ISREG(meta.st_mode) or meta.st_uid!=0 or meta.st_mode&0o022 or meta.st_nlink!=1:raise OSError('file non sicuro')
                raw=handle.read(262145)
            if len(raw)>262144:
                warnings.append('file too large: '+path.name);continue
            text=raw.decode('utf-8','replace')
        except OSError:
            warnings.append('unreadable: '+path.name);continue
        for no,line in enumerate(text.splitlines(),1):
            line=line.strip()
            if not line or line.startswith('#'):continue
            if 'NOPASSWD' in line or HELPER in line:
                # Do not expose any exact command arguments from the host.
                broad='NOPASSWD' in line and ('ALL' in line or '/bin/' in line and '*' in line)
                matches.append({'source':path.name,'line':no,'has_nopasswd':bool('NOPASSWD' in line),
                                'mentions_helper':bool(HELPER in line),'needs_review':broad or '*' in line})
    syntax='unavailable'
    visudo=shutil.which('visudo')
    if visudo:
        try:syntax='valid' if capture([visudo,'-c'],timeout=10,stdout_limit=65536,stderr_limit=65536).returncode==0 else 'invalid'
        except (OSError,ValueError):syntax='unavailable'
    return {'ok':True,'readonly':True,'mode':'audit-only','syntax':syntax,
            'helper_path':HELPER,'rules_found':len(matches),'rules':matches,
            'warnings':warnings,'ready_for_replacement':False,
            'required_next_step':'Verify all current web, CLI and cron commands before narrowing any live sudoers rule.'}

if __name__=='__main__':
    try:print(json.dumps(find_rules()))
    except (AuditError,OSError) as exc:
        print(json.dumps({'ok':False,'error':str(exc)}));sys.exit(1)
