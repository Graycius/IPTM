#!/usr/bin/env python3
"""Read-only privileged access assessment for staged sudoers migration.

This deliberately does not rewrite sudoers. Retiring the existing helper's
sudo grant before an on-device command-by-command validation can lock admins
out of their gateway. See migration roadmap in MIGRATION.md.
"""
from __future__ import annotations
import json, os, pathlib, sys

HELPER='/usr/local/sbin/iptm-helper'
SUDOERS=pathlib.Path('/etc/sudoers')
DROPIN=pathlib.Path('/etc/sudoers.d')

class AuditError(Exception):pass

def find_rules():
    if os.geteuid()!=0:raise AuditError('Verifica sudoers riservata a root')
    files=[SUDOERS]
    if DROPIN.is_dir() and not DROPIN.is_symlink():
        files.extend(sorted(p for p in DROPIN.iterdir() if not p.name.startswith('.') and not p.name.endswith('~')))
    warnings=[];matches=[]
    for path in files:
        if path.is_symlink() or not path.is_file():warnings.append('non regular: '+path.name);continue
        st=path.stat()
        if st.st_uid!=0 or st.st_mode & 0o022:
            warnings.append('unsafe permissions: '+path.name);continue
        try:text=path.read_text(errors='replace')
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
    return {'ok':True,'readonly':True,'mode':'audit-only',
            'helper_path':HELPER,'rules_found':len(matches),'rules':matches,
            'warnings':warnings,'ready_for_replacement':False,
            'required_next_step':'Verify all current web, CLI and cron commands before narrowing any live sudoers rule.'}

if __name__=='__main__':
    try:print(json.dumps(find_rules()))
    except (AuditError,OSError) as exc:
        print(json.dumps({'ok':False,'error':str(exc)}));sys.exit(1)
