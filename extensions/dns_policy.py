#!/usr/bin/env python3
"""Transactional Unbound hardening profiles for IPTM. All inputs are allowlisted."""
import json,os,pathlib,re,shutil,stat,subprocess,sys,tempfile
from datetime import datetime,timezone
PROFILES={
'balanced':{'hide-identity':'yes','hide-version':'yes','harden-glue':'yes','harden-dnssec-stripped':'yes','qname-minimisation':'yes','qname-minimisation-strict':'no','aggressive-nsec':'yes','prefetch':'yes','minimal-responses':'yes','log-queries':'no','log-replies':'no'},
'strict':{'hide-identity':'yes','hide-version':'yes','harden-glue':'yes','harden-dnssec-stripped':'yes','qname-minimisation':'yes','qname-minimisation-strict':'yes','aggressive-nsec':'yes','prefetch':'yes','minimal-responses':'yes','log-queries':'no','log-replies':'no'},
'compatible':{'hide-identity':'yes','hide-version':'yes','harden-glue':'yes','harden-dnssec-stripped':'yes','qname-minimisation':'yes','qname-minimisation-strict':'no','aggressive-nsec':'yes','prefetch':'no','minimal-responses':'no','log-queries':'no','log-replies':'no'},
}
MARK='# IPTM managed Unbound hardening v3.9.115'
CONF=pathlib.Path('/etc/unbound/unbound.conf.d/iptm-hardening.conf')
MAIN=pathlib.Path('/etc/unbound/unbound.conf')
BACKUP=pathlib.Path('/var/lib/iptables-manager/backups/unbound-managed')
def fail(msg):raise RuntimeError(msg)
def command(argv,timeout=15):
 p=subprocess.run(argv,timeout=timeout,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
 if p.returncode:fail(' '.join(argv[:2])+' non riuscito: '+(p.stderr or p.stdout)[-400:])
 return p.stdout
def secure(path):
 if path.is_symlink():fail('Symlink non consentito: '+str(path))
 if path.exists():
  st=path.lstat()
  if not stat.S_ISREG(st.st_mode) or st.st_uid!=0:fail('File non regolare o non posseduto da root: '+str(path))
def data(profile):return MARK+'\nserver:\n'+''.join('    '+k+': '+v+'\n' for k,v in sorted(PROFILES[profile].items()))
def run(profile,mode):
 if profile not in PROFILES:fail('Profilo non previsto')
 secure(MAIN);secure(CONF)
 if not MAIN.is_file():fail('Unbound non configurato nel percorso standard')
 cfg=MAIN.read_text(errors='replace')
 if not re.search(r'(?m)^\s*include(?:-toplevel)?:\s*["\']?/etc/unbound/unbound\.conf\.d/\*\.conf',cfg):
  fail('File principale non include /etc/unbound/unbound.conf.d/*.conf: nessuna modifica')
 for p in (CONF.parent, BACKUP):
  if p.is_symlink():fail('Directory backup/config symlink')
  if p.exists() and (p.stat().st_uid!=0 or (p.stat().st_mode&0o022)):fail('Directory scrivibile da non-root')
 old=CONF.read_bytes() if CONF.exists() else None
 if old is not None and not old.startswith(MARK.encode()):fail('Configurazione Unbound personalizzata: non sovrascrivo')
 proposed=data(profile).encode()
 if mode=='preview':
  print(json.dumps({'ok':True,'profile':profile,'changed':old!=proposed,'config':proposed.decode(),'note':'Non cambia listener, forwarder né upstream. Nessun riavvio in anteprima.'}));return
 if os.geteuid()!=0:fail('Richiede root')
 if shutil.which('unbound-checkconf') is None:fail('unbound-checkconf assente')
 if old==proposed:
  print(json.dumps({'ok':True,'changed':False,'profile':profile}));return
 command(['unbound-checkconf'],12)
 CONF.parent.mkdir(parents=True,exist_ok=True)
 BACKUP.mkdir(parents=True,exist_ok=True,mode=0o700)
 os.chmod(BACKUP,0o700)
 stamp=datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')
 if old is not None:
  dest=BACKUP/('iptm-hardening.'+stamp+'.conf')
  with open(dest,'xb') as fd:fd.write(old)
  dest.chmod(0o600)
 live=subprocess.run(['systemctl','is-active','--quiet','unbound'],timeout=8,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0
 tmp=None
 try:
  with tempfile.NamedTemporaryFile(dir=CONF.parent,prefix='.iptm-unbound-',delete=False) as fd:
   tmp=pathlib.Path(fd.name);os.fchmod(fd.fileno(),0o644);fd.write(proposed);fd.flush();os.fsync(fd.fileno())
  os.replace(tmp,CONF);tmp=None
  command(['unbound-checkconf'],12)
  if live:command(['systemctl','reload','unbound'],25)
  # Only if the currently installed profile uses the standard local port.
  # A failure during this optional probe does NOT change custom Unbound ports.
  if live and shutil.which('dig') is not None:
   listener=''.join([cfg,proposed.decode()])
   if re.search(r'(?m)^\s*port:\s*5335\s*$',listener):
    command(['dig','+time=2','+tries=1','@127.0.0.1','-p','5335','example.com','A','+short'],10)
 except BaseException:
  if tmp is not None:tmp.unlink(missing_ok=True)
  if old is None:CONF.unlink(missing_ok=True)
  else:
   with tempfile.NamedTemporaryFile(dir=CONF.parent,delete=False) as fb:
    t=pathlib.Path(fb.name);os.fchmod(fb.fileno(),0o644);fb.write(old);fb.flush();os.fsync(fb.fileno())
   os.replace(t,CONF)
  if live:
   try:command(['systemctl','reload','unbound'],25)
   except Exception:pass
  raise
 backups=sorted(BACKUP.glob('iptm-hardening.*.conf'),key=lambda p:p.stat().st_mtime,reverse=True)
 for oldfile in backups[10:]:
  if not oldfile.is_symlink() and oldfile.is_file():oldfile.unlink()
 print(json.dumps({'ok':True,'changed':True,'profile':profile,'backup':str(dest) if old is not None else None,'reloaded':live,'note':'Configurazione validata; rollback locale in caso di errore.'}))
if __name__=='__main__':
 try:
  if len(sys.argv)!=3 or sys.argv[1] not in ('preview','apply'):fail('Uso: preview|apply balanced|strict|compatible')
  run(sys.argv[2],sys.argv[1])
 except Exception as exc:
  print(json.dumps({'ok':False,'error':str(exc)}));sys.exit(1)
