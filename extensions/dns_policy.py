#!/usr/bin/env python3
"""Transactional Unbound hardening profiles for IPTM. All inputs are allowlisted."""

from command_transport import capture
import json,os,pathlib,re,shutil,stat,subprocess,sys,tempfile,fcntl,secrets
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
 p=capture(argv,timeout=timeout)
 if p.returncode:fail(' '.join(argv[:2])+' non riuscito: '+(p.stderr or p.stdout)[-400:])
 return p.stdout
def secure(path):
 if path.is_symlink():fail('Symlink non consentito: '+str(path))
 if path.exists():
  st=path.lstat()
  if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_mode&0o022:fail('File non regolare o non protetto: '+str(path))
def data(profile):return MARK+'\nserver:\n'+''.join('    '+k+': '+v+'\n' for k,v in sorted(PROFILES[profile].items()))
def probe_dns_answer(output):
 import ipaddress
 for line in output.splitlines():
  try:
   if ipaddress.ip_address(line.strip()).version==4:return True
  except ValueError:continue
 return False

def validate_dns_response(output,query):
 """Check an actual complete A response, following one unambiguous CNAME chain."""
 import ipaddress
 headers=re.findall(r'(?m)^;; ->>HEADER<<-.*status: ([A-Z]+),',output)
 flags=re.findall(r'(?m)^;; flags: ([^;]*); QUERY: (\d+), ANSWER: (\d+),',output)
 if headers!=['NOERROR'] or len(flags)!=1:return False
 bits,questions,count=flags[0];bits=bits.split()
 if 'qr' not in bits or 'tc' in bits or questions!='1' or int(count)<1:return False
 sections={};current=None
 for line in output.splitlines():
  m=re.match(r'^;; (QUESTION|ANSWER) SECTION:',line)
  if m:
   current=m.group(1)
   if current in sections:return False
   sections[current]=[];continue
  if line.startswith(';;') or not line.strip():current=None;continue
  if current:sections[current].append(line)
 name=query.lower().rstrip('.')+'.'
 question=[row.lstrip(';').lower().split() for row in sections.get('QUESTION',[])]
 if question!=[[name,'in','a']] or len(sections.get('ANSWER',[]))!=int(count):return False
 aliases={};addresses=set()
 for row in sections['ANSWER']:
  fields=row.split()
  if len(fields)<5 or fields[2].upper()!='IN':continue
  owner,ttl,_,kind=fields[:4];owner=owner.lower();kind=kind.upper()
  if kind not in ('CNAME','A'):continue
  if len(fields)!=5 or not ttl.isdigit():return False
  value=fields[4].lower()
  if kind=='CNAME':
   if not value.endswith('.') or (owner in aliases and aliases[owner]!=value):return False
   aliases[owner]=value
  else:
   try:
    if ipaddress.ip_address(value).version!=4:return False
   except ValueError:return False
   addresses.add(owner)
 if addresses.intersection(aliases):return False
 seen=set()
 while name not in seen:
  if name in addresses:return True
  seen.add(name)
  if name not in aliases:return False
  name=aliases[name]
 return False

def run(profile,mode):
 if mode not in ('preview','apply'):fail('Modalità non valida')
 if mode=='preview':return _run(profile,mode)
 if os.geteuid()!=0:fail('Richiede root')
 from command_transport import transaction_gate
 with transaction_gate(domain='/run/lock/iptm-unbound-hardening.lock'):
  return _run(profile,mode)

def _run(profile,mode):
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
 stamp=datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')+'-'+secrets.token_hex(3)
 if old is not None:
  dest=BACKUP/('iptm-hardening.'+stamp+'.conf')
  from command_transport import durable_replace
  durable_replace(dest,old,create_only=True)
 live=capture(['systemctl', 'is-active', '--quiet', 'unbound'], timeout=8, text=False, stdout_limit=1048576, stderr_limit=262144).returncode==0
 from command_transport import durable_replace,durable_unlink,StatePublishError
 published=False
 try:
  try:
   durable_replace(CONF,proposed,mode=0o644)
   published=True
  except StatePublishError as exc:
   published=exc.published
   raise
  command(['unbound-checkconf'],12)
  if live:command(['systemctl','reload','unbound'],25)
  # Only if the currently installed profile uses the standard local port.
  # A failure during this optional probe does NOT change custom Unbound ports.
  if live and shutil.which('dig') is not None:
   listener=''.join([cfg,proposed.decode()])
   if re.search(r'(?m)^\s*port:\s*5335\s*$',listener):
    answer=command(['dig','+time=2','+tries=1','@127.0.0.1','-p','5335','example.com','A','+noall','+comments','+question','+answer'],10)
    if not validate_dns_response(answer,'example.com'):fail('Test DNS: nessuna risposta IPv4 valida')
 except BaseException as original:
  if published:
   try:
    if old is None:durable_unlink(CONF)
    else:durable_replace(CONF,old,mode=0o644)
    if live:command(['systemctl','reload','unbound'],25)
   except Exception as rollback:
    raise RuntimeError('Rollback Unbound non verificato: '+str(rollback)) from original
  raise
 print(json.dumps({'ok':True,'changed':True,'profile':profile,'backup':str(dest) if old is not None else None,'reloaded':live,'note':'Configurazione validata; rollback locale in caso di errore.'}))
if __name__=='__main__':
 try:
  if len(sys.argv)!=3 or sys.argv[1] not in ('preview','apply'):fail('Uso: preview|apply balanced|strict|compatible')
  run(sys.argv[2],sys.argv[1])
 except Exception as exc:
  print(json.dumps({'ok':False,'error':str(exc)}));sys.exit(1)
