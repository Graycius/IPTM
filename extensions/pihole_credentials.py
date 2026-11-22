#!/usr/bin/env python3
"""Root-only local Pi-hole v6 application-password storage, not a password API.

The web panel can SAVE/DELETE/CHECK presence but cannot retrieve the secret.
A distinct root-owned key encrypts the password on disk through GnuPG AES256.
Encryption on the same host does not defend against root compromise.
"""
from __future__ import annotations
import base64, fcntl, json, os, pathlib, secrets, shutil, subprocess, sys, tempfile

STORE = pathlib.Path('/etc/iptables-manager-secrets')
KEY = STORE/'storage.key'
SECRET = STORE/'pihole-password.gpg'
LOCK = STORE/'pihole.lock'

class SecretError(Exception): pass

def ensure_root():
    if os.geteuid()!=0:raise SecretError('Operazione riservata a root')

def safe_regular(p, mode_private=True):
    if p.is_symlink() or not p.is_file():raise SecretError('File segreto non regolare')
    st=p.stat()
    if st.st_uid!=0 or (st.st_mode & (0o077 if mode_private else 0o022)):
        raise SecretError('Permessi file segreto non sicuri')

def ensure_store(create=False):
    ensure_root()
    if not STORE.exists() and create:
        STORE.mkdir(mode=0o700)
    if not STORE.exists():return False
    if STORE.is_symlink() or not STORE.is_dir():raise SecretError('Archivio segreti non regolare')
    st=STORE.stat()
    if st.st_uid!=0 or st.st_mode & 0o077:raise SecretError('Archivio segreti non protetto')
    return True

def create_key():
    if KEY.exists() or KEY.is_symlink():
        safe_regular(KEY);return
    # create with O_EXCL|O_NOFOLLOW to avoid clobbering attacker paths
    fd=os.open(KEY,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,'wb') as f:
            f.write(base64.urlsafe_b64encode(secrets.token_bytes(48)))
            f.flush();os.fsync(f.fileno())
    finally:pass

def gpg_crypt(mode,blob):
    if not shutil.which('gpg'):raise SecretError('GnuPG richiesto per archivio cifrato')
    safe_regular(KEY)
    fd=os.open(KEY,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        base=['gpg','--no-options','--no-tty','--batch','--yes','--pinentry-mode','loopback','--passphrase-fd',str(fd)]
        if mode=='encrypt':base+=['--cipher-algo','AES256','--symmetric','--output','-']
        elif mode=='decrypt':base+=['--decrypt','--output','-']
        else:raise SecretError('Operazione crittografica non valida')
        proc=subprocess.run(base,input=blob,pass_fds=(fd,),stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=25)
        if proc.returncode or len(proc.stdout)>8192:raise SecretError('Cifratura o decrittazione fallita')
        return proc.stdout
    finally:os.close(fd)

def get_password():
    ensure_root()
    if not ensure_store() or not SECRET.exists():return ''
    safe_regular(SECRET)
    if SECRET.stat().st_size>8192:raise SecretError('Archivio password troppo grande')
    result=gpg_crypt('decrypt',SECRET.read_bytes())
    try:pw=result.decode('utf-8')
    except UnicodeDecodeError:raise SecretError('Password memorizzata non valida')
    if not 1<=len(pw)<=256 or '\0' in pw or '\n' in pw or '\r' in pw:raise SecretError('Password memorizzata non valida')
    return pw

def status():
    ensure_root()
    if not ensure_store():return {'ok':True,'stored':False}
    if SECRET.exists() or SECRET.is_symlink():
        safe_regular(SECRET)
        return {'ok':True,'stored':True,'updated_at':int(SECRET.stat().st_mtime)}
    return {'ok':True,'stored':False}

def write_password(pw):
    ensure_store(create=True)
    if not isinstance(pw,str) or not (8<=len(pw)<=256) or any(c in pw for c in ('\0','\r','\n')):
        raise SecretError('Password Pi-hole non valida (8-256 caratteri, senza newline)')
    create_key()
    encrypted=gpg_crypt('encrypt',pw.encode('utf-8'))
    tmpfd,tmp=tempfile.mkstemp(prefix='.pihole-',dir=STORE)
    try:
        with os.fdopen(tmpfd,'wb') as f:
            os.fchmod(f.fileno(),0o600);f.write(encrypted);f.flush();os.fsync(f.fileno())
        os.replace(tmp,SECRET)
        dfd=os.open(STORE,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(dfd)
        finally:os.close(dfd)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)
    return {'ok':True,'stored':True}

def run():
    ensure_root()
    action=sys.argv[1] if len(sys.argv)==2 else ''
    if action=='status':return status()
    if action not in ('save','clear'):raise SecretError('Uso: save|clear|status')
    ensure_store(create=True)
    fd=os.open(LOCK,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,'rb+') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX)
            if action=='clear':
                if SECRET.exists() or SECRET.is_symlink():safe_regular(SECRET);SECRET.unlink()
                return {'ok':True,'stored':False}
            raw=sys.stdin.buffer.read(2048)
            if len(raw)>2047:raise SecretError('Input password eccessivo')
            payload=json.loads(raw)
            if not isinstance(payload,dict) or set(payload)!={'password'}:raise SecretError('Payload non valido')
            return write_password(payload['password'])
    finally:pass

if __name__=='__main__':
    try:
        print(json.dumps(run()))
    except (SecretError,ValueError,OSError,subprocess.TimeoutExpired) as exc:
        # Never echo credential values or raw GPG process output.
        print(json.dumps({'ok':False,'error':str(exc)}));sys.exit(1)
