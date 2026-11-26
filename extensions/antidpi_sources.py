#!/usr/bin/env python3
"""Opt-in multi-source Anti-DPI hostlists.

Sources are curated, HTTPS-only CSV feeds. They are *testing candidates*, not
verified blocks. A privileged background job stages its output. Import is
confirmed separately and never changes the active firewall or NFQUEUE state.
"""
from __future__ import annotations
import csv, fcntl, hashlib, io, json, os, pathlib, re, secrets, subprocess, sys, tempfile, time
from contextlib import contextmanager
import urllib.request, urllib.parse

from command_transport import capture

ROOT = pathlib.Path('/var/lib/iptm-antidpi/sources')
MAX_SOURCE = 2 * 1024 * 1024
MAX_HOSTLIST = 16 * 1024 * 1024
MAX_AGE = 1200
MAX_JOB_JSON = 3 * MAX_HOSTLIST + 65536
SOURCE_ROOT = 'https://raw.githubusercontent.com/citizenlab/test-lists/master/lists/'
COUNTRIES = (
 ('it','Italia · Citizen Lab/OONI', 'Catalogo di URL da verificare, non elenco certificato di blocchi'),
 ('global','Catalogo globale', 'URL di interesse generale per test di accessibilità'),
 ('fr','Francia', 'URL di test selezionati per la Francia'),
 ('de','Germania', 'URL di test selezionati per la Germania'),
 ('es','Spagna', 'URL di test selezionati per la Spagna'),
 ('gb','Regno Unito', 'URL di test selezionati per il Regno Unito'),
 ('nl','Paesi Bassi', 'URL di test selezionati per i Paesi Bassi'),
 ('be','Belgio', 'URL di test selezionati per il Belgio'),
)
CATALOG={k:{'id':k,'name':name,'note':note,'url':SOURCE_ROOT+k+'.csv','format':'csv','license':'CC BY-NC-SA 4.0'} for k,name,note in COUNTRIES}
CATALOG['agcom_archive']={'id':'agcom_archive','name':'Italia · AGCOM archivio 2024 (storico)', 'note':'Elenco storico, NON aggiornato e NON garanzia di superamento di blocchi DNS/IP; scegliere solo se necessario', 'url':'https://raw.githubusercontent.com/Antonio-Prado/it-censura/main/censorship/agcom_baseline_2024-06.txt', 'format':'text','license':'vedi repository di origine'}
HOST = re.compile(r'(?=.{4,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\Z')
TOKEN = re.compile(r'[a-f0-9]{24}\Z')

class SourceError(Exception): pass

def root():
    if os.geteuid()!=0:raise SourceError('Operazione riservata a root')

def directory():
    root()
    if ROOT.is_symlink():raise SourceError('Directory sorgenti non sicura')
    ROOT.mkdir(parents=True,exist_ok=True,mode=0o700)
    if not ROOT.is_dir() or ROOT.stat().st_uid!=0 or ROOT.stat().st_mode & 0o077:
        raise SourceError('Directory sorgenti non protetta')
    os.chmod(ROOT,0o700)

@contextmanager
def operation_lock():
    directory()
    from command_transport import domain_lock
    with domain_lock(ROOT/'operations.lock'):
        yield


def safe_read(path,maxbytes=MAX_JOB_JSON):
    from command_transport import read_private_json
    try:result=read_private_json(path,limit=maxbytes)
    except (OSError,ValueError,UnicodeError) as exc:raise SourceError('File report non sicuro') from exc
    if result is None:raise SourceError('File report mancante')
    return result


def write(path,data):
    directory()
    from command_transport import durable_json
    durable_json(path,data,ensure_ascii=False)

class HttpsOnly(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        u=urllib.parse.urlsplit(newurl)
        if u.scheme!='https' or u.hostname!='raw.githubusercontent.com' or u.port is not None or u.username or u.password:
            raise SourceError('Redirect della lista non consentito')
        return super().redirect_request(req,fp,code,msg,headers,newurl)

def download(source_id):
    url=CATALOG[source_id]['url']
    opener=urllib.request.build_opener(HttpsOnly())
    request=urllib.request.Request(url,headers={'User-Agent':'IPTM-antidpi-catalog/4.3.7','Accept':'text/csv'})
    with opener.open(request,timeout=15) as response:
        if response.status!=200:raise SourceError('Fonte '+source_id+': HTTP '+str(response.status))
        b=response.read(MAX_SOURCE+1)
    if len(b)>MAX_SOURCE:raise SourceError('Fonte '+source_id+' oltre 2 MiB')
    return b

def parse_csv_domains(blob):
    text=blob.decode('utf-8-sig')
    out=set()
    # OONI/CitizenLab test lists use url,category_code,category_description,date_added,...
    for row in csv.DictReader(io.StringIO(text)):
        url=(row.get('url') or row.get('URL') or '').strip()
        if not url:continue
        if not url.startswith(('http://','https://')):continue
        try:
            parsed=urllib.parse.urlsplit(url)
            domain=(parsed.hostname or '').lower().rstrip('.').encode('idna').decode('ascii')
        except (ValueError,UnicodeError):continue
        if HOST.fullmatch(domain):out.add(domain)
    return out

def parse_plain_domains(blob):
    """Parse domains, URL lines and basic hosts files without DNS/network calls."""
    out=set()
    for raw in blob.decode('utf-8-sig').splitlines():
        line=raw.split('#',1)[0].strip()
        if not line or line.startswith('!'):continue
        parts=line.split()
        if len(parts)>1 and parts[0] in ('0.0.0.0','127.0.0.1','::','::1'):
            tokens=parts[1:]
        elif len(parts)==1:
            tokens=parts
        else:
            continue
        for token in tokens:
            if token.lower().startswith(('http://','https://')):
                try:token=urllib.parse.urlsplit(token).hostname or ''
                except ValueError:continue
            token=token.lower().rstrip('.')
            try:token=token.encode('idna').decode('ascii')
            except UnicodeError:continue
            if HOST.fullmatch(token):out.add(token)
    return out

def stage_file(token):
    if not TOKEN.fullmatch(token):raise SourceError('Token hostlist non valido')
    return ROOT/(token+'.hosts')

def write_stage(token, names):
    """Stage a single root-owned UTF-8 hostlist, no JSON duplication per chunk."""
    directory()
    content=('\n'.join(names)+'\n').encode('utf-8')
    if len(content)>MAX_HOSTLIST:raise SourceError('Hostlist oltre il limite di sicurezza')
    dest=stage_file(token)
    if dest.is_symlink():raise SourceError('Hostlist simbolica rifiutata')
    fd,tmp=tempfile.mkstemp(dir=ROOT,prefix='.hosts-')
    try:
        with os.fdopen(fd,'wb') as file:
            os.fchmod(file.fileno(),0o600)
            file.write(content);file.flush();os.fsync(file.fileno())
        os.replace(tmp,dest)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)
    return len(content)

def read_stage(token,job):
    """Used only when preparing the legacy explicit server-side preview."""
    if 'stage_bytes' not in job:return job.get('staged_domains')
    path=stage_file(token)
    if path.is_symlink() or not path.is_file():raise SourceError('Hostlist scaricata mancante')
    meta=path.stat()
    if meta.st_uid!=0 or meta.st_mode&0o077 or meta.st_size!=job['stage_bytes'] or meta.st_size>MAX_HOSTLIST:
        raise SourceError('Hostlist scaricata non protetta')
    names=path.read_text('utf-8').splitlines()
    if len(names)!=job['download_total']:raise SourceError('Hostlist scaricata incompleta')
    return names

def tool(engine):
    sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
    if engine=='zapret2':
        import zapret2_manager as target
        return target,target.config_read
    if engine=='classic':
        import zapret_manager as target
        return target,target.read_config
    raise SourceError('Motore non valido')

def config_hash(cfg):return hashlib.sha256(json.dumps(cfg,sort_keys=True,separators=(',',':')).encode()).hexdigest()

def ensure_inactive():
    import antidpi_live
    if antidpi_live.current() is not None or (antidpi_live.persistent() or {}).get('enabled'):
        raise SourceError('Arresta prima Anti-DPI live e disattiva la persistenza: aggiornamento hostlist non applicato')

def request_start(data):
    if not isinstance(data,dict) or not {'engine','sources','mode'}.issubset(data) or not set(data).issubset({'engine','sources','mode','local','draft'}):raise SourceError('Richiesta non valida')
    engine,ids,mode=data['engine'],data['sources'],data['mode']
    if engine not in ('zapret2','classic') or mode not in ('merge','replace'):
        raise SourceError('Scelta importazione non valida')
    if not isinstance(ids,list) or len(ids)>len(CATALOG) or len(set(ids))!=len(ids) or any(not isinstance(s,str) or s not in CATALOG for s in ids):
        raise SourceError('Selezione fonti non valida')
    local=data.get('local','')
    if not isinstance(local,str) or len(local.encode('utf-8'))>MAX_HOSTLIST:
        raise SourceError('Elenco locale oltre il limite di 16 MiB')
    local_domains=parse_plain_domains(local.encode('utf-8'))
    if not ids and not local_domains:raise SourceError('Seleziona almeno una fonte online, un servizio noto o un file TXT valido')
    ensure_inactive()
    target,readcfg=tool(engine)
    saved=readcfg()
    proposed=data.get('draft')
    if proposed is not None:
        if not isinstance(proposed,dict) or set(proposed)!={'wan_if','clients','domains','queue','strategy'}:
            raise SourceError('Campi del profilo di destinazione incompleti')
        supplied=[] if mode=='replace' else proposed.get('domains')
        if not isinstance(supplied,list) or any(not isinstance(x,str) for x in supplied):
            raise SourceError('Domini del profilo non validi')
        if len('\n'.join(supplied).encode('utf-8'))>MAX_HOSTLIST:
            raise SourceError('Domini correnti del profilo oltre 16 MiB')
        # The final hostlist is validated again before commit. The temporary
        # dummy domain only permits validation of an as-yet-empty new profile.
        preview=dict(proposed);preview['domains']=supplied or ['example.org']
        cfg=target.validate(preview)
        if not supplied:cfg['domains']=[]
    else:
        cfg=saved
    if not cfg:raise SourceError('Completa WAN e reti client nel profilo prima di importare')
    baseline=config_hash(saved) if saved is not None else None
    directory()
    prev=ROOT/'latest.json'
    if prev.exists():
        latest=safe_read(prev)
        if latest.get('state') in ('queued','running'):
            previous=safe_read(ROOT/(str(latest['token'])+'.json'))
            if int(time.time())-int(previous.get('created',0))<600:
                raise SourceError('Importazione precedente ancora in corso')
    token=secrets.token_hex(12)
    job={'token':token,'state':'queued','engine':engine,'sources':ids,'mode':mode,
         'created':int(time.time()),'cfg_sha':baseline,'profile':cfg,'local_domains':sorted(local_domains),
         'downloaded_sources':0,'source_total':len(ids),'per_source':[]}
    write(ROOT/(token+'.json'),job);write(prev,{'token':token,'state':'queued'})
    # Local-only imports stage downloads immediately; preview is always a separate, explicit action.
    if not ids:
        done=do_work(token)
        if not done.get('ok'):raise SourceError('Elaborazione lista locale fallita: verifica il report')
        return {'ok':True,'state':'downloaded','token':token,'notice':'Fonti acquisite: crea ora l’anteprima, senza applicare nulla'}
    # no shell and no user-controlled command: the network worker outlives web request
    cmd=['systemd-run','--quiet','--collect','--unit=iptm-antidpi-source-'+token,
         '--property=Nice=10','--property=CPUQuota=30%',
         '/usr/bin/python3','-B',str(pathlib.Path(__file__).resolve()),'work',token]
    try:
        result=capture(cmd, timeout=12, text=False, stdout_limit=1048576, stderr_limit=262144)
    except (OSError,subprocess.TimeoutExpired) as ex:
        job['state']='failed';job['error']='systemd-run non disponibile';write(ROOT/(token+'.json'),job);write(prev,{'token':token,'state':'failed'})
        raise SourceError('Avvio worker non riuscito') from ex
    if result.returncode:
        job['state']='failed';job['error']='systemd-run exit '+str(result.returncode)
        write(ROOT/(token+'.json'),job);write(prev,{'token':token,'state':'failed'})
        raise SourceError(job['error'])
    return {'ok':True,'state':'queued','token':token,'notice':'Download di tutte le fonti avviato: attendi che ogni origine abbia un esito prima di creare l’anteprima'}

def do_work(token):
    """Download and stage ALL selected sources; never generate or commit a preview here."""
    directory()
    path=ROOT/(token+'.json');job=safe_read(path)
    if job.get('token')!=token or job.get('state')!='queued':raise SourceError('Job non valido')
    job['state']='running';write(path,job);write(ROOT/'latest.json',{'token':token,'state':'running'})
    try:
        ensure_inactive()
        _,readcfg=tool(job['engine']);saved=readcfg()
        if (config_hash(saved) if saved is not None else None)!=job['cfg_sha']:
            raise SourceError('Profilo modificato durante il download')
        if not (job.get('profile') or saved):raise SourceError('Profilo non disponibile')
        fetched=set(job.get('local_domains',[]));groups=[]
        if fetched:groups.append({'id':'local','count':len(fetched),'status':'ok'})
        for code in job['sources']:
            try:
                blob=download(code)
                domains=parse_csv_domains(blob) if CATALOG[code]['format']=='csv' else parse_plain_domains(blob)
                if not domains:raise SourceError('Nessun dominio valido nel documento')
                fetched.update(domains)
                groups.append({'id':code,'count':len(domains),'status':'ok'})
            except (SourceError,OSError,UnicodeError,ValueError,TimeoutError) as ex:
                groups.append({'id':code,'count':0,'status':'error','detail':str(ex)[:160]})
            job.update({'per_source':groups,'downloaded_sources':len(groups)-(1 if fetched and groups[0]['id']=='local' else 0)})
            write(path,job)
        job['per_source']=groups
        if not fetched:raise SourceError('Nessuna fonte utilizzabile: consulta gli errori di download. Profilo invariato')
        staged=sorted(fetched)
        if len(('\n'.join(staged)+'\n').encode('utf-8'))>MAX_HOSTLIST:
            raise SourceError('L’insieme delle fonti supera 16 MiB: riduci le raccolte selezionate')
        size=write_stage(token,staged)
        job.pop('local_domains',None)
        job.update({'state':'downloaded','stage_bytes':size,'download_total':len(staged),
                    'downloaded_at':int(time.time()),'finished':int(time.time())})
    except Exception as ex:
        job.pop('local_domains',None)
        job.update({'state':'failed','error':(type(ex).__name__+': '+str(ex))[:300],'finished':int(time.time())})
    write(path,job)
    if safe_read(ROOT/'latest.json').get('token')==token:
        write(ROOT/'latest.json',{'token':token,'state':job['state']})
    return {'ok':job['state']=='downloaded','state':job['state']}


def fetch_chunk(token, engine, offset, limit=1500):
    """Authenticated web helper reads chunks only after ALL downloads end.

    Staged lists remain root-owned; this bounded output is used to populate
    the operator's existing hostlist textarea before any profile save.
    """
    if not TOKEN.fullmatch(token) or engine not in ('zapret2','classic'):
        raise SourceError('Richiesta download non valida')
    if offset < 0 or not 1 <= limit <= 2000:
        raise SourceError('Intervallo download non valido')
    directory()
    job=safe_read(ROOT/(token+'.json'))
    if job.get('token')!=token or job.get('engine')!=engine or job.get('state')!='downloaded':
        raise SourceError('La raccolta non è ancora completa o non è più disponibile')
    if safe_read(ROOT/'latest.json').get('token')!=token:
        raise SourceError('La raccolta è stata sostituita da una più recente')
    if int(time.time())-int(job.get('downloaded_at',0))>MAX_AGE:
        raise SourceError('Raccolta scaduta: esegui nuovamente il download')
    if job.get('mode')=='replace' and any(item.get('status')=='error' for item in job.get('per_source',[])):
        raise SourceError('Sostituzione incompleta vietata: almeno una raccolta è fallita')
    if 'stage_bytes' in job:
        # Offsets are BYTE offsets for a staged file; one bounded read per call.
        path=stage_file(token)
        if path.is_symlink():raise SourceError('Hostlist simbolica rifiutata')
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            metadata=os.fstat(fd)
            if metadata.st_uid!=0 or metadata.st_mode&0o077 or metadata.st_size!=job['stage_bytes'] or metadata.st_size>MAX_HOSTLIST:
                raise SourceError('File hostlist non protetto o modificato')
            if offset>metadata.st_size:raise SourceError('Offset raccolta non valido')
            collected=[];used=0
            with os.fdopen(fd,'rb',closefd=False) as inp:
                inp.seek(offset)
                while len(collected)<limit and used<256*1024:
                    line=inp.readline(260)
                    if not line:break
                    used+=len(line)
                    try:domain=line.decode('utf-8').strip()
                    except UnicodeError:raise SourceError('Hostlist non UTF-8')
                    if not HOST.fullmatch(domain):raise SourceError('Dominio scaricato non valido')
                    collected.append(domain)
                next_offset=inp.tell()
            return {'ok':True,'token':token,'state':'downloaded','offset':offset,
                    'next':next_offset,'total':int(job['download_total']),
                    'done':next_offset==metadata.st_size,'domains':collected,'changes_live':False}
        finally:os.close(fd)
    # Support a preexisting in-memory staged job during a bridge migration.
    names=job.get('staged_domains')
    if not isinstance(names,list):raise SourceError('Hostlist scaricata non disponibile')
    if offset>len(names):raise SourceError('Offset raccolta non valido')
    chunk=names[offset:offset+limit]
    if any(not isinstance(x,str) or not HOST.fullmatch(x) for x in chunk):
        raise SourceError('Domini scaricati non validi')
    return {'ok':True,'token':token,'state':'downloaded','offset':offset,
            'next':offset+len(chunk),'total':len(names),'done':offset+len(chunk)>=len(names),
            'domains':chunk,'changes_live':False}


def preview(token,engine=None):
    """Only after ALL downloads finish may the operator explicitly create a preview."""
    if not TOKEN.fullmatch(token):raise SourceError('Identificatore download non valido')
    directory();path=ROOT/(token+'.json');job=safe_read(path)
    if engine is not None and job.get('engine')!=engine:raise SourceError('Motore download non corrispondente')
    if safe_read(ROOT/'latest.json').get('token')!=token:
        raise SourceError('Esiste una raccolta più recente: ripeti il download')
    if job.get('state')!='downloaded':raise SourceError('Attendi che il download di tutte le fonti sia terminato')
    if int(time.time())-int(job.get('downloaded_at',0))>MAX_AGE:
        raise SourceError('Download scaduto: aggiorna le fonti')
    if int(job.get('downloaded_sources',0))!=len(job.get('sources',[])):
        raise SourceError('Download non completo: anteprima non permessa')
    if job.get('mode')=='replace' and any(x.get('status')=='error' for x in job.get('per_source',[])):
        raise SourceError('Sostituzione non sicura: una o più raccolte non sono state scaricate. Riprova il download oppure scegli Unisci')
    ensure_inactive()
    _,readcfg=tool(job['engine']);saved=readcfg()
    if (config_hash(saved) if saved is not None else None)!=job['cfg_sha']:
        raise SourceError('Profilo modificato dopo il download: ripeti la raccolta')
    cfg=job.get('profile') or saved
    if not isinstance(cfg,dict):raise SourceError('Profilo non disponibile')
    staged=read_stage(token,job)
    if not isinstance(staged,list) or not staged or any(not isinstance(x,str) or not HOST.fullmatch(x) for x in staged):
        raise SourceError('Dati scaricati non validi')
    previous=set(cfg.get('domains',[]))
    combined=sorted(set(staged)|(previous if job['mode']=='merge' else set()))
    if len(('\n'.join(combined)+'\n').encode('utf-8'))>MAX_HOSTLIST:
        raise SourceError('Hostlist risultante oltre 16 MiB: riduci le raccolte o i domini esistenti')
    job.pop('staged_domains',None)
    if isinstance(job.get('profile'),dict):job['profile']['domains']=[]
    job.update({'state':'ready','added':len(set(combined)-previous),'removed':len(previous-set(combined)),
                'total':len(combined),'examples':combined[:12], 'domains':combined,'finished':int(time.time())})
    write(path,job);write(ROOT/'latest.json',{'token':token,'state':'ready'})
    return {'ok':True,'state':'ready','token':token,'total':len(combined),'changes_live':False}

def status(engine=None):
    directory();latest=ROOT/'latest.json'
    if not latest.exists():return {'ok':True,'state':'none','catalog':list(CATALOG.values())}
    brief=safe_read(latest)
    token=brief.get('token','')
    if not TOKEN.fullmatch(str(token)):raise SourceError('Puntatore job errato')
    job=safe_read(ROOT/(token+'.json'))
    if engine is not None and job.get('engine')!=engine:
        return {'ok':True,'state':'none','catalog':list(CATALOG.values())}
    public={key:value for key,value in job.items() if key not in ('domains','staged_domains','cfg_sha','local_domains','profile')}
    public['ok']=True;public['catalog']=list(CATALOG.values())
    return public

def apply(token,engine=None):
    if not TOKEN.fullmatch(token):raise SourceError('Token importazione non valido')
    directory();job=safe_read(ROOT/(token+'.json'))
    if engine is not None and job.get('engine')!=engine:raise SourceError('Motore importazione non corrispondente')
    if safe_read(ROOT/'latest.json').get('token')!=token:
        raise SourceError('Esiste una nuova importazione: questa anteprima non è più attuale')
    if job.get('state')!='ready' or int(time.time())-job.get('finished',0)>MAX_AGE:
        raise SourceError('Anteprima scaduta: aggiorna le fonti')
    ensure_inactive()
    target,readcfg=tool(job['engine'])
    saved=readcfg()
    current_hash=config_hash(saved) if saved is not None else None
    if current_hash!=job['cfg_sha']:
        raise SourceError('Profilo modificato: ripeti anteprima')
    domains=job['domains']
    if not isinstance(domains,list):raise SourceError('Dati job non validi')
    cfg=job.get('profile') or saved
    if not isinstance(cfg,dict):raise SourceError('Profilo target non valido')
    new=dict(cfg);new['domains']=domains
    # use existing atomic configuration routines; no iptables, systemd or NFQUEUE change
    target.configure(new)
    job['state']='applied';job['domains']=[];job['applied_at']=int(time.time())
    write(ROOT/(token+'.json'),job);write(ROOT/'latest.json',{'token':token,'state':'applied'})
    return {'ok':True,'state':'applied','engine':job['engine'],'total':len(domains),'changes_live':False}

def main():
    root()
    if len(sys.argv)<2:raise SourceError('Operazione mancante')
    op=sys.argv[1]
    if op=='catalog' and len(sys.argv)==2:return {'ok':True,'catalog':list(CATALOG.values())}
    if op=='status' and len(sys.argv) in (2,3):
        engine=sys.argv[2] if len(sys.argv)==3 else None
        if engine is not None and engine not in ('zapret2','classic'):raise SourceError('Motore non valido')
        return status(engine)
    if op=='start' and len(sys.argv)==2:
        raw=sys.stdin.buffer.read(2*MAX_HOSTLIST+8192+1)
        if len(raw)>2*MAX_HOSTLIST+8192:raise SourceError('Parametri troppo grandi')
        with operation_lock():return request_start(json.loads(raw))
    if op=='preview' and len(sys.argv) in (3,4):
        engine=sys.argv[3] if len(sys.argv)==4 else None
        if engine is not None and engine not in ('zapret2','classic'):raise SourceError('Motore non valido')
        with operation_lock():return preview(sys.argv[2],engine)
    if op=='apply' and len(sys.argv) in (3,4):
        engine=sys.argv[3] if len(sys.argv)==4 else None
        if engine is not None and engine not in ('zapret2','classic'):raise SourceError('Motore non valido')
        with operation_lock():return apply(sys.argv[2],engine)
    if op=='fetch' and len(sys.argv)==6 and TOKEN.fullmatch(sys.argv[2]):
        return fetch_chunk(sys.argv[2],sys.argv[3],int(sys.argv[4]),int(sys.argv[5]))
    if op=='work' and len(sys.argv)==3 and TOKEN.fullmatch(sys.argv[2]):return do_work(sys.argv[2])
    raise SourceError('Operazione non autorizzata')

def coordinated_main():
    from command_transport import driver_admission
    with driver_admission('antidpi_sources',sys.argv[1:]):
        return main()

if __name__=='__main__':
    try:print(json.dumps(coordinated_main(),ensure_ascii=False))
    except (SourceError,OSError,ValueError,TypeError,KeyError) as ex:
        print(json.dumps({'ok':False,'error':str(ex)},ensure_ascii=False));sys.exit(1)
