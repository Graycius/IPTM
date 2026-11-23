#!/usr/bin/env python3
"""RethinkDNS list source audit, no automatic subscription/import.

Use the upstream catalogue as a list of selectable sources. Never probe the
reachability of individual lists to decide whether checkboxes may be selected.
Import is still validated and its real outcome reported after API operations.
"""
import hashlib,json,os,pathlib,stat,sys,tempfile,time,urllib.error,urllib.parse,urllib.request

URL='https://raw.githubusercontent.com/serverless-dns/blocklists/main/config.json'
CACHE=pathlib.Path('/var/cache/iptm-rethinkdns/catalog.json')
USER_AGENT='IPTM-catalog-check/5.30.23'
MAX_AGE=24*3600

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        raise urllib.error.HTTPError(req.full_url,code,'Redirect rifiutato',headers,fp)

def fetch(url,max_bytes=600000,method='GET'):
    p=urllib.parse.urlsplit(url)
    if p.scheme!='https' or p.hostname!='raw.githubusercontent.com' or p.username or p.password or p.port not in (None,443):
        raise ValueError('Dominio sorgente non ammesso')
    if not p.path.startswith('/') or p.query or p.fragment or '\\' in url or '\n' in url:
        raise ValueError('Percorso sorgente non valido')
    opener=urllib.request.build_opener(NoRedirect())
    req=urllib.request.Request(url,headers={'User-Agent':USER_AGENT,'Accept':'text/plain, application/json',**({'Range':f'bytes=0-{max_bytes-1}'} if max_bytes<=32768 else {})},method=method)
    with opener.open(req,timeout=6) as res:
        status=res.status
        if status not in (200,206):raise ValueError('Risposta HTTP '+str(status))
        data=res.read(max_bytes+1)
        if len(data)>max_bytes:raise ValueError('Risorsa troppo grande')
        return data

def parse_config(raw):
    try:
        cfg=json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError('Catalogo JSON incompleto o non valido; download annullato, riprovare la verifica. '+str(exc)[:120]) from exc
    if not isinstance(cfg,dict) or not isinstance(cfg.get('conf'),list):raise ValueError('Catalogo RethinkDNS non valido')
    items=[];seen=set()
    for row in cfg['conf']:
        if not isinstance(row,dict):continue
        urls=row.get('url',[]);formats=row.get('format',[])
        if isinstance(urls,str):urls=[urls]
        if isinstance(formats,str):formats=[formats]*len(urls)
        if not isinstance(urls,list) or not isinstance(formats,list):continue
        for idx,url in enumerate(urls):
            fmt=formats[idx] if idx<len(formats) else ''
            # Pi-hole can consume domain and hosts text files; wildcard,
            # ABP, and native Rethink binary formats are not imported.
            if fmt not in ('domains','hosts') or not isinstance(url,str) or len(url)>300:continue
            try: fetch_host_check(url)
            except ValueError:continue
            ident='rd'+hashlib.sha256(url.encode('utf-8')).hexdigest()[:16]
            if ident in seen:continue
            seen.add(ident)
            items.append({'id':ident,'name':str(row.get('vname') or 'RethinkDNS')[:80],
                         'group':str(row.get('group') or 'Altro')[:50],
                         'format':fmt,'url':url,'state':'unverified','why':'Non ancora verificata'})
    return items # tutte le fonti conformi al catalogo; dimensione cache protetta

def fetch_host_check(url):
    p=urllib.parse.urlsplit(url)
    if p.scheme!='https' or p.hostname!='raw.githubusercontent.com' or p.port not in (None,443) or p.query or p.fragment or '\\' in url or '\n' in url:
        raise ValueError('URL non consentito')

def _secure_cache_directory(create=False):
    """Only IPTM's dedicated root-owned cache directory is writable by this worker.

    The common /var/lib/iptables-manager directory may legitimately be group-writable
    for the web application and must not be chmod'ed or trusted for root-owned files.
    """
    folder=CACHE.parent
    if create and not folder.exists() and not folder.is_symlink():
        # No `parents=True`: a missing unexpected parent is a configuration error.
        folder.mkdir(mode=0o700)
    try:
        st=folder.lstat()
    except FileNotFoundError:
        if not create:return False
        raise
    if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or (st.st_mode & 0o077):
        raise ValueError('Directory cache RethinkDNS non sicura (richiesti root:root e permessi 0700)')
    return True


def _read_secure_file():
    # O_NOFOLLOW and fstat protect against replacing the cache file with a symlink.
    flags=os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_CLOEXEC',0)
    try: fd=os.open(CACHE,flags)
    except FileNotFoundError:return None
    with os.fdopen(fd,'r',encoding='utf-8') as stream:
        st=os.fstat(stream.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or (st.st_mode & 0o077) or st.st_size>200000:
            raise ValueError('File cache RethinkDNS non sicuro')
        return json.load(stream)


def cache_read():
    if not _secure_cache_directory():
        return {'ok':True,'updated':0,'lists':[],'verified':0,'message':'Catalogo non ancora verificato: premi Aggiorna.'}
    result=_read_secure_file()
    if result is None:
        return {'ok':True,'updated':0,'lists':[],'verified':0,'message':'Catalogo non ancora verificato: premi Aggiorna.'}
    if not isinstance(result,dict) or not isinstance(result.get('lists'),list):
        raise ValueError('Cache RethinkDNS corrotta: aggiorna il catalogo')
    if time.time()-float(result.get('updated',0))>MAX_AGE:
        for item in result['lists']:
            if isinstance(item,dict):
                item['state']='selectable';item['why']='Catalogo in cache: aggiorna per nuove fonti (selezionabile)' 
    return result


def cache_save(rows):
    if os.geteuid()!=0:raise ValueError('Richiede root')
    _secure_cache_directory(create=True)
    # Refuse an existing symlink or untrusted cache, rather than touching it.
    _read_secure_file()
    result={'ok':True,'updated':int(time.time()),'source':URL,'lists':rows,'verified':0,'selectable':len(rows)}
    temp=None
    try:
        with tempfile.NamedTemporaryFile(mode='w',encoding='utf-8',delete=False,dir=CACHE.parent,prefix='.rethink-',suffix='.tmp') as f:
            os.fchmod(f.fileno(),0o600)
            json.dump(result,f,ensure_ascii=False)
            f.flush();os.fsync(f.fileno());temp=f.name
        os.replace(temp,CACHE)
        temp=None
    finally:
        if temp is not None:
            try:os.unlink(temp)
            except FileNotFoundError:pass
    return result

def refresh():
    raw=fetch(URL,max_bytes=550000)
    candidates=parse_config(raw)
    # Do not fetch every URL: a 404/timeout must not hide the checkbox.
    # URL schema is checked by fetch_host_check() while parsing.
    selectable=[x|{'state':'selectable','why':'Selezionabile; raggiungibilità non verificata'} for x in candidates]
    return cache_save(selectable)

def get_importable(identifiers):
    result=cache_read()
    catalogue={x['id']:x for x in result.get('lists',[]) if isinstance(x,dict) and isinstance(x.get('url'),str) and x.get('format') in ('hosts','domains')}
    if any(x not in catalogue for x in identifiers):raise ValueError('Lista non presente nel catalogo ufficiale memorizzato')
    for x in identifiers: fetch_host_check(catalogue[x]['url'])
    return [(id,catalogue[id]['url']) for id in identifiers]

if __name__=='__main__':
    try:
        if len(sys.argv)!=2 or sys.argv[1] not in ('list','refresh'):raise ValueError('Uso: list|refresh')
        print(json.dumps(refresh() if sys.argv[1]=='refresh' else cache_read(),ensure_ascii=False))
    except Exception as exc:
        print(json.dumps({'ok':False,'error':str(exc)}));sys.exit(2)
