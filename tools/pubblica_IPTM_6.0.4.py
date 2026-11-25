#!/usr/bin/env python3
"""Publish the exact Native Update to Graycius/IPTM using Git + GitHub CLI.
Run on a trusted development workstation, not on the router.
"""
import hashlib,json,pathlib,subprocess,tempfile,zipfile,sys,shutil,os
HERE=pathlib.Path(__file__).resolve().parent
VERSION='6.0.4'; REPO='Graycius/IPTM'; BRANCH='release/iptm-6.0.4'; TAG='v6.0.4'
EXPECTED='c0ca2653024d86b6736abbfffe69a1896282e5a1778816f668ce6efe598307db'
ARCHIVE=HERE/f'IPTM_{VERSION}_UPDATE.zip'
DIRS={'actions','assets','extensions','loader','modules','runtime'}
NOTES='''# IPTM 6.0.4 — pre-release

Aggiornamento nativo schema 1, tramite HTTP, con verifica SHA-256. Include il riconoscimento del recovery DNS legacy e la bonifica selettiva delle release. Il riferimento residuo a iptm-dns-boot-recover.service sulla 4.3.9 è ancora segnalato sul DietPi reale: non rimuovere manualmente quella directory. Il collaudo completo su DietPi reale non è concluso. L'installer e i test storici del repository non sono una distribuzione FULL 6.0.4.
'''
def run(*args,cwd=None,capture=False):
    return subprocess.run(args,cwd=cwd,check=True,text=True,stdout=subprocess.PIPE if capture else None).stdout.strip() if capture else subprocess.run(args,cwd=cwd,check=True)
def inspect():
    assert hashlib.sha256(ARCHIVE.read_bytes()).hexdigest()==EXPECTED,'SHA-256 ZIP errato'
    with zipfile.ZipFile(ARCHIVE) as z:
        names=z.namelist(); m=json.loads(z.read('native-manifest.json')); hashes=m['sha256']
        assert m['version']==VERSION and m['format']=='iptm-native' and m['schema']==1
        assert len(hashes)==116 and len(names)==len(set(names))==117
        assert set(names)==set(hashes)|{'native-manifest.json'} and z.testzip() is None
        for name in names:
            p=pathlib.PurePosixPath(name)
            assert not p.is_absolute() and '..' not in p.parts and '\\' not in name and not name.endswith('/')
            assert (len(p.parts)==2 and p.parts[0] in DIRS) or name in ('CHANGELOG.md','native-manifest.json')
            if name in hashes: assert hashlib.sha256(z.read(name)).hexdigest()==hashes[name],name
    print('ZIP e manifest: 116/116 hash validi',flush=True)
def install_sources(root):
    with zipfile.ZipFile(ARCHIVE) as z:
        # Replace only the application source directories owned by the Native package.
        # Preserve all unrelated directories, prior packages, tests and installer.
        for name in DIRS:
            p=root/name
            if p.is_symlink(): raise RuntimeError(f'Directory non sicura: {p}')
            if p.exists(): shutil.rmtree(p)
        for name in z.namelist():
            target=root/name; target.parent.mkdir(parents=True,exist_ok=True); target.write_bytes(z.read(name))
    rel=root/'release'; rel.mkdir(exist_ok=True)
    shutil.copyfile(ARCHIVE,rel/ARCHIVE.name)
    (rel/f'IPTM_{VERSION}_UPDATE.sha256').write_text(f'{EXPECTED}  {ARCHIVE.name}\n',encoding='utf-8')
    (rel/f'IPTM_{VERSION}_RELEASE_NOTES.md').write_text(NOTES,encoding='utf-8')
    readme=root/'README.md'; old=readme.read_text(encoding='utf-8') if readme.exists() else '# IPTM\n'
    intro=f'''## IPTM {VERSION} — pre-release corrente

- [Native Update](release/{ARCHIVE.name})
- [SHA-256](release/IPTM_{VERSION}_UPDATE.sha256)
- [Note e limiti](release/IPTM_{VERSION}_RELEASE_NOTES.md)

Aggiornamenti HTTP mantenuti. Le sezioni sottostanti sono documentazione storica; l'installer precedente non è un FULL {VERSION}.

'''
    lines=old.splitlines(keepends=True)
    if lines and lines[0].startswith('# '): new=lines[0]+'\n'+intro+''.join(lines[1:])
    else: new='# IPTM\n\n'+intro+old
    readme.write_text(new,encoding='utf-8')
    # Verify extracted sources after writing; no installation, no privileged commands.
    with zipfile.ZipFile(ARCHIVE) as z:
        for name in z.namelist(): assert (root/name).read_bytes()==z.read(name)

def main():
    if not __debug__: raise RuntimeError('Non usare Python -O: i controlli di integrità devono essere attivi.')
    inspect()
    if '--verify-only' in sys.argv:
        with tempfile.TemporaryDirectory(prefix='iptm-verify-') as d: install_sources(pathlib.Path(d))
        print('Estrazione e verifica sorgenti: OK. Nessuna scrittura su GitHub.'); return
    run('gh','auth','status'); run('gh','auth','setup-git')
    with tempfile.TemporaryDirectory(prefix='iptm-publish-') as d:
        root=pathlib.Path(d)/'IPTM'
        run('git','clone','--branch','main',f'https://github.com/{REPO}.git',str(root))
        base=run('git','rev-parse','HEAD',cwd=root,capture=True)
        if base!='4d11a137037e7ed2fc11b6d9eed60e5a5e71394e': raise RuntimeError(f'main è cambiato ({base}): serve riconciliare la nuova base prima di pubblicare.')
        run('git','switch','-c',BRANCH,cwd=root)
        install_sources(root)
        run('git','add','--all',cwd=root)
        run('git','diff','--cached','--stat',cwd=root)
        run('git','commit','-m',f'IPTM {VERSION}: Native Update, source and release notes',cwd=root)
        commit=run('git','rev-parse','HEAD',cwd=root,capture=True)
        # Git filters or line-ending conversion must not modify packaged source bytes.
        with zipfile.ZipFile(ARCHIVE) as z:
            for name in z.namelist():
                b=subprocess.check_output(['git','show',f'{commit}:{name}'],cwd=root)
                if b!=z.read(name): raise RuntimeError(f'Git ha modificato il contenuto: {name}')
        run('git','push','-u','origin',BRANCH,cwd=root)
        print(f'Commit: {commit}',flush=True)
        if '--commit-only' in sys.argv:
            return
        pr=run('gh','pr','create','--repo',REPO,'--base','main','--head',BRANCH,'--title',f'IPTM {VERSION}', '--body',NOTES,capture=True,cwd=root)
        print(f'Pull request: {pr}',flush=True)
        # Stop on failing or absent checks; never bypass repository protections.
        run('gh','pr','checks',pr,'--watch','--fail-fast','--repo',REPO,cwd=root)
        run('gh','pr','merge',pr,'--merge','--match-head-commit',commit,'--repo',REPO,cwd=root)
        data=json.loads(run('gh','pr','view',pr,'--repo',REPO,'--json','state,mergeCommit',cwd=root,capture=True))
        if data['state']!='MERGED': raise RuntimeError('Merge non confermato: release non pubblicata')
        merged=data['mergeCommit']['oid']
        run('gh','release','create',TAG,str(root/'release'/ARCHIVE.name),str(root/'release'/f'IPTM_{VERSION}_UPDATE.sha256'),'--repo',REPO,'--target',merged,'--title',f'IPTM {VERSION}','--notes',NOTES,'--prerelease',cwd=root)
        print(run('gh','release','view',TAG,'--repo',REPO,'--json','url,isPrerelease,tagName',cwd=root,capture=True))
if __name__=='__main__':
    main()
