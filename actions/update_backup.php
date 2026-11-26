<?php
/* IPTM action domain: update_backup. Inherits the authenticated controller scope. */
switch ($a) {
case 'release_cleanup_run': {
    $back='p=update';
    if(($_SESSION['role']??'')!=='admin'||($_POST['release_cleanup_confirm']??'')!=='1'){flash('Conferma amministratore richiesta.','err');break;}
    if (($_POST['release_cleanup_mode']??'')==='archive') {
        $digest=$_POST['release_plan_sha256']??null;
        if(!is_string($digest)||!preg_match('/^[a-f0-9]{64}$/D',$digest)){flash('Anteprima archivio non valida.','err');break;}
        [$rc,$out,$err]=priv('release-cleanup',null,['archive-apply',$digest]);$r=$rc===0?json_decode($out,true):null;
        if(is_array($r)){
            $issues=(array)($r['errors']??[]);$m=count((array)($r['archived']??[]));
            flash('Copie helper archiviate: '.$m.' · Protette: '.count((array)($r['deferred']??[])).($issues?' · '.implode('; ',$issues):' · Originali conservati nell’archivio root.'),$issues?'err':'ok');
            audit('Bonifica copie helper: '.$m);
        }else flash('Archiviazione non eseguita: '.herr($err?:$out),'err');
        $back='p=update&release_force_preview=1';break;
    }
    if (($_POST['release_cleanup_mode']??'')==='migrate') {
        $digest=$_POST['release_plan_sha256']??null;
        if(!is_string($digest)||!preg_match('/^[a-f0-9]{64}$/D',$digest)){flash('Anteprima migrazione non valida.','err');break;}
        [$rc,$out,$err]=priv('release-cleanup',null,['migrate-apply',$digest]);$r=$rc===0?json_decode($out,true):null;
        if(is_array($r)){
            $m=count((array)($r['migrated']??[]));$d=count((array)($r['deferred']??[]));$issues=(array)($r['errors']??[]);
            flash('Unità migrate: '.$m.' · Unità preservate: '.$d.($issues?' · '.implode('; ',$issues):' · Nessun servizio riavviato.'),$issues?'err':'ok');
            audit('Migrazione riferimenti release: '.$m);
        }else flash('Migrazione non eseguita: '.herr($err?:$out),'err');
        $back='p=update&release_force_preview=1';break;
    }
    if (($_POST['release_cleanup_mode']??'')==='selected') {
        $versions=$_POST['release_versions']??null;$digest=$_POST['release_plan_sha256']??null;
        if(!is_array($versions)||!array_is_list($versions)||count($versions)<1||count($versions)>100||!is_string($digest)||!preg_match('/^[a-f0-9]{64}$/D',$digest)) {flash('Selezione o anteprima non valida.','err');break;}
        foreach($versions as $v)if(!is_string($v)||!preg_match('/^[0-9]+(?:\.[0-9]+){1,3}$/D',$v)){flash('Versione non valida.','err');break 2;}
        if(count(array_unique($versions))!==count($versions)){flash('Versioni duplicate.','err');break;}
        $args=array_merge(['select-apply',$digest],$versions);
    }else{$args=['apply'];}
    [$rc,$out,$err]=priv('release-cleanup',null,$args);$r=$rc===0?json_decode($out,true):null;
    if(is_array($r)){
        $removed=count((array)($r['deleted']??[]));$issues=array_merge((array)($r['errors']??[]),empty($r['reason'])?[]:[(string)$r['reason']]);
        foreach((array)($r['quarantined']??[]) as $q)$issues[]='Rimozione interrotta, residuo protetto: '.$q;
        flash('Release rimosse: '.$removed.($issues?' · '.implode('; ',$issues):' · configurazioni e archivi di ripristino conservati.'),$issues?'err':'ok');
        audit('Pulizia directory release: '.$removed);
    }else flash('Pulizia non eseguita: '.herr($err?:$out),'err');
    break;
}
case 'upgrade_cleanup_run': {
    $back='p=update';
    if (($_SESSION['role'] ?? '') !== 'admin') { flash('Solo amministratori.', 'err'); break; }
    $expected=$_POST['cleanup_sha256']??null;
    if (!is_string($expected)||!preg_match('/^[a-f0-9]{64}$/D',$expected)||($_POST['cleanup_confirm']??null)!=='1') {flash('Calcola e conferma prima l’anteprima di bonifica.','err');break;}
    [$code, $out, $err] = priv('upgrade-cleanup', null, ['retire',$expected]);
    $result = $code === 0 ? json_decode($out, true) : null;
    if ($code === 0 && is_array($result) && !empty($result['ok'])) {
        flash('Pulizia verificata: '.count((array)($result['retired']??[])).' unità ritirate, '.count((array)($result['archived']??[])).' copie obsolete archiviate; componenti operativi preservati.', 'ok');
        audit('Pulizia post-update: '.substr((string)($result['state']??''),0,64));
    } else flash('Pulizia non eseguita: '.herr((string)($result['error']??$out.$err)), 'err');
    break;
}
case 'retention_save': {
    $back='p=retention';
    if (($_SESSION['role']??'')!=='admin') { flash('Solo amministratori.', 'err'); break; }
    $fields=iptm_retention_fields();
    $values=[];$valid=true;
    foreach ($fields as $key=>[$label,$min,$max]) {
        $value=iptm_retention_value($_POST[$key]??null);
        if ($value===false || $value<$min || $value>$max) {$valid=false;break;}
        $values[$key]=(int)$value;
    }
    if (!$valid) { flash('Valori di conservazione non validi.', 'err'); break; }
    [$rc,$out,$err]=priv('retention',json_encode($values,JSON_THROW_ON_ERROR),['configure']);
    $response=json_decode($out,true);$saved=$rc===0&&($response['ok']??false)===true;
    flash($saved?'Politica di rotazione salvata.':'Salvataggio non riuscito: '.herr($out.$err), $saved?'ok':'err');
    if ($saved) audit('rotazione backup/log: politica aggiornata');
    break;
}
case 'retention_run': {
    $back='p=retention';
    if (($_SESSION['role']??'')!=='admin') { flash('Solo amministratori.', 'err'); break; }
    [$rc,$out,$err]=priv('retention',null,['trigger']);
    flash($rc===0?'Rotazione programmata in background. Ricarica la pagina per visualizzare il risultato.':'Rotazione non avviata: '.herr($out.$err),$rc===0?'ok':'err');
    if ($rc===0) audit('rotazione backup/log: esecuzione manuale richiesta');
    break;
}
case 'policy_export': {
            $yaml = policy_export_yaml();
            header('Content-Type: text/yaml; charset=utf-8');
            header('Content-Disposition: attachment; filename="iptm-policy-' . date('Ymd-His') . '.yaml"');
            echo $yaml; exit;
        }
        case 'backup_named': {
            [$c, $msg] = backup_named((string)($_POST['label'] ?? ''));
            flash($c === 0 ? ('Backup creato: ' . $msg) : $msg, $c === 0 ? 'ok' : 'err');
            $back = 'p=apply'; break;
        }
        case 'whatsnew_ack': {
            $_SESSION['whatsnew_seen'] = APP_VERSION; // compatibilità notifiche già confermate
            if (!update_notice_mark_seen(APP_VERSION)) flash('Non è stato possibile salvare la conferma della notifica tramite iptm-helper.', 'err');
            $back = 'p=status'; break;
        }
        case 'postcheck_restart': {
            $unit = (string)($_POST['unit'] ?? '');
            if (!preg_match('/^[A-Za-z0-9@._-]{1,60}$/D', $unit)) {
                flash('Unità di servizio non valida.', 'err'); $back = 'p=postcheck'; break;
            }
            [$rc, $out, $err] = priv('post-restart', null, [$unit]);
            flash($rc === 0 ? trim($out) : 'Riavvio non riuscito: '.herr($out.$err), $rc === 0 ? 'ok' : 'err');
            $back = 'p=postcheck'; break;
        }
        case 'postcheck_script': {
            $conf = post_conf();
            if (iptm_post_legacy_script((string)($conf['script'] ?? ''))) {
                flash('Script IoT precedente disabilitato: non sarà eseguito. Usa Zone IoT.', 'err');
                $back = 'p=postcheck'; break;
            }
            [$rc, $out, $err] = priv('post-script');
            flash($rc === 0 ? trim($out) : 'Script non eseguito: '.herr($out.$err), $rc === 0 ? 'ok' : 'err');
            $back = 'p=postcheck'; break;
        }
        case 'postcheck_all': {
            [$rc, $out, $err] = priv('post');
            $failed = $rc !== 0 || preg_match('/^FAIL /m', $out) === 1;
            flash('Post-apply: '.(trim($out) ?: ($failed ? 'operazione non riuscita' : 'nessun servizio configurato')).
                ($err !== '' ? "\n".$err : ''), $failed ? 'err' : 'ok');
            $back = 'p=postcheck'; break;
        }
        case 'config_bundle_import': {
            $back='p=config';
            if (($_SESSION['role'] ?? '') !== 'admin') { flash('Solo admin.', 'err'); break; }
            $f=$_FILES['config'] ?? null;
            if (!is_array($f) || ($f['error'] ?? 1)!==UPLOAD_ERR_OK || ($f['size'] ?? 0)>5*1048576 || !is_uploaded_file($f['tmp_name'])) {
                flash('Seleziona un file JSON IPTM valido (max 5 MiB).','err'); break;
            }
            $raw=file_get_contents($f['tmp_name']);
            $importLock=@fopen(DATA_DIR.'/apply.lock','c');
            if(!$importLock || !@flock($importLock,LOCK_EX|LOCK_NB)) {if(is_resource($importLock))fclose($importLock);flash('Altra transazione in corso.','err');break;}
            try {
                $plan=iptm_import_plan((string)$raw);
                iptm_stage_configuration($plan['settings'],$plan['draft'],$plan['draft6']??null);
                audit('importazione profilo portabile IPTM: solo bozza');
                flash('Profilo importato nella bozza: rimossi ' . (int)($plan['removed_comments']??0) . ' commenti del vecchio rules.v4 (incluse regole disattivate). Regole attive e marcatori IPTM preservati. Nessuna regola live modificata. Verifica prima in Applica.');
                $back='p=apply';
            } catch (Throwable $e) { flash('Bundle rifiutato: '.substr($e->getMessage(),0,500),'err'); } finally {iptm_release_apply_lock($importLock);}
            break;
        }
        
        case 'release_rollback': {
            $ver = trim((string)($_POST['target_version'] ?? ''));
            if (!preg_match('/^\d+(?:\.\d+){1,3}$/D', $ver)) {
                flash('Versione non valida.', 'err');
                $back = 'p=update';
                break;
            }
            if ($ver === APP_VERSION) {
                flash('La versione selezionata è già attiva.', 'err');
                $back = 'p=update';
                break;
            }
            $web = realpath((string)($_SERVER['SCRIPT_FILENAME'] ?? '')) ?: '';
            [$c, $o, $e] = priv('release-rollback', null, [$web, $ver]);
            if ($c !== 0) {
                flash('Ripristino release fallito: ' . herr(trim($e ?: $o)), 'err');
            } else {
                flash("Ripristino completato:\n" . trim($o));
            }
            $back = 'p=update';
            break;
        }

        case 'ui_update_apply': { flash('Aggiornamento UI separato ritirato. Usa il pacchetto completo dalla pagina Aggiornamenti.', 'err'); $back='p=update'; break; }
        case 'update_apply':
        case 'update_url_apply': {
            $back = 'p=update';
            if (($_SESSION['role'] ?? '') !== 'admin') { flash('Solo admin.', 'err'); break; }
            // Both paths deliberately calculate SHA-256 locally: no manual hash needed.
            // An HTTP transport does NOT authenticate the release publisher.
            $dir = DATA_DIR . '/update';
            if (is_link($dir) || (!is_dir($dir) && !@mkdir($dir, 0700, true)) || !is_dir($dir) || !is_writable($dir)) {
                flash('Directory aggiornamenti non disponibile o non sicura.', 'err'); break;
            }
            // Signed redirect query parameters and package files must not leak
            // through a world-readable staging directory.
            if (((int)@fileperms($dir) & 0077) !== 0 &&
                (!@chmod($dir,0700) || (((int)@fileperms($dir) & 0077) !== 0))) {
                flash('Directory aggiornamenti con permessi non sicuri.', 'err'); break;
            }
            $name = 'package-' . bin2hex(random_bytes(16)) . '.zip';
            $path = $dir . '/' . $name;
            if ($a === 'update_url_apply') {
                $url = trim((string)($_POST['package_url'] ?? ''));
                if (strlen($url)>1500) {
                    flash('URL aggiornamento troppo lungo.', 'err'); break;
                }
                // HTTP is supported for LAN deployments. A bare transport hash
                // is insufficient to authenticate an update: HTTP *requires*
                // an author-published SHA-256 verified from an independent source.
                try { $urlScheme = iptm_update_url_parts($url)['scheme']; }
                catch (InvalidArgumentException $ex) { flash('URL rifiutato: '.$ex->getMessage(),'err'); break; }
                $httpSha = strtolower(trim((string)($_POST['sha'] ?? '')));
                if ($urlScheme === 'http' && !preg_match('/^[a-f0-9]{64}$/D', $httpSha)) {
                    flash('Aggiornamento HTTP: serve SHA-256 attendibile del pacchetto (64 caratteri).','err'); break;
                }
                [$dlrc, $dlerr] = iptm_update_download_zip($url, $path);
                if ($dlrc !== 0) {
                    @unlink($path);
                    flash('Download ZIP non riuscito: ' . $dlerr . '. Usa un URL diretto attendibile oppure carica il ZIP.', 'err');
                    break;
                }
            } else {
                $f = $_FILES['pkg'] ?? null;
                if (!$f || ($f['error'] ?? 1) !== UPLOAD_ERR_OK || !is_uploaded_file($f['tmp_name'])) {
                    flash('Caricamento non riuscito (file mancante o superiore al limite PHP).', 'err'); break;
                }
                if ($f['size'] < 100 || $f['size'] > 8 * 1048576) {
                    flash('Pacchetto ZIP non valido o troppo grande (max 8 MiB).', 'err'); break;
                }
                if (!move_uploaded_file($f['tmp_name'], $path)) {
                    flash('Impossibile salvare il pacchetto.', 'err'); break;
                }
            }
            @chmod($path, 0600);
            // Helpful, optional preflight. The privileged validator STILL verifies every
            // member/CRC/hash; this branch never authorizes an otherwise invalid update.
            if (class_exists('ZipArchive')) {
                $probe = new ZipArchive();
                if ($probe->open($path) === true) {
                    $names = [];
                    for ($i = 0; $i < $probe->numFiles; $i++) {
                        $names[] = (string)$probe->getNameIndex($i);
                    }
                    $probe->close();
                    $native = in_array('native-manifest.json', $names, true);
                    if (!$native) {
                        @unlink($path);
                        $nested = count(array_filter($names, static fn($n) => str_ends_with(strtolower($n), '.zip'))) > 0;
                        flash($nested
                            ? 'Archivio contenitore non installabile: carica il solo ZIP Native Update.'
                            : 'Formato non supportato: usa un pacchetto Native Update con manifest SHA-256.', 'err');
                        break;
                    }
                }
            }
            $sha = hash_file('sha256', $path);
            if (!is_string($sha) || !preg_match('/^[a-f0-9]{64}$/D', $sha)) {
                @unlink($path); flash('Impossibile verificare l’integrità della copia ZIP.', 'err'); break;
            }
            $manualSha = strtolower(trim((string)($_POST['sha'] ?? '')));
            if ($manualSha !== '' && (!preg_match('/^[a-f0-9]{64}$/D', $manualSha) || !hash_equals($manualSha, $sha))) {
                @unlink($path); flash('Hash facoltativo diverso da quello calcolato.', 'err'); break;
            }
            [$c, $o, $e] = priv('self-update', null, [realpath((string)($_SERVER['SCRIPT_FILENAME'] ?? '')) ?: '', !empty($_POST['force']) ? 'force' : '-', $name, $sha]);
            @unlink($path);
            if ($c !== 0) { flash(herr($o . $e), 'err'); break; }
            if (function_exists('opcache_reset')) @opcache_reset();
            $vl = ''; foreach (explode("\n", $o) as $ln) {
                if (str_starts_with($ln, 'versione ')) { $vl = trim($ln); break; }
            }
            audit('aggiornamento da web (' . ($a === 'update_url_apply' ? 'URL' : 'upload') . '): '
                . ($vl !== '' ? $vl : trim(strtok($o, "\n"))) . ' sha256=' . substr($sha, 0, 16));
            flash("Aggiornamento completato:\n" . trim($o)
                . (str_contains($o, 'FULL') ? "\nEseguire anche update-dietpi.sh --full via SSH." : ''));
            break;
        }
        case 'dismiss_reset_flag': if (!reset_notice_dismiss()) flash('Avviso non chiuso: controlla i permessi della cartella dati.', 'err'); else flash('Avviso chiuso.'); $back = 'p=status'; break;
        case 'backup_prune': {
            $back='p=apply';
            if (($_SESSION['role']??'')!=='admin') { flash('Solo amministratori.', 'err'); break; }
            $dir=DATA_DIR.'/backups';
            $all=array_filter(glob($dir.'/rules.v*.*') ?: [], static function($f) {
                return is_file($f) && !is_link($f) && preg_match('/^rules\.v[46]\.\d{8}-\d{6}$/D',basename($f));
            });
            usort($all,static fn($x,$y)=>strcmp(basename($y),basename($x)));
            $protected=array_fill_keys(array_slice($all,0,10),true);
            $requested=array_unique(array_map('strval',(array)($_POST['backup_files']??[])));
            $deleted=0;$skipped=0;
            foreach($requested as $name) {
                if (!preg_match('/^rules\.v[46]\.\d{8}-\d{6}$/D',$name)) { $skipped++;continue; }
                $file=$dir.'/'.$name;
                if (!in_array($file,$all,true) || isset($protected[$file]) || filemtime($file)>time()-7*86400) {$skipped++;continue;}
                if (@unlink($file)) $deleted++; else $skipped++;
            }
            audit('backup cleanup selected='.$deleted.' skipped='.$skipped);
            flash('Backup automatici eliminati: '.$deleted.'; conservati/non idonei: '.$skipped.'. Gli snapshot di emergenza, i backup etichettati e i 10 più recenti non sono stati toccati.');
            break;
        }
        case 'restore_backup': {
            $name=$_POST['name']??null;
            if(!is_string($name)){flash('Nome backup non valido.','err');break;}
            $lock=@fopen(DATA_DIR.'/apply.lock','c');
            if(!$lock||!@flock($lock,LOCK_EX|LOCK_NB)){if(is_resource($lock))fclose($lock);flash('Altra transazione in corso.','err');break;}
            try {
                if(is_file(DATA_DIR.'/pending.json'))throw new RuntimeException('Prova firewall pendente.');
                $text=iptm_rules_backup_read($name);$v6=$name[7]==='6';
                [$rc,$out,$err]=priv($v6?'test6':'test',$text);
                if($rc!==0)throw new RuntimeException('Test regole fallito: '.herr($out.$err));
                $seen=$v6?v6_expected():($GLOBALS['_draft_read_sha']??null);
                $old=$v6?v6_get():get_draft();
                if(!is_string($seen)||!hash_equals($seen,hash('sha256',$old)))throw new RuntimeException('Bozza cambiata o revisione assente. Ricarica la pagina Storico.');
                $backup=DATA_DIR.'/backups/rules.v'.($v6?'6':'4').'.'.gmdate('Ymd-His').'.'.bin2hex(random_bytes(4));
                if(!atomic_data_write($backup,$old,0600))throw new RuntimeException('Backup della bozza corrente non riuscito.');
                if(!($v6?v6_put($text):put_draft($text)))throw new RuntimeException('Scrittura bozza fallita.');
                flash('Backup caricato nella bozza, non applicato. Le impostazioni possono richiedere riallineamento.');
            }catch(Throwable $e){flash($e->getMessage(),'err');}finally{iptm_release_apply_lock($lock);}
            break;
        }

        
}
