<?php
/* IPTM action domain: update_backup. Inherits the authenticated controller scope. */
switch ($a) {
case 'upgrade_cleanup_run': {
    $back='p=update';
    if (($_SESSION['role'] ?? '') !== 'admin') { flash('Solo amministratori.', 'err'); break; }
    [$code, $out, $err] = priv('upgrade-cleanup', null, ['apply']);
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
    $fields=['backup_days'=>[7,730], 'backup_keep'=>[3,100], 'report_days'=>[7,365],
             'report_keep'=>[3,100], 'stats_days'=>[14,365],
             'max_backup_mib'=>[128,65536], 'log_copies'=>[3,90]];
    $values=[];$valid=true;
    foreach ($fields as $key=>[$min,$max]) {
        $value=filter_var($_POST[$key]??null,FILTER_VALIDATE_INT);
        if ($value===false || $value<$min || $value>$max) {$valid=false;break;}
        $values[$key]=(int)$value;
    }
    if (!$valid) { flash('Valori di conservazione non validi.', 'err'); break; }
    [$rc,$out,$err]=priv('retention',json_encode($values,JSON_THROW_ON_ERROR),['configure']);
    flash($rc===0?'Politica di rotazione salvata.':'Salvataggio non riuscito: '.herr($out.$err), $rc===0?'ok':'err');
    if ($rc===0) audit('rotazione backup/log: politica aggiornata');
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
            try {
                $plan=iptm_import_plan((string)$raw);
                // Validate iptables syntax before any persistent write; do not touch the running firewall.
                [$tc,$to,$te]=priv('test',$plan['draft']);
                if ($tc!==0) { flash('Regole incompatibili: importazione annullata. '.herr($to.$te),'err'); break; }
                settings_snapshot('bundle-import');
                $prev=get_draft(); $old=S_get();
                S_put($plan['settings']);
                if (!put_draft($plan['draft'])) {
                    $GLOBALS['_Sc']=null; S_put($old); put_draft($prev);
                    flash('Importazione bozza fallita: ripristino delle impostazioni tentato.','err'); break;
                }
                audit('importazione profilo portabile IPTM: solo bozza');
                flash('Profilo importato nella bozza: rimossi ' . (int)($plan['removed_comments']??0) . ' commenti del vecchio rules.v4 (incluse regole disattivate). Regole attive e marcatori IPTM preservati. Nessuna regola live modificata. Verifica prima in Applica.');
                $back='p=apply';
            } catch (Throwable $e) { flash('Bundle rifiutato: '.substr($e->getMessage(),0,250),'err'); }
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
        case 'restore_backup':
            $n = (string)($_POST['name'] ?? ''); if (preg_match('/^rules\.v[46]\.\d{8}-\d{6}$/', $n) && is_file(DATA_DIR . '/backups/' . $n)) { ($n[7] === '6' ? 'v6_put' : 'put_draft')((string)file_get_contents(DATA_DIR . '/backups/' . $n)); flash('Backup caricato nella bozza (non ancora applicato).'); } else flash('Backup non trovato.', 'err'); break;
        
}
