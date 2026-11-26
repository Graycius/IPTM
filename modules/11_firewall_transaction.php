<?php
// ===================== v2: APPLICAZIONE, IPv6, CONFIGURAZIONE GUIDATA =====================
function write_live(string $txt, string $fam = '4'): array {
    // Backup verificato, file 0600 e nome univoco anche con due richieste
    // nello stesso secondo. Mai scrivere il nuovo rules.vN se la copia fallisce.
    if (is_link(DATA_DIR . '/backups') || (!is_dir(DATA_DIR . '/backups') && !@mkdir(DATA_DIR . '/backups', 0700, true)))
        return [1, 'Directory backup regole non disponibile o non sicura'];
    if ($fam === '6') { [$rc, $cur, $err] = priv('cat6'); }
    else { $cur = rules_live(); $rc = 0; $err = ''; }
    if ($rc !== 0) return [1, 'Impossibile leggere le regole esistenti: ' . $err];
    $bootFile = $fam === '6' ? '/etc/iptables/rules.v6' : RULES_FILE;
    if (is_link($bootFile) || (is_file($bootFile) && trim($cur) === ''))
        return [1, 'Backup negato: file regole persistenti presente ma vuoto, simbolico o non leggibile'];
    if ($cur !== '') {
        $bk = DATA_DIR . '/backups/rules.v' . $fam . '.' . date('Ymd-His') . '-' . bin2hex(random_bytes(4));
        if (!atomic_data_write($bk, $cur, 0600)) return [1, 'Backup regole non riuscito, scrittura annullata'];
    }
    [$c, , $e] = priv($fam === '6' ? 'write6' : 'write', $txt);
    if ($c === 0) iptm_rotate_backups('rules.v' . $fam, 10, $bk ?? null);
    return [$c, $e];
}
function cs_chains_for(array $S, string $txt): array {   // catene su cui il bouncer deve agganciare la propria (iptables_chains)
    $ch = ['INPUT']; if (wan_ready($S) || !empty($S['nat_masq']) || $S['lan_nets'] !== '') $ch[] = 'FORWARD';
    if (!empty($S['cs_docker']) && (isset((live_dump()['chains']['filter'] ?? [])['DOCKER-USER']) || preg_match('/^:DOCKER-USER\b/m', $txt))) $ch[] = 'DOCKER-USER';
    return $ch;
}
function cs_prune_missing(string $txt, array $have): array {   // toglie le regole dirette su set CrowdSec inesistenti: il bouncer li crea solo per le origini che hanno decisioni
    $rm = []; $out = [];
    foreach (explode("\n", $txt) as $l) { if (preg_match('/^-A .*--match-set (crowdsec6?-blacklists\S*) /', $l, $m) && !isset($have[$m[1]])) { $rm[$m[1]] = 1; continue; } $out[] = $l; }
    return [implode("\n", $out), array_keys($rm)];
}
/** Only a root-side probe may declare IPv6 fully disabled on the gateway.
 * Any failed/missing probe means active or unknown: fail closed.
 */
function iptm_gateway_ipv6_disabled(): bool {
    [$rc, $out] = priv('v6cap');
    return $rc === 0 && trim($out) === 'disabled';
}
/** Diagnostic metadata is display-only and must never bypass a firewall preflight. */
function iptm_v6_diagnostic(): array {
    [$rc, $out] = priv('v6diag');
    if ($rc !== 0) return ['state'=>'unknown', 'filter'=>'unknown', 'backend'=>'unknown', 'all'=>'?', 'default'=>'?'];
    $diag=[];
    foreach (explode("\n", $out) as $line) {
        if (preg_match('/^(state|filter|backend|all|default)=(.{0,120})$/D',trim($line),$m))
            $diag[$m[1]]=$m[2];
    }
    return $diag;
}
/** A suspended MAC plan is informational data, not a firewall draft. */
function iptm_mac_pending_file(): string { return DATA_DIR . '/mac-plan-suspended.json'; }
function iptm_mac_pending_read(): ?array {
    $raw=@file_get_contents(iptm_mac_pending_file());
    if (!is_string($raw) || strlen($raw)>262144) return null;
    $plan=json_decode($raw,true);
    return is_array($plan) && ($plan['schema']??null) === 1 ? $plan : null;
}
/** Mandatory guard for any attempt to activate or persist IPv4-only MAC isolation. */
function iptm_mac_ipv6_guard(): string {
    $settings = S_get();
    if (($settings['iot_strategy'] ?? '') === 'iptm_mac' &&
        ($settings['iot_ipv6_status'] ?? '') === 'gateway-disabled' &&
        !iptm_gateway_ipv6_disabled())
        return 'IPv6 è stato riabilitato o non è verificabile dopo il salvataggio della policy MAC solo IPv4. Nessuna regola applicata o salvata, anche con Forza. Rigenera la policy e verifica ip6tables oppure disabilita IPv6 in modo completo.';
    return '';
}
/** Validate selectively generated IoT filter rules before invoking privileged
 * preflight calls.  This is intentionally independent of PHP session state and
 * never mutates the live firewall or the draft.  It is a static guard, NOT an
 * alternative to iptables-restore --test or the timed rollback watchdog. */
function iptm_iot_rules_diagnose(string $txt): array {
    $problems = []; $inFilter = false; $inIoT = false;
    foreach (preg_split('/\r?\n/', $txt) as $index => $raw) {
        $line = trim($raw);
        if ($line === '*filter') { $inFilter = true; $inIoT = false; continue; }
        if ($line === 'COMMIT') { $inFilter = false; $inIoT = false; continue; }
        if (!$inFilter) continue;
        if (preg_match('/^# >>> IPTM:(?:iot-|iot-g\\d+|cust-.*-filter-)/', $line)) $inIoT = true;
        if (preg_match('/^# <<< IPTM:(?:iot-|iot-g\\d+|cust-.*-filter-)/', $line)) $inIoT = false;
        if (!$inIoT || !str_starts_with($line, '-A ')) continue;
        if (!str_contains($line, '--mac-source')) continue;
        if (!preg_match('/(?:^|\s)--mac-source\s+((?:[a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2})(?:\s|$)/D', $line)) {
            $problems[] = 'Riga '.($index+1).': MAC non valido nel filtro IoT'; continue;
        }
        if (!preg_match('/^-A\s+(?:FORWARD|INPUT)\s/', $line))
            $problems[] = 'Riga '.($index+1).': filtro MAC inserito in una catena inattesa';
        if (!preg_match('/\s-j\s+(?:DROP|REJECT|ACCEPT|IPTM-MAC-(?:FWD|IN))(?:\s|$)/', $line))
            $problems[] = 'Riga '.($index+1).': target IoT non riconosciuto';
        if (count($problems) >= 6) break;
    }
    return $problems;
}
/** Prepare a rollback candidate while preserving the unchanged original. */
function iptm_recovery_prepare(string $snapshot, string $family): array {
    if (!in_array($family,['4','6'],true)||trim($snapshot)===''||strlen($snapshot)>2097152)
        return [1,'','Snapshot di rollback non valido'];
    [$rc,$prepared,$err]=priv('rollback-prepare',$snapshot,[$family]);
    if($rc!==0||trim($prepared)==='')return [1,'','IPSet non verificabili: '.herr($err)];
    [$testRc,$out,$testErr]=priv($family==='6'?'test6':'test',$prepared);
    if($testRc!==0)return [1,'','Preflight delle vecchie regole fallito: '.herr($out.$testErr)];
    return [0,$prepared,$err];
}

function iptm_release_apply_lock($lock): void {
    if (is_resource($lock)) {
        @flock($lock, LOCK_UN);
        @fclose($lock);
    }
}
/** Strict form validation; missing field remains compatible with older clients. */
function iptm_trial_seconds($raw = null): int {
    if ($raw === null) return max(30, min(600, ROLLBACK_SECS));
    if ((!is_int($raw) && !is_string($raw)) || !preg_match('/^[0-9]{1,3}$/D', (string)$raw) || (int)$raw < 30 || (int)$raw > 600)
        throw new RuntimeException('Timeout non valido: indicare da 30 a 600 secondi. Nessuna regola applicata.');
    return (int)$raw;
}
function iptm_trial_timeout_field(string $family): string {
    $id = 'iptm-trial-secs-'.$family;
    return '<label class="iptm-trial-timeout" for="'.$id.'">Tempo per confermare (secondi)<input id="'.$id.'" name="secs" type="number" min="30" max="600" step="1" value="'.iptm_trial_seconds().'" required></label>';
}
function do_apply(int $secs, string $fam = '4', bool $force = false, bool $confirmDnsGuardRemoval = false): string {
    if (!in_array($fam,['4','6'],true)) return 'Famiglia firewall non valida.';
    $GLOBALS['apply_notes'] = [];
    $GLOBALS['_iptm_post_stage']='firewall:locking';
    // Serialize applies before reading pending/draft; competing POSTs must not race
    // while replacing the live kernel rules and sharing the rollback timer.
    $applyLock = @fopen(DATA_DIR . '/apply.lock', 'c');
    if (!$applyLock || !@flock($applyLock, LOCK_EX | LOCK_NB)) return 'Altra applicazione firewall in corso; riprova.';
    try {
    $sx = $fam === '6' ? '6' : '';
    // A queued concurrent request can change draft.rules after the page was
    // loaded and before this apply lock was obtained. The expected SHA-256 is
    // set by get_draft()/put_draft() and never trusted from a URL parameter.
    $GLOBALS['_iptm_post_stage']='firewall:draft_revision';
    if ($fam === '4') {
        $expectedDraft = $GLOBALS['_draft_read_sha'] ?? null;
        if (!is_string($expectedDraft) || !preg_match('/^[a-f0-9]{64}$/D', $expectedDraft))
            return 'Revisione bozza non disponibile: applicazione annullata.';
        $onDiskDraft = get_draft();
        if (!hash_equals($expectedDraft, hash('sha256', $onDiskDraft)))
            return 'La bozza è cambiata durante la richiesta: applicazione annullata, ricarica.';
    }
    if (is_file(DATA_DIR . '/pending.json')) return 'Esiste un rollback pendente o incompleto: verifica lo stato da console prima di applicare altre regole.';
    // A MAC plan staged while IPv6 was disabled must not be applied after
    // IPv6 is enabled: there would be no IPv6 isolation rules in the draft.
    // This guard is mandatory, including with the 'force' checkbox.
    if ($fam === '4' && ($ipv6Risk = iptm_mac_ipv6_guard()) !== '') return $ipv6Risk;
    if ($fam === '6') {
        $expected6 = $GLOBALS['_v6_read_sha'] ?? null;
        $onDisk6 = v6_get();
        if (!is_string($expected6) || !hash_equals($expected6,hash('sha256',$onDisk6)))
            return 'La bozza IPv6 è cambiata o non è verificabile: applicazione annullata, ricarica.';
    }
    $txt = $fam === '6' ? $onDisk6 : $onDiskDraft; // immutable snapshot already revision-checked
    if ($fam === '4' && !$confirmDnsGuardRemoval) {
        try {$removed=iptm_dns_guard_losses(rules_live(),$txt);}
        catch(RuntimeException $ex){return 'Confronto protezioni DNS non disponibile: '.$ex->getMessage();}
        if($removed)return 'Protezione DNS/DoT su disco mancante dalla bozza: '.implode(', ',$removed).'. Ripristina in Setup oppure conferma espressamente la rimozione nella pagina Applica. Nessuna regola live modificata.';
    }
    if ($fam === '4') {
        $cfg = S_get(); $cfgNotes = []; $safeCfg = iptm_safe_settings($cfg,$cfgNotes);
        if (!empty($safeCfg['lockout_on']) && !empty($safeCfg['lan_nets']) && !iptm_management_nets($safeCfg))
            return 'Rete amministrativa non univoca: impostare Reti amministrative in Sicurezza e rigenerare la bozza. Regole live invariate.';
    }
    if ($fam === '4' && ($bad = iptm_reject_unsafe_rules($txt)) !== '') return $bad;
    if ($fam === '4' && ($iotIssues = iptm_iot_rules_diagnose($txt)))
        return 'Policy IoT non applicabile: '.implode('; ', $iotIssues).'. Rigenera la bozza IoT: nessuna regola caricata.';
    if ($fam === '6') { $iv = ipset_inventory(); if ($iv['ok']) { [$t3, $rm3] = cs_prune_missing($txt, $iv['sets']); if ($rm3) { $txt = $t3; if (!v6_put($txt)) return 'Impossibile salvare la bozza IPv6 normalizzata.'; $GLOBALS['apply_notes'][] = ['ok', 'Tolti dalla bozza IPv6 i riferimenti a set CrowdSec non esistenti (' . implode(', ', $rm3) . '): il bouncer ci pensa con la sua catena.']; } } }
    if ($fam === '6' && !$force && preg_match_all('/--match-set\s+(\S+)/', $txt, $mm6)) { $inv6 = ipset_inventory(); if ($inv6['ok']) { $ms6 = array_values(array_filter(array_unique($mm6[1]), fn($x) => !isset($inv6['sets'][$x]))); if ($ms6) return 'Set ipset inesistenti nel sistema: ' . implode(', ', $ms6) . '. Il bouncer CrowdSec è avviato? (set IPv6: ' . CS_V6 . '-0 …)'; } }
    if ($fam === '4') {
        if (!$force) {
            $cur = rules_live();
            if ($cur !== '' && rules_equiv($txt, $cur)) {
                [$runtimeCode, $runtimeText, $runtimeErr] = priv('save');
                if ($runtimeCode !== 0 || trim($runtimeText) === '')
                    return 'Impossibile verificare le regole realmente caricate nel kernel: ' . herr($runtimeErr);
                if (!rules_equiv($txt, $runtimeText))
                    return 'Le regole persistenti coincidono con la bozza, ma il kernel è diverso (Docker/CrowdSec/modifiche runtime). Nessuna modifica automatica: controlla il runtime e riprova dalla console.';
                $wc = $txt !== $cur ? write_live($txt, '4')[0] : 0;
                if ($wc !== 0) return 'Persistenza delle regole equivalenti fallita; bozza conservata.';
                iptm_draft_remove_if_same($txt,'4');
                return '@skip';
            }
        }
        $GLOBALS['_iptm_post_stage']='firewall:chain_normalization';
        [$t2, $fx, $ms] = fix_chain_decls($txt);
        if ($ms) return 'La bozza salta a catene che non esistono né nel kernel né nella bozza: ' . implode(', ', $ms) . '. Dichiarale o rimuovi le regole (Strumenti → Rilevamento sistema).';
        if ($fx) { $txt = $t2; if (!put_draft($txt)) return 'Impossibile salvare la bozza normalizzata; applicazione annullata.'; $GLOBALS['apply_notes'][] = ['ok', 'Dichiarate nella bozza le catene create a runtime (restano vuote finché il servizio non le ricrea): ' . implode(', ', $fx)]; }
        $inv = ipset_inventory();
        if ($inv['ok']) { [$t3, $rm3] = cs_prune_missing($txt, $inv['sets']); if ($rm3) { $txt = $t3; if (!put_draft($txt)) return 'Impossibile salvare la bozza dopo la pulizia ipset.'; $GLOBALS['apply_notes'][] = ['ok', 'Tolti dalla bozza i riferimenti a set CrowdSec non esistenti (' . implode(', ', $rm3) . '): il bouncer li crea solo per le origini con decisioni; il blocco resta garantito dalla catena ' . CS_CHAIN . '.']; } }
        if ($inv['ok']) { $miss = sets_missing($txt, $inv['sets']); if ($miss && !$force) return 'Set ipset inesistenti nel sistema: ' . implode(', ', $miss) . '. ' . set_hint($miss, $inv['sets']) . ' Usa Strumenti → Rilevamento sistema → «Usa i set e la catena CrowdSec rilevati», oppure «forza» per ignorare.'; }
        $GLOBALS['_iptm_post_stage']='firewall:preflight';
        try { $pf = apply_preflight($txt); }
        catch (\Throwable $ex) {
            $incident=iptm_request_id();
            error_log('IPTM preflight '.$incident.' class='.get_class($ex).' file='.basename($ex->getFile()).':'.$ex->getLine());
            return 'Preflight firewall/IoT non disponibile (rif. '.$incident.'). Nessuna regola applicata. Controlla il log PHP e non usare «Forza» per aggirare un errore interno.';
        }
        if ($pf['block'] !== '' && (!empty(S_get()['continuity_priority']) || str_starts_with($pf['block'], 'LAN→WAN:') || !$force || str_contains($txt,'--mac-source')))
            return $pf['block'] . (str_contains($txt,'--mac-source')
                ? ' Per le policy MAC non è consentito aggirare il controllo amministrativo con «Forza».'
                : ' (Con «forza» procedi comunque.)');
        foreach ($pf['warn'] as $w) $GLOBALS['apply_notes'][] = ['err', '⚠ ' . $w];
        // Opzione: conserva catene/regole runtime (Docker, CrowdSec) nel restore
        if (!empty($_POST['preserve_runtime']) && function_exists('rules_inject_runtime')) {
            [$txt2, $added, $err] = rules_inject_runtime($txt);
            if ($err === '' && $added) {
                $txt = $txt2;
                $GLOBALS['apply_notes'][] = ['ok', 'Runtime conservato nel restore: ' . count($added) . ' elementi (Docker/CrowdSec…).'];
            } elseif ($err !== '') {
                $GLOBALS['apply_notes'][] = ['err', 'Preserve runtime: ' . $err];
            }
        }
        ipsets_prepare();
    }
    $GLOBALS['_iptm_post_stage']='firewall:syntax_test';
    [$c, $o, $e] = priv('test' . $sx, $txt); if ($c) return (($fam === '4' && str_contains($txt, '--mac-source')) ? 'Test iptables-restore della bozza IoT fallito: ' : 'Test fallito: ') . herr(trim($o . $e)) . ' Nessuna regola applicata. Verifica moduli xt_mac, catene e backend iptables.';
    // Never apply an IPv6 draft with OUTPUT DROP and no outbound exceptions.
    if ($fam === '6' && preg_match('/^:OUTPUT\s+DROP\b/m', $txt) &&
        !preg_match('/^-A OUTPUT\s/m', $txt))
        return 'Bozza IPv6 non sicura: OUTPUT DROP senza eccezioni di uscita. Completa la policy prima di applicarla.';
    // Fail closed: an IPv6-disabled kernel cannot furnish a valid rollback snapshot.
    if ($fam === '6' && trim((string)@file_get_contents('/proc/sys/net/ipv6/conf/all/disable_ipv6')) === '1')
        return 'IPv6 risulta disabilitato nel kernel: nessuna regola applicata. Non forzare il rollback senza uno stato IPv6 salvabile.';
    // Preserve the last reachable live IPv4 rules before replacing a policy.
    // Rescue only covers IPTM firewall access; it never toggles NetworkManager.
    if ($fam === '4') {
        [$rescueRc, $rescueOut, $rescueErr] = priv('rescue', null, ['save']);
        if ($rescueRc !== 0)
            return 'Backup di recupero non disponibile: regole non applicate. ' . herr($rescueOut . $rescueErr);
    }
    $GLOBALS['_iptm_post_stage']='firewall:rollback_snapshot';
    [$c, $live, $e] = priv('save' . $sx);
    $snapshotInvalid = $c !== 0 || trim($live) === '' ||
        !preg_match('/^\*filter\s*$/m', $live) || !preg_match('/^COMMIT\s*$/m', $live) ||
        !preg_match('/^:INPUT\s+(?:ACCEPT|DROP|REJECT)\s+\[[0-9]+:[0-9]+\]/m', $live);
    if ($snapshotInvalid)
        return 'Impossibile salvare uno snapshot IPv' . $fam . ' valido per il rollback (exit ' . $c .
            ', dati ' . (trim($live) === '' ? 'vuoti' : 'presenti') . '). Regole NON applicate. '
            . herr(trim($e . "\n" . ($c !== 0 ? $live : ''))) .
            ' Controlla da SSH: ip6tables-save, ip6tables -t filter -S, ip6tables -V e /proc/sys/net/ipv6/conf/all/disable_ipv6.';
    // A backup that cannot pass iptables-restore --test is NOT a safety net.
    // Refuse the new policy BEFORE arm/start, preserving connectivity.
    [$safeRc,$safePrevious,$safeError]=iptm_recovery_prepare($live,$fam);
    if($safeRc!==0)return 'Preflight rollback non superato; nessuna regola applicata. '.$safeError;
    if(!hash_equals(hash('sha256',$live),hash('sha256',$safePrevious)))
        $GLOBALS['apply_notes'][]=['err','Snapshot contiene IPSet dinamici CrowdSec obsoleti: il watchdog userà una copia normalizzata.'];
    $rb = DATA_DIR . "/rollback$sx.rules"; $pf = DATA_DIR . '/pending.json'; $ap = DATA_DIR . "/applied$sx.rules";
    $secs = max(30, min(600, $secs));
    $csch = ($fam === '4' && !empty(S_get()['crowdsec'])) ? cs_chains_for(S_get(), $txt) : [];
    // Save complete recovery state and start an independent watchdog BEFORE
    // touching the live kernel rules; otherwise a network disconnect before
    // systemd-run leaves the administrator locked out without a rollback.
    if (!atomic_data_write($rb, $live, 0600) || !atomic_data_write($ap, $txt, 0600))
        return 'Impossibile salvare il rollback: nessuna regola caricata.';
    $trialSettings = $fam === '4' ? @file_get_contents(DATA_DIR . '/settings.json') : false;
    $trialSettingsHash = is_string($trialSettings) ? hash('sha256',$trialSettings) : '';
    $txid = bin2hex(random_bytes(16)); // identificativo monotematico per il timer indipendente
    $pendingData = json_encode(['until' => time() + $secs, 'secs' => $secs, 'fam' => $fam,
                                'txid' => $txid, 'status' => 'pending', 'health_ok' => false, 'settings_hash' => $trialSettingsHash, 'rules_hash' => hash('sha256',$txt)]);
    if (!is_string($pendingData) || !atomic_data_write($pf, $pendingData, 0600))
        return 'Impossibile registrare il rollback automatico: nessuna regola caricata.';
    $GLOBALS['_iptm_post_stage']='firewall:watchdog';
    [$watchCode, $watchOut, $watchErr] = priv('rollback-arm', null, [(string)$secs, $fam, $txid]);
    if ($watchCode !== 0) {
        // systemd-run may have started a timer even when its client exits with
        // an error. Keep the txid journal so an uncertain timer is harmless
        // and cannot roll back a later transaction. Operator recovery required.
        return 'Avvio watchdog NON verificato: regole non applicate. Stato pending conservato per sicurezza; verificare e riconciliare da console prima di riprovare. ' . herr($watchOut . $watchErr);
    }
    if (time() >= (int)(json_decode($pendingData, true)['until'] ?? 0))
        return 'Finestra di sicurezza scaduta durante il preflight: nessuna regola caricata; watchdog mantenuto per riconciliazione.';
    $GLOBALS['_iptm_post_stage']='firewall:restore_live';
    [$c, $o, $e] = priv('restore' . $sx, $txt);
    if ($c) {
        [$safeRc,$restorable]=iptm_recovery_prepare($live,$fam);
        $backCode=1; if($safeRc===0)[$backCode]=priv('restore' . $sx,$restorable);
        $cancelled = false;
        if ($backCode === 0) {
            [$cancelCode] = priv('rollback-cancel', null, [$txid]);
            if ($cancelCode === 0) { @unlink($pf); $cancelled = true; }
        }
        // If restore or timer cancellation failed, retain the independent watchdog.
        $recovery = $backCode !== 0 ? 'ripristino immediato non riuscito; watchdog mantenuto' :
            ($cancelled ? 'stato precedente ripristinato' : 'regole precedenti ripristinate, watchdog non verificabile');
        return 'Applicazione fallita: ' . $recovery . '. ' . herr($o . $e);
    }
    if ($csch) priv('cs-chains', null, $csch);   // dice al bouncer dove agganciarsi; lo riavvia subito dopo 'post'
    [$postCode, $po, $postErr] = priv('post');
    if ($postCode !== 0 || str_contains($po, 'FAIL'))
        $GLOBALS['apply_notes'][] = ['err', 'POST-APPLY NON COMPLETATO: servizi e script devono essere verificati. Codice ' . $postCode . '. ' . herr($po . "\n" . $postErr)];
    elseif (trim($po) !== '') $GLOBALS['apply_notes'][] = ['ok', "Servizi post-applicazione:\n" . trim($po)];
    [$testCode, $st, $testErr] = priv('selftest');
    $bad = array_values(array_filter(explode("\n", trim($st)), fn($l) => str_starts_with(trim($l), 'FAIL')));
    if ($testCode !== 0 || $bad)
        $GLOBALS['apply_notes'][] = ['err', "Test GATEWAY incompleto:\n" . implode("\n", $bad) . ' ' . herr($testErr)];
    else
        $GLOBALS['apply_notes'][] = ['ok', 'Test GATEWAY completato.'];
    // A separate browser request must confirm a healthy trial. Never confirm
    // under the apply lock or merely because a gateway probe succeeds.
    if ($postCode !== 0 || str_contains($po, 'FAIL') || $testCode !== 0 || $bad)
        return 'Test post-applicazione fallito: conferma bloccata, rollback automatico attivo.';
    $record = json_decode($pendingData, true);
    if (time() >= (int)$record['until']) return 'Prova scaduta: rollback automatico attivo.';
    [$runtimeRc,$runtimeText,$runtimeErr]=priv('save'.$sx);
    if($runtimeRc!==0 || !preg_match('/^\*filter\s*$/m',$runtimeText)) return 'Snapshot runtime dopo la prova non disponibile: watchdog attivo.';
    $record['runtime_hash']=iptm_runtime_fingerprint($runtimeText);
    $record['health_ok'] = true;
    if (!atomic_data_write($pf, json_encode($record), 0600))
        return 'Impossibile registrare esito dei test: rollback automatico attivo.';
    $GLOBALS['apply_notes'][] = ['ok', 'Prova attiva: verifica SSH, DNS e LAN da un altro collegamento, poi conferma.'];
    return '';
    } finally {
        iptm_release_apply_lock($applyLock);
    }
}
/** Fingerprint ordered iptables-save statements; ignore only comments/timestamps and counters. */
function iptm_runtime_fingerprint(string $text): string {
    $lines=[];
    foreach(preg_split('/\r?\n/',$text) as $raw) {
        $line=trim($raw); if($line==='' || str_starts_with($line,'#')) continue;
        if(preg_match('/^:/',$line)) $line=preg_replace('/\[[0-9]+:[0-9]+\]$/','[0:0]',$line);
        $line=preg_replace('/^\[[0-9]+:[0-9]+\]\s+/','',$line);
        $lines[]=$line;
    }
    return hash('sha256',implode("\n",$lines));
}
/** Single staging path for portable import and wizard. Caller holds apply.lock. */
/** Stage ordinary settings/restore through the same nonblocking transaction gate as the wizard. */
function iptm_stage_settings(array $settings,string $draft4): void {
    $lock=@fopen(DATA_DIR.'/apply.lock','c');
    if(!$lock||!@flock($lock,LOCK_EX|LOCK_NB)){if(is_resource($lock))fclose($lock);throw new RuntimeException('Altra transazione in corso.');}
    try {iptm_stage_configuration($settings,$draft4);} finally {iptm_release_apply_lock($lock);}
}
function iptm_stage_configuration(array $settings,string $draft4,?string $draft6=null): void {
    if(is_file(DATA_DIR.'/pending.json'))throw new RuntimeException('Transazione firewall pendente.');
    if(trim($draft4)==='')throw new RuntimeException('Bozza IPv4 vuota.');
    foreach(['4'=>$draft4,'6'=>$draft6] as $family=>$draft){
        if($draft===null||($family===6&&trim($draft)===''))continue;
        [$rc,$out,$err]=priv($family===6?'test6':'test',$draft);
        if($rc!==0)throw new RuntimeException('Test bozza IPv'.$family.' fallito: '.herr($out.$err));
    }
    $observed=$GLOBALS['_draft_read_sha']??null;
    $has6=$draft6!==null&&trim($draft6)!=='';
    $observed6=$has6?v6_expected():null;
    $settingsObserved=$GLOBALS['_settings_read_sha']??null;
    $old=S_get();$old4=get_draft();$old6=$has6?v6_get():null;
    if(is_string($settingsObserved)&&isset($GLOBALS['_settings_read_sha'])&&!hash_equals($settingsObserved,$GLOBALS['_settings_read_sha']))throw new RuntimeException('Impostazioni modificate durante la preparazione.');
    if($has6&&is_string($observed6)&&!hash_equals($observed6,hash('sha256',$old6)))throw new RuntimeException('Bozza IPv6 modificata durante la preparazione.');
    if(is_string($observed)&&!hash_equals($observed,hash('sha256',$old4)))throw new RuntimeException('Bozza IPv4 modificata durante la preparazione.');
    if(is_file(DATA_DIR.'/settings.json')&&settings_snapshot('stage-profile')===null)throw new RuntimeException('Backup impostazioni non riuscito.');
    if(!atomic_data_write(DATA_DIR.'/backups/rules.v4.'.gmdate('Ymd-His').'.'.bin2hex(random_bytes(4)),$old4,0600))throw new RuntimeException('Backup bozza non riuscito.');
    if($has6&&!atomic_data_write(DATA_DIR.'/backups/rules.v6.'.gmdate('Ymd-His').'.'.bin2hex(random_bytes(4)),$old6,0600))throw new RuntimeException('Backup bozza IPv6 non riuscito.');
    $done=[];
    try{
        S_put($settings);$done[]='settings';
        if(!put_draft($draft4))throw new RuntimeException('Scrittura bozza IPv4 fallita');$done[]='4';
        if($draft6!==null&&trim($draft6)!==''){if(!v6_put($draft6))throw new RuntimeException('Scrittura bozza IPv6 fallita');$done[]='6';}
    }catch(Throwable $failure){
        $issues=[];foreach(array_reverse($done) as $part){try{
            if($part==='settings')S_put($old);
            elseif($part==='4'){if(!put_draft($old4))$issues[]='IPv4';}
            elseif($part==='6'){if(!v6_put($old6, true))$issues[]='IPv6';}
        }catch(Throwable $ignored){$issues[]=$part;}}
        throw new RuntimeException($failure->getMessage().($issues?' — ripristino incompleto: '.implode(', ',$issues):' — scritture parziali compensate'));
    }
}
function confirm_pending(): string {
    $applyLock = @fopen(DATA_DIR . '/apply.lock', 'c');
    if (!$applyLock || !@flock($applyLock, LOCK_EX | LOCK_NB)) return 'Applicazione firewall ancora in corso: attendi prima di confermare.';
    try {
    $p = pending();
    if (!$p) return 'Nessuna applicazione in attesa (forse è già scaduta e annullata).';
    // A late confirmation can race the independent watchdog; never promote an
    // already-expired experimental ruleset to the persistent boot rules.
    if (!empty($p['invalid']) || time() >= (int)$p['until']) return 'Transazione scaduta o non leggibile: non confermare. Usa «Ripristina» per recuperare le regole precedenti.';
    $fam = ($p['fam'] ?? '4') === '6' ? '6' : '4';
    // Never confirm an IPv4-only MAC policy after IPv6 has become available.
    // Leave the pending watchdog armed so its rollback remains effective.
    if ($fam === '4' && ($ipv6Risk = iptm_mac_ipv6_guard()) !== '') return $ipv6Risk . ' Il watchdog di rollback rimane attivo.';
    $sx = $fam === '6' ? '6' : '';
    // A failed health check is not safe to confirm, even if the browser stayed
    // connected. Leave the independent rollback watchdog armed.
    if (($p['health_ok'] ?? false) !== true) return 'Prova non validata: ripristina e ripeti i test.';
    {
        [$healthCode, $healthOut, $healthErr] = priv('selftest');
        $failed = array_filter(explode("\n", trim((string)$healthOut)),
            fn($line) => str_starts_with(trim($line), 'FAIL'));
        if ($healthCode !== 0 || $failed)
            return 'Conferma impedita: test gateway fallito. Il ripristino automatico resta attivo; ' .
                   'verifica DNS, LAN e accesso prima di riprovare. ' . herr($healthErr);
    }
    $txt = @file_get_contents(DATA_DIR . "/applied$sx.rules");
    if (!is_string($txt) || trim($txt) === '') return 'Snapshot delle regole applicate assente: watchdog ancora attivo.';
    if (!is_string($p['rules_hash'] ?? null) || !preg_match('/^[a-f0-9]{64}$/D',$p['rules_hash']) || !hash_equals($p['rules_hash'],hash('sha256',$txt))) return 'Snapshot modificato durante la prova: conferma negata, watchdog attivo.';
    [$runtimeCode,$runtimeRules,$runtimeErr]=priv('save'.$sx);
    if($runtimeCode!==0 || trim((string)$runtimeRules)==='') return 'Runtime non verificabile: watchdog attivo. '.herr($runtimeErr);
    if(!is_string($p['runtime_hash']??null) || !hash_equals($p['runtime_hash'],iptm_runtime_fingerprint($runtimeRules))) return 'Le regole runtime sono cambiate durante la prova o manca il nuovo snapshot: conferma negata; watchdog attivo.';
    if (time() >= (int)$p['until']) return 'Prova scaduta durante i test: rollback attivo.';
    [$c, $e] = write_live($txt, $fam);
    if ($c) return 'Regole attive ma NON salvate su file; watchdog ancora attivo: ' . $e;
    [$cc, $co, $ce] = priv('rollback-cancel', null, isset($p['txid']) ? [(string)$p['txid']] : []);
    if ($cc !== 0) {
        // Cancellation is uncertain. Attempt to restore BOTH runtime and boot
        // configuration to the old snapshot; retain pending for any timer still
        // scheduled. Never mark an uncertain apply as last-good.
        $old = @file_get_contents(DATA_DIR . "/rollback$sx.rules");
        $recovery = 'snapshot precedente non disponibile';
        if (is_string($old) && trim($old) !== '') {
            [$safeRc,$restorable]=iptm_recovery_prepare($old,$fam);
            $rr=$wr=1;
            if($safeRc===0){
                [$rr]=priv('restore'.$sx,$restorable);
                if($rr===0)[$wr]=priv('write'.$sx,$restorable);
            }
            $recovery = ($rr === 0 && $wr === 0) ? 'ripristino immediato tentato e comandi riusciti' :
                'ATTENZIONE: ripristino immediato del kernel o del file non riuscito';
        }
        return 'Impossibile verificare l’arresto del watchdog: ' . $recovery . '. ' . herr($co . $ce);
    }
    if (!@unlink(DATA_DIR . '/pending.json'))
        return 'Regole salvate, ma impossibile chiudere pending.json: necessario intervento da console.';
    if ($fam === '4') {
        // Never delete a different draft created by another administrator
        // between the last read and successful firewall confirmation.
        iptm_draft_remove_if_same($txt,'4');
        priv('ipset-persist');
        $currentSettings = @file_get_contents(DATA_DIR . '/settings.json');
        if (is_string($currentSettings) && !empty($p['settings_hash']) && hash_equals((string)$p['settings_hash'],hash('sha256',$currentSettings))) {
            if (atomic_data_write(DATA_DIR . '/last-good.json',$currentSettings,0600))
                atomic_data_write(DATA_DIR . '/last-good.time',(string)time(),0600);
        }
    } else iptm_draft_remove_if_same($txt,'6');
    return '';
    } finally { iptm_release_apply_lock($applyLock); }
}
function revert_pending(): string {
    $applyLock = @fopen(DATA_DIR . '/apply.lock', 'c');
    if (!$applyLock || !@flock($applyLock, LOCK_EX | LOCK_NB)) { return 'Applicazione firewall ancora in corso: riprova.'; }
    try {
    $p = pending(); if (!$p) return 'Nessuna applicazione in attesa.';
    if (!empty($p['invalid'])) return 'Stato pendente danneggiato: usare il recupero da console, senza cancellare il file.';
    $sx = ($p['fam'] ?? '4') === '6' ? '6' : '';
    $old = @file_get_contents(DATA_DIR . "/rollback$sx.rules");
    if (!is_string($old) || trim($old) === '') {
        return 'Snapshot precedente mancante: watchdog lasciato attivo.';
    }
    // Manual and timed rollback use the SAME preflight normalizer.
    [$checkCode, $prepared, $checkErr] = iptm_recovery_prepare($old,$sx==='6'?'6':'4');
    if ($checkCode !== 0)
        return 'Preflight ripristino fallito; regole non modificate e watchdog conservato. '.$checkErr;
    [$rc, $out, $err] = priv('restore' . $sx, $prepared);
    if ($rc !== 0) {
        return 'Ripristino manuale fallito: watchdog lasciato attivo. ' . herr($out . $err);
    }
    [$cc, $co, $ce] = priv('rollback-cancel', null, isset($p['txid']) ? [(string)$p['txid']] : []);
    if ($cc !== 0) {
        return 'Regole precedenti ripristinate ma watchdog non verificabile: ' . herr($co . $ce);
    }
    if (!@unlink(DATA_DIR . '/pending.json'))
        return 'Regole ripristinate, ma pending.json non può essere chiuso: verificare i permessi da console.';
    priv('post');
    return '';
    } finally { iptm_release_apply_lock($applyLock); }
}
function v6_def(): array { return ['on' => 0, 'mode' => 'host', 'lan_if' => '', 'wan_if' => '', 'lan_prefix' => 'fe80::/10', 'icmp' => 1, 'dhcp6' => 1, 'ssh' => 1, 'ssh_port' => 22, 'ports' => '', 'log' => 0, 'crowdsec' => 0, 'cs_sets' => '', 'bogon' => 1, 'ssh_rl' => 1, 'invalid' => 1, 'rpfilter' => 0, 'dot_block' => 0, 'wg_on' => 0, 'wg_if' => 'wg0', 'wg_prefix' => '', 'wg_port' => 51820, 'wg_input' => 0, 'wg_lan' => 1]; }
function v6_get(): string {
    $f = DATA_DIR . '/draft6.rules';
    if (is_file($f)) { $s = @file_get_contents($f); if (!is_string($s)) throw new RuntimeException('Bozza IPv6 non leggibile'); }
    else { [$c, $o] = priv('cat6'); $s = $c === 0 ? $o : ''; }
    $GLOBALS['_v6_read_sha'] = hash('sha256', $s);
    return $s;
}
function v6_expected(): ?string {
    // I form HTML inviano la revisione vista dal browser, non quella letta dal server durante il POST.
    $r = $_POST['rev6'] ?? null;
    if ($r !== null) {
        if (!is_string($r) || !preg_match('/^[a-f0-9]{64}$/', $r)) throw new RuntimeException('Revisione IPv6 non valida');
        return $r;
    }
    return $GLOBALS['_v6_read_sha'] ?? null;
}
function v6_put(string $t, bool $compensating=false): bool {
    if (!is_dir(DATA_DIR) && !@mkdir(DATA_DIR, 0700, true) && !is_dir(DATA_DIR)) return false;
    $lock = @fopen(DATA_DIR . '/draft6.lock', 'c');
    if (!$lock || !@flock($lock, LOCK_EX)) throw new RuntimeException('Lock bozza IPv6 non disponibile');
    try {
        $f = DATA_DIR . '/draft6.rules';
        $cur = @file_get_contents($f);
        if (!is_string($cur) && is_file($f)) return false;
        if (!is_string($cur)) { [$rc, $out] = priv('cat6'); $cur = $rc === 0 ? $out : ''; }
        $expected = $compensating ? ($GLOBALS['_v6_read_sha'] ?? null) : v6_expected();
        if ($expected !== null && !hash_equals($expected, hash('sha256', $cur)))
            throw new RuntimeException('Conflitto IPv6: bozza modificata da un’altra richiesta. Ricarica la pagina.');
        if (!atomic_data_write($f, $t, 0600)) return false;
        $GLOBALS['_v6_read_sha'] = hash('sha256', $t);
        return true;
    } finally { @flock($lock, LOCK_UN); @fclose($lock); }
}
function v6_reset_draft(): bool {
    $lock = @fopen(DATA_DIR . '/draft6.lock', 'c');
    if (!$lock || !@flock($lock, LOCK_EX)) throw new RuntimeException('Lock bozza IPv6 non disponibile');
    try {
        $f = DATA_DIR . '/draft6.rules';
        if (!is_file($f)) return true;
        $cur = @file_get_contents($f);
        if (!is_string($cur)) return false;
        $expected = v6_expected();
        if ($expected !== null && !hash_equals($expected, hash('sha256', $cur)))
            throw new RuntimeException('Conflitto IPv6: impossibile cancellare una bozza modificata da altri');
        return @unlink($f);
    } finally { @flock($lock, LOCK_UN); @fclose($lock); }
}
/** Elenco di prefissi IPv6 separati da virgola: indirizzo valido ed eventuale maschera 0-128 (la sola regex accettava "1", "fe80:::/10", "/999"). */
function v6_prefixes_ok(string $v): bool {
    if ($v === '') return false;
    foreach (explode(',', $v) as $p) {
        [$a, $m] = array_pad(explode('/', $p, 2), 2, null);
        if (!filter_var($a, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) return false;
        if ($m !== null && (!preg_match('/^(0|[1-9]\d{0,2})$/D', $m) || (int)$m > 128)) return false;
    }
    return true;
}
function v6_gen(array $V): string {
    $V = array_replace(v6_def(),$V);
    $lan = (string)$V['lan_if']; $wan = (string)$V['wan_if'];
    foreach ([$lan,$wan,(string)$V['wg_if']] as $iface) if ($iface !== '' && !v_ok('if',$iface)) throw new RuntimeException('Interfaccia IPv6 non valida');
    if (!v6_prefixes_ok((string)$V['lan_prefix']) || !v_ok('port',(string)$V['ssh_port']) || !v_ok('ports',(string)$V['ports'])) throw new RuntimeException('Prefissi o porte IPv6 non validi');
    $L = ['# Generato da iptables-manager (IPv6)', '*filter', ':INPUT DROP [0:0]', ':FORWARD DROP [0:0]', ':OUTPUT ACCEPT [0:0]', '-A INPUT -i lo -j ACCEPT'];
    foreach (['INPUT','FORWARD'] as $c) { $L[] = "-A $c -m conntrack --ctstate INVALID -j DROP"; $L[] = "-A $c ! -i lo -s ::1 -j DROP"; }
    // NDP on the local link; router advertisements only on the upstream.
    foreach ([135,136] as $type) $L[] = "-A INPUT -p ipv6-icmp --icmpv6-type $type -m hl --hl-eq 255 -j ACCEPT";
    if ($lan !== '' && $V['mode'] === 'router') $L[] = "-A INPUT -i $lan -p ipv6-icmp --icmpv6-type 133 -m hl --hl-eq 255 -j ACCEPT";
    $ra = $wan !== '' ? $wan : ($V['mode'] === 'host' ? $lan : '');
    if ($ra !== '') $L[] = "-A INPUT -i $ra -s fe80::/10 -p ipv6-icmp --icmpv6-type 134 -m hl --hl-eq 255 -j ACCEPT";
    if (!empty($V['bogon']) && $wan !== '' && $wan !== $lan) foreach (['INPUT','FORWARD'] as $c) foreach (['fc00::/7','2001:db8::/32','::/128'] as $n) $L[] = "-A $c -i $wan -s $n -j DROP";
    if (!empty($V['crowdsec'])) foreach (array_filter(explode(',', (string)$V['cs_sets'])) as $x) if (v_ok('setlist',$x) && (($iv6 = ipset_inventory())['ok'] ? isset($iv6['sets'][$x]) : true)) foreach (['INPUT','FORWARD'] as $c) $L[] = "-A $c -m set --match-set $x src -j DROP";
    if (!empty($V['dot_block'])) foreach (['tcp','udp'] as $proto) $L[] = "-A FORWARD -p $proto --dport 853 -j REJECT --reject-with icmp6-port-unreachable";
    foreach (['INPUT','FORWARD'] as $c) {
        // Essential ICMPv6 error messages (PMTU and routing) must work even when optional echo is off.
        foreach ([1,2,3,4] as $type) $L[] = "-A $c -p ipv6-icmp --icmpv6-type $type -j ACCEPT";
        if ($V['icmp']) {
            if ($c === 'INPUT') {
                $L[] = "-A $c -p ipv6-icmp --icmpv6-type echo-request -m limit --limit 10/sec --limit-burst 20 -j ACCEPT";
                $L[] = "-A $c -p ipv6-icmp --icmpv6-type echo-request -j DROP";
            }
        } else $L[] = "-A $c -p ipv6-icmp --icmpv6-type echo-request -j DROP";
        $L[] = "-A $c -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT";
    }
    if ($V['icmp']) foreach ([130,131,132,143] as $type) $L[] = "-A INPUT -s fe80::/10 -p ipv6-icmp --icmpv6-type $type -m hl --hl-eq 1 -j ACCEPT";
    if ($V['dhcp6'] && $ra !== '') $L[] = "-A INPUT -i $ra -p udp --sport 547 --dport 546 -j ACCEPT";
    if (!empty($V['wg_on']) && v_ok('if',(string)$V['wg_if']) && v_ok('port',(string)$V['wg_port']) && $wan !== '') {
        $wg = $V['wg_if'];
        $L[] = "-A INPUT -i $wan -p udp --dport {$V['wg_port']} -j ACCEPT";
        // No unscoped IPv6 tunnel grants: explicit peer prefix required.
        $peer = (string)($V['wg_prefix']??'');
        if ($peer !== '' && v6_prefixes_ok($peer)) foreach (explode(',',$peer) as $src) {
            if (str_ends_with($src,'/0')) continue;
            if (!empty($V['wg_input'])) $L[] = "-A INPUT -i $wg -s $src -j ACCEPT";
            if (!empty($V['wg_lan']) && $lan !== '') foreach (explode(',',$V['lan_prefix']) as $dst) if (!str_ends_with($dst,'/0')) $L[] = "-A FORWARD -i $wg -o $lan -s $src -d $dst -j ACCEPT";
            if (!empty($V['wg_lan']) && $V['mode'] === 'router' && $wan !== $wg) $L[] = "-A FORWARD -i $wg -o $wan -s $src -j ACCEPT";
        }
    }
    if ($lan !== '' && ($lan !== $wan || $V['mode'] === 'host')) foreach (explode(',',$V['lan_prefix']) as $src) {
        if (str_ends_with($src,'/0')) continue;
        if ($V['ssh']) {
            $base = "-A INPUT -i $lan -s $src -p tcp --dport {$V['ssh_port']} -m conntrack --ctstate NEW --syn";
            if ($V['ssh_rl']) { $L[] = "$base -m recent --name IPTM6-SSH --update --seconds 60 --hitcount 5 -j DROP"; $L[] = "$base -m recent --name IPTM6-SSH --set -j ACCEPT"; }
            else $L[] = "$base -j ACCEPT";
        }
        if ($V['ports'] !== '') foreach (explode(',',$V['ports']) as $port) {
            [$lo,$hi] = array_pad(explode(':',$port,2),2,null); $lo=(int)$lo; $hi=$hi===null?$lo:(int)$hi;
            $ssh=(int)$V['ssh_port']; $ranges=[[$lo,$hi]];
            if ($V['ssh'] && $V['ssh_rl'] && $lo<=$ssh && $ssh<=$hi) $ranges=[[$lo,$ssh-1],[$ssh+1,$hi]];
            foreach ($ranges as [$a,$b]) if ($a<=$b) $L[] = "-A INPUT -i $lan -s $src -p tcp --dport ".($a===$b?(string)$a:$a.':'.$b).' -j ACCEPT';
        }
    }
    if ($V['mode'] === 'router' && $lan !== '' && $wan !== '' && $lan !== $wan) foreach (explode(',',$V['lan_prefix']) as $src) if (!str_ends_with($src,'/0')) $L[] = "-A FORWARD -i $lan -o $wan -s $src -j ACCEPT";
    if ($V['log']) foreach (['INPUT','FORWARD'] as $c) $L[] = "-A $c -m limit --limit 10/min -j LOG --log-prefix \"IPT6-DROP: \" --log-level 4";
    $L[] = 'COMMIT'; return implode("\n",$L)."\n";
}

const ZSVC = ['dns' => ['DNS locale', 'tcp,udp', '53', ''], 'dhcp' => ['Server DHCP', 'udp', '67,68', '', true], 'smb' => ['Condivisione file Windows (SMB)', 'tcp', '139,445', ''], 'nfs' => ['NFS', 'tcp,udp', '2049', ''],
    'mqtt' => ['MQTT', 'tcp', '1883,8883', ''], 'hass' => ['Home Assistant', 'tcp', '8123', ''], 'plex' => ['Plex', 'tcp', '32400', ''], 'ntp' => ['Server orario (NTP)', 'udp', '123', ''],
    'snmp' => ['SNMP', 'udp', '161', ''], 'mdns' => ['mDNS / Bonjour', 'udp', '5353', '224.0.0.251'], 'ssdp' => ['UPnP / SSDP', 'udp', '1900', '239.255.255.250']];
function cut40(string $s): string { preg_match('/^.{0,40}/us', $s, $m); return $m[0] ?? ''; }
function zero_skeleton(): string {
    $t = fn($n, $cs) => "*$n\n" . implode('', array_map(fn($c) => ":$c ACCEPT [0:0]\n", $cs)) . "COMMIT\n";
    return "# Creato dalla configurazione guidata di iptables-manager\n" . $t('raw', ['PREROUTING', 'OUTPUT']) . $t('mangle', BUILTIN['mangle']) . $t('filter', BUILTIN['filter']) . $t('nat', BUILTIN['nat']);
}
/** Impostazioni minime per una connessione funzionante e gestibile.
 * Conserva topologia di rete (WAN/LAN/NAT/DNS/WG) da $keep; tutto il resto è base sicura. */
function minimal_settings(array $keep = []): array {
    $S = S_def();
    // topologia / identità di rete
    foreach (['wan_if', 'lan_if', 'lan_ingress_map', 'external_ifs', 'wan_rfc1918_spoof', 'lan_nets', 'mgmt_nets', 'ui_nets', 'mgmt_ports', 'ssh_acc', 'ssh_nets', 'ssh_acc_port', 'ssh_conn', 'ssh_hits', 'ssh_secs', 'guest_on', 'guest_nets', 'guest_ports', 'guest_allow', 'iso_on', 'iso_nets', 'iot_policies', 'masq_ifs', 'single_nic', 'nat_masq', 'mss', 'dns_redirect', 'dns_ip', 'dot_block',
              'wg_on', 'wg_if', 'wg_port', 'wg_input', 'wg_lan', 'wg_net', 'wg_internet', 'wg_local_tcp', 'wg_local_udp', 'wg_fwd_nets', 'wg_fwd_tcp', 'wg_fwd_udp', 'wg_lan_to_vpn', 'drop_chain'] as $k) {
        if (array_key_exists($k, $keep) && $keep[$k] !== '' && $keep[$k] !== null) $S[$k] = $keep[$k];
    }
    // nucleo sempre attivo: SPI, anti-spoof, invalid, drop finale
    foreach (['spi', 'antispoof', 'invalid', 'final_drop', 'icmp_limit'] as $o) $S[$o] = 1;
    $lan = trim((string)($S['lan_nets'] ?? ''));
    $mgmt = iptm_management_nets($S);
    if (!$mgmt || empty($S['mgmt_ports'])) throw new RuntimeException('Reset minimo annullato: configurare reti e porte amministrative valide prima di proseguire. Nessuna apertura globale.');
    $S['mgmt_nets'] = implode(',', $mgmt);
    $S['lockout_on'] = 1;
    $S['svc_in'] = []; // gestione e WireGuard generati dai rispettivi moduli
    // router: NAT se già configurato
    if (!empty($S['nat_masq']) && trim((string)($S['masq_ifs'] ?? $S['wan_if'] ?? '')) === '' && ($S['wan_if'] ?? '') !== '') {
        $S['masq_ifs'] = $S['wan_if'];
    }
    if (!empty($S['nat_masq'])) $S['mss'] = 1;
    // Con NAT attivo i client LAN devono poter uscire: SPI mette FORWARD in DROP e senza
    // lan_out_fwd il MASQUERADE conservato resterebbe inutile (LAN senza Internet dopo il reset).
    if (!empty($S['nat_masq']) && $lan !== '') $S['lan_out_fwd'] = 1;
    // nessuna lista, portscan, stealth, tarpit, custom_opts
    $S['custom_opts'] = [];
    $S['fwd'] = [];
    $S['acl'] = [];
    return $S;
}

function iptm_validate_wizard_answers(array $answers): void {
    $choices=['mode'=>['host','router','single'],'level'=>['base','standard'],'vpn'=>['none','wireguard','openvpn'],'base'=>['keep','zero'],'logging'=>['none','drops','all'],'recovery'=>['yes','no']];
    foreach($choices as $key=>$options)if(isset($answers[$key])&&(!is_string($answers[$key])||!in_array($answers[$key],$options,true)))throw new RuntimeException('Scelta wizard non valida: '.$key);
    foreach(['ssh_from','svcs','lists'] as $key){if(!isset($answers[$key]))continue;if(!is_array($answers[$key])||count($answers[$key])>100)throw new RuntimeException('Lista wizard non valida: '.$key);foreach($answers[$key] as $value)if(!is_string($value)||strlen($value)>100)throw new RuntimeException('Voce wizard non valida: '.$key);}
    if(isset($answers['fwd'])){if(!is_array($answers['fwd'])||count($answers['fwd'])>100)throw new RuntimeException('Port forwarding non valido');foreach($answers['fwd'] as $row){if(!is_array($row))throw new RuntimeException('Riga port forwarding non valida');foreach($row as $value)if(!is_string($value)||strlen($value)>100)throw new RuntimeException('Campo port forwarding non valido');}}
    foreach($answers as $key=>$value)if(!in_array($key,['ssh_from','svcs','lists','fwd'],true)&&(!is_scalar($value)||strlen((string)$value)>4096))throw new RuntimeException('Campo wizard non valido: '.$key);
    if(!empty($answers['dns_local'])&&!in_array($answers['dns_local'],['0','no','false'],true)&&!filter_var($answers['dns_ip']??'',FILTER_VALIDATE_IP,FILTER_FLAG_IPV4))throw new RuntimeException('DNS locale: indirizzo IPv4 obbligatorio.');
}
function zero_build(array $A): array {
    iptm_validate_wizard_answers($A);
    $S = S_def(); $w = []; $g = fn($k, $d = '') => trim((string)($A[$k] ?? $d)); $yes = fn($k) => !empty($A[$k]) && !in_array($A[$k], ['no', '0', 'false'], true);
    $mode = in_array($g('mode'), ['router', 'single', 'host'], true) ? $g('mode') : 'host'; $routing = $mode !== 'host';
    $wan = v_ok('if', $g('wan_if')) ? $g('wan_if') : ''; $lan = ($g('lan_nets') !== '' && v_ok('nets', $g('lan_nets'))) ? $g('lan_nets') : '';
    $S['wan_if'] = $wan; $S['lan_nets'] = $lan; $S['single_nic'] = $mode === 'single' ? 1 : 0;
    if ($lan === '' || !iptm_vpn_networks($lan)) throw new RuntimeException('Indicare almeno una subnet LAN IPv4 specifica: nessuna bozza modificata.');
    if ($routing && ($wan==='' || $wan==='lo')) throw new RuntimeException('Interfaccia WAN obbligatoria in modalità gateway.');
    $lvl = in_array($g('level'), ['base', 'standard'], true) ? $g('level') : 'standard';
    foreach (['spi', 'antispoof', 'invalid', 'final_drop'] as $o) $S[$o] = 1;
    if ($lvl !== 'base') foreach (['icmp_limit', 'igmp_accept', 'dos', 'closeports'] as $o) $S[$o] = 1;
    if ($lvl === 'strict' || $lvl === 'paranoid') {
        $S['ident'] = 1; $S['multicast'] = ($routing && wan_ready($S)) ? 1 : 0; $S['drop_frag'] = 1; if ($routing) { $S['egress_smtp'] = 1; $S['lan_flood'] = 1; }
        $wip = sys_ifaces()[$wan][0] ?? ''; if ($mode === 'router' && $wan !== '' && $wip !== '' && !preg_match('/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)/', $wip)) $S['bogon_wan'] = 1;
    }
    if ($lvl === 'paranoid') {
        // Maximum practical hardening inspired by commercial UTM / CIS benchmarks
        $S['stealth'] = 1; $S['synproxy'] = 1; $S['sp_ports'] = ''; $S['tarpit'] = tarpit_ok() ? 1 : 0;
        $S['dns_rebind'] = $routing ? 1 : 0; $S['bad_mss'] = 1; $S['amp_block'] = $routing ? 1 : 0;
        $S['udp_rl'] = 1; $S['web_rl'] = $routing ? 1 : 0; $S['conn_limit'] = 1; $S['cl_max'] = 40;
        $S['blockping'] = $routing ? 1 : 0; $S['quic_block'] = $routing ? 1 : 0;
        $S['raw_drop'] = 1; $S['logdrop_on'] = 1; $S['drop_chain'] = $S['drop_chain'] ?: 'LOG-DROP';
        $S['ps_hits'] = 10; $S['ps_secs'] = 45; $S['ps_ban'] = 7200; // more aggressive port-scan
        $S['raw_invalid'] = 1; $S['arp_protect'] = 1; $S['tcp_fastopen_off'] = 1;
        $S['glob_new_limit'] = 1; $S['gn_rate'] = 80; $S['gn_burst'] = 160;
        if ($routing) { $S['svc_ban'] = 1; $S['sb_ports'] = '22,23,3389,5900,445,139'; $S['sb_hits'] = 5; $S['sb_secs'] = 45; $S['sb_ban'] = 7200; }
    }
    if ($lvl !== 'base' && $lan !== '') $S['portscan'] = 1;
    $S['harden'] = ['rpf' => '2'] + array_fill_keys(
        $lvl === 'base' ? ['syncookies', 'bcast', 'bogus', 'srcroute', 'redirects'] :
        ($lvl === 'standard' ? ['syncookies', 'bcast', 'bogus', 'srcroute', 'redirects', 'sendredir', 'rfc1337'] :
        array_keys(HARDEN)), 1);
    if (in_array($g('logging'), ['drops', 'all'], true)) { $S['drop_chain'] = 'LOG-DROP'; $S['logdrop_on'] = 1; if ($g('logging') === 'all' && wan_ready($S)) { $S['log_in'] = 1; $S['log_out'] = $routing ? 1 : 0; } }
    $vpn = in_array($g('vpn'), ['wireguard', 'openvpn'], true) ? $g('vpn') : 'none'; $vif = v_ok('if', $g('vpn_if')) ? $g('vpn_if') : ''; $vnet = ($vpn !== 'none' && $g('vpn_net') !== '' && v_ok('nets', $g('vpn_net'))) ? $g('vpn_net') : ''; $vport = v_ok('port', $g('vpn_port')) && $g('vpn_port') !== '' ? $g('vpn_port') : ($vpn === 'openvpn' ? '1194' : '51820');
    if ($routing && $yes('nat') && $wan !== '') { $S['nat_masq'] = 1; $S['masq_ifs'] = $wan . (($vpn !== 'none' && $vif !== '') ? ',' . $vif : ''); }
    if ($routing) $S['mss'] = 1;
    if ($yes('dns_local') && v_ok('ip', $g('dns_ip')) && $g('dns_ip') !== '' && $lan !== '') { $S['dns_redirect'] = 1; $S['dns_ip'] = $g('dns_ip'); $S['dot_block'] = $yes('dot') ? 1 : 0; }
    $row = fn($name, $proto, $ports, $src = '', $dst = '', $iif = '', $after = 0) => ['on' => 1, 'name' => cut40($name), 'iif' => $iif, 'src' => $src, 'dst' => $dst, 'proto' => $proto, 'ports' => $ports, 'ct' => '', 'act' => 'ACCEPT', 'after' => $after];
    $wp = v_ok('ports', $g('web_ports', '80,443,8089,8489')) && $g('web_ports', '80,443,8089,8489') !== '' ? $g('web_ports', '80,443,8089,8489') : '80,443,8089,8489';
    $S['svc_in'][] = $row('Gestione web', 'tcp', $wp, $lan);
    $from = (array)($A['ssh_from'] ?? []); $sp = v_ok('port', $g('ssh_port', '22')) && $g('ssh_port', '22') !== '' ? $g('ssh_port', '22') : '22';
    $extraWeb = ($yes('pihole_web') && v_ok('ports', $g('pihole_ports', '8089,8489')))
        ? explode(',', $g('pihole_ports', '8089,8489')) : [];
    $S['lockout_on'] = $lan !== '' ? 1 : 0;
    $S['mgmt_ports'] = implode(',', array_slice(array_unique(array_merge(explode(',', $wp), [$sp], $extraWeb)), 0, 15));
    if ($g('gateway_ip') !== '' && !v_ok('ip', $g('gateway_ip'))) $w[] = 'Gateway dichiarato non valido: controlla il routing prima di Applica.';
    if ($g('recovery') === 'no') $w[] = 'Nessuna console indipendente: verifica da un client LAN e usa il watchdog prima di confermare.';
    if (in_array('lan', $from, true) && $lan !== '') { if ($yes('ssh_limit')) { $S['ssh_acc'] = 1; $S['ssh_nets'] = $lan; $S['ssh_acc_port'] = (int)$sp; } else $S['svc_in'][] = $row('SSH dalla LAN', 'tcp', $sp, $lan); }
    if (in_array('vpn', $from, true) && $vnet !== '') $S['svc_in'][] = $row('SSH dalla VPN', 'tcp', $sp, $vnet);
    if ($routing && in_array('wan', $from, true)) { $S['svc_in'][] = $row('SSH da Internet', 'tcp', $sp); if (wan_ready($S)) { $S['ssh_limit'] = 1; $S['ssh_port'] = (int)$sp; } else $w[] = 'SSH da Internet: definisci la WAN per attivare il limite anti brute-force.'; }
    foreach ((array)($A['svcs'] ?? []) as $id) if (isset(ZSVC[$id])) { [$n, $pp, $ports, $dst] = ZSVC[$id]; $any = !empty(ZSVC[$id][4]); foreach (explode(',', $pp) as $pr) $S['svc_in'][] = $row($n, $pr, $ports, ($dst === '' && !$any) ? $lan : '', $dst); }
    foreach (preg_split('/[\s;]+/', $g('custom_ports'), -1, PREG_SPLIT_NO_EMPTY) as $c) if (preg_match('/^(tcp|udp):(.+)$/', $c, $m) && v_ok('ports', $m[2])) $S['svc_in'][] = $row('Servizio ' . $c, $m[1], $m[2], $lan);
    if ($vpn !== 'none') {
        if (!$vif || $vif==='lo' || !iptm_vpn_networks($vnet) || !v_ok('port',$g('vpn_port')) || $g('vpn_port')==='') throw new RuntimeException('Parametri VPN non validi.');
        $S['svc_in'][] = $row(($vpn === 'wireguard' ? 'WireGuard' : 'OpenVPN') . ' (ingresso)', 'udp', $vport);
        $w[]='VPN: accesso ai servizi soltanto se autorizzato; configura inoltro e destinazioni nella pagina VPN.';
    }
    if ($yes('docker')) { $S['svc_in'][] = $row('Container Docker', '', '', '172.16.0.0/12', '', '', 1); $S['cs_docker'] = 1; }
    if ($yes('crowdsec')) $S['crowdsec'] = 1;
    if ($routing) {
        foreach (array_filter(explode(',', $lan)) as $n) $S['svc_fwd'][] = ['on' => 1, 'name' => cut40('LAN → Internet ' . $n), 'iif' => '', 'oif' => $wan, 'src' => $n, 'dst' => '', 'proto' => '', 'ports' => '', 'ct' => '', 'act' => 'ACCEPT'];
        // Inoltro VPN non implicito: configurare destinazioni e servizi esplicitamente.
        if ($yes('docker')) $S['svc_fwd'][] = ['on' => 1, 'name' => 'Risposte verso Docker', 'iif' => '', 'oif' => '', 'src' => '', 'dst' => '172.16.0.0/12', 'proto' => '', 'ports' => '', 'ct' => 'RELATED,ESTABLISHED', 'act' => 'ACCEPT'];
        foreach ((array)($A['fwd'] ?? []) as $f) {
            if (!is_array($f)) continue; $x = ['on' => 1, 'name' => trim((string)($f['name'] ?? '')), 'proto' => in_array($f['proto'] ?? '', ['tcp', 'udp', 'both'], true) ? $f['proto'] : 'both', 'src' => '', 'eport' => trim((string)($f['eport'] ?? '')), 'ip' => trim((string)($f['ip'] ?? '')), 'tport' => trim((string)($f['tport'] ?? ''))];
            if ($x['eport'] !== '' && preg_match('/^\d{1,5}(:\d{1,5})?$/D', $x['eport']) && v_ok('name', $x['name']) && $x['ip'] !== '' && v_ok('ip', $x['ip']) && v_ok('port', $x['tport'])) $S['fwd'][] = $x; else $w[] = 'Port forward ignorato: «' . $x['name'] . '»';
        }
    }
    foreach ((array)($A['lists'] ?? []) as $id) if (isset(BL_PRESETS[$id])) $S['blocklists'][] = ['on' => 1, 'id' => $id, 'name' => BL_PRESETS[$id][0], 'url' => BL_PRESETS[$id][1], 'dir' => 'in'];
    $cc = strtoupper(preg_replace('/\s+/', '', $g('geo_codes'))); if ($cc !== '' && v_ok('cc', $cc)) { $S['geo_on'] = 1; $S['geo_codes'] = $cc; $S['geo_dir'] = 'in'; }
    $v6 = null; if ($yes('v6')) { $v6 = v6_def(); $v6['on'] = 1; $v6['mode'] = $mode === 'router' ? 'router' : 'host'; $S['v6'] = $v6; }
    return [$S, $w, $v6];
}

