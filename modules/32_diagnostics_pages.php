<?php
/** Diagnostic page: all probes are fixed, bounded, redacted and read-only. */
function iptm_diag_call(string $op,int $timeout=25): array {
    [$rc,$out,$err]=run([BIN_SUDO,'-n',HELPER,'diag',$op],null,$timeout,1048576);
    $j=$rc===0?json_decode($out,true):null;
    if(!is_array($j) || empty($j['ok']))return ['ok'=>false,'error'=>substr(herr($out.$err),0,180)];
    return $j;
}
function pg_diag(): void {
    if (($_SESSION['role']??'viewer')!=='admin') {
        echo '<div class="msg warn">La diagnostica dei servizi è riservata agli amministratori.</div>';return;
    }
    $j=iptm_diag_call('snapshot',40);
    echo '<div class="card"><h3>Centro errori e manutenzione</h3>';
    echo '<p class="mut">Errori disponibili nel journal degli ultimi 7 giorni, organizzati per data e ricorrenza. Il dump include versioni pacchetti, kernel, disco e stato dei servizi. Password, token, indirizzi IP e MAC vengono oscurati. Non è una raccolta completa di ogni log applicativo.</p>';
    if(empty($j['ok'])) {echo '<p class="msg err">Diagnostica non disponibile: '.h((string)($j['error']??'helper')).'. Verifica sudoers e deploy.</p></div>';return;}
    $inc=$j['incidents']??[];
    echo '<p><b>'.(int)($inc['count']??0).' eventi</b> nel periodo · '.count((array)($inc['days']??[])).' giorni interessati · fonte: '.h((string)($inc['source']??'')).'</p>';
    if(empty($inc['days']))echo '<p class="mut">Nessun errore raccolto dai servizi monitorati, oppure journal non disponibile. Questo non significa assenza di errori.</p>';
    foreach((array)($inc['days']??[]) as $day) {
        echo '<details><summary><b>'.h((string)$day['date']).'</b> · '.(int)$day['total'].' occorrenze</summary>';
        foreach((array)($day['entries']??[]) as $event){
            echo '<details style="margin:8px 0 8px 12px"><summary>'.(int)$event['count'].' × · '.h((string)$event['id']).' · '.h(substr((string)$event['example'],0,95)).'</summary>';
            echo '<pre>'.h((string)$event['example']).'</pre><small>Fonte: '.h((string)$event['source']).' · dati sensibili oscurati</small></details>';
        }
        echo '</details>';
    }
    echo '<h4>Informazioni di sistema e programmi</h4><details><summary>Apri dump diagnostico redatto</summary><pre>'.h(json_encode($j['system']??[],JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES)).'</pre></details>';
    echo '<p><a class="btn s" href="?p=diag&amp;diag_export=1">Esporta unico dump JSON (system + errori + ultimo test)</a></p>';
    echo '</div>';
    echo '<div class="card"><h3>Simulazione di manutenzione · senza applicazione</h3>';
    echo '<p class="mut">Tre livelli: validazione di schema, combinazioni pairwise/terne in memoria e dipendenze delle impostazioni salvate; preflight su interfacce/bozze DNS-firewall reali senza applicazione; e test del parser in un namespace di rete temporaneo quando supportato. Nessuno dei livelli modifica il firewall o i servizi live; i controlli nel namespace non simulano il traffico dei client. Non viene eseguito alcun rollback virtuale. Il rollback delle operazioni live resta separato e invariato.</p>';
    echo '<form method="post">'.fh('p=diag').'<input type="hidden" name="action" value="diag_manage"><input type="hidden" name="diag_op" value="start">';
    echo '<label>Livello di verifica <select name="diag_level" required><option value="schema">1 · Schema (valori di prova in memoria)</option><option value="preflight" selected>2 · Preflight reale (sola lettura e iptables --test)</option><option value="isolated">3 · Isolato (anche namespace temporaneo, se disponibile)</option></select></label>';
    echo '<label><input type="checkbox" name="diag_network" value="1"> Includi prove delle opzioni a rischio rete, delle bozze MAC/IPv4/IPv6 e delle interfacce reali (non applica regole; le query DNS locali possono aggiornare la cache)</label>'; 
    echo '<button>Avvia diagnostica senza modifiche live</button></form>';
    $state=$j['state']??[];$pct=min(100,max(0,(int)($state['progress']??0)));
    echo '<div id="iptm-diag-status" role="status">'.h((string)($state['status']??'idle')).' · '.h((string)($state['message']??'')).'</div>';
    echo '<progress id="iptm-diag-progress" value="'.$pct.'" max="100" style="width:100%">'.$pct.'%</progress><p id="iptm-diag-pct">'.$pct.'%</p>';
    $last=(array)($state['run']??[]);
    echo '<p id="iptm-diag-summary">Risultati: '.(int)($last['passed']??0).' passati · '.(int)($last['warning']??0).' avvisi · '.(int)($last['unknown']??0).' non verificabili · '.(int)($last['failed']??0).' falliti · '.(int)($last['skipped']??0).' esclusi</p>';
    echo '<details id="iptm-diag-combinations" open><summary>Compatibilità fra funzioni · coppie, terne e configurazione corrente</summary><div id="iptm-diag-combo-results">';
    $comboCount=0;
    foreach((array)($last['results']??[]) as $item) {
        if(!is_array($item) || !str_starts_with((string)($item['option']??''),'combo:'))continue;
        $comboCount++;
        echo '<details><summary>'.h((string)($item['option']??'')).' · '.h((string)($item['result']??'unknown')).'</summary><p>'.h((string)($item['detail']??'')).'</p></details>';
    }
    if(!$comboCount)echo '<p class="mut">Avvia almeno il preflight per verificare le combinazioni fra funzioni.</p>';
    echo '</div></details>';
    echo '<details id="iptm-diag-run"><summary>Ultimo log unico (con esiti e motivazioni)</summary><pre id="iptm-diag-report">'.h(json_encode($state['run']??[],JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES)).'</pre></details>';
    echo '<h4>Simulazioni precedenti</h4>';
    foreach((array)($j['runs']??[]) as $r)echo '<p>'.h((string)($r['started']??'')).' · '.h((string)($r['status']??'')).' · passati '.(int)($r['passed']??0).' · esclusi '.(int)($r['skipped']??0).' · avvisi '.(int)($r['warning']??0).' · non verificati '.(int)($r['unknown']??0).' · falliti '.(int)($r['failed']??0).'</p>';
    echo '<div class="ops"><form method="post">'.fh('p=diag').'<input type="hidden" name="action" value="diag_manage"><input type="hidden" name="diag_op" value="clear">';
    echo '<button class="d">Pulisci report IPTM</button></form></div>';
    echo '<p class="mut">La pulizia non cancella i log journalctl, i log PHP o le informazioni degli altri programmi.</p></div>';
}
