<?php
/** Bounded read-only diagnostics; no direct access to logs or service configuration. */
function iptm_diag_call(string $op,int $timeout=25): array {
    [$rc,$out,$err]=run([BIN_SUDO,'-n',HELPER,'diag',$op],null,$timeout,1048576);
    $j=$rc===0?json_decode($out,true):null;
    if(!is_array($j)||($j['ok']??false)!==true)return ['ok'=>false,'error'=>substr(herr($out.$err),0,180)];
    return $j;
}
function iptm_diag_render_incidents(array $inc): void {
    iptm_view_start('Eventi degli ultimi 7 giorni','Il journal dei servizi monitorati è una fonte parziale. Password, token, IP e MAC sono oscurati dal backend.');
    $days=iptm_view_rows($inc['days']??[]);
    echo '<p>'.(int)($inc['count']??0).' eventi · '.count($days).' giorni · fonte: '.iptm_view_text($inc['source']??null).'</p>';
    if(!$days)echo '<p>Nessun evento restituito: il journal potrebbe non essere disponibile.</p>';
    foreach($days as $day){
        echo '<details><summary>'.iptm_view_text($day['date']??null).' · '.(int)($day['total']??0).' occorrenze</summary>';
        $rows=[];foreach(iptm_view_rows($day['entries']??[]) as $entry)$rows[]=[$entry['count']??null,$entry['id']??null,$entry['example']??null,$entry['source']??null];
        iptm_view_table(['Numero','Identificatore','Esempio redatto','Fonte'],$rows,'Eventi della giornata');echo '</details>';
    }
    echo '<p><a class="btn s" href="?p=diag&amp;diag_export=1">Esporta dump JSON</a></p>';iptm_view_end();
}
function iptm_diag_render_trial(array $state): void {
    iptm_view_start('Simulazione di manutenzione','Schema e combinazioni in memoria, preflight in sola lettura o parser in namespace temporaneo. Non simula il traffico reale né il rollback live.');
    iptm_view_form('diag','diag_manage',['diag_op'=>'start']);
    echo '<label for="iptm-diag-level">Livello di verifica</label><select id="iptm-diag-level" name="diag_level" required><option value="schema">1 · Schema</option><option value="preflight" selected>2 · Preflight reale (sola lettura e iptables --test)</option><option value="isolated">3 · Namespace temporaneo, se disponibile</option></select><label><input type="checkbox" name="diag_network" value="1"> Includi opzioni a rischio rete, bozze MAC/IPv4/IPv6 e interfacce reali (non applica regole; le query DNS locali possono aggiornare la cache).</label>';
    iptm_view_submit('Avvia diagnostica');
    $pct=min(100,max(0,(int)($state['progress']??0)));$last=(array)($state['run']??[]);
    echo '<p id="iptm-diag-status" role="status">'.iptm_view_text($state['status']??'idle').' · '.iptm_view_text($state['message']??'','').'</p><label for="iptm-diag-progress">Avanzamento</label><progress id="iptm-diag-progress" value="'.$pct.'" max="100" style="width:100%">'.$pct.'%</progress><p id="iptm-diag-pct">'.$pct.'%</p><p id="iptm-diag-summary">Risultati: '.(int)($last['passed']??0).' passati · '.(int)($last['warning']??0).' avvisi · '.(int)($last['unknown']??0).' non verificabili · '.(int)($last['failed']??0).' falliti · '.(int)($last['skipped']??0).' esclusi</p>';
    echo '<details id="iptm-diag-combinations" open><summary>Compatibilità fra funzioni · coppie e terne</summary><div id="iptm-diag-combo-results">';
    $n=0;foreach(iptm_view_rows($last['results']??[]) as $item){if(!str_starts_with((string)($item['option']??''),'combo:'))continue;$n++;echo '<details><summary>'.iptm_view_text($item['option']??null).' · '.iptm_view_text($item['result']??'unknown').'</summary><p>'.iptm_view_text($item['detail']??null).'</p></details>';}
    if(!$n)echo '<p>Avvia il preflight per ottenere una verifica combinatoria.</p>';
    echo '</div></details><details id="iptm-diag-run"><summary>Ultimo report completo</summary><pre id="iptm-diag-report">'.iptm_view_json($state['run']??[]).'</pre></details>';iptm_view_end();
}
function pg_diag(): void {
    if(($_SESSION['role']??'viewer')!=='admin'){iptm_view_error('Diagnostica riservata agli amministratori.');return;}
    $j=iptm_diag_call('snapshot',40);
    if(empty($j['ok'])){iptm_view_error('Diagnostica non disponibile: '.(string)($j['error']??'helper'));return;}
    iptm_diag_render_trial((array)($j['state']??[]));
    iptm_diag_render_incidents((array)($j['incidents']??[]));
    iptm_view_start('Sistema e cronologia');
    echo '<details><summary>Dump diagnostico redatto</summary><pre>'.iptm_view_json($j['system']??[]).'</pre></details>';
    $rows=[];foreach(iptm_view_rows($j['runs']??[]) as $r)$rows[]=[$r['started']??null,$r['status']??null,$r['passed']??null,$r['warning']??null,$r['unknown']??null,$r['failed']??null,$r['skipped']??null];
    iptm_view_table(['Avvio','Stato','Passati','Avvisi','Non verificati','Falliti','Esclusi'],$rows,'Simulazioni precedenti');
    iptm_view_form('diag','diag_manage',['diag_op'=>'clear']);iptm_view_submit('Pulisci solo i report IPTM','d');
    echo '<p class="mut">Non cancella journal di sistema, log PHP o informazioni di altri programmi.</p>';iptm_view_end();
}
