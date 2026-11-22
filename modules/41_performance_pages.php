<?php
/** Read-only rules cost audit; no application, service or firewall mutation. */
function pg_performance(): void {
    $admin=($_SESSION['role']??'viewer')==='admin';
    $scope=(($_GET['scope']??'draft')==='kernel')?'kernel':'draft';
    if($scope==='kernel') {
        [$r,$rules,$e]=priv('save');
        if($r!==0) $rules='';
    } else $rules=get_draft();
    $audit=null;$error='';
    if(trim((string)$rules)!=='') {
        [$r,$raw,$e]=priv('rules-performance',(string)$rules);
        $audit=$r===0?json_decode($raw,true):null;
        if(!is_array($audit)||empty($audit['ok']))$error=herr((string)($audit['error']??$e??$raw));
    } else $error='Rules non disponibili. Non vengono inventati risultati o modificato il firewall.';
    echo '<div class="hero"><h2>Prestazioni rete · Audit firewall</h2><p>Analisi in sola lettura dei costi delle regole e accesso agli strumenti CAKE/RTT. Non modifica alcuna policy.</p></div>';
    echo '<section class="card"><h3>Analisi costi delle regole firewall</h3><p class="mut">L’audit è in sola lettura; i risultati segnalano rischi di prestazioni, non equivalgono a un benchmark o a una valutazione di sicurezza completa.</p>';
    echo '<nav class="row"><a class="btn" href="?p=performance&amp;scope=draft">Analizza bozza</a> <a class="btn" href="?p=performance&amp;scope=kernel">Analizza kernel attivo</a></nav>';
    echo '<p>Origine: <b>'.($scope==='kernel'?'kernel iptables-save':'bozza non applicata').'</b></p>';
    if($error!=='')echo '<p class="msg err">'.h($error).'</p>';
    if(is_array($audit)&&!empty($audit['ok'])){
        $c=(array)($audit['counts']??[]);
        echo '<div class="tiles">'.tile('Regole',(string)(int)($c['rules']??0),'Viste nel dump')
            .tile('Logging',(string)(int)($c['logging']??0),'Possibile carico CPU e disco')
            .tile('IPSet',(string)(int)($c['ipset_lookups']??0),'Verifiche nelle catene')
            .tile('Limiti DROP',(string)(int)($c['rate_drops']??0),'Possibile degrado TCP').'</div>';
        echo '<table><thead><tr><th>Priorità</th><th>Elemento</th><th>Effetto e proposta</th></tr></thead><tbody>';
        foreach(array_slice((array)($audit['findings']??[]),0,25) as $finding) {
            if(!is_array($finding))continue;
            echo '<tr><td>'.h((string)($finding['priority']??'')).'</td><td><b>'.h((string)($finding['title']??'')).'</b></td><td>'.h((string)($finding['detail']??'')).'<p class="mut">'.h((string)($finding['recommendation']??'')).'</p><p class="mut">Sicurezza: '.h((string)($finding['security_tradeoff']??'')).'</p></td></tr>';
        }
        echo '</tbody></table><p class="mut">Nessuna opzione viene disattivata automaticamente. Confronta throughput, RTT e contatori prima/dopo.</p>';
    }
    echo '<p><a class="btn" href="?p=security">Modifica le impostazioni di sicurezza</a> <a class="btn" href="?p=sqm">Gestisci CAKE e calibrazione</a></p></section>';
}
