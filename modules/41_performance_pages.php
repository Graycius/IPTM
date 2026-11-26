<?php
/** Read-only page: data acquisition and presentation are separate, no mutation. */
function iptm_performance_snapshot(string $scope): array {
    if(!in_array($scope,['draft','kernel'],true))return ['ok'=>false,'error'=>'Origine regole non valida.'];
    if($scope==='kernel') {[$rc,$rules]=priv('save');if($rc!==0)return ['ok'=>false,'error'=>'Lettura del kernel non disponibile.'];}
    else $rules=get_draft();
    if(trim((string)$rules)==='')return ['ok'=>false,'error'=>'Nessuna regola disponibile.'];
    return iptm_view_probe('rules-performance',[],(string)$rules);
}
function pg_performance(): void {
    $scope=($_GET['scope']??'draft')==='kernel'?'kernel':'draft';
    $result=iptm_performance_snapshot($scope);
    iptm_view_start('Costo delle regole','Audit di sola lettura: i risultati non equivalgono a un benchmark o a una valutazione completa di sicurezza.');
    echo '<nav class="iptm-workspace-actions" aria-label="Origine regole">'.iptm_view_link('performance','Analizza bozza',['scope'=>'draft']).iptm_view_link('performance','Analizza kernel',['scope'=>'kernel']).'</nav><p>Origine selezionata: <strong>'.($scope==='kernel'?'kernel iptables-save':'bozza non applicata').'</strong></p>';
    if(empty($result['ok']))iptm_view_error((string)($result['error']??'Audit non disponibile.'));
    else {
        $counts=(array)($result['counts']??[]);
        $rows=[];foreach(['rules'=>'Regole','logging'=>'Logging','ipset_lookups'=>'IPSet','rate_drops'=>'Limiti DROP'] as $k=>$label)$rows[]=[$label,$counts[$k]??null];
        iptm_view_table(['Indicatore','Numero'],$rows,'Riepilogo del dump');
        $findings=iptm_view_rows($result['findings']??[]);$rows=[];
        foreach(array_slice($findings,0,25) as $f)$rows[]=[$f['priority']??null,$f['title']??null,$f['detail']??null,$f['recommendation']??null,$f['security_tradeoff']??null];
        iptm_view_table(['Priorità','Elemento','Effetto','Proposta','Compromesso sicurezza'],$rows,'Risultati audit');
        if(count($findings)>25)echo '<p>Mostrati i primi 25 risultati.</p>';
    }
    echo '<p class="mut">Nessuna opzione viene disattivata automaticamente. Confronta throughput, RTT e contatori prima e dopo ogni modifica.</p><div class="iptm-workspace-actions">'.iptm_view_link('security','Impostazioni firewall').iptm_view_link('sqm','CAKE e calibrazione').'</div>';iptm_view_end();
}
