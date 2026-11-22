<?php
/** IPTM retention overview: no filesystem access from PHP, only the typed root helper. */
function pg_retention(): void {
    $admin=(($_SESSION['role']??'')==='admin');
    [$rc,$raw,$err]=priv('retention',null,['status']);
    $status=$rc===0?json_decode($raw,true):null;
    if (!is_array($status) || empty($status['ok'])) {
        echo '<div class="msg err">Stato rotazione non disponibile: '.h(herr($raw.$err)).'</div>';return;
    }
    $pol=(array)($status['policy']??[]);
    $last=(array)($status['last_run']??[]);
    echo '<div class="hero"><h2>Rotazione backup e log</h2><p>Conservazione automatica IPTM. Non cancella backup manuali, configurazioni attive, ripristini pendenti o i log di altri programmi.</p></div>';
    echo '<div class="card"><h3>Stato e ultima esecuzione</h3>';
    echo '<p>Timer: <code>iptm-retention.timer</code> · Frequenza: giornaliera (systemd).</p>';
    echo '<table><tr><th>Indicatore</th><th>Valore</th></tr>';
    foreach (['time'=>'Ultima esecuzione UTC','deleted'=>'Elementi eliminati','reclaimed_bytes'=>'Byte recuperati','logs'=>'Rotazione log IPTM'] as $key=>$label) {
        echo '<tr><td>'.h($label).'</td><td>'.h($last[$key]??'Non ancora eseguita').'</td></tr>';
    }
    echo '</table>';
    foreach ((array)($last['warnings']??[]) as $msg) echo '<p class="mut">⚠ '.h($msg).'</p>';
    foreach ((array)($last['errors']??[]) as $msg) echo '<p class="msg err">'.h($msg).'</p>';
    echo '</div>';
    $fields=[
        'backup_days'=>['Backup automatici: giorni',7,730],
        'backup_keep'=>['Backup recenti da proteggere per categoria',3,100],
        'report_days'=>['Report diagnostici/Lynis: giorni',7,365],
        'report_keep'=>['Report recenti per categoria',3,100],
        'stats_days'=>['Statistiche: giorni (minimo 14)',14,365],
        'max_backup_mib'=>['Budget backup automatici (MiB)',128,65536],
        'log_copies'=>['Archivi log IPTM compressi',3,90]
    ];
    echo '<div class="card"><h3>Politica di conservazione</h3><p class="mut">Un backup viene eliminato solo quando supera l’età indicata e non rientra nei più recenti protetti. In caso di quota superata vengono considerati solo backup vecchi di almeno 24 ore, mai i più recenti. Le impostazioni sono applicate dal processo root.</p>';
    if ($admin) echo '<form method="post" class="acc">'.fh('p=retention').'<input type=hidden name=action value=retention_save>';
    foreach ($fields as $key=>[$label,$low,$high]) {
        echo '<label class="fl"><span>'.h($label).'</span><input type=number '.($admin?'':'disabled').' name="'.h($key).'" value="'.(int)($pol[$key]??$low).'" min="'.$low.'" max="'.$high.'" required></label>';
    }
    if ($admin) echo '<p><button class=g>Salva politica</button></p></form>';
    echo '</div>';
    echo '<div class="card"><h3>Anteprima e manutenzione</h3><p>Anteprima di sola lettura. La rotazione dei log applicativi usa logrotate; non modifica journald, Pi-hole, CrowdSec o Suricata.</p>';
    echo '<a class="btn" href="?p=retention&amp;preview=1">Calcola elementi eliminabili</a>';
    if (($_GET['preview']??'')==='1') {
        [$prc,$pout,$perr]=priv('retention',null,['preview']);
        $view=$prc===0?json_decode($pout,true):null;
        if (is_array($view)&&!empty($view['ok'])) {
            echo '<p><b>'.(int)$view['total'].'</b> elementi eliminabili · '.number_format(((int)($view['reclaim_bytes']??0))/1048576,2,',','.').' MiB recuperabili.</p>';
            echo '<table><tr><th>Categoria</th><th>Elementi</th><th>MiB</th></tr>';
            foreach ((array)($view['groups']??[]) as $group=>$row) echo '<tr><td>'.h($group).'</td><td>'.(int)$row['items'].'</td><td>'.number_format(((int)$row['bytes'])/1048576,2,',','.').'</td></tr>';
            echo '</table>';
            foreach ((array)($view['warnings']??[]) as $warning) echo '<p class="mut">⚠ '.h($warning).'</p>';
        } else echo '<p class="msg err">Anteprima non disponibile: '.h(herr($pout.$perr)).'</p>';
    }
    if ($admin) echo '<form method=post>'.fh('p=retention').'<input type=hidden name=action value=retention_run><p><button>Esegui rotazione in background</button></p></form>';
    echo '<p class=mut>Backup manuali, lock, journal di recupero, policy e configurazioni correnti non vengono eliminati. Il sistema mantiene i log nativi dei servizi sotto le rispettive politiche.</p></div>';
}
