<?php
/** IPTM 4.2 visual core: a single, deterministic SVG chart renderer.
 * No live probes, network requests, framework, or JavaScript needed to see data.
 */
function iptm_visual_escape($value): string {
    return htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}
function iptm_visual_number(float $v): string {
    if (!is_finite($v)) return '—';
    $negative = $v < 0 ? '−' : '';
    $v = abs($v);
    foreach ([[1000000000, 'G'], [1000000, 'M'], [1000, 'k']] as [$unit, $suffix]) {
        if ($v >= $unit) return $negative . rtrim(rtrim(number_format($v / $unit, 1, '.', ''), '0'), '.') . $suffix;
    }
    return $negative . ($v < 1000 && abs($v - round($v)) < .05 ? number_format($v, 0, '.', '') : number_format($v, 1, '.', ''));
}
function iptm_visual_coord(float $v): string { return number_format($v, 2, '.', ''); }
function iptm_visual_color($candidate, string $fallback): string {
    $c = is_string($candidate) ? trim($candidate) : '';
    if (preg_match('/^#[0-9a-fA-F]{3}(?:[0-9a-fA-F]{3})?$/D', $c) || preg_match('/^var\(--chart-[a-z-]+\)$/D', $c)) return $c;
    return $fallback;
}
function iptm_visual_text_short(string $s, int $limit): string {
    if (function_exists('mb_strlen') && function_exists('mb_substr')) return mb_strlen($s, 'UTF-8') > $limit ? mb_substr($s, 0, $limit - 1, 'UTF-8') . '…' : $s;
    if (strlen($s) <= $limit) return $s;
    return substr($s, 0, max(0, $limit - 3)) . '...';
}
function iptm_visual_rows(array $source, string $type, int $limit): array {
    $rows = [];
    foreach ($source as $r) {
        if (!is_array($r) || !isset($r['value']) || !is_numeric($r['value'])) continue;
        $n = (float)$r['value'];
        if (!is_finite($n)) continue;
        if ($type === 'donut' || $type === 'hbar') { if ($n <= 0) continue; }
        else $n = max(0, $n);
        $rows[] = ['label' => substr((string)($r['label'] ?? '—'), 0, 512), 'value' => $n, 'color' => $r['color'] ?? null];
    }
    if ($type === 'line') return array_slice($rows, -$limit);
    return array_slice($rows, 0, $limit);
}
function iptm_visual_arc(float $cx, float $cy, float $outer, float $inner, float $start, float $sweep): string {
    // A single SVG arc cannot describe a full circle. Two half-arcs are safe.
    if ($sweep >= 359.999) $sweep = 359.999;
    $a = deg2rad($start); $b = deg2rad($start + $sweep);
    $at = fn(float $r, float $t): string => iptm_visual_coord($cx + $r * cos($t)) . ' ' . iptm_visual_coord($cy + $r * sin($t));
    $big = $sweep > 180 ? 1 : 0;
    return 'M ' . $at($outer, $a) . ' A ' . iptm_visual_coord($outer) . ' ' . iptm_visual_coord($outer) . ' 0 ' . $big . ' 1 ' . $at($outer, $b)
       . ' L ' . $at($inner, $b) . ' A ' . iptm_visual_coord($inner) . ' ' . iptm_visual_coord($inner) . ' 0 ' . $big . ' 0 ' . $at($inner, $a) . ' Z';
}
function iptm_visual_chart(string $type, array $source, array $options = []): string {
    if (!in_array($type, ['bar','hbar','line','donut'], true)) throw new InvalidArgumentException('Tipo grafico non supportato');
    $limit = $type === 'line' ? 72 : ($type === 'hbar' ? min(30, max(1, (int)($options['max'] ?? 12))) : 36);
    $rows = iptm_visual_rows($source, $type, $limit);
    if (!$rows) return '<p class="mut iptm-chart-empty">Nessun dato valido disponibile per questo grafico.</p>';
    static $sequence = 0; ++$sequence;
    $id = 'iptm-chart-' . $sequence;
    $title = trim((string)($options['title'] ?? ['bar'=>'Distribuzione', 'hbar'=>'Valori principali', 'line'=>'Andamento storico','donut'=>'Ripartizione'][$type]));
    $palette = ['var(--chart-blue)','var(--chart-green)','var(--chart-orange)','var(--chart-purple)','var(--chart-cyan)','var(--chart-red)','var(--chart-warm)'];
    $color = iptm_visual_color($options['color'] ?? null, $palette[0]);
    $w = $type === 'line' ? 640 : ($type === 'donut' ? 280 : 640);
    $h = $type === 'donut' ? 260 : ($type === 'hbar' ? min(1100, max(130, 30 * count($rows) + 40)) : max(160, min(310, (int)($options['h'] ?? 210))));
    $sum = array_sum(array_column($rows, 'value'));
    $maximum = max(1., max(array_column($rows, 'value')));
    $svg = '<svg viewBox="0 0 '. $w .' '. $h .'" role="img" focusable="false" aria-labelledby="'.$id.'-title '.$id.'-desc">'
        . '<title id="'.$id.'-title">'.iptm_visual_escape($title).'</title>'
        . '<desc id="'.$id.'-desc">'.iptm_visual_escape(count($rows).' valori, totale '.iptm_visual_number((float)$sum).'. La tabella dati completa segue il grafico.').'</desc>';
    $tip = static fn(array $r): string => '<title>'.iptm_visual_escape($r['label'].': '.iptm_visual_number($r['value'])).'</title>';
    if ($type === 'bar' || $type === 'line') {
        $l = 52; $r = 12; $t = 18; $b = 42; $iw = $w-$l-$r; $ih = $h-$t-$b;
        for ($i = 0; $i <= 4; ++$i) {
            $y = $t + $ih * (1-$i/4);
            $svg .= '<line class="iptm-chart-grid" x1="'.$l.'" y1="'.iptm_visual_coord($y).'" x2="'.($w-$r).'" y2="'.iptm_visual_coord($y).'"/>';
            $svg .= '<text class="iptm-chart-axis" x="'.($l-8).'" y="'.iptm_visual_coord($y+4).'" text-anchor="end">'.iptm_visual_escape(iptm_visual_number($maximum*$i/4)).'</text>';
        }
        $n = count($rows);
        if ($type === 'bar') {
            $slot = $iw/$n; $bw = min(52, max(1.5, $slot*.67));
            foreach ($rows as $i=>$row) {
                $x = $l+$slot*$i+($slot-$bw)/2; $height = $ih*$row['value']/$maximum; $y = $t+$ih-$height;
                $svg .= '<rect class="iptm-chart-mark" x="'.iptm_visual_coord($x).'" y="'.iptm_visual_coord($y).'" width="'.iptm_visual_coord($bw).'" height="'.iptm_visual_coord($height).'" rx="3" fill="'.iptm_visual_escape($color).'">'.$tip($row).'</rect>';
                if ($n <= 12 || $i % (int)ceil($n/12) === 0) $svg .= '<text class="iptm-chart-axis" x="'.iptm_visual_coord($x+$bw/2).'" y="'.($h-14).'" text-anchor="middle">'.iptm_visual_escape(iptm_visual_text_short($row['label'], 12)).'</text>';
            }
        } else {
            $points=[]; $dots='';
            foreach ($rows as $i=>$row) {
                $x=$l+$iw*($n===1?.5:$i/($n-1));$y=$t+$ih*(1-$row['value']/$maximum);
                $points[]=iptm_visual_coord($x).','.iptm_visual_coord($y);
                $dots.='<circle class="iptm-chart-mark" cx="'.iptm_visual_coord($x).'" cy="'.iptm_visual_coord($y).'" r="'.($n>48?2.5:3.5).'" fill="'.iptm_visual_escape($color).'">'.$tip($row).'</circle>';
            }
            $base=$t+$ih;
            $svg.='<polygon points="'.iptm_visual_coord($l+$iw*($n===1?.5:0)).','.$base.' '.implode(' ',$points).' '.iptm_visual_coord($l+$iw*($n===1?.5:1)).','.$base.'" fill="'.iptm_visual_escape($color).'" opacity=".11"/>';
            $svg.='<polyline class="iptm-chart-trend" points="'.implode(' ',$points).'" stroke="'.iptm_visual_escape($color).'"/>'.$dots;
            $positions=$n===1?[0]:[0,$n-1];foreach ($positions as $index) {
                $svg.='<text class="iptm-chart-axis" x="'.iptm_visual_coord($l+$iw*($n===1?.5:$index/($n-1))).'" y="'.($h-14).'" text-anchor="'.($index===0?'start':'end').'">'.iptm_visual_escape(iptm_visual_text_short($rows[$index]['label'],24)).'</text>';
            }
        }
    } elseif ($type === 'hbar') {
        $left = min(270,max(120,(int)($options['label_w']??145)));$right=73;$top=18;$iw=$w-$left-$right;$rh=30;
        foreach ([0,.25,.5,.75,1] as $f) {
            $x=$left+$iw*$f;
            $svg.='<line class="iptm-chart-grid" x1="'.iptm_visual_coord($x).'" y1="'.$top.'" x2="'.iptm_visual_coord($x).'" y2="'.($h-12).'"/>';
        }
        foreach ($rows as $i=>$row) {
            $width=$iw*$row['value']/$maximum;$y=$top+$i*$rh;
            $svg.='<text class="iptm-chart-axis" x="'.($left-8).'" y="'.($y+17).'" text-anchor="end">'.iptm_visual_escape(iptm_visual_text_short($row['label'],min(36,(int)floor($left/7)))).'</text>';
            $svg.='<rect class="iptm-chart-mark" x="'.$left.'" y="'.($y+4).'" width="'.iptm_visual_coord($width).'" height="20" rx="4" fill="'.iptm_visual_escape($color).'">'.$tip($row).'</rect>';
            $svg.='<text class="iptm-chart-axis" x="'.iptm_visual_coord(min($w-37,$left+$width+6)).'" y="'.($y+18).'">'.iptm_visual_escape(iptm_visual_number($row['value'])).'</text>';
        }
    } else {
        $cx=135.;$cy=126.;$outer=97.;$inner=63.;$angle=-90.;
        foreach ($rows as $i=>$row) {
            $sweep=360*$row['value']/($sum?:1.);$col=iptm_visual_color($row['color'], $palette[$i%count($palette)]);
            $svg.='<path class="iptm-chart-mark" d="'.iptm_visual_arc($cx,$cy,$outer,$inner,$angle,$sweep).'" fill="'.iptm_visual_escape($col).'">'.$tip($row).'</path>';
            $angle+=$sweep;
        }
        $center=(string)($options['center']??iptm_visual_number((float)$sum));
        $svg.='<text class="iptm-chart-center" x="'.$cx.'" y="'.$cy.'" text-anchor="middle">'.iptm_visual_escape($center).'</text>';
    }
    $svg.='</svg>';
    $table='<details class="iptm-chart-data"><summary>Mostra dati del grafico ('.count($rows).' righe)</summary><div class="iptm-chart-table-wrap"><table><thead><tr><th scope="col">Voce</th><th scope="col">Valore</th></tr></thead><tbody>';
    foreach ($rows as $row) $table.='<tr><th scope="row">'.iptm_visual_escape($row['label']).'</th><td data-iptm-num="'.iptm_visual_escape((string)$row['value']).'">'.iptm_visual_escape(iptm_visual_number($row['value'])).'</td></tr>';
    $table.='</tbody></table></div></details>';
    $legend='';
    if ($type==='donut') {
        $legend='<div class="iptm-chart-legend" aria-label="Legenda">';
        foreach ($rows as $i=>$row) {
            $col=iptm_visual_color($row['color'], $palette[$i%count($palette)]);
            $legend.='<span><i aria-hidden="true" style="background:'.iptm_visual_escape($col).'"></i>'.iptm_visual_escape($row['label']).' <b>'.iptm_visual_escape(iptm_visual_number($row['value'])).'</b></span>';
        }
        $legend.='</div>';
    }
    return '<figure class="iptm-visual iptm-chart-'.iptm_visual_escape($type).'" data-iptm-chart="'.iptm_visual_escape($type).'">'
       . '<div class="iptm-chart-graphic">'.$svg.$legend.'</div>'
       . '<figcaption class="iptm-chart-footer"><span>'.iptm_visual_escape($title).'</span><button class="s sm iptm-chart-copy" type="button" aria-label="Copia i dati del grafico '.iptm_visual_escape($title).'">Copia dati CSV</button></figcaption>'
       . $table.'<p class="iptm-chart-feedback" role="status" aria-live="polite"></p></figure>';
}
