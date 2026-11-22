<?php
/* IPTM action domain: identity. Inherits the authenticated controller scope. */
switch ($a) {
case 'notify_save': case 'notify_test': {
            $S = S_get();
            $n = [
                'tg_token' => trim((string)($_POST['tg_token'] ?? '')),
                'tg_chat' => trim((string)($_POST['tg_chat'] ?? '')),
                'webhook' => trim((string)($_POST['webhook'] ?? '')),
                'ev' => array_values(array_intersect((array)($_POST['ev'] ?? []), ['apply', 'confirm', 'revert', 'rollback', 'login', 'loginfail', 'rulehit', 'ct_high'])),
                'rule_on' => !empty($_POST['rule_on']) ? 1 : 0,
                'rule_min' => max(1, min(1000000, (int)($_POST['rule_min'] ?? 20))),
                'rule_patterns' => trim((string)($_POST['rule_patterns'] ?? 'DROP,REJECT')),
            ];
            if (!preg_match('/^(\d{5,12}:[A-Za-z0-9_-]{30,50})?$/', $n['tg_token']) || !preg_match('/^(-?\d{3,20})?$/', $n['tg_chat']) || !preg_match('~^(https://[^\s\'"\\\\]{5,200})?$~', $n['webhook'])) { flash('Dati di notifica non validi.', 'err'); break; }
            if ($n['rule_patterns'] !== '' && !preg_match('/^[A-Za-z0-9_,\-]{0,200}$/', $n['rule_patterns'])) { flash('Pattern alert regole non validi (solo lettere, numeri, virgole).', 'err'); break; }
            $S['notify'] = $n; S_put($S); notify_env($n); rule_alerts_write($n);
            if ($a === 'notify_test') {
                $n['ev'][] = 'test'; $S['notify'] = $n; S_put($S);
                notify('test', 'Notifica di prova da iptables-manager');
                if ($n['rule_on']) { [$c, $o] = priv('rule-alerts'); flash('Prova inviata. Test alert regole: ' . trim($o ?: 'ok')); }
                else flash('Prova inviata (controlla Telegram/webhook).');
                $n['ev'] = array_values(array_diff($n['ev'], ['test'])); $S['notify'] = $n; S_put($S);
            } else flash('Notifiche e alert regole salvati.');
            break;
        }

        case 'user_add': {
            if (($_SESSION['role'] ?? 'viewer') !== 'admin') break; $n = trim((string)($_POST['user'] ?? '')); $pw = (string)($_POST['pw'] ?? ''); $U = users_get();
            if (!preg_match('/^[a-z0-9_.-]{2,20}$/', $n) || isset($U[$n])) flash('Nome utente non valido o già esistente.', 'err'); elseif (strlen($pw) < MIN_PW) flash('Password troppo corta (min ' . MIN_PW . ').', 'err');
            else { $U[$n] = ['hash' => iptm_password_hash($pw), 'role' => in_array($_POST['role'] ?? '', ['admin', 'viewer'], true) ? $_POST['role'] : 'viewer', 'totp' => '']; users_put($U); flash("Utente $n creato."); } break;
        }
        case 'user_del': case 'user_role': case 'user_reset2fa': {
            if (($_SESSION['role'] ?? 'viewer') !== 'admin') break; $n = (string)($_POST['user'] ?? ''); $U = users_get(); if (!isset($U[$n])) break;
            $admins = count(array_filter($U, fn($u) => ($u['role'] ?? '') === 'admin'));
            if ($a === 'user_del') { if ($n === me() || (($U[$n]['role'] ?? '') === 'admin' && $admins < 2)) flash('Non puoi eliminare te stesso o l\'ultimo amministratore.', 'err'); else { unset($U[$n]); users_put($U); flash('Utente eliminato.'); } }
            elseif ($a === 'user_role') { $r = in_array($_POST['role'] ?? '', ['admin', 'viewer'], true) ? $_POST['role'] : 'viewer'; if ($r === 'viewer' && ($U[$n]['role'] ?? '') === 'admin' && $admins < 2) flash('Deve restare almeno un amministratore.', 'err'); else { $U[$n]['role'] = $r; users_put($U); flash('Ruolo aggiornato.'); } }
            else { $U[$n]['totp'] = ''; users_put($U); flash('2FA azzerata per ' . $n . '.'); } break;
        }
        case 'totp_start': $_SESSION['totp_pend'] = b32enc(random_bytes(10)); break;
        case 'totp_on': { $sec = (string)($_SESSION['totp_pend'] ?? ''); if ($sec !== '' && totp_ok($sec, (string)($_POST['code'] ?? ''))) { $U = users_get(); $U[me()]['totp'] = $sec; users_put($U); unset($_SESSION['totp_pend']); flash('2FA attivata.'); } else flash('Codice errato.', 'err'); break; }
        case 'totp_off': { $U = users_get(); if (iptm_password_verify((string)($_POST['old'] ?? ''), (string)($U[me()]['hash'] ?? ''))) { $U[me()]['totp'] = ''; users_put($U); flash('2FA disattivata.'); } else flash('Password errata.', 'err'); break; }
        case 'chpw': {
            $U = users_get(); $n = (string)($_POST['pw'] ?? '');
            if (!iptm_password_verify((string)($_POST['old'] ?? ''), (string)($U[me()]['hash'] ?? ''))) flash('Password attuale errata.', 'err'); elseif (strlen($n) < MIN_PW || $n !== ($_POST['pw2'] ?? '')) flash('Nuova password troppo corta o diversa dalla conferma.', 'err');
            else { $U[me()]['hash'] = iptm_password_hash($n); users_put($U); flash('Password cambiata.'); } break;
        }
        case 'api_token_save': {
            api_token_set(trim((string)($_POST['api_token'] ?? '')));
            flash('Token API salvato' . (api_token_get() === '' ? ' (API disabilitata)' : ''));
            $back = 'p=admin'; break;
        }
        case 'api_token_gen': {
            $tok = bin2hex(random_bytes(24));
            api_token_set($tok);
            flash('Nuovo token generato. Copialo ora: ' . $tok);
            $back = 'p=admin'; break;
        }
        
}
