# Audit firewall recovery / QoS — 22 novembre 2026

**Ambito:** repository IPTM `5.30.1`, revisione di `runtime/iptm-helper`, `modules/11_firewall_transaction.php`, `extensions/qos_engine.py`, `extensions/retention_manager.py`, `extensions/postinstall.py`, UI QoS. Revisione statica e test offline; **non** collaudo reale di iptables, CAKE, SSH e line rate sul gateway DietPi. Nessuna prova di equivalenza cFosSpeed.

## Difetti riproducibili e rischi

1. **CRITICO — Snapshot di recupero legato a IPSet CrowdSec effimero.** `modules/11_firewall_transaction.php:revert_pending`, `runtime/iptm-helper:rollback-run`. Stato: snapshot contiene `-m set --match-set crowdsec-blacklists-3 src -j DROP` mentre il bouncer ha distrutto il set. `iptables-restore --test` interrompe il rollback, mantiene pending e può prolungare un lockout SSH. **Correzione:** `firewall_recovery.py` identifica i set esistenti tramite `ipset list -name`, conserva lo snapshot originale e prepara una copia che elimina soltanto un DROP diretto di un set CrowdSec inesistente; rifiuta altri riferimenti, input malformati e inventari non verificabili.
2. **CRITICO — Mancava la prova di ripristinabilità prima dell'Apply.** `modules/11_firewall_transaction.php:do_apply`. Stato: backup live creato correttamente ma non ripristinabile, nuova policy rompe SSH. **Correzione:** preflight del rollback prima di armare il watchdog o modificare il kernel.
3. **CRITICO — Teardown CAKE proseguiva anche dopo errore ingress.** `extensions/qos_engine.py:restore`. Stato: `tc qdisc del ingress` fallisce, processo passa alla rimozione dell'IFB. **Correzione:** codice di ritorno controllato, verifica dell'assenza ingress, arresto immediato e stato `rollback-failed`.
4. **ALTO — Speedtest periodici interferivano con la WAN non shaped.** `extensions/qos_engine.py:auto_tick`. Stato: il timer rileva NIC idle per 500 ms, poi parte Ookla mentre un client avvia un download; saturazione e jitter. **Correzione:** timer orario passivo; misura di banda solo azionata manualmente.
5. **ALTO — Regolatore RTT non applicava riduzioni della congestione.** `extensions/qos_engine.py:adapt_tick`. Stato: RTT sale durante load ma il profilo non si adatta; la sola ripresa di velocità pregressa non ricalibra. **Correzione:** riduzione massima 2% per prova, pavimento 90% del limite confermato, una modifica/ora, 3 osservazioni RTT elevato con utilizzo >=75%, journal e verifica RTT con rollback.
6. **ALTO — Continuità di prova RTT tra versioni.** `extensions/qos_engine.py:adapt_tick`. Stato: journal della versione precedente senza `trial.kind` provocherebbe eccezione. **Correzione:** classifica un trial storico come `recover` e resta nel percorso di verifica/rollback.
7. **ALTO — Descrizione QoS duplicata al posto delle funzioni richieste.** `modules/34_qos_pages.php:pg_sqm`. Stato: una seconda tabella ripete lo stato e dichiara L7/processi non implementati. **Correzione:** rimozione della matrice; vista diagnostica fondata su app_proto Suricata e socket `ss`.
8. **MEDIO — Nessun inventario L7 operativo nella UI.** `extensions/traffic_observer.py:read_eve,parse_eve`. Stato: Suricata EVE assente, illeggibile o record invalidi. **Correzione:** lettura limitata e read-only, filtraggio record, classi suggerite, diagnosi esplicita se mancante. **Limite:** non è un engine DPI inline né agisce su CAKE/DSCP.
9. **MEDIO — Nessuna associazione ai processi locali.** `extensions/traffic_observer.py:parse_ss`. Stato: porte usate da più servizi e processi di client LAN non visibili al gateway. **Correzione:** classificazione dei socket del gateway per processo tramite `ss -tunap`. **Limite:** nessuna attribuzione di processi sui dispositivi remoti; nessun per-packet enforcement automatico.
10. **ALTO — Retention post-aggiornamento non effettivamente installata.** `runtime/iptm-helper:iptm_retention_install` era definita ma non invocata, `extensions/postinstall.py:ensure`. Stato: vecchi backup crescono indefinitamente quando non si avvia manualmente install. **Correzione:** installazione idempotente di timer di retention giornaliero dopo commit verificato, con report separato.
11. **ALTO — Cancellazione backup durante tentativi di recupero non riconosciuti.** `extensions/retention_manager.py:active_recovery`. Stato: journaling QoS/NetworkManager/network trial pendente. **Correzione:** blocco della cancellazione in presenza di stato incerto/pending/rollback-failed.
12. **MEDIO — Comando diagnostico non autorizzato dalla allowlist root.** `runtime/iptm-helper:qos-engine` e `modules/01_core_utilities.php:priv`. Stato: interfaccia vuole analisi traffico ma root worker risponde exit 2. **Correzione:** `traffic-inspect` esplicitamente riconosciuto come comando di sola lettura con tempo massimo.

## Priorità e semantica di sicurezza

- Non eliminare, rimpiazzare o assumere qdisc/IFB esterni: nel dubbio bloccare l'operazione e mostrare diagnostica.
- Nessuna calibrazione di banda sotto CAKE già confermato; non deriva capacità internet dal link NIC.
- Nessun cambio firewall senza snapshot ripristinabile, watchdog verificabile e possibilità di conferma reale SSH/LAN/DNS.
- I dati `Suricata app_proto` sono osservazioni storiche, non classificazione automatica a velocità di linea. La classe di un processo locale NON identifica i client LAN in forwarding.
- Pulizia backup: età di default 45 giorni, almeno 10 backup recenti per categoria, età minima 24 h, nessuna operazione quando esiste recovery attivo. Vecchie release gestite dal cleanup nativo con verifica manifest, esclusione di link simbolici, conservazione di versioni referenziate.

## Test offline e output atteso

Esecuzione: `python tests/test_firewall_qos_recovery.py`. Nel workflow GitHub Actions `.github/workflows/security-ci.yml`.

| Caso | Stimolo | Output atteso |
|---|---|---|
| 1 | Restore CrowdSec DROP con set -3 mancante | Solo quel DROP assente dalla copia, INPUT policy e SSH conservati |
| 2 | Set CrowdSec ancora esistente | Snapshot identico byte per byte |
| 3 | Set non CrowdSec mancante | `RecoveryError`, nessuna manipolazione |
| 4 | Match-set CrowdSec con target ACCEPT | `RecoveryError` |
| 5 | Regola CrowdSec in tabella NAT | `RecoveryError` |
| 6 | Set IPv6 valido / famiglia sbagliata | IPv6 corretto; famiglia errata bloccata |
| 7 | Input binario, vuoto, eccessivo, comando invalido | `RecoveryError` |
| 8 | ipset indisponibile | `RecoveryError`, nessuna supposizione |
| 9 | JSON Suricata valido + alterato | Contati solo `app_proto` validi |
| 10 | Processi sshd/rsync in socket del gateway | Classi `interactive` / `background` |
| 11 | Suricata EVE symlink | `available=false` |
| 12 | QoS schema con velocità negative, overflow, interfaccia malformata | `QosError` |
| 13 | Due speedtest manuali coerenti | Proposta 92% del valore mediano, mai cambio qdisc |
| 14 | Dati di banda rumorosi o degradati | Parametri precedenti conservati |
| 15 | Timer orario senza CAKE | `passive-only`, nessuno speedtest |
| 16 | Ingress removal fallisce | `rollback-failed`, IFB non rimossa |
| 17 | RTT alto senza contatori validi | Nessuna riduzione |
| 18 | Trial RTT peggiora la latenza | Ripristino esatto del rate precedente |
| 19 | Journal RTT della versione precedente | Compatibilità e prova verificata |

**Criterio di rilascio:** CI sintassi/test verde, controllo sicurezza completato, test integrati in namespace Linux isolato, verifica di rollback a perdita di SSH, CAKE/IFB in upload e download, fallimento DNS e Pi-hole. **Non effettuare il merge o abilitare queste regole su un gateway remoto senza canale di recupero indipendente.**
