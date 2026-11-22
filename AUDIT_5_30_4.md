# IPTM 5.30.4 — Audit tecnico, correzioni e regressioni (22 novembre 2026)

## Programma


## Problemi verificati e risolti

1. **CRITICO — Stato CAKE corrotto durante la ricalibrazione.** `extensions/qos_engine.py`, `calibration_start` e `start_unshaped_calibration`. Con JSON `active.json` formalmente valido ma privo di `ifindex`, `mac` o limiti, il codice sollevava `KeyError` o invocava funzioni con dati incompleti. Introdotto `validate_confirmed_state`: tipi rigorosi, campi obbligatori, limiti numerici e identità WAN/IFB. Il controllo precede qualsiasi `tc`.
2. **CRITICO — Ripristino della banda su una topologia diversa.** `extensions/qos_engine.py`, `restore_cake_after_calibration`. Se l'IFB o le velocità cambiano durante una prova, il ripristino usava il profilo corrente senza confrontare tutti gli attributi registrati. Aggiunti nel journal `ifindex`, `ifb_ifindex`, MAC e limiti originari, con verifica prima di scrivere nel kernel.
3. **ALTO — Operazioni adattive concorrenti durante CAKE unlimited.** `extensions/qos_engine.py`, `adapt_change_one`, `adapt_disable`. Possibile cambio di rate o disattivazione del controller durante il test di banda. Ora entrambi rifiutano operazioni quando `UNSHAPED` è pendente. `adapt_tick` e timer automatico già rispettavano questo vincolo.
4. **ALTO — Risposta JSON tc/ip non validata elemento per elemento.** `extensions/qos_engine.py`, `jcmd`, `identity`. Una lista JSON contenente stringhe o `null` provocava `AttributeError` invece di un errore diagnostico. Ora sono accettate solo liste di oggetti.
5. **ALTO — Verifica dell'owner PID watchdog non rigorosa.** `extensions/qos_engine.py`, `watchdog`. Con `owner_pid=0`, `os.kill(0,0)` interroga il gruppo processi anziché un singolo worker; PID assente, negativo, booleano o 1 poteva falsare il recupero. Ora il PID deve essere un intero maggiore di 1, altrimenti la prova viene dichiarata scaduta.
6. **ALTO — Stato malformato nelle operazioni di disattivazione.** `extensions/qos_engine.py`, `restore`. Uno stato `confirmed` senza proprietà essenziali poteva causare un'eccezione non controllata durante la rimozione. Aggiunta verifica fail-closed prima di tentare l'operazione.
7. **ALTO — Risultati speedtest a cavallo della scadenza.** `extensions/qos_engine.py`, `calibration_worker`. Il watchdog poteva essere sul punto di ripristinare il rate mentre il worker approvava campioni. Ora il ramo di accettazione esamina anche la scadenza del journal e non approva campioni se scaduto.
10. **MEDIO — Snapshot iptables non bilanciato.** `extensions/firewall_recovery.py`, `normalized`. `*filter` seguito da altra tabella senza `COMMIT`, o `COMMIT` spuri, poteva superare controlli parziali ed essere respinto solo dal test successivo. Ora il parser verifica la sequenza delle tabelle e il `COMMIT` di `*filter`.
11. **MEDIO — Mismatch tra test e funzionalità di ricalibrazione.** Test precedenti assumevano che la misura sotto CAKE fosse sempre proibita; la misura corrente è ammessa solo con limiti `bandwidth unlimited` e watchdog. La suite è stata riallineata alla politica di sicurezza e sono stati aggiunti test per profili malformati.
12. **MEDIO — Versione non incrementata.** Il pacchetto precedentemente distribuito era 5.30.3 e non avrebbe accettato l'installazione ordinaria di una build rivista con stesso numero. Aggiornati helper, loader, moduli, script, manifest e riferimenti a 5.30.4.

## Rischi residui da collaudare prima di usare su gateway di produzione

1. **CRITICO:** continuità dell'accesso SSH e applicazione di regole IPv4/IPv6 su kernel/iptables legacy e nft. Richiedono prova in namespace o host di riserva e canale di recupero indipendente.
2. **CRITICO:** arresto improvviso del sistema tra le due modifiche WAN/IFB, riavvio durante la calibrazione e reimpostazione del watchdog al boot. I test isolati non sostituiscono il collaudo reale.
5. **MEDIO:** condizioni di race esterne di systemd, NetworkManager, kernel e servizi terzi non riproducibili con i mock.
6. **MEDIO:** risultati della classificazione applicativa Suricata sono diagnostici e non equivalgono alla classificazione per processo del traffico inoltrato o a DPI inline.

## Test mirati — input / comportamento atteso

| ID | Input/stato | Output atteso |
|---|---|---|
| T01 | profilo CAKE confermato ma senza `ifindex` | `QosError`, zero invocazioni `tc` |
| T02 | profilo CAKE integro e stessa WAN | Validazione completata |
| T03 | profilo CAKE integro, WAN diversa | `QosError`, zero cambiamenti |
| T04 | interfaccia `../bond0` | Rifiuto path non valido |
| T05 | indice interfaccia `True` | Rifiuto tipizzazione (`bool` != `int`) |
| T06 | velocità negativa | Rifiuto limiti fuori intervallo |
| T07 | MAC nullo | Rifiuto identità incompleta |
| T08 | conteggio filtri ingress enorme | Rifiuto valori fuori intervallo |
| T09 | versione journal estranea | Rifiuto stato di altra release |
| T10 | `tc -j` restituisce `[null,{}]` | Errore controllato senza traceback |
| T11 | `tc -j` restituisce `['bad']` | Errore controllato |
| T12 | avvio calibrazione con `active.json` incompleto | `QosError` prima di `set_unlimited` |
| T13 | controller cerca di cambiare velocità con journal unlimited pendente | Modifica vietata |
| T14 | controller RTT viene disattivato durante la misura | Disattivazione vietata |
| T15 | journal IFB con indice diverso | Ripristino banda rifiutato |
| T16 | journal con rate originale diverso dal confermato | Ripristino banda rifiutato |
| T17 | CrowdSec set inesistente referenziato in DROP | Solo DROP non valido escluso dallo snapshot; policy preservata |
| T18 | `*filter` non chiuso prima di `*nat` | `RecoveryError` |
| T19 | `COMMIT` spuri | `RecoveryError` |
| T22 | HTTPS CONNECT / ACL | CONNECT ristretto, LAN autorizzate prima del deny all |
| T23 | retention durante transazione pendente | Eliminazione backup bloccata |
| T24 | retention `backup_keep=-1` | Rifiuto configurazione |
| T25 | audit con sole chain senza regole | Risposta read-only, zero regole |

