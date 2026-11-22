# IPTM 5.30.1 — Relazione di diagnosi e interventi

**Sorgente:** `Testo incollato.txt` fornito dall'utente (rules.v4 generato).

## Causa delle disconnessioni SSH (critica)

Le righe 51–60 del file originale impiegano regole `-m recent --update --hitcount 15` e `connlimit` sull'intera connessione TCP/22, senza `-m conntrack --ctstate NEW --syn`; sono poste prima di `ESTABLISHED`. Ogni pacchetto SSH può far avanzare i contatori recent. Al raggiungimento della soglia scatta `LOG-DROP`: SSH si interrompe o rallenta ripetutamente. Questo è un difetto di ordine e di selezione dei pacchetti.

La 5.30.1: (1) usa `--ctstate NEW --syn` nei limiti SSH generati; (2) mantiene SSH ESTABLISHED per le sessioni in corso; (3) presenta un pulsante per recuperare da web l'accesso SSH di un client LAN già autorizzato; (4) riscrive le regole legacy in **bozza in memoria** senza alterare il kernel. Rinnovare o applicare manualmente senza rollback può ancora interrompere la sessione: il software non esegue l'operazione automaticamente.

## QoS / CAKE (alta)

Il motore della versione precedente utilizzava speedtest ad alto traffico per stimare la banda. CAKE già attivo altera la misura, impedendo calibrazioni significative. Durante le misure la WAN può saturarsi, penalizzando client e SSH. La 5.30.1 controlla stato CAKE e proprietà della qdisc, rileva traffico Ethernet prima di ogni prova e rinvia la calibrazione se occupata. Con CAKE attivo usa solo sonde RTT leggere; **non** modifica i rate preesistenti senza conferma. La calibrazione produce proposte e non è un sistema di ottimizzazione della velocità sotto carico.

| Capacità | Implementazione | Limitazione |
| --- | --- | --- |
| CAKE bidirezionale | Disponibile | Verifica qdisc e IFB richieste sul kernel |
| IPv4 ingress pre-IFB | Disponibile quando topologia e ownership verificati | Non assume operatività con policy assente |
| DSCP flow IPv4 | Gestione disponibile | Stato attivo verificato con policy e filtri |
| Adattamento latenza | Sonde RTT | Non classifica traffico e non identifica con certezza il collo di bottiglia |
| Layer 7 | Non implementato | Evita DPI pesante su Atom N450 |
| Per-process classification | Non implementato | Il firewall non attribuisce automaticamente processi ai pacchetti instradati |

## HTTP update (alto)

Ristabiliti download HTTP/HTTPS con verifica dell'hash SHA-256 del pacchetto per HTTP, oltre ai controlli del contenuto Native Update. Il canale HTTP resta leggibile e modificabile da terzi; lo SHA-256 deve essere prelevato da una fonte affidabile distinta da quel download, altrimenti non prova l'autenticità. Redirect a IP non consentiti e downgrade HTTPS→HTTP sono bloccati.

## Rischi residui e limiti del collaudo

- L'accesso SSH reale dipende anche da qdisc/IFB, sistema di rete, `sshd`, interfacce, catene di terze parti e configurazioni eseguite fuori da IPTM; il solo `rules.v4` non consente diagnosi completa di tutti i problemi.
- Test offline non sostituiscono prove sul DietPi reale con client LAN, DNS, tunnel VPN, throughput bidirezionale e rollback watchdog.
- Le funzionalità Layer 7 e per-process non sono state implementate né dichiarate attive.
- I 49.152 scenari e 1.300 coppie includono molti stati, non tutti gli stati teoricamente possibili.
- Non è possibile garantire software privo di bug o produzione sicura senza test sul kernel e recupero out-of-band.
