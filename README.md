# IPTM — iptables Manager

IPTM è un pannello web per DietPi/Debian che gestisce regole iptables, firewall IPv4/IPv6, accessi di rete, politiche IoT, DNS e qualità del traffico.

## Firewall e continuità

La gestione firewall include anteprima delle regole, verifica sintattica, rilevamento delle dipendenze IPSet, backup, restore protetto, watchdog di rollback e conferma esplicita delle modifiche. Le impostazioni possono essere esportate e ripristinate.

## Qualità del traffico

Il motore di QoS controlla CAKE su WAN e IFB, usa marcature DSCP IPv4, verifica la proprietà delle qdisc ed espone lo stato del kernel. La ricalibrazione manuale misura upload e download con shaping non attivo; quando è presente un CAKE confermato, sospende temporaneamente i limiti con bandwidth unlimited e li ripristina tramite watchdog. Il controllo periodico misura RTT senza speedtest automatici.

## Prestazioni e cache

Un analizzatore esamina le regole del firewall, individua configurazioni potenzialmente onerose e propone modifiche compatibili con i requisiti di sicurezza. Il proxy opzionale Squid usa cache su disco e memoria per contenuti HTTP cacheable, accetta soltanto subnet LAN autorizzate e inoltra HTTPS con CONNECT senza decodificarne il contenuto. Il proxy non modifica automaticamente il firewall e non sostituisce la CDN dei siti web.

## DNS, IDS e integrazioni

Le funzionalità di rete comprendono Pi-hole, Unbound, DNSCrypt, CrowdSec e Suricata quando disponibili sul dispositivo. Le informazioni di Suricata EVE permettono una classificazione diagnostica dei protocolli Layer 7; i processi locali vengono correlati ai socket senza identificare processi sui client remoti. Sono supportati inventario di rete, report diagnostici e gestione conservativa della retention dei backup.

## Interfaccia

Il pannello riunisce diagnostica di rete, generazione delle regole, servizi di sicurezza, politiche DNS, stato CAKE, audit delle prestazioni, gestione della cache e operazioni di backup. Le modifiche al firewall e al proxy richiedono operazioni esplicite.
