# IPTM — Firewall, rete e qualità del traffico

IPTM è un'interfaccia web per la gestione di firewall iptables, protezione delle reti locali, configurazione DNS e qualità del traffico su DietPi e Debian Linux. Usa PHP, Python, Bash e JavaScript per interagire con il sistema e i servizi disponibili.

## Funzionalità

- **Firewall:** gestione delle regole IPv4/IPv6, catene, liste IP, NAT, controlli di precedenza e anteprime prima dell'applicazione.
- **Protezione dell'accesso:** controllo delle regole SSH, verifiche di continuità e ripristino watchdog dopo applicazioni non confermate.
- **Reti e IoT:** inventario interfacce, segmentazione e impostazioni di isolamento, protezioni DNS e politiche di accesso.
- **DNS e privacy:** integrazione con Pi-hole, Unbound e DNSCrypt; diagnosi e gestione delle configurazioni disponibili.
- **Qualità del traffico:** gestione CAKE bidirezionale e IFB quando la topologia è compatibile, policy DSCP, misure RTT e ricalibrazione manuale della banda con limiti CAKE temporaneamente sospesi e ripristino automatico.
- **Sicurezza e diagnostica:** integrazione opzionale CrowdSec e Suricata, audit delle regole, monitoraggio dello stato e classificazione applicativa diagnostica.
- **Cache HTTP:** installazione opzionale Squid, proxy esplicito oppure intercettazione HTTP/80 automatica per le LAN servite dal gateway IPv4 IPTM, memorizzazione delle preferenze e disattivazione indipendente dal servizio. HTTPS resta cifrato, senza intercettazione TLS.
- **Aggiornamenti e archivi:** importazione/export delle impostazioni, pacchetti di aggiornamento nativi verificati, rotazione conservativa dei backup e log IPTM.

## Ambiente

Linux Debian/DietPi, PHP 8+, Python 3, Bash, systemd e iptables. Le funzionalità avanzate richiedono i relativi pacchetti e moduli kernel. La console usa principalmente iptables; gli altri servizi sono opzionali e gestiti separatamente.
