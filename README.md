# IPTM — Firewall, rete e qualità del traffico

IPTM è un'interfaccia web per la gestione di firewall iptables, protezione delle reti locali, configurazione DNS e qualità del traffico su DietPi e Debian Linux. Usa PHP, Python, Bash e JavaScript per interagire con il sistema e i servizi disponibili.

## Funzionalità

- **Firewall:** gestione delle regole IPv4/IPv6, catene, liste IP, NAT, controlli di precedenza e anteprime prima dell'applicazione.
- **Protezione dell’accesso:** controllo delle regole SSH distinto per interfaccia d’ingresso quando verificabile (LAN, VLAN, VPN), verifiche di continuità e ripristino watchdog dopo applicazioni non confermate.
- **Audit delle policy:** verifica in sola lettura della bozza per aperture duplicate, sorgenti LAN senza interfaccia, rischio di bypass delle protezioni SSH, accessi WireGuard troppo ampi e incoerenze MAC/IoT. Rigenerazione controllata dei soli blocchi IPTM.
- **Topologia WAN/LAN:** vincoli d’ingresso per i servizi locali, anti-spoofing RFC1918 automatico solo su una WAN pubblica distinta e verificata; nessun blocco indiscriminato delle LAN condivise o in doppio NAT.
- **Reti e IoT:** inventario interfacce, segmentazione e impostazioni di isolamento, protezioni DNS e politiche di accesso. Le policy MAC gestite dalla UI restano attive durante la rigenerazione, con controllo di coerenza tra preferenze e regole generate.
- **DNS e privacy:** integrazione con Pi-hole, Unbound e DNSCrypt; diagnosi e gestione delle configurazioni disponibili.
- **Qualità del traffico:** gestione CAKE bidirezionale e IFB quando la topologia è compatibile, policy DSCP, misure RTT e ricalibrazione manuale della banda con limiti CAKE temporaneamente sospesi e ripristino automatico.
- **Sicurezza e diagnostica:** integrazione opzionale CrowdSec e Suricata, audit delle regole, monitoraggio dello stato e classificazione applicativa diagnostica.
- **Aggiornamenti e archivi:** importazione/export delle impostazioni, pacchetti di aggiornamento nativi verificati, rotazione conservativa dei backup e log IPTM.

## Ambiente

Linux Debian/DietPi, PHP 8+, Python 3, Bash, systemd e iptables. Le funzionalità avanzate richiedono i relativi pacchetti e moduli kernel. La console usa principalmente iptables; gli altri servizi sono opzionali e gestiti separatamente.

- **Ingress LAN e anti-spoof:** collegamento delle subnet alle interfacce reali o alle associazioni esplicite, vincoli su INPUT/FORWARD/DNS NAT e protezione RFC1918 soltanto sulle interfacce esterne pubbliche verificate; anteprima nella pagina WAN, LAN e NAT.


## Release 5.30.22 — sicurezza e integrazioni

La 5.30.22 introduce protezioni per la sessione e l'accesso web, controlli incrociati delle impostazioni e riconoscimento CrowdSec anche in ambienti nftables/ipset. Include le evoluzioni dalla 5.30.12: retention/ripristino release, prestazioni UI, ricalibrazione, applicazione, e prenotazioni DHCP Pi-hole.

- **Pacchetto nativo:** [IPTM_5.30.22_UPDATE.zip](release/IPTM_5.30.22_UPDATE.zip).
- **Note e limiti della release:** [IPTM 5.30.22 — note di rilascio](release/IPTM_5.30.22_RELEASE_NOTES.md).
- Squid rimane escluso dalle funzionalità; è presente soltanto il ritiro sicuro dei residui di installazioni precedenti.

**Avvertenza per gateway remoti:** nella 5.30.22 l'applicazione firewall può confermare automaticamente la transazione senza una verifica manuale della raggiungibilità SSH/LAN. Inoltre, la sincronizzazione DHCP Pi-hole può sostituire l'intero elenco `dhcp.hosts`. Prima dell'installazione effettuare backup e collaudo in ambiente di prova. La suite CI esegue test offline, **non** convalida la continuità della rete sul DietPi reale.

## Novità IPTM 5.30.23 — rollback firewall, Pi-hole DHCP e VPN→LAN

Questa release corregge due rischi della 5.30.22: (1) `do_apply()` non conferma più automaticamente le regole nel kernel: il watchdog resta attivo per la finestra configurata, e una sessione amministrativa deve premere **Conferma e salva** dopo il collaudo SSH, LAN, DNS e VPN; (2) le prenotazioni `dhcp.hosts` vengono **aggiunte senza eliminare quelle esistenti**, con rifiuto dei conflitti MAC/IP, backup root-only (0600) e verifica post-scrittura su `pihole.toml`.

- [Aggiornamento nativo IPTM 5.30.23](release/IPTM_5.30.23_UPDATE.zip)
- [Guida VPN→LAN: SSH, Home Assistant, routing e policy](docs/VPN_ACCESS_53023.md)
- Protezioni DoT/DNS e policy `FORWARD DROP` preservate; nessuna nuova apertura indiscriminata su `wg0`.
- Finestra di rollback predefinita: **180 s**, personalizzabile in `/etc/iptables-manager.web.json` (se già definita, prevale la configurazione esistente).

**Collaudo richiesto su DietPi:** la CI verifica offline sintassi e regressioni, ma non prova firewall, raggiungibilità SSH e Home Assistant reali né il demone FTL reale. Su Pi-hole che usa array DHCP di formato non interpretabile, IPTM rifiuta l'operazione senza sovrascrivere nulla. Non applicare da remoto senza una console di recupero.

## Novità 5.30.12 — sola diagnostica prestazionale, nessun proxy HTTP

La cache HTTP LAN è stata eliminata dall’interfaccia, dal controller, dalla gestione dei programmi e dall’helper: non esistono più attivazione, configurazione né reindirizzamenti HTTP gestiti dall’applicazione. L’aggiornamento nativo dismette prima della sostituzione dell’helper soltanto i componenti con ownership IPTM verificabile, usando le regole di rimozione exact-match del motore già installato. Se i redirect NAT non sono verificabili o i file sono stati modificati, **l’aggiornamento viene bloccato** prima del cambio di runtime: nessun flush di `nat`, `filter` o riduzione di `FORWARD DROP`.

I pacchetti Debian non vengono disinstallati automaticamente: potrebbero essere usati fuori da IPTM. Se un’applicazione esegue un proxy esterno configurato nei browser, è necessario disattivare manualmente anche le preferenze client. Le eventuali regole `IPTM:cache-proxy-allow` salvate manualmente in `rules.v4` o in una bozza **non** vengono eliminate automaticamente: eliminarle solo dopo controllo delle differenze e applicazione con watchdog, per non modificare alla cieca regole personali. Le protezioni IoT, DNS/DoT, SSH, VLAN, anti-spoofing e CAKE rimangono indipendenti.

**Alternative a basso impatto:** analisi overhead iptables nella pagina Prestazioni (solo lettura), regolazione misurata CAKE/fq_codel nelle pagine SQM, verifica cache DNS Pi-hole/Unbound e analisi della latenza sotto carico. Nessuna accelerazione è promessa senza misure pre/post né vengono cambiati automaticamente i limiti di banda.

## Recupero regole DoT e DNS (da 5.30.11)

**Problema corretto:** in 5.30.9–5.30.10 il form Setup non includeva i controlli `dns_redirect`, `dot_block`, `dns_ip` benché il controller potesse azzerare le prime due opzioni. Riaprendo e salvando Setup si potevano perdere i blocchi `IPTM:dot` (FORWARD TCP/UDP 853) e `IPTM:dns-redir` (PREROUTING TCP/UDP 53) dalla bozza, perfino senza chiedere di disattivarli. Il messaggio «ingresso non verificato» è informativo e non deve essere interpretato come richiesta di eliminazione.

La pagina **Setup → Protezione DNS LAN** espone nuovamente i tre controlli. In caso di mismatch fra file persistente e bozza, appare il pulsante **Ripristina DoT/DNS dal file su disco (solo bozza)**: il recupero controlla il numero, i protocolli, i CIDR LAN, l'IP DNS di destinazione e le azioni di tutte le regole. Se non coincidono, non modifica nulla. Sincronizza opzioni e bozza, non tocca il kernel né `rules.v4`. La rigenerazione preserva i blocchi presenti in bozza anche se i flag salvati risultano inattivi; un'eventuale rimozione intenzionale richiede una conferma esplicita.

La pagina **Applica** impedisce di applicare o scrivere permanentemente una bozza priva dei blocchi DoT/DNS ancora presenti in `rules.v4` senza una conferma separata. Nessuna modifica alla policy `FORWARD DROP`, alle eccezioni IoT/MAC o all'anti-spoofing. Se l'ingresso LAN non è verificato, i vincoli per subnet sorgente rimangono, ma non sono una misura completa contro lo spoofing; usare le interfacce LAN verificate quando possibile. Questo aggiornamento non aggiunge un blocco DoH sulla 443 e non modifica la configurazione Pi-hole/Unbound/DNSCrypt.

Test offline: `php tests/test_dns_guard_preservation_5311.php`, oltre alle suite di regressione firewall, IoT, ingress e QoS. Prima di applicare sul gateway verificare **bozza → differenze**, eseguire il preflight e applicare con watchdog/rollback SSH.
