# IPTM 5.30.4 — Rafforzamento stati QoS, recupero firewall e proxy

- Validazione rigorosa dello stato CAKE e delle identità delle interfacce prima della calibrazione.
- Arresto delle regolazioni concorrenti durante la misura senza shaping e controllo dello scadere della prova.
- Confronto dei parametri originali nel journal prima del ripristino dei limiti CAKE.
- Controlli sui permessi e sul risultato delle operazioni di rollback del servizio Squid.
- Verifica bilanciata dei blocchi iptables negli snapshot CrowdSec.
- Suite di test di regressione e aggiornamento versione.

# IPTM 5.30.4 — Installazione Squid da Strumenti → Programmi

- Squid è presente nel catalogo dei programmi installabili tramite APT, nella selezione multipla e nei registri di installazione.
- Rilevamento installazione e disponibilità pacchetto integrato nei controlli esistenti.
- Per una nuova installazione, il servizio Squid predefinito è mantenuto disattivato; il proxy LAN IPTM si configura separatamente nella pagina Prestazioni con conferma esplicita.
- La pagina Prestazioni rimanda alla voce Squid di Strumenti → Programmi quando il pacchetto manca.

# IPTM 5.30.2 — Prestazioni e continuità di rete

- Analisi in sola lettura delle regole IPv4: limiti DROP, QUIC, logging, IPSet, code in userspace, duplicati e controlli che possono aumentare latenza.
- Proxy HTTP Squid isolato per subnet LAN esplicitamente autorizzate, con cache configurabile, HTTPS CONNECT senza intercettazione TLS, anteprima e attivazione a conferma.
- Calibrazione della banda con CAKE **bandwidth unlimited** temporaneo su entrambe le direzioni; watchdog indipendente per ripristinare i limiti confermati.
- Miglioramento del recupero firewall quando snapshot IPSet contengono riferimenti CrowdSec dinamici scaduti.
- Riduzione carico QoS automatico, analisi Suricata EVE Layer 7, socket dei processi locali e retention backup conservativa.

# IPTM 5.30.2 — Continuità SSH, HTTP Update, QoS non invasivo (22 novembre 2026)

**Priorità:** continuità SSH e traffico lecito, nessuna modifica automatica al kernel durante l'aggiornamento.

- Correzione concreta della perdita SSH nel rules.v4 incollato: `ssh-acc` non conta più i pacchetti `ESTABLISHED` nelle soglie `recent/connlimit`, ma soltanto le nuove connessioni TCP SYN. Conservata l'autorizzazione di management dalla LAN prima dei limiti quando `continuity_priority` è attiva.
- Nuova azione admin nella pagina Sicurezza: `Recupera SSH da questo PC`, limitata al client IPv4 privato configurato e alle regole TCP/22 già ammesse dalle subnet di management; aggiunge solo eccezioni SSH temporanee specifiche e idempotenti senza flush o cambio policy. Nessuna esecuzione automatica dopo update.
- `rules_optimizer.py`: nuova diagnosi `SSH_ESTABLISHED_RATE_LIMIT`, correzione in memoria delle sole regole IPTM gestite, mai applicazione diretta delle regole salvate.
- Aggiornamenti **HTTP o HTTPS** come richiesto. Per HTTP è obbligatorio confrontare lo SHA-256 del file ottenuto con un valore attendibile indicato separatamente. Ogni redirect è riverificato e non si consente downgrade HTTPS→HTTP; no URL con credenziali o loopback/local-link.
- QoS: ricalibrazione velocità impedita con CAKE o altro proprietario QoS già attivo e rinviata se l'interfaccia WAN è occupata. Verifica nuovamente NIC e CAKE prima di ogni misura di velocità; nessuno speedtest automatico sotto shaping. Controllo orario con CAKE confermato in **sola lettura RTT** senza variare limiti o qdisc.
- UI QoS: tabella di effettive capacità CAKE/IFB/DSCP; layer7 e classificazione per processo segnalati **non implementati** per evitare carico aggiuntivo e false promesse. Distinzione tra misurazione velocità, adattamento RTT e modifica dei valori confermati.
- Test mirati PHP/Python, suite da 49.152 configurazioni + 1.300 coppie, casi di recovery SSH idempotenti, test dei redirect HTTP/HTTPS, optimizer ed effetti QoS occupato/CAKE (tutti offline).

**Limiti:** non dimostrata continuità di rete sul DietPi reale. Se SSH è già bloccato prima di aggiornare, la correzione live va azionata esplicitamente dalla console web amministrativa; la rigenerazione di `rules.v4` serve per la persistenza. Il comando di recupero interviene solo se l'origine è una LAN attendibile già autorizzata da `iptables`.

# IPTM 5.30.0 — Security audit, input validation and safe-upgrade (22 novembre 2026)

Versione della serie 5.30 pubblicata come 5.30.0 per compatibilità con il validatore Native Update 5.20.29, che richiede almeno tre componenti numerici.

- Validazione CIDR di gestione `ui_nets` rigorosa: maschere vuote, negative, non numeriche e >32 non diventano `/0`.
- Gestione IPv6 amministrativa distinta (`ALLOWED_NETS6`): quando `ALLOWED_NETS` viene personalizzato, un IPv6 ULA/LL non bypassa automaticamente le restrizioni IPv4. Accesso da localhost IPv6 preservato; l'ACL di default senza personalizzazioni conserva i precedenti ambiti privati per compatibilità.
- Alias porte non validi/non risolti rifiutati anche in FORWARD: mai `ACCEPT` o `DROP` generico conseguente a una risoluzione fallita; rifiutati anche abbinamenti porta/protocollo che altrimenti scarterebbero il filtro porta.
- Importazione e lettura impostazioni legacy tolleranti a tipi JSON inattesi; le righe servizio malformate non generano aperture implicite.
- Preflight LAN→WAN: con default-drop e protezione della connettività attiva, uscita non determinabile blocca Apply anziché generare un semplice avviso.
- Download di codice eseguito come root solamente su HTTPS (redirect a HTTP rifiutati); ZIP locale da UI disponibile per reti senza connettività HTTPS. SHA-256 verifica integrità, NON firma digitale.
- Login: pulizia e limite massimo delle voci IP nello storico dei tentativi falliti; le voci scadute non vengono conservate indefinitamente; il formato JSON storico corrotto non azzera i contatori di sicurezza.
- UI aggiornamenti allineata al requisito HTTPS per i download via URL.
- Test aggiuntivi su concorrenza della bozza (compare-and-swap) e 384 configurazioni di servizi TCP/UDP INPUT/FORWARD.
- Suite di regressioni mirate e strutturali fornita separatamente; nessuna regola applicata al kernel e nessun test client reale eseguito.

Limiti di audit: non è possibile dimostrare assenza totale di bug, race, memory leak o assenza di blocchi leciti per tutte le topologie. L'installazione su DietPi reale, le dipendenze e i test di failover/rollback necessitano collaudo su un dispositivo di prova.

# IPTM 5.20.29 — Priorità continuità di rete e 2.097.152 combinazioni (22 novembre 2026)

- Matrice deterministica offline 16 profili × 131.072 stati, 17 toggle: verifiche strutturali su SSH, routing, DNS, NAT, QUIC/DoT, conntrack, LAN e WAN.
- Nuova opzione **Proteggi la connettività** (attiva per impostazione predefinita, disattivabile in Sicurezza) per evitare rate-limit generici e conservare risposte ESTABLISHED/RELATED e loopback anche senza SPI.
- Mantiene isolamento, ACL, DNS e blocchi esplicitamente richiesti; segnala interazioni con QUIC, DoT e zone IoT anziché disattivarli silenziosamente.
- Anti-lockout sempre generato per LAN attendibili quando la protezione è attiva; il preflight che rileva una perdita di connessione non è aggirabile tramite "Forza".
- La conferma finale ripete il selftest gateway quando la protezione è attiva: in caso di errore mantiene il watchdog e non rende persistente la bozza.
- Test unicamente su modelli offline: la copertura non dimostra l'assenza di interruzioni per qualsiasi dispositivo o configurazione reale. Nessuna applicazione automatica sul kernel.

# IPTM 5.20.28 — Matrice di 500.000 combinazioni e controlli di generazione (22 novembre 2026)

- Eseguiti **500.000 scenari riproducibili** di generazione delle regole, con **8.493.232 asserzioni** e 16 opzioni booleane su 8 profili WAN/LAN (sette spazi completi 2^16 + 41.248 casi dell’ottavo). Nessun test modifica iptables in esecuzione.
- Regolarizzato l’ambito degli accessi SSH generati: `ssh_nets` accetta solo CIDR privati attendibili; voci `/0`, pubbliche o con maschere errate non producono eccezioni INPUT.
- `lan_nets` rifiuta maschere CIDR malformate invece di degradarle implicitamente a singolo host `/32`.
- In fase di generazione i nomi delle interfacce WAN/LAN/VPN e l’elenco delle interfacce NAT sono validati anche quando arrivano da settings legacy o import; nomi non validi sospendono le regole dipendenti.
- Risoluzione fail-closed degli alias porte dei servizi INPUT: alias sconosciuti, ambiti porta vuoti, porte/alias 2375/2376 e intervalli che le includono non producono aperture all’host; le porte non pericolose restano utilizzabili.
- Schermata **Protezione → Analizza rules.v4**: nuovo pannello compatto, espandibile e read-only **Controllo opzioni attive**, con gli avvisi di generazione per la configurazione selezionata (nessuna modifica al firewall o alla bozza).
- Suite separata e riproducibile, con bootstrap PHP, fixture e report JSON. Inclusi i regressioni precedenti 49.152 scenari / 1.300 coppie e test Python per l’ottimizzatore.
- **Limiti:** le 500.000 combinazioni appartengono a un sottoinsieme specificato; non equivalgono alla totalità delle configurazioni possibili. Non sono stati eseguiti test sul kernel né applicazioni reali delle regole sul DietPi.

# IPTM 5.20.27 — Generazione firewall e combinazioni (22 novembre 2026)

- Regole `raw-drop` limitate alla WAN fisica quando veramente separata; in Single-NIC o senza WAN identificabile il blocco anticipato viene sospeso, preservando INPUT/FORWARD e gli eventuali servizi LAN.
- `LAN → uscita` usa ora la catena gestita `IPTM-LAN-EGRESS`: RETURN per tutte le subnet LAN configurate e ACCEPT soltanto sulle interfacce di uscita autorizzate; nessuna generazione di `FORWARD -s LAN -j ACCEPT` senza WAN.
- DoT/853 e QUIC/443 limitati alle subnet LAN esplicite, senza blocchi generici su tutte le origini.
- Aperture automatiche TCP/UDP senza porta e regole del servizio host che espongono Docker TCP/2375/2376 vengono escluse dalla bozza; Docker API non viene aperta tramite profilo app.
- Profili `solo LAN` con `lan_nets` vuoto adesso falliscono chiusi (in precedenza diventavano accessibili da qualsiasi origine); profili VPN marcati esplicitamente con ambito `any` restano tali.
- Subnet `lan_nets` usate come rete di fiducia normalizzate e filtrate: niente `0.0.0.0/0`, subnet pubbliche o malformate in auto-aperture UI/SSH.
- Protezioni di Apply: preflight aggiuntivo sulle sezioni IPTM legacy insicure (TCP generico, Docker, raw globale, UI `0/0`); non modifica regole di altri tool.
- Rules audit: modalità **Controlla soltanto** (nessun backup/salvataggio della bozza) oppure **Crea bozza corretta** (con backup), senza conferme testuali; avvisi più sintetici.
- L'analizzatore distingue un blocco raw limitato alla WAN da un blocco globale; segnala NAT senza sorgente, permessi FORWARD ampi e SSH su interfacce fisiche.
- Test off-line: 49.152 scenari esaustivi per 14 flag sulle tre topologie, 1.300 combinazioni di coppie su 26 opzioni, 526.902 asserzioni; regressioni aggiuntive per software LAN/VPN, SSH, WAN raw e idempotenza.
- **Limite:** i test combinatori sono esaustivi nel sottoinsieme dichiarato e non per ogni configurazione possibile; iptables-restore --test e rollback sul DietPi reale restano indispensabili. Nessuna modifica al kernel durante l'aggiornamento.

# IPTM 5.20.26 — Audit rules.v4 e bozza sicura

- Nuova pagina Firewall → Analizza rules.v4: carica un file vecchio (o usa la bozza corrente), genera offline una bozza e salva il report nella sessione. Nessuna modifica immediata alle regole attive.
- Analizzatore Python con parsing statico, limiti di input, diagnostica di precedenza raw/filter, SSH, Docker, DNS, DoT, dispositivi IoT, NAT, VPN e limiti di IPv6.
- Importazione transazionale della bozza con controllo della revisione, copia di sicurezza e validazione del modello.
- Generatore protetto: disabilitate aperture LAN TCP indiscriminate e preset API Docker; eliminazione delle aperture SSH TCP22 senza sorgente; limiti SSH prima degli allow di gestione; DoT prima di FORWARD permissivi; risolti raw-drop in conflitto con i servizi ammessi in INPUT.
- Migrazione settings schema 43; invariati MAC/zone IoT senza conferma di topologia.
- Test statici dell'analisi sul rules.v4 fornito, idempotenza, sintassi PHP/Python/Bash/JS, validazione manifest e pacchetti. Nessuna prova sulla rete reale.

# IPTM 5.20.25 — DSCP selective safe disable

- Disattivazione DSCP ripetibile anche dopo rigenerazione delle catene iptables: pulizia dello stato obsoleto quando la catena è assente e il backend mangle risponde regolarmente.
- Rimozione esclusiva delle regole DSCP descritte dal profilo IPTM con controlli `iptables -C`; nessun flush o reset di tabelle/catene condivise.
- Hook/catene/modifiche di terzi conservati quando contengono regole o riferimenti non riconosciuti; eliminata soltanto la catena rimasta vuota e senza riferimenti.
- Persistenza systemd disabilitata solo quando la relativa unità è riconosciuta come IPTM; protezioni CAKE e controllo dei dati salvati conservati.
- Messaggi di disattivazione differenziati tra profilo assente, rimozione completa e presenza di regole esterne.

# IPTM 5.20.25 — CAKE senza blocco DSCP non verificato

- Corretto il rifiuto «policy DSCP non verificata: classificazione ingresso sospesa» durante la prova CAKE: la classificazione download facoltativa viene esclusa, senza alterare le regole firewall esistenti.
- CAKE/IFB conserva la gestione download e upload, incluso il redirect universale IFB e rollback.
- Il controllo della proprietà DSCP viene eseguito prima di creare qdisc e IFB; le anomalie strutturali/di permessi continuano a bloccare in sicurezza.
- Mostrato lo stato delle priorità download nella risposta della prova e nella pagina SQM.
- Nessuna applicazione automatica di DSCP e nessuna disattivazione di servizi o catene di terze parti.

# IPTM 5.20.25 — Aggiornamento versione Build 2

- Incremento versione da 5.20.22 (Build 2) a 5.20.25 per aggiornamento web nativo.
- Aggiornati loader, helper, riferimenti release, identificatori build e cache degli asset.
- Nessuna modifica funzionale a firewall, DNS, servizi e interfaccia.

## IPTM 5.20.22 — UI chiara e navigazione senza sfondi blu

- Build `20261122.2.iptm-5.20.22` (stessa versione 5.20.22): include le correzioni elencate di seguito.
- Corretto un conflitto fatale con l'estensione PHP pgsql: la pagina Aggiornamenti usava la funzione `pg_update()`, omonima di una funzione di PHP; ora è `iptm_page_update()`.
- Il pulsante «Copia dati CSV» dei grafici ora funziona: `charts.js` viene caricato e incluso nell'elenco degli asset consentiti.
- Rimosso un `;;` residuo nel renderer; rimossi import e variabili inutilizzati nei moduli Python e due chiamate `tc filter show` eseguite a vuoto in `qos_engine.py`.
- Rimossi dalla release i CSS sorgente `styles.css`, `networkui.css` e `console.css` (già contenuti in `app.css`, circa 187 KB in meno).
- Corretto il selettore `nav` generico che applicava uno sfondo blu ai sei collegamenti della dashboard. Sfondo neutro e schede separate, con colori leggibili nei temi chiaro/scuro.
- Semplificati i sei accessi principali: Interfacce, Zone, DNS, Accessi, Firewall e Applica. Conservate tutte le rotte e le azioni.
- Rimossa la seconda navigazione ridondante nella pagina Stato; accessi essenziali all'inizio della dashboard.
- Accorciate etichette, riepiloghi e descrizioni ripetitive. Protezioni e messaggi essenziali (rollback, mancanza regole e provenienza aggiornamenti) restano visibili.
- Nessuna modifica a iptables, DNS, servizi, ruoli, moduli di gestione, CSRF, controllo di versione e rollback.

# IPTM 5.20.21 — Ottimizzazione delle risorse UI e diagnostica

- CSS precompilato nel pacchetto in `assets/app.css`, rispettando l'ordine della cascata esistente; nessuna lettura CSS o concatenazione ad ogni richiesta PHP.
- Risorse browser servite da un endpoint in sola lettura del loader, con allowlist fissa, limiti di dimensione, MIME, `nosniff`, ETag e cache immutable legata alla versione. Sessione/login, POST, azioni root e protezioni firewall non vengono invocati dagli asset.
- Tutti gli JavaScript caricati da file riutilizzabili invece di essere rispediti come stringhe dentro ogni HTML; ordine di esecuzione e MODEL/FH delle pagine regole invariati.
- La diagnostica ispirata a IPTM6 usa un'unica acquisizione `iptables-save -t filter` per CrowdSec/Suricata e riduce le chiamate `systemctl` a una interrogazione multiunità con fallback.
- Eliminata l'osservazione della pagina per la topologia su tutte le altre sezioni; scansioni accessibilità deduplicate durante gli aggiornamenti DOM asincroni.
- Nessuna modifica automatica a DNS, NAT, regole attive, servizi, watchdog, kernel o impostazioni persistenti. Resta la pulizia conservativa già presente nell'aggiornamento nativo.
- Verificati generazione e hash manifest, completezza delle risorse, PHP/Python/Bash/JS, rendering HTML equivalente e risposte dell'endpoint asset.

# IPTM 5.20.20 — Integrazioni mirate da IPTM 6.11.3

- Portate nella release 5.20.20 le verifiche conservative della versione 6.11.3 per la salute locale di CrowdSec (bouncer e riferimenti iptables), Suricata (rilevazione NFQUEUE e fonti), DNS Pi-hole/Unbound, stato IPv6, watchdog e transazioni.
- Nuovo pannello «Integrità di rete e servizi» in Salute sistema: un solo clic, nessuna conferma, nessuna prova automatica che rallenti la navigazione.
- Le verifiche non certificano l'enforcement IPS o la raggiungibilità da altri client: niente falsi positivi che dichiarino la rete sicura senza traffico reale.
- Backend di sola lettura con comandi statici in allowlist, timeout brevi e nessuna esposizione di log grezzi o segreti.
- Evitata la sostituzione dei moduli più avanzati IPTM 5.20 con implementazioni più limitate della 6.11.3 (la gestione delle liste Pi-hole e WireGuard rimane quella corrente).
- Aggiornamento web nativo con validazione manifest SHA-256; nessuna interruzione di servizi, regole o DNS durante il passaggio di versione.

# IPTM 5.20.20 — NAT Single-NIC: avviso corretto, regole più sicure

- Corretto il falso allarme «NAT Single-NIC: interfacce masquerade limitate alle subnet LAN»: è il comportamento sicuro previsto, non una condizione di errore. Non compare più negli avvisi rossi.
- In Rete → WAN, LAN e NAT, stato chiaro e accessibile: subnet sorgenti, interfacce di uscita ed esclusione destinazioni LAN; comparsa soltanto quando NAT Single-NIC è attivo.
- Descrizione interfacce NAT corretta: non genera mai masquerade incondizionato.
- Per WAN e LAN separate è stata eliminata la fallback `0.0.0.0/0`: NAT esclusivamente per sorgenti LAN esplicite, come il validatore di IPTM 6.11.3.
- Preflight Single-NIC contro regole MASQUERADE globali esteso a tutte le interfacce di uscita NAT selezionate.
- Nessuna catena/salto NAT inutili quando manca un’interfaccia di uscita.
- Non cambia il firewall live durante l'aggiornamento; preflight e rollback del sistema restano disponibili.

# IPTM 5.20.20 — Controlli rapidi e selezioni persistenti (22 novembre 2026)

- Tolte le richieste di digitazione di parole di conferma e le attestazioni «possiedo accesso SSH/console» dai moduli e dalle azioni HTTP.
- Pulsanti diretti per attivare, disattivare, installare e riparare componenti, senza finestre `confirm()` ripetute.
- DNSCrypt applicabile direttamente: validazione DNS e dei certificati, backup, test di raggiungibilità e watchdog rimangono nel gestore root; il controllo in anteprima è facoltativo.
- Ripristino configurazione DNS dal file in un clic (contenuti, checksum e passphrase obbligatoria se cifrato sono verificati prima della scrittura).
- Salvataggio locale dei multi-selettori (Pi-hole, sorgenti Anti-DPI, IoT e altre liste) durante la navigazione. Nessuna credenziale, token, valore di password o segreto è memorizzato dal componente di persistenza. Le impostazioni già salvate nel backend restano autoritative.
- Operazioni con conseguenze sulla rete mantengono verifiche effettive (CSRF, ruolo admin, test kernel/sintassi, snapshot, timer watchdog, fallback), senza challenge testuali.
- Stage Pi-hole oltre dieci adlist automaticamente sicuro: nuove liste disabilitate senza eseguire Gravity.
- Conservata l'opzione di annullamento per le modifiche con rollback e di verifica facoltativa su richiesta.

# IPTM 5.20.20 — Network UI Accessibile (22 novembre 2026)

- Restyling completo della console per tutte le pagine esistenti: sidebar e superfici uniformi, pannelli, moduli, tabelle, pulsanti, badge, barra globale e layout mobile. Ispirazione all'organizzazione funzionale del pacchetto IPTM 6.11.3 fornito e alle convenzioni di accessibilità di Bootstrap Italia; nessuna risorsa CDN.
- Navigazione rapida mobile per sei aree della rete, icone SVG inline, ricerca funzioni con supporto ARIA e scorciatoia per applicare modifiche in attesa.
- Aree interattive con target 44 px, focus visibile, colori ad alto contrasto, tabelle scorrevoli, intestazioni di regione, campi etichettati anche ove mancanti, collegamento agli aiuti, avvisi per lettori di schermo, navigazione laterale mobile con focus contenuto, rispetto reduced motion.
- Uniformazione visiva delle operazioni di modifica, delle azioni secondarie e distruttive senza cambiare endpoint, nomi di POST, validazioni backend o meccanismi anti-lockout.
- Aggiornati versioni, riferimenti assoluti, helper e manifest Native Update. Nessuna attivazione automatica di opzioni firewall o servizi di rete durante l'aggiornamento UI.

# IPTM 5.20.16 – Nuova console Network Control (22 novembre 2026)

- Interfaccia ridisegnata con una struttura unica: barra superiore, ricerca rapida,
  barra laterale per flusso di rete, pagine riconoscibili, componenti e controlli omogenei.
- Navigazione che segue connessione → rete locale → DNS → protezione → manutenzione;
  funzioni principali in primo piano e tutte le altre disponibili dalla stessa sidebar.
- Dashboard con percorso rapido verso le quattro aree operative, senza introdurre pagine
  riepilogative prive di azioni. Indice della pagina a scomparsa per form molto lunghi.
- Ricerca globale da tastiera Ctrl+K o Cmd+K, con filtro e accesso alle destinazioni
  già autorizzate. Ricerca/sidebar operano solo su pagine e non invocano azioni root.
- Nuovo stile responsive mobile/tablet, tema chiaro/scuro, tabelle scorrevoli,
  gerarchia dei contenuti e controlli consistenti, focus e navigazione da tastiera.
- Integrazione senza CDN: CSS e JS locali contenuti nel pacchetto, layout login
  allineato al design system. Restano immutati POST, nomi action, CSRF, funzioni backend.
- Aggiornamento web nativo con manifest SHA-256; uniformati loader, helper,
  runtime e estensioni alla 5.20.16. Nessun riavvio servizi aggiuntivo richiesto dalla UI.
- Restano le salvaguardie di Apply/watchdog per le modifiche firewall che possono
  interrompere l'accesso. Non sono generate nuove anteprime o richieste di conferma UI.

## 5.20.15 — Network-first UI e ritiro servizi non più supportati

- Sidebar ordinata secondo il traffico: stato → WAN/interfacce → LAN/dispositivi → DNS → firewall → gestione. Le rotte e le azioni esistenti restano funzionanti.
- Navigazione compatta: sei gruppi, sole funzioni frequenti subito visibili, un singolo selettore per tutte le opzioni avanzate e ricerca su tutte le voci.
- Dashboard: azioni ordinate per flusso di rete invece della vecchia lista eterogenea di scorciatoie.
- Opzioni booleane: interruttore diretto Attivo/Disattivo in luogo di coppie di radio button. Salvataggio impostazioni: azione primaria «Salva e applica» con anti-lockout, azione secondaria «Salva per dopo». Rimossa una conferma JavaScript ridondante; rimane la conferma del watchdog per i cambi firewall realmente rischiosi.
- Aggiornamento da ZIP: rimosse conferme browser duplicate; il validatore nativo, il journal e il ripristino restano obbligatori.
- Pulizia automatica: rilevamento delle unità IPTM orfane (solo firmate, spente, disabilitate, senza riferimenti), snapshot root verificato, conversione attivatore IoT Warden disabilitato, elenco motivi residui e rimozione idempotente; servizi attivi e funzioni supportate sempre protetti.
- Conservati iptables-legacy come backend Linux e i servizi correnti di guardia, QoS, Anti-DPI, DNS e rete.

## 5.20.15 — Native-only / Cleanup transazionale

- Abolito aggiornamento web tramite ZIP monolitico a nove file: soltanto pacchetti nativi con manifest e verifiche SHA-256.
- Introdotta pulizia automatica dopo commit, con snapshot root:0700, inventario, doppia verifica, journal, preservazione servizi attivi.
- Ritirate unita QoS obsolete solo se ufficiali, inattive e disabilitate; archiviati backup di software superflui solo dopo 30 giorni (minimo tre copie recenti).
- Conservati iptables-legacy (backend reale, non codice obsoleto), impostazioni DNS e firewall live, qdisc e configurazioni personalizzate.
- Conservati tutti i servizi di rete attivi e le release ancora referenziate; gestione degli aggiornamenti anche con iptm-guard e anti-DPI abilitati.
- Conversione sicura dell’attivatore IoT Warden disabilitato (POST_SCRIPT) in valore vuoto, con snapshot dell’intero file; non viene rimossa alcuna regola o script IoT attivo.
- Rapporto della pulizia consultabile nella pagina Aggiornamenti.

## 5.20.15 RC — correzioni generatore regole e scansione URL
- Generatore: l'inserimento «dopo l'ultima regola» di una catena che termina con un blocco IPTM avanza oltre il marcatore di chiusura. Prima il DROP finale poteva finire davanti a ESTABLISHED/loopback (SPI) e a lan-out, rendendoli irraggiungibili.
- VirusTotal: la validazione dell'URL usava `#` sia come delimitatore sia nella classe di caratteri e rifiutava ogni URL; ora delimitatore `~`.
- Generatore: l'inserimento «prima del catch-all finale» considerava catch-all anche un salto a catena utente (`-j IPTM-PS`, `-j IPTM-WAN-IN`); il DROP finale finiva davanti e oscurava il ban port-scan e il filtro WAN. Ora conta solo ACCEPT/DROP/REJECT.
- Validazione: `chain` rifiuta nomi che iniziano con «-» o coincidono con target/catene built-in (DROP, ACCEPT, LOG, INPUT…); `port`/`ports` rifiutano zeri iniziali (`080`), intervalli con estremi uguali (`80:80`) e più di 15 porte (un intervallo vale 2). `mgmt_ports` viene normalizzato e limitato così da restare entro 15 con le 5 porte obbligatorie. Prima iptables-restore rifiutava l'intero ruleset.
- IPv6: la validazione di `lan_prefix` accettava valori non indirizzi (`1`, `fe80:::/10`, maschera `/129` o `/999`) che facevano fallire ip6tables-restore all'Apply; ora indirizzo IPv6 valido e maschera 0-128 (`v6_prefixes_ok`).
- nm_control: percorso di release obsoleto (5.18.0) allineato alla release corrente; la costante non era usata.
- Verifica offline (PHP 8.3, iptables-restore --test); non equivale a collaudo su gateway.

- 5.20.12 RC: istruzioni operative CAKE nella pagina diagnostica; guard non interferisce con Apply pendente; preflight restore; dedup locale solo IPTM.
## 5.20.12 RC — NAT per subnet e blocco masquerade globale Single-NIC
- Regole NAT in modalita Single-NIC sempre limitate alle subnet LAN, anche con masq_ifs.
- Preflight blocca masquerade globale -o WAN in Single-NIC; nessuna modifica live automatica.
- Preservati set/regole esterne Docker, CrowdSec e WireGuard.

## 5.20.9 RC — controllo LAN→WAN prima di Apply

Preflight multi-subnet sulle regole proposte: verifica FORWARD NEW e ritorno ESTABLISHED, anche con regole manuali e senza lan_out_fwd. In caso di blocco simulato con final_drop, Apply viene rifiutato anche con Forza. NAT e ip_forward sono segnalati; nessuna modifica automatica. Test offline non equivalgono a collaudo su gateway.

## 5.20.7 RC — audit di correlazione e hardening non distruttivo
- Timeout esplicito di 8 secondi per il controllo dello stato systemd prima di modifiche Unbound e DNSCrypt; processi con stdin/stdout/stderr isolati.
- Eseguiti controlli strutturali e suite offline; le criticità Apply/rollback e networking client restano aperte e richiedono verifica su gateway.
- Nessuna rimozione automatica di legacy, configurazioni, timer o regole.

IPTM 5.20.5: hardening Apply: backup configurazione legacy verificato prima della migrazione, timeout snapshot separato, hook post-Apply limitato e controllato, segnalazione esplicita che i test gateway non verificano i client. Nessun cambio automatico a NAT o DNS.
IPTM 5.20.7: correzione multi-subnet generator (NAT, anti-lockout, limiti, loopback e ACL). Nessuna modifica automatica al firewall live.
## 5.18.0
- Rinnovato il selettore Priorità applicative DSCP IPv4: checkbox consistenti, righe cliccabili, gruppi e selezione rapida.
- Catalogo aumentato a 27 preset opzionali (Teams/Zoom, RDP, VoIP, gaming, IoT, backup), classificazione per porta con avvisi sui limiti.
- Selezione ricordata nella sessione dopo una corretta anteprima; applicazione QoS invariata e protetta.

## 5.18.0 — DSCP direzionale e migrazione QoS post-commit

- Profili DSCP IPv4 upload e download separati e consigliati opt-in.
- Verifica dell'installazione senza intervento su watchdog/qdisc, con handoff di proprietà dopo commit.
- Journal di migrazione e recupero protetto per systemd e stato QoS.

# IPTM 5.16.0 — ripartenza verificabile dalla 5.13.1

- Il verificatore nativo del modulo è separato dal post-install: il watchdog viene riconciliato attraverso `postinstall.py ensure`, con diagnostica leggibile.
- Preflight delle transazioni di rete prima dell’aggiornamento; rifiuto di modifiche su profili CAKE posseduti da altre release.
- Calibrazione Ookla oraria, avviabile dal pannello, con risultati download e upload valutati indipendentemente, conservazione dei migliori limiti affidabili, job ID e serializzazione del commit.
- Legacy systemd: inventario, verifica firme, conferma hash, archiviazione recuperabile. Non rimuove servizi attivi o personalizzati.
- Aggiornamento di tutte le dipendenze runtime alla release selezionata.

La calibrazione eseguita con CAKE attivo è diagnostica e **non** aggiorna automaticamente il massimo di banda fisica. La regolazione RTT può variare i limiti operativi entro il profilo già confermato.

IPTM 5.13.1: stabilizzazione Ookla, NM e cleanup release protetto.

## 5.13.0 — Classificazione DSCP in ingresso prima di IFB

- Filtri flower IPv4 per le porte dei servizi remoti con pedit DSCP, preservazione ECN, checksum e redirect verso IFB.
- Verifica delle priorità dei filtri e arresto sicuro per topologie inattese.
- Applicazione subordinata alla proprietà verificata della policy DSCP IPTM.

## 5.13.0
- Persistenza sicura classificatore QoS IPv4 in uscita dopo reboot con servizio systemd e rifiuto del conflitto firewall.

## 5.8.1 — diagnostica CAKE/IFB e calibrazione indipendente
- Rilevamento esplicito delle qdisc preesistenti senza takeover.
- Misurazione con due prove Ookla, proposta conservativa, nessun apply automatico.
- Interfaccia QoS aggiornata e watchdog protetto fra versioni.

# 5.5.0 — unified kernel topology inspector and guarded integration readiness

- New fail-closed CAKE/IFB inspector derives the IFB target from live tc JSON, no name assumption.
- CGI read-only inventory and CrowdSec/Suricata/NetworkManager integrations remain protected.
- No live network mutation by the new kernel inspector. Existing transactional operations preserved pending field validation.

## 5.4.8 - osservabilita e controlli integrazioni

- Inventario operativo JSON via helper con nmcli, cscli, suricata-update, EveBox.
- CLI CrowdSec feed da file locale root-owned con staging e conferma SHA-256 in console root; nessun import automatico web.
- Normalizzazione/deduplicazione IPv4/IPv6 e blocco reti private, riservate e intervalli protetti.
- Diagnostica CAKE riparata: tc JSON root=true e parent=root compatibili.
- Nessuna eliminazione qdisc e nessun cambiamento NetworkManager/Suricata automatico.
- Sicurezza: formato native <=95 membri; installazioni via updater preesistente.

## 5.4.7 - integrazioni diagnostiche e SQM v2 (preview)\n\n- Inventory JSON in sola lettura CAKE, ingress, IFB e redirect.\n- Controllo locale tool CrowdSec, Suricata, EveBox, NetworkManager.\n- Preparazione feed CIDR IP pubblici con esclusione delle reti protette (solo sorgente CLI, non esposta alla web).\n- Nessuna rimozione automatica di qdisc o attivazione di GUI esterne.\n\n## 5.4.5
- Comandi NetworkManager tipizzati `nm-config`, limitati a NIC secondarie indipendenti e profili inattivi.
- Nessuna attivazione automatica del DHCP o modifica dei limiti CAKE.

## 5.4.4 - 20 novembre 2026
- Ripristino firewall da console, descrizioni delle opzioni semplificate e interfaccia Pi-hole vincolabile tramite API con watchdog.
- Nessuna modifica automatica di interfacce, DNS, DHCP o CAKE durante l’aggiornamento.

## 5.4.3 — Interfacce NetworkManager e separazione DHCP (20 novembre 2026)

- Rilevata impostazione `dns.interface` di Pi-hole v6: non confondere la porta WAN con il master DHCP e segnalare esplicitamente il rischio dell'auto-rilevamento.
- Inventario e azioni limitate ad Ethernet fisiche di riserva: `nmcli device up/down` protetto dalla route predefinita, slave del bond, indirizzo sorgente del client web e da Pi-hole.
- Preparazione persistente di un profilo statico NetworkManager secondario non-autoconnect, senza attivare la scheda, route, DNS o DHCP.
- NIC down selezionabili per progettare il secondo pool; attivazione runtime DHCP vietata finché Pi-hole non è vincolato al master dichiarato e non è disponibile il link.
- Preflight DHCP controlla lo scope di UDP 67 (FTL sul master, nessuna seconda istanza su eth1).
- Pagina semplificata NetworkManager-first; funzioni avanzate conservate in una sezione separata, non eliminate dal backend.
- CAKE: nessuna riparazione automatica, conserva `sqm-status` e le protezioni di 4.3.8/5.4.2.

## 5.4.3 — Mappa di rete logica e diagnosi CAKE osservazionale (20 novembre 2026)

- Vista della topologia rinnovata con gerarchia WAN → gateway → zone, icone SVG, gruppi dispositivi ordinati, ricerca, zoom, accessibilità e dettaglio; la mappa non pretende di conoscere cablaggio o L2.
- Su mobile, zone in schede compatte, con collegamento al dettaglio e senza overflow della pagina.
- Status CAKE: distingue profilo salvato e banda realmente attiva nella qdisc, segnala IFB/redirect non verificati; nessuna modifica automatica.
- Salvaguardati wizard DHCP, bozza IoT, gestione interfacce e contratti di aggiornamento dalla 4.3.8.

## 5.4.3 — Network UI unificata e QoS osservazionale (20 novembre 2026)

- Wizard unico per DHCP, NIC, bonding, bridge, VLAN, zone e switch, con precompilazione delle interfacce e dei CIDR esistenti.
- Lettura locale in sola lettura dei parametri DHCP di Pi-hole FTL v6, con origine dei dati e distinzione fra TOML e runtime; nessuna API PATCH automatica.
- NetworkManager riconosciuto correttamente; bond e bridge con IP utilizzabili nelle bozze senza convertire le porte slave in LAN separate.
- Misura Ookla separata da CAKE: speedtest osservazionale asincrono non esegue modifiche tc/IFB; calibrazione completa richiede ancora preflight verificato.
- Tabelle Connessioni con intestazioni ripristinate e pulsanti Chiudi leggibili; allineamenti Zone di rete e mappa responsive.
- Nuovi test di integrazione per binding backend, profilo bond esistente e whitelist helper.

# 5.4.0 — UX rete, wizard DHCP e diagnostica CAKE

- Header fisso, tabelle compatte e pannelli tecnici progressivi.
- Wizard DHCP con primaria bond/bridge e secondaria valida solo se pronta.
- Classificazione IoT gestita esclusivamente dalla pagina Dispositivi.
- Diagnostica Ookla con controllo read-only e report registri mancanti.
- Test ipset in namespace classificato come dipendenza non verificata.

## 5.4.0 — Interfaccia unificata e contratti dei flussi (2026-11-20)

- Revisione della navigazione PHP: una sola mappa di 58 pagine, 7 gruppi coerenti,
  funzioni frequenti subito accessibili e strumenti avanzati raggiungibili dalla ricerca.
- Ricerca con sinonimi tecnici (CAKE, SQM, Anti-DPI, VLAN, bonding, DHCP), scorciatoia /,
  messaggi accessibili, ripristino dell'espansione dei menu dopo il filtro.
- Nuova gerarchia visiva per schede, moduli e azioni, layout responsivo per mobile,
  tabelle con scorrimento dedicato e ricerca solo sulle tabelle di sola lettura.
- Verifica automatizzata del mapping di 58 pagine e 201 azioni POST, con controlli di
  duplicati, sintassi PHP/JS, permessi di aggiornamento e compatibilità monointerfaccia.
- Conservati gli endpoint, gli action name, i percorsi URL e SETTINGS_SCHEMA=42.
  Nessuna operazione su IP, NetworkManager, DHCP, routing, CAKE, NAT, iptables o Pi-hole
  viene eseguita durante l'installazione o dal solo livello UI.
- I motori di rete privilegiati sono mantenuti per retrocompatibilità: il presente
  pacchetto NON è una riscrittura completa da zero del loro funzionamento.

## 5.2.0 — Network Fabric local-only, DHCP bond, CAKE WAN egress multi-interface (2026-11-20)

- Rimosso il registro degli adattatori per router esterni: sole funzionalità Linux locali.
- Pi-hole DHCP primario su master bond/bridge riconosciuto; porta API locale esplicita e controllo della portante fisica del DHCP secondario.
- CAKE egress su 2–4 uplink in un unico trial transazionale protetto e rollback per NIC.
- Nessuna riconfigurazione della rete durante l’aggiornamento.
- Collaudo fisico del failover e del DHCP duale ancora richiesto.

## 5.1.1 — Sidebar e audit topologia (2026-11-20)
- Una icona per gruppo menu (rimossa duplicazione CSS).
- Rilevamento read-only bond ridondanza assente, portante NIC fisica non disponibile e IPv4 multi-subnet su bond.
- Nessuna modifica alle impostazioni di rete durante aggiornamento.

# IPTM release log

## 5.1.1 — Sicurezza rollback NIC, verifica DHCP e CAKE uplink controllato
- Il rollback di bridge/bond verifica ifindex, MAC, master e marker IPTM prima di scollegare una porta slave; un cambiamento esterno viene segnalato, non sovrascritto.
- Verifica live dei binding UDP/67 e dei servizi DHCP prima di creare un secondo dnsmasq: binding wildcard, servizi concorrenti o listener non attribuibile a Pi-hole causano un rifiuto esplicito.
- Nuovo `net-safety` per verifiche di ownership NIC (NetworkManager, networkd, ifupdown) e DHCP, senza modifiche di sistema.
- Nuovo trial `sqm-uplink` per CAKE **solo upload/egress** su un link con qdisc di default compatibile: root/TTY, timer e rollback, nessuna autocalibrazione sotto shaping.
- Aggiornamento Native/Bridge invariato: installa codice e strumenti, **non** cambia rete, route, DHCP, SQM o gestore in fase d'upgrade.
- Non coperto: migrazione automatica tra gestori, ingress IFB, firmware router commerciali, collaudo su DietPi reale.

## 5.0.1 — Protezione selettore WAN, Pi-hole API e recovery tra versioni
- Nuovi selettori a doppio buffer `IPTM5_PICK_A` / `IPTM5_PICK_B`; la catena di selezione attiva non viene svuotata durante il failover.
- Sostituzione atomica del salto iptables, fallimento sicuro quando la catena è alterata e regressioni per errori a metà aggiornamento.
- Client API Pi-hole locale non segue redirect, evitando di divulgare SID; risposta HTTP 204 per PATCH supportata.
- Recovery: un worker nuovo rifiuta di adottare journal attivi di versioni precedenti senza migrazione esplicita.
- Aggiornamento Native/Legacy non modifica automaticamente route, interfacce, DHCP o gestori di rete.
- Validator aggiornati a 128 membri con limite complessivo di estrazione per evitare il blocco delle release successive.
- Collaudo offline: nessuna garanzia sul traffico reale senza test di sistema ed accesso console.


## 5.0.0 — Motore transazionale Network Fabric
- Esecutore root-only per operazioni additive di VLAN, bridge e bonding su porte libere, alias IPv4, segmentazione iptables e masquerade, nonché routing WAN con tabelle dedicate.
- API Pi-hole v6 autenticata sulla loopback e istanza dnsmasq DHCP secondaria con controllo di subnet e coesistenza, senza accesso web privilegiato diretto.
- Journal fsync root-only, systemd timer 180 secondi armato prima delle modifiche e rollback per singola risorsa.
- Rifiuto di route predefinita sostituita, NIC di gestione asservita a bridge/bond, conflitti di IP, regole o tabelle già occupate.
- Recupero al boot per configurazioni confermate e suite di regressione con kernel/systemd simulati.
- Nessuna migrazione dei gestori di rete durante l’aggiornamento web; le funzioni live richiedono conferma via console root.


## 4.9.0 — Trial protetto di IPv4 aggiuntivo su scheda spare
- Motore `network_alias_trial.py` root/TTY-only, non richiamabile da HTTP, con macchina a stati e blocco interprocesso.
- Solo indirizzo privato IPv4 /32 su NIC fisica spare inutilizzata: niente cambi su WAN, route, interfacce, iptables, Pi-hole, DNS, DHCP o CAKE.
- Watchdog systemd 120 secondi armato **prima** del comando ip; conferma con token e rollback su scadenza. Recupero stato al riavvio, alias non persistente.
- Rifiuto di IP duplicati, route sovrapposte, NIC down, master bridge/bond, link fisici non verificati e vecchi trial pendenti.
- Contratto Native/Bridge e modalità monointerfaccia invariati; nuovo pannello informativo e test con kernel finto.
- Non comprende ancora secondario DHCP, migrazioni network manager o policy routing live.

## 4.8.0 — Guard di rete, backup sicuro e integrità dei watchdog
- Nuovo `network-guard preflight`: diagnostica coordinata dei gestori, dei domini DHCP e della migrazione monointerfaccia/multi-NIC, senza modifiche di rete.
- Nuovo `network-guard snapshot` / `verify ID`: copie root-only (0700/0600) dei file di rete rilevati, con hash, verifica drift e nessun ripristino automatico dei file sensibili.
- DHCP doppio: blocco esplicito dei casi con isolamento Layer 2 o binding UDP 67 non comprovato; il payload Pi-hole v6 resta anteprima.
- Risolto il riferimento erroneo del watchdog VLAN alla release 4.6.0; test che vincola la versione del modulo runtime a quella costruita.
- Pannello Network Fabric: preflight su richiesta dell'amministratore, accessibile con singola NIC, senza applicazione live.
- Invariato il contratto di installazione Native/Bridge: nessun backend di rete, indirizzo, route o server DHCP viene cambiato dall'updater.


## 4.7.1 — Compatibilità upgrade web e modalità monointerfaccia
- Installer Native e Bridge mantenuti: versioni modulari e versioni pre-Dual LAN possono aggiornarsi senza creare NIC, DHCP o route.
- Downloader HTTP(S): fino a tre redirect verificati uno per volta, con pin DNS a ogni hop e divieto di downgrade HTTPS→HTTP.
- HTTP non è una firma software: preferire HTTPS e verificare SHA-256 del produttore.
- Network Fabric supporta inventario e bozza di una sola NIC, con strategia WAN singola e dual DHCP non esposto.
- Nessun cambiamento automatico di Pi-hole, bonding, routing, NetworkManager, firewall o CAKE durante upgrade.
- Regressioni: controllo dei pacchetti tramite validator nativo e legacy, test su NIC unica e redirect sospetti.

## 4.7.0 — Network Audit, doppio DHCP e IPv4 aggiuntivi (fase di preflight)
- Rilevamento dei file di rete e delle dipendenze per scheda, senza esportare credenziali.
- Verifica conflitti DHCP, gestori concorrenti e semantica Pi-hole v6; validatore della configurazione del secondo dnsmasq (solo anteprima).
- Schema e anteprima PATCH Pi-hole v6 ristretto ai campi DHCP, senza mutazioni da HTTP.
- Indirizzo IPv4 aggiuntivo sulle NIC, con controllo alias duplicati, subnet e master bond/bridge.
- Anteprima doppio DHCP nella pagina Network Fabric e rilevamento pacchetti installati / bridge / bond.
- Registry di capability router FRITZ!Box (TR-064), Huawei, ZTE e generic; nessuna modifica remota non autorizzata.
- Inventario e piano di migrazione da console, senza riconfigurazione automatica del sistema produttivo.

## 4.6.0 — Network Fabric: prova VLAN transazionale
- Motore `fabric-runtime` root-console-only per prova di nuove interfacce VLAN Layer 2, con firme SHA-256 delle bozze e token univoci.
- Watchdog systemd a 120 secondi, rollback su scadenza, protezione al riavvio e verifica dell'alias prima di rimuovere interfacce.
- Nessuna modifica a route predefinita, iptables, conntrack, DNS, DHCP, CAKE, proprietario di interfaccia o porte fisiche.
- Rifiuto esplicito di bonding/bridge di porte attive, configurazione di switch esterni e VLAN con indirizzi IP o WAN: non ancora applicabili dal runtime.
- Aggiornati modulo CLI, helper e pagina Network Fabric; niente operazioni di attivazione da web.

# IPTM 4.5.0 — Network Fabric unificato, dismissione Multi-WAN legacy

- Unica pagina **Rete → Gestione multi-NIC** per i ruoli fisici, le VLAN 802.1Q, i bridge Linux con STP/VLAN filtering, bond active-backup/LACP, zone, policy e inventario delle porte switch.
- Planner routing multi-uplink (singola WAN, failover, bilanciamento per flusso) con tabelle per interfaccia, pesi e note su simmetria SNAT/conntrack; **nessuna attivazione in questa fase**.
- Interfacce DietPi e NetworkManager rimangono di sola lettura, salvo la bozza persistente root-only. Nessun servizio di rete o pacchetto viene installato/disinstallato automaticamente.
- Rimosse pagina, azione POST e gestore attivo del vecchio Multi-WAN. I comandi storici `wanfo-run` e `wanfo-set` sono stub compatibili innocui; `wanfo-run` non altera più route e conntrack.
- Disabilitazione esplicita del vecchio timer `sudo iptm-helper multi-nic legacy-retire` da console root indipendente; conservazione di `wanfo.conf` per possibile audit/recupero.
- Validazione anti-loop, porte univoche, subnet sovrapposte, LACP con conferma, native VLAN/access/trunk coerenti, policy default deny, input bounded e autorizzazione admin già esistente.
- Test aggiuntivi di fabric, routing e migrazione; preservati Anti-DPI, DNS, firewall iptables, CAKE e altri servizi.

**Limite di sicurezza:** IPTM 4.5.0 crea una topologia *progettata*, non rende le VLAN/zone operative nel kernel; non promette isolamento, failover, QoS o migrazione dei gestori prima di un applicatore transazionale testato su DietPi reale.

# IPTM 4.4.0 — Piani multi-NIC DietPi / NetworkManager (fase non distruttiva)

- Inventario schede fisiche/logiche, IPv4, link, contatori RX/TX, default route e gestori attivi.
- Pannello Rete → Gestione multi-NIC: ruoli WAN/LAN/IoT/ospiti/gestione/VPN-underlay, priorità, DHCP, capacità; anteprima e bozza persistente root-only.
- Backend desiderato DietPi nativo o NetworkManager; guida alla migrazione, comandi di anteprima non eseguiti e analisi conflitti/overlap.
- Strategie WAN primaria, failover, bilanciamento per flusso (solo piano); pesi condizionati dalla banda nominale, senza variazioni al routing live.
- Nessuna installazione/disinstallazione di gestori, nessuna disconnessione di NIC, nessuna regola firewall/NAT/CAKE applicata dal nuovo pannello. L'attivazione multi-NIC è subordinata a rollback/console testati sul dispositivo reale.
- Legacy Multi-WAN e funzioni esistenti lasciati invariati; regression tests estesi.

# IPTM 4.3.8 — Fix validazione profilo per raccolte Anti-DPI Zapret2

- Ripristinata l’interfaccia `zapret2_manager.validate(payload)` richiesta da `antidpi_sources.request_start`: delega alla validazione rigorosa `zapret_manager.validate`, già usata da Zapret2 in `configure()` e `config_read()`.
- Test reali (senza mock di `validate`) sul contratto dei due motori e sull’avvio dell’importazione locale. Nessuna regola o servizio attivato automaticamente.
- Build e manifest aggiornati, release 4.3.7 conservata nella cronologia.

# IPTM 4.3.7 — Manutenzione e allineamento release

- Wizard DNS/TLS limitato a topologia e profili DNS: rimossi i controlli Anti-DPI JS irraggiungibili, i campi retry Anti-DPI, il salvataggio obsoleto e il relativo dispatcher. Le azioni Anti-DPI operative restano nel pannello unico `#dns-zapret-manager`.
- Aggiornati test DNS-only e regressioni del percorso Anti-DPI autonomo; i vecchi POST `dns_wizard_save_antidpi` non salvano più profili.
- Allineati APP_BUILD e helper al build `20261119.iptm-4.3.7`; versione helper 4.3.7. Docstring retention e import Python non utilizzati puliti.
- Completato CHANGELOG con 4.3.5 e 4.3.3; rigenerati manifest JSON e SHA-256 ZIP nativo/bridge dalla sorgente.
- Nessuna attivazione automatica di iptables, DNS, NFQUEUE, CAKE, servizi o profili Anti-DPI.

# IPTM 4.3.6 — Ripristino download raccolte Anti-DPI

- Fix: registrata l'azione POST `antidpi_sources` nel dispatcher modulare; in 4.3.5 era assente, causando un reindirizzamento HTML al posto della risposta JSON dopo il clic sul pulsante di download.
- Errori JSON per handler mancanti, eccezioni PHP, CSRF scaduto, account senza privilegi e sessione terminata (solo richieste asincrone Anti-DPI).
- Il browser distingue risposta HTML, HTTP 413, problemi di accesso e errori HTTP non JSON senza alterare la configurazione del firewall.
- Non sono modificati i flussi di prova, conferma NFQUEUE o persistenza; selezioni e domini rimangono nel wizard e vengono importati solo dopo la fine del job.

## [4.3.5] — Wizard Anti-DPI a download completati

- Raccolte selezionabili e servizi noti consolidati nel riquadro domini; la pagina viene aggiornata solo dopo la conclusione del download e dell'importazione.
- Job lato server con monitoraggio, recupero dopo ricarica, lettura a blocchi e deduplicazione; selezioni del catalogo ricordate localmente.
- Anteprima, salvataggio e attivazione restano passaggi separati, con limiti di byte per prevenire esaurimento risorse.

## [4.3.4] — Log rotation e backup retention

- Pagina **Sistema → Rotazione e spazio**: stato, preferenze, anteprima, avvio job.
- Timer systemd giornaliero e archiviazione compressa dei log IPTM con logrotate.
- Pulizia conservativa dei backup automatici (firewall, DNS, aggiornamenti) e dei report completati.
- Protezione dei backup manuali, dei journal di ripristino, degli audit attivi e dei link simbolici.

## [4.3.3] — Raccolte Anti-DPI e selezione multipla

- Selezione multipla dei servizi noti e delle raccolte nel pannello Anti-DPI, con importazione in un'unica anteprima e opzioni conservate.
- Verifiche di coerenza della raccolta prima dell'applicazione, senza modificare automaticamente il traffico live.

# IPTM 4.3.2 — Aggiornamenti ZIP: errori espliciti

- Riconoscimento preventivo di kit completi, sorgenti e archivi contenenti ZIP annidati.
- Messaggi di errore espliciti in Aggiornamenti, senza rimuovere controlli SHA-256, CRC o manifest.
- Etichetta e guida caricamento chiarite: installabili soltanto Native Update o Legacy Bridge.
- Nessuna modifica alla configurazione di rete, DNS, CAKE, Anti-DPI o alle policy applicate.

## IPTM 4.3.1 — Unificazione importazione Anti-DPI

- Un solo importatore per cataloghi online, servizi noti e TXT/hosts, con anteprima e conferma.
- Fonti online che non rispondono non bloccano quelle valide; ogni fonte ha un esito.
- Stato dell’anteprima separato per motore e conferma indipendente dal token nella sessione browser.
- Nessuna applicazione NFQUEUE durante l’importazione; hostlist protetta.

## IPTM 4.3.0 — Anti-DPI persistente e hostlist multiple Italia/Europa
- Anti-DPI temporaneo invariato: prova 120 secondi, conferma. Aggiunta attivazione persistente su conferma separata con unità systemd esplicita e file d'intento root-only.
- Al riavvio profilo e hash controllati prima delle regole; watchdog indipendente e verifica locale dopo 20 secondi; fallimento => rimozione regole, disabilitazione del prossimo boot.
- Arresto esplicito disabilita anche la persistenza. La persistenza non viene attivata automaticamente dall'aggiornamento.
- Importazione multipla in background di URL da test Citizen Lab/OONI per Italia, Europa e globale, e archivio storico AGCOM 2024. Solo HTTPS e URL in allowlist; anteprima, deduplicazione e conferma prima del salvataggio.
- Le liste di test non rappresentano necessariamente siti bloccati. Anti-DPI non sostituisce VPN né aggira blocchi IP/DNS/geografici; non c'è attivazione automatica dell'hostlist importata.
- Nuovi test isolati su persistenza, hash del profilo, merge delle fonti, limiti e sicurezza dei file. Nessun intervento sui limiti CAKE, sui servizi DNS o sul firewall fuori dalla prova esplicitamente autorizzata.

## IPTM 4.2.0 — Motore grafico unificato
- Riscritti i quattro rendering SVG delle statistiche (barre, barre orizzontali, andamento, donut) su un unico core tipizzato con assi e scale condivisi, gestione di valori nulli/NaN, stili responsive e protezione dell'output HTML/SVG.
- Ogni grafico ha title/description accessibili, tooltip, tabella espandibile e copia CSV progressiva senza servizi esterni. Nessun nuovo accesso ai dati del gateway per disegnare i grafici.
- Riscritto il motore topologico JavaScript con modello di stato coerente, rilevamento avvisi O(N), zoom e navigazione tastiera, senza cambiare il salvataggio nella sola bozza IoT.
- Nessuna modifica a iptables, Pi-hole, Unbound, DNSCrypt, nftables, NFQUEUE, servizi, CAKE o utenti; il pacchetto nativo resta utilizzabile da 4.1.0.
- Versione candidata: le prove browser usano fixture e non certificano i dati del gateway reale.

## IPTM 4.1.0 — Mappa rete, NFQWS2, diagnostica FastCGI
- Hostlist nfqws2 runtime leggibile dopo il drop privilegi; configurazione riservata invariata.
- Mappa interattiva locale: dispositivi MAC/OUI, avvisi e salvataggio bozza IoT.
- Identificazione sottocomandi nei timeout FastCGI; timeout inventario MAC limitato.
- Tabelle e grafici uniformati. Nessuna policy live applicata durante l’aggiornamento.

# IPTM 4.0.0 — Major release: aggiornamenti riproducibili e integrità runtime

- Le estensioni Python chiamate dagli worker root sono tutte collegate alla release corrente, inclusi RethinkDNS e credenziali Pi-hole.
- L'updater nativo verifica la sintassi Python in memoria, senza generare `__pycache__` nella directory release immutabile.
- Rimossa una copia byte-identica di test legacy e aggiunti controlli automatici di igiene, integrità e percorsi di migrazione.
- Conservati: iptables prioritario, IPv6 disabilitabile, Pi-hole/Unbound/DNSCrypt, Anti-DPI opt-in con watchdog, CAKE solo Ookla, Lynis asincrono, rollback delle regole live.
- Nessuna regola viene applicata dall'aggiornamento. Le firme restano facoltative e HTTP resta disponibile, come richiesto.
- Release candidate: modifica dei privilegi sudoers e transazioni API Pi-hole end-to-end richiedono collaudo dedicato sul gateway.

# IPTM 3.9.139 — Anti-DPI: rilevamento, preflight diagnostico, UI unica e watchdog

# IPTM 3.9.138 — Diagnostica delle combinazioni e IPv6 non disponibile

- Copertura pairwise deterministica su tutti i 145 campi catalogati (41.760 assegnazioni astratte in 12 scenari) e 10 terne operative ad alto rischio (80 combinazioni di schema). Non esegue le combinazioni live.
- Validazione di dipendenze e possibili conflitti sulle impostazioni salvate; verifica incrociata opzionale di WAN, DNS redirect, IoT, CrowdSec e stato servizi.
- IPv6 deliberatamente disabilitato: bozza v6 saltata, senza false segnalazioni di fallimento; backend legacy con tabella filter indisponibile = non verificabile.
- Report espandibile dedicato alle combinazioni, integrato nel log unico e nella barra di avanzamento.
- Nessuna modifica a firewall, CAKE, DNS, servizi, aggiornamento HTTP, firme digitali o criteri di autorizzazione.
- Limite noto: combinazioni di schema e consistenza non dimostrano raggiungibilità o effettiva interoperabilità dei servizi sulla rete.

# IPTM 3.9.137 — Lynis audit completo e interattivo

- Worker Lynis streaming senza limite artificiale 600 s; singolo report per audit e consultazione dopo chiusura pagina.
- Raccomandazioni guidate, stato revisione persistente, stato audit JSON leggero e nessuna applicazione automatica.
- Rimangono i controlli di accesso root, la conferma esplicita delle modifiche sysctl e gli aggiornamenti HTTP consentiti.

# IPTM 3.9.136 — DNSCrypt compatibility, SNI IDS and guarded Anti-DPI

- New DNSCrypt configurations omit the unsupported `doh_check_cert_hashes_on_connect` option; explicit backed-up repair for previously generated config requires timed confirmation.
- Fix Zapret2 preview NameError; add separate privileged, bounded FORWARD-only NFQUEUE trial with 120-second systemd watchdog and explicit administrator confirmation.
- Add real Suricata TLS/SNI `alert` rules (no inline IPS blocking) validated and reloaded through the existing privileged helper.
- Make expensive DietPi and APT/systemd Health audits opt-in to avoid dashboard timeouts during Lynis.
- Align scheduled Ookla unit environment with manual invocation; never use failed measurements to reduce CAKE.
- No automatic firewall, DNS, NFQUEUE, QoS changes on installation.

# IPTM 3.9.135 — Diagnostica reale a livelli, sempre non distruttiva

- Tre livelli selezionabili: schema, preflight reale non distruttivo e controllo in namespace temporaneo ove supportato.
- Preflight del file draft.rules e draft6.rules tramite iptables-restore/ip6tables-restore --test (mai restore live), con avvisi espliciti e controllo del pending rollback.
- Inventario delle interfacce/route effettive (incluso bond0 quando presente), stato forwarding, listener DNS, relazione Pi-hole/Unbound/DNSCrypt dedotta in modo conservativo.
- Check sintattici unbound e DNSCrypt, controllo recupero DNS al boot incluso esito oneshot e avvio in questo boot. Inactive/dead non è un errore di per sé.
- Report con pass/warning/unknown/failed/skipped separati; percentuale di avanzamento, nessun finto rollback virtuale.
- Consenso esplicito richiesto per le prove su configurazioni di rete. Le verifiche isolate sono limitate al parser nel namespace, non dimostrano la connettività end-to-end.
- Nessun cambio a iptables, servizi, DNS, CAKE, speedtest o aggiornamenti HTTP. Niente firme digitali obbligatorie.

IPTM 3.9.134 — DNS/TLS wizard: explicit Anti-DPI opt-in, safe field validation and retry state.
# IPTM 3.9.133 — Misurazione QoS solo Ookla

- Rimosso da UI Programmi, coda installazione APT, log programmi, diagnostica, preflight e calibrazione qualsiasi motore alternativo di misura.
- L'unico motore speedtest attivo è l'eseguibile nativo Ookla (`speedtest`), con output JSON validato e misure complete di download/upload; script omonimi non sono accettati come equivalenti.
- Se la misurazione fallisce o il motore non è installato, i limiti CAKE restano invariati. I risultati storici di altri motori non sono riutilizzati per modifiche dei rate.
- Confermati guard/watchdog, ripristino dei limiti di prova, conferma manuale e test di latenza sotto carico.
- Nessuna rimozione automatica di pacchetti dal sistema operativo, nessuna modifica live del firewall o delle qdisc durante l'upgrade.

# IPTM 3.9.132 — Interfaccia DNS/TLS unificata e profilo a doppio livello

- Wizard DNS/TLS semplificato con 4 scelte, inclusa Pi-hole → Unbound → DNSCrypt.
- Proposta dipendente da attività, DNSSEC, test configurazione e listener; preserva il profilo attivo se già verificato.
- Anti-DPI facoltativo: le anteprime DNS non richiedono WAN, client o hostlist.
- Strumenti DNSCrypt, SNI e gestione Zapret riuniti in sezioni avanzate a espansione; nessun cambio live automatico.
- Anteprima con conferma separata e collegamento alla pagina esistente per applicare l’architettura DNS.
- Validazione del piano e test di regressione PHP senza accedere al firewall del sistema.

# IPTM 3.9.131 — Importazione domini noti Anti-DPI

- Catalogo locale opt-in per servizi noti (video, social, chat, gaming, lavoro, cloud) utilizzabile nel wizard e nel profilo Zapret2/classico. Nessun dominio è indicato come necessariamente bloccato dal DPI.
- Import TXT/hosts locale dal browser, anteprima con conteggio validi/duplicati/scartati, scelta unione o sostituzione; nessuna attivazione di NFQUEUE.
- Rimosso il tetto arbitrario di 100 domini dalla validazione PHP e dai backend Python; sostituito il controllo duplicati quadratico con un set.
- Limite di sicurezza in byte: 4 MiB per elenco, 8 MiB per payload root; non vi è un numero massimo predefinito di domini.
- Il riepilogo del wizard mostra il conteggio e un campione, senza caricare decine di migliaia di voci nel DOM.
- Restano invariati controlli di autenticazione, anteprima, separazione engine, e divieto di attivazione automatica delle regole di rete.
- Firme digitali e HTTPS per gli aggiornamenti non sono resi obbligatori, come richiesto.

## 4.3.3 — Anti-DPI: importazioni a fasi e selezioni persistenti
- Pulsanti indipendenti **Seleziona tutti / Deseleziona tutti** per servizi noti e raccolte online, con contatori.
- Persistenza locale delle selezioni checkbox e della modalità Unisci/Sostituisci, distinta per Zapret2 e Zapret classico (nessun invio delle preferenze a server esterni).
- Workflow esplicito **Scarica tutte le fonti → Crea anteprima → Conferma e salva**, con download in background e stato per origine.
- Un errore di rete viene mostrato per singola fonte; la modalità Sostituisci impedisce sempre una sostituzione parziale.
- Le configurazioni e le regole NFQUEUE/iptables non vengono toccate dall'importazione fino all'attivazione manuale già prevista.
