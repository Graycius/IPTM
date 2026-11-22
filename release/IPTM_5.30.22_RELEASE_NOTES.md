# IPTM 5.30.22 — note di pubblicazione

**Artefatto:** [IPTM_5.30.22_UPDATE.zip](IPTM_5.30.22_UPDATE.zip)

**SHA-256 archivio:** `4d266e113aa8cb5922b42e50cfb3a9dd010ef854b9c6a2de336aef18bb6ca305`

**Provenienza:** pacchetto Native Update 5.30.22 fornito dall'utente; pubblicato senza modificare alcuno dei 115 payload verificati nel relativo manifest. I test e la documentazione di GitHub sono mantenuti separati dall'archivio binario.

## Novità rispetto alla 5.30.12

- Miglioramenti del controllo regole iptables e della gestione delle sezioni IoT con criteri identici.
- Gestione delle release precedenti e aggiornamenti dell'analisi delle prestazioni.
- Prenotazioni DHCP Pi-hole con verifiche su MAC, IP, hostname e subnet.
- Rafforzamento autenticazione web, CSRF, sessioni e protezione download.
- Validazioni incrociate delle impostazioni prima del salvataggio.
- Rilevamento CrowdSec migliorato per iptables, ipset e nftables.

## Problemi noti — non risolti da questa pubblicazione

1. **Conferma firewall:** `do_apply()` richiama `confirm_pending()` senza attendere una conferma esplicita SSH/LAN successiva alla modifica. Anche con watchdog e controlli locali, una disconnessione differita può non causare rollback. Evitare applicazioni firewall non presidiate su gateway remoti.
2. **Prenotazioni Pi-hole:** il percorso di applicazione scrive il valore completo `dhcp.hosts`; non è garantito il merge con prenotazioni esterne né il ripristino automatico della configurazione precedente se la verifica successiva fallisce.
3. L'integrità ZIP e la suite CI locale sono verificate, ma non è stato eseguito un test end-to-end sul dispositivo DietPi con connessioni SSH, Pi-hole e regole firewall attive.

## Verifiche di pubblicazione

- Manifest nativo: 115/115 hash SHA-256 coerenti.
- Sintassi PHP, Python, JavaScript e Bash.
- Regressioni offline firewall, DNS/DoT, SSH, IoT e QoS.
- Test preesistenti adeguati alle regole IoT raggruppate e alla migrazione residual-only del vecchio proxy.
- Workflow GitHub da verificare sul commit/PR.

L'aggiornamento dei test nel repository non modifica l'archivio Native Update fornito.
