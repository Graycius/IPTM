# IPTM GitHub Copilot code review instructions

Rispondi **in italiano** e controlla soprattutto regressioni funzionali e vulnerabilità, evitando osservazioni cosmetiche non necessarie.

1. **Critico: lockout remoto.** Verifica ordine delle catene INPUT/FORWARD, conntrack `ESTABLISHED,RELATED`, management SSH/HTTP e rollback prima di proporre modifiche a `iptables-restore`, `tc` o `ip`.
2. **SSH.** Controlla `--ctstate NEW --syn` per recent/connlimit e diffida di ACL IP troppo generiche. Non contare o droppare indiscriminatamente il traffico SSH esistente.
3. **Escalation.** Identifica shell injection, path traversal, symlink e TOCTOU tra PHP e helper root. Le opzioni devono essere allowlist e i file sensibili root-owned.
4. **HTTP update.** È un requisito mantenere HTTP; preserva anche la compatibilità esplicita con pacchetti non firmati. Distingui integrità da autenticità: uno SHA-256 proveniente dallo stesso canale HTTP non autentica il pacchetto. Verifica redirect/SSRF, manifest, rollback e segnala i rischi senza eliminare HTTP.
5. **FW policy.** Controlla alias porte non risolti, subnet malformate, `-j ACCEPT` generici, servizi Docker 2375/2376, bypass di blacklists via `ESTABLISHED`, chain ownership, conntrack, NAT, ICMP e disallineamento IPv4/IPv6.
6. **Traffico lecito.** Considera DNS/DHCP/MDNS, Pi-hole/Unbound, LAN, VPN, IoT, WireGuard e scenari Single-NIC. Non proporre blocchi indiscriminati come falso miglioramento di sicurezza.
7. **CAKE/IFB.** Non lanciare speedtest sotto CAKE già attivo o WAN occupata; non alterare rate senza conferma. Distingui qdisc verificata da funzioni solo presenti a livello di codice; non suggerire DPI/Layer7 pesante come feature esistente.
8. **Tests.** Per ogni problema fornisci caso riproducibile, input/stato coinvolto, effetto e regressione suggerita. Evidenzia ciò che richiede kernel DietPi reale.

Se trovi una vulnerabilità, attribuisci gravità **critica, alta, media o bassa** e cita file/funzione. Segui anche `AGENTS.md` e `SECURITY.md`.

9. **DHCP:** verifica merge non distruttivo, conflitti MAC/IP, backup, lock, rilettura e rollback. Non sostituire l'intera configurazione Pi-hole.
10. **Suggerimenti:** indica file/funzione, scenario riproducibile, impatto, correzione proposta e test. Non considerare l'approvazione AI sufficiente per il merge e non indebolire i test. Non eseguire comandi live o accedere a segreti durante la revisione.
