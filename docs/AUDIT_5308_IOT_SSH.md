# Revisione policy IoT, SSH, servizi locali — IPTM 5.30.8

L'archivio di regole denominato `rules.v4 (2)_3.txt` non era presente tra i file accessibili alla revisione. I rilievi puntuali sul numero delle sezioni provengono dalla descrizione fornita dall'utente; i controlli automatici usano un modello con 14 MAC e tre subnet. La correzione è stata applicata al generatore e alla UI della versione 5.30.7.

## Verifiche e risultati

1. **IoT gestito dalla UI:** `iot_policies` è la fonte delle opzioni salvate e `IPTM:iot-<mac>` produce le regole FORWARD richieste. Queste sezioni sono indipendenti dai salti delle catene MAC esterne. Non vanno rimosse finché la policy è abilitata.
2. **Incoerenza delle policy:** l'audit segnala le policy UI attive ma assenti dalla bozza, e viceversa le sezioni non presenti nelle impostazioni, senza cancellazione automatica.
3. **MAC importati:** normalizzazione maiuscolo/minuscolo, blocco di chiavi non conformi, scarto di flag sconosciuti e salvaguardia delle opzioni note.
4. **SSH dalle LAN:** `recent` e `connlimit` su SYN NEW, mantenimento delle sessioni ESTABLISHED; generazione con reti trusted quando `ssh_nets` è vuoto ma l'anti-lockout protegge la porta.
5. **SSH da VLAN/VPN:** per ogni subnet viene individuata la propria interfaccia di ingresso attraverso le reti IPv4 realmente assegnate. Se non è distinguibile ma la WAN è pubblica, si esclude il WAN; in caso di ambiguità non si crea un match di ingresso che possa interrompere l'accesso.
6. **Aperture INPUT:** i servizi DNS, SMB e applicativi ricevono lo stesso scope per-sorgente ove dimostrabile. Su bond0 condivisa non si può attestare l'origine tramite la sola interfaccia.
7. **Anti-spoof RFC1918:** conservato esclusivamente se WAN distinta e pubblica verificata; non attivato su rete piatta o doppio NAT.
8. **Profili applicativi:** report dei profili abilitati senza listener osservato (indicativo, non conclusivo). La rimozione di una voce deve essere selezionata e salvata esplicitamente dall'amministratore.
9. **Limitazione L2:** IPv4 iptables non isola il traffico diretto fra due dispositivi sullo stesso switch o SSID; occorrono VLAN o isolamento client.

Nessuna modifica del firewall attivo è apportata dall'installazione dell'aggiornamento. La rigenerazione della bozza e la successiva applicazione restano azioni amministrative separate, con il sistema di conferma e rollback di IPTM.
