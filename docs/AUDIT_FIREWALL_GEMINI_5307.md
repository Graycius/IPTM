# Revisione firewall — IPTM 5.30.7

## Esito dell'analisi dell'esempio rules.v4

| Rilievo | Esito | Intervento |
|---|---|---|
| INPUT: servizi locali autorizzati per sola sorgente LAN | Confermato nei servizi/app della bozza | Bind all'interfaccia LAN quando disponibile; se interfaccia non distinguibile avviso visibile |
| SSH: anti-lockout che può bypassare `recent` e `connlimit` | Rischio di precedenza dipendente dall'ordine reale; non si assume il bypass se `ssh-acc` precede il lockout | Protezione SSH prima delle aperture di gestione, esclusione della porta da ACL generiche, preflight per bozze legacy insicure |
| Telnet limitatore senza apertura del servizio | Confermato e inutile per porta chiusa | Eliminato dalla generazione e dall'interfaccia |
| Duplicazioni Pi-hole/AdGuard/Unbound, servizi web | Confermate nelle aperture generate | Dedup per porta/protocollo/subnet, mantenendo visibile il profilo responsabile |
| WireGuard `FORWARD -o wg0 -j ACCEPT` indiscriminato | Confermato nel modulo `svc-fwd` | Rimosso per impostazione predefinita; accesso LAN→VPN esclusivamente per opt-in ed ambito LAN |
| Duplicati `-i wg0` e stato `RELATED,ESTABLISHED` | Confermati con moduli VPN/SPI attivi | Deduplicazione senza sopprimere `ESTABLISHED` funzionale |
| Policy MAC IoT e salti IPTM-MAC incoerenti | Rilevabili nel dump (il numero dipende dalla configurazione) | Audit con elenco delle aree da riconciliare, nessun salto su catene non verificate |
| MAC non isola traffico Ethernet sulla stessa subnet | Limite strutturale, non bug solo iptables | Avviso in UI; raccomandazione VLAN o AP isolation |
| WAN RFC1918 anti-spoof | Giusto soltanto con WAN pubblica distinta | Regole INPUT/FORWARD limitate a interfaccia WAN verificata; sospensione in doppio NAT o interfaccia condivisa |
| DNS forzato, IPSet, TCP MSS clamping | Funzioni valide con verifiche topologiche | Conservate, senza ottimizzazioni distruttive |

### Limiti

Le regole manuali, la lista MAC di IoT Warden e le regole attive nel kernel non sono modificate automaticamente. `iptables` non può impedire ARP o traffico L2 diretto tra due host della stessa subnet. Il blocco di UDP/443 e DoT non rende impossibile DoH su TCP/443 o altri tunnel. Una WAN condivisa con LAN non consente di certificare l'ingresso dei pacchetti usando solo `-i`. Il comportamento SSH, DNS e VPN richiede un test su DietPi reale prima dell'applicazione.
