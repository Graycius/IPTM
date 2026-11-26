## 6.0.8 — Aggiornamenti HTTP senza firma obbligatoria

- ZIP non firmati ammessi anche con chiave Ed25519 configurata. Le firme presenti vengono verificate quando la chiave attendibile è disponibile; firme malformate o non valide non vengono accettate.
- Invariati SHA-256 esterno per HTTP, controlli di integrità del manifest e protezioni dell’updater.
- Nessuna modifica alle policy firewall della 6.0.7.

## 6.0.7 — Hardening gestione, reset, VPN e IPv6

- Reti amministrative distinte dalle LAN di transito; fallback automatico solo per una subnet non ambigua, non ospiti/isolata. In presenza di più LAN configurare esplicitamente i CIDR amministrativi in Sicurezza. Applicazione bloccata se la rete amministrativa non è determinabile.
- Reset minimo conserva topologia, mappa ingressi, policy guest/IoT/isolamento, impostazioni SSH e VPN; non apre mai gestione globale. Se manca una rete amministrativa, annulla il reset prima di salvare le nuove impostazioni.
- Isolamento e blocklist destinazioni valutati prima di SPI; rete ospiti non beneficia più di un ACCEPT generico ESTABLISHED prima dell'isolamento. Le eccezioni esplicite restano gestite.
- WireGuard IPv4: accesso completo esplicito vincolato alle reti peer configurate, LAN e WAN. Verificare wg_net. Nessuna variazione automatica alle regole live durante l'aggiornamento.
- IPv6: ingressi di gestione vincolati all'interfaccia, NDP/RA distinti, errori ICMPv6 essenziali conservati, limite echo non aggirabile da ACCEPT generico, DoT prima di SPI, prefissi peer VPN espliciti. La parità completa delle policy multi-zona IPv6 richiede ancora configurazione e collaudo dedicati.
- HTTP resta disponibile. SHA-256 esterno attendibile obbligatorio per download HTTP. Supporto Ed25519 con chiave pubblica root-pinned `/etc/iptm-update-ed25519.pub`: dopo provisioning tutti i nuovi aggiornamenti devono essere firmati. Senza chiave, compatibilità con gli aggiornamenti precedenti. Nessuna chiave di terzi viene installata automaticamente.
- Revisione bozza: segnalazione reti amministrative ambigue e ingressi non verificati.
- Collaudi statici e generazione offline; nessuna certificazione di traffico reale, CAKE o prestazioni su DietPi.

## 6.0.6 — Ordine delle regole aziendali, profilo minimo, IPv6

- Ordine FORWARD: isolamento tra reti, rete ospiti e blocklist in uscita sono ora valutati subito dopo `ESTABLISHED` e **prima** dei permessi di uscita e dei port-forward. Prima potevano essere aggirati (LAN/SERVER/ospiti verso un host DMZ pubblicato, ospiti verso reti private raggiungibili dalla WAN, IP presenti in una blocklist in uscita). Verificato con traffico reale tra network namespace; il contenuto dei ruleset resta identico, cambia solo l'ordine.
- `blockping` ora precede la regola ICMP limitata: con `icmp_limit` attivo il ping dalla WAN restava invece accettato.
- Profilo minimo: con NAT attivo imposta `lan_out_fwd`, così la LAN non perde Internet dopo il reset.
- IPv6: neighbor discovery sempre accettato (anche con `icmp` disattivato); i DROP anti-bogon precedono gli ICMPv6 opzionali; rimosso un `INVALID` duplicato.
- IPv4: rimossa la regola duplicata `--tcp-flags FIN,SYN FIN,SYN` (identica a `SYN,FIN SYN,FIN`).
- Limite noto, non modificato: l'anti-lockout concede la gestione (SSH/UI) a tutte le reti in `lan_nets`; una rete DMZ o SERVER inserita in `lan_nets` può quindi raggiungere l'amministrazione del firewall.

