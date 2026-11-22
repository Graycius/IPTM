# Checklist di revisione sicurezza

1. Connessione SSH già stabilita: non viene interrotta da SSH recent/connlimit, logging o conntrack?
2. Management: la rete amministrativa è esplicitamente configurata e l'accesso non è esposto alla WAN?
3. Preflight: cosa accade con IP/iface/CIDR NULL, vuoti, malformati, inattendibili o cambiati durante Apply?
4. Rollback: watchdog armato, precedente ruleset salvato, conferma solo dopo test di connettività reali?
5. Docker/container: nessuna esposizione non richiesta di API TCP 2375/2376; preservata la coesistenza con catene di terzi?
6. Servizi leciti: DNS/53, DHCP 67/68, ICMP PMTUD, mDNS/5353, SSDP/1900, WireGuard e VPN sono preservati quando abilitati?
7. QoS: qdisc e IFB realmente verificate, nessun speedtest massivo sotto CAKE o WAN occupata, rollback per `tc`?
8. Aggiornamenti: ZIP, manifest, SHA-256 fidato quando HTTP, redirect/SSRF, decompression bomb e TOCTOU verificati?
9. Input: argomenti shell, import JSON/CSV e percorsi validati; nessun injection/path traversal.
10. Performance: Atom N450, limiti di CPU/RAM, timeouts, semafori e gestione dei processi figli.
11. IPv6: flussi legittimi e disable totale gestiti esplicitamente, mai delegati a iptables IPv4.
12. Tests: fixture offline senza toccare il kernel + test in VM per networking, fault injection e disconnessione.
