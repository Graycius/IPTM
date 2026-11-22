
## Risultati e gravità

6. **Alto — transazioni firewall concorrenti**, `modules/11_firewall_transaction.php`: rimozione NAT prima del restore IPv4, successiva riconciliazione protetta.
8. **Medio — stato della UI fuorviante**, `modules/41_performance_pages.php`, `actions/performance.php`: stato di pacchetto, binario, servizio e NAT distinti, errori JSON decodificati, profilo effettivo separato dalla bozza.
10. **Medio — form incompleto o dimenticato**, `modules/41_performance_pages.php:iptm_proxy_form_defaults`: IP/subnet privata IPv4 assegnata, porta precompilata e preferenze persistenti.

## Comportamento testato offline


## Limiti e precondizioni

L'intercettazione riguarda soltanto client IPv4 il cui traffico attraversa fisicamente IPTM come gateway. HTTPS, HTTP/3 e QUIC non sono cachati/intercettati. Configurazioni IoT con restrizioni FORWARD negano il redirect per evitare bypass; rimane utilizzabile il proxy esplicito. Nessun test offline può dimostrare la continuità SSH/DNS e l'affidabilità del watchdog su hardware DietPi reale: occorre un collaudo di rete prima del rollout di produzione.
