# IPTM 5.30.5 — Audit proxy e intercettazione HTTP

## Risultati e gravità

1. **Alto — rilevamento Squid**, `extensions/cache_proxy.py:trusted_binary`: la verifica storica rigettava symlink e packaging Debian 13 (`squid-gnutls` e `squid-openssl`), producendo la falsa diagnosi di installazione assente. Risolto verificando la destinazione e le directory possedute da root, e il database file dpkg.
2. **Alto — applicazione senza possibilità di anteprima**, `extensions/cache_proxy.py:stage`: il preview dipendeva dall'eseguibile Squid anche con servizio fermo. Ora preferenze e configurazione vengono validate e salvate senza installazione.
3. **Alto — traffico non intercettato**, `extensions/cache_redirect.py`: in precedenza Squid richiedeva configurazione manuale del browser. È disponibile REDIRECT IPv4 solo HTTP/TCP80 con attivazione esplicita; HTTPS/443 non viene MITM/intercettato.
4. **Critico — potenziale aggiramento filtri forwarding**, `extensions/cache_redirect.py:security_preflight`: il proxy può far passare il traffico client in INPUT/OUTPUT. Disabilitata l'intercettazione automatica quando le ACL di FORWARD sono restrittive o non interpretabili.
5. **Critico — blocco HTTP se Squid si arresta**, `extensions/cache_proxy.py:failopen,reconcile`: pulizia NAT prima dello stop, ExecStopPost e timer recovery (intervallo nominale 30s); non è una garanzia deterministica in tutti i crash kernel.
6. **Alto — transazioni firewall concorrenti**, `modules/11_firewall_transaction.php`: rimozione NAT prima del restore IPv4, successiva riconciliazione protetta.
7. **Alto — regole non IPTM**, `extensions/cache_redirect.py:chain_trusted`: rifiuto del flush di catene alterate o di proprietà incerta; rimozione puntuale dei soli hook propri.
8. **Medio — stato della UI fuorviante**, `modules/41_performance_pages.php`, `actions/performance.php`: stato di pacchetto, binario, servizio e NAT distinti, errori JSON decodificati, profilo effettivo separato dalla bozza.
9. **Medio — disattivazione quando servizio non disponibile**, `extensions/cache_proxy.py:disable`: rimozione NAT e aggiornamento stato senza dipendere dal binario di Squid.
10. **Medio — form incompleto o dimenticato**, `modules/41_performance_pages.php:iptm_proxy_form_defaults`: IP/subnet privata IPv4 assegnata, porta precompilata e preferenze persistenti.

## Comportamento testato offline

I test in `tests/test_cache_redirect_5305.py` coprono: configurazione valida; booleano falso/None/malformato; CIDR esterno o injection; no SSL-Bump/HTTPS; cache esplicita; stage offline; solo NAT/80; install/remove; doppio install; catena estranea; fallimento hook; stop senza binario; monitor su servizio giù; ExecStopPost; binario in /tmp; IP non primario; prefill PHP; FORWARD restrittivo; ACL custom; preflight sicuro; backend non ammesso.

## Limiti e precondizioni

L'intercettazione riguarda soltanto client IPv4 il cui traffico attraversa fisicamente IPTM come gateway. HTTPS, HTTP/3 e QUIC non sono cachati/intercettati. Configurazioni IoT con restrizioni FORWARD negano il redirect per evitare bypass; rimane utilizzabile il proxy esplicito. Nessun test offline può dimostrare la continuità SSH/DNS e l'affidabilità del watchdog su hardware DietPi reale: occorre un collaudo di rete prima del rollout di produzione.
