# IPTM 5.30.11 — Recupero DNS e protezione rigenerazione

## Errore riprodotto

Con ingressi LAN non verificati, le sei regole `IPTM:dot` e le sei `IPTM:dns-redir` erano presenti nel rules.v4 su disco ma scomparivano dalla bozza. La causa non era la mancata risoluzione delle interfacce: la pagina Setup non presentava `dns_redirect`, `dot_block`, `dns_ip`, sebbene il controller `settings_save` trattasse i booleani mancanti dal POST come off (0).

## Correzioni

- I tre campi sono ora visibili in Setup; nessun reset invisibile dei booleani.
- `regen()` preserva i blocchi IPTM DoT/DNS già nella bozza se le impostazioni non sono allineate, con validazione rigorosa e avviso; il pulsante di conferma permette la rimozione esplicita in bozza.
- Il recupero da rules.v4 verifica le regole di entrambe le porte, tutti i CIDR LAN e l'indirizzo di destinazione; preserva firewall e kernel.
- In applicazione/persistenza, le regole DoT/DNS presenti su disco e assenti dalla bozza richiedono conferma esplicita; il controllo funziona anche con `force` e con la scrittura diretta su disco.
- La tabella d'ingresso non presume che un'interfaccia LAN condivisa o non verificata sia affidabile; le regole sorgente esistenti non vengono eliminate per questo motivo.

## Casi di test

- 3 subnet / 6 regole DoT / 6 DNS
- discrepanza flags-off/bozza-on: conservazione
- rigenerazione idempotente
- rimozione solo su conferma
- recupero dalla copia su disco con sincronizzazione opzioni
- associazione `-i` già presente
- rifiuto DNAT DNS esterno o di regole FORWARD non autorizzate
- compatibilità test LAN/IoT/SSH e semantica iptables con policy FORWARD DROP

**Limiti:** test offline su sorgenti PHP/Python. Non è stato eseguito un collaudo sul gateway remoto: `iptables-restore --test` e verifica SSH/DNS vanno svolti sul DietPi prima dell'applicazione definitiva.
