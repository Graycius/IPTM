# IPTM 5.20.25 — Pacchetto di prima installazione

**Destinazione:** DietPi / Debian con `systemd`, Python 3, PHP **8+**, `sudo`, `visudo`, `iptables` e **server web esistente configurato per eseguire file PHP**. Un web server che serve solamente file statici o il web server integrato di Pi-hole **non basta** per eseguire PHP.

## Installare

1. Copia l'archivio ZIP sul server Linux ed estrailo, senza modificare i file interni.
2. In una shell locale/SSH sul server, dentro la cartella estratta, esegui:

   ```bash
   sudo bash install.sh --dry-run
   sudo bash install.sh
   ```

3. Apri `http://IP_DEL_SERVER/iptables-manager.php` **sulla porta del server web che già esegue PHP**, preferibilmente via HTTPS o un tunnel SSH.
4. Nel primo accesso imposta la password `admin` usando il codice letto sul server:

   ```bash
   sudo cat /var/lib/iptables-manager/setup-token.txt
   ```

   Il codice scade come token di setup quando viene impostata la password ed è eliminato dall'applicazione.

### Document root / utente PHP diversi

```bash
sudo bash install.sh --web-root /percorso/del/document-root --web-user nome-utente-php
```

Il percorso web deve esistere ed essere protetto da root. **Non puntare alla cartella di Pi-hole** se il suo server non gestisce PHP; non riavviare Pi-hole per questa installazione.

## Che cosa installa

- Console in `<document-root>/iptables-manager.php`.
- Moduli e risorse immutabili in `/usr/local/lib/iptables-manager/web/releases/5.20.25/`.
- Helper root in `/usr/local/sbin/iptm-helper`, strumenti Python sotto `/usr/local/lib/iptables-manager/`.
- Directory dati privata `/var/lib/iptables-manager/` e primo codice di configurazione.
- Regola sudo per **il solo helper** da parte dell'utente PHP scelto, con comandi consentiti dal dispatch del helper. Considerala una delega privilegiata: il server PHP deve essere adeguatamente protetto e raggiungibile soltanto da reti fidate.
- Recupero aggiornamenti con unità `iptm-update-recover.service` e copia stabile di `iptm-update-rescue.py`.

**Non** installa o abilita Pi-hole, Unbound, DNSCrypt, CrowdSec, Suricata, QoS o ulteriori servizi opzionali. **Non** modifica il firewall live, la configurazione DNS, NAT, indirizzi, routing e altre porte web.

## Correzione CAKE / DSCP

Quando le priorità DSCP salvate non corrispondono più alle regole iptables attive, CAKE non rifiuta l’intera prova: usa il normale redirect IFB, senza filtri DSCP facoltativi e senza modificare il classificatore esistente. La pagina QoS mostra la classificazione download sospesa. Stati DSCP corrotti, permessi insicuri o link simbolici continuano a bloccare l’operazione.

## Compatibilità e limiti

- Questo ZIP è per la **prima installazione** e si rifiuta di sovrascrivere una installazione già presente. Per aggiornare una console IPTM funzionante usa `IPTM_5_20_25_DSCP_SAFE_DISABLE_NATIVE_WEB_UPDATE.zip` dalla pagina web Aggiornamenti.
- Il server deve già eseguire PHP (ad esempio Apache, Lighttpd o nginx con PHP-FPM). Il pacchetto **non installa né riconfigura il web server** e non assicura automaticamente un endpoint HTTP funzionante se il server è configurato male.
- La UI permette modifiche di rete con effetti reali **solo dopo il primo accesso**, quando l'utente le attiva. Evitare di esporre la console a Internet.
- Se è attivo IPv6, la console controlla e visualizza servizi IPv6; l'installazione non lo disabilita né cambia il backend iptables.
- L'archivio deve provenire da una fonte attendibile: gli hash SHA-256 del manifest verificano l'integrità rispetto al manifest incluso, **non** costituiscono firma dell'autore.
- Operazioni iniziali e di aggiornamento sono collaudate tramite test di sintassi e installazione simulata. **Non** esiste una prova end-to-end su una macchina DietPi reale allegata.

## Sorgenti

`source/` riproduce il contenuto completo del Native Update IPTM 5.20.25, compreso il manifest.

## Licenza

GNU GPL v3 (vedi `LICENSE`). Per dipendenze esterne consultare le rispettive licenze.
