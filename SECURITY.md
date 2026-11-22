# Security policy — IPTM

## Supported versions

La versione attualmente pubblicata è **5.30.1**. Le correzioni di sicurezza sono indirizzate alla linea più recente. Non presumere che le release precedenti siano mantenute.

## Reporting vulnerabilities

Per vulnerabilità che permettono bypass SSH/firewall, escalation privilegi, disclosure di token o remote command execution, **non pubblicare dettagli di exploit in issue o discussioni pubbliche**.

Se il repository abilita Private vulnerability reporting, usa la pagina **Security → Advisories → Report a vulnerability**. Se non disponibile, contatta il maintainer tramite un canale privato prima di rendere pubblici dettagli sensibili. Non pubblicare log con token o dati privati.

Include versione IPTM, configurazione non sensibile, prerequisiti e impatto atteso/effettivo; oscura credenziali, indirizzi e identificativi privati.

## Security boundaries

- L'helper privilegiato deve accettare solo azioni validate e autorizzate; l'utente web non deve poter eseguire comandi arbitrari come root.
- Le politiche `iptables` e `tc` sono state solo parzialmente testate fuori da un kernel reale. Una CI verde non rende sicura un'applicazione live.
- HTTP Update è supportato per compatibilità: richiede l'hash SHA-256 **atteso da fonte attendibile distinta dal trasporto HTTP**. La sola presenza di SHA-256 dentro il pacchetto non dimostra provenienza.
- Le modifiche a firewall, SSH, DNS, routing e QoS richiedono fail-safe e rollback; non disabilitare il watchdog per accelerare le modifiche.
