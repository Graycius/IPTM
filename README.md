# IPTM — Network Control

**IPTM** è una console web per gestire e diagnosticare firewall, interfacce, rete locale, DNS e servizi di sicurezza su sistemi **DietPi / Debian**. L’interfaccia raggruppa le funzioni secondo il percorso della rete: connessione → dispositivi → DNS → accessi → firewall → applicazione delle modifiche.

![Anteprima illustrativa dell'interfaccia IPTM](docs/images/dashboard-overview.svg)

*Anteprima schematica della UI: non rappresenta dati live né lo stato di un dispositivo reale.*

## Funzionalità

- **Firewall:** gestione delle regole iptables, IPv4/IPv6, NAT, bozze, verifiche e applicazione con protezioni anti-lockout.
- **Rete:** interfacce WAN/LAN, VLAN, zone IoT, inventario dei dispositivi e politiche di accesso.
- **DNS e privacy:** strumenti e integrazioni per Pi-hole, Unbound e DNSCrypt, quando presenti sul sistema.
- **Sicurezza:** diagnostica e integrazioni opzionali per CrowdSec e Suricata.
- **Prestazioni:** monitoraggio della rete, strumenti QoS/SQM e diagnostica dei servizi.
- **Manutenzione:** backup, import/export, aggiornamento web nativo con manifest SHA-256 e pulizia conservativa dei componenti obsoleti.

Le integrazioni opzionali **non sono incluse automaticamente**: il loro funzionamento dipende da software, servizi e configurazioni disponibili sulla macchina.

## Installazione e aggiornamento

### Requisiti

- Sistema di riferimento: **DietPi / Debian GNU/Linux**, con i componenti di rete richiesti dalle funzioni utilizzate.
- Un'**installazione IPTM già funzionante**, con console PHP, helper privilegiato e meccanismo di recupero dell'aggiornamento.
- Accesso alla console come **amministratore** e un backup recente della configurazione.

### Aggiornare IPTM dalla console web

1. Apri la console IPTM e accedi come **amministratore**.
2. Vai a **Sistema e strumenti → Aggiornamenti** (pagina `?p=update`).
3. Scarica l'archivio **Native Update** dalla cartella [`release/`](release/). Il pacchetto attualmente pubblicato con questi sorgenti è [`IPTM_5_20_22_CLEAN_UI_NATIVE_WEB_UPDATE.zip`](release/IPTM_5_20_22_CLEAN_UI_NATIVE_WEB_UPDATE.zip).
4. Nella pagina Aggiornamenti seleziona **solo il file ZIP Native Update** e premi **Installa pacchetto completo**.
5. Al termine verifica la versione indicata nella console e consulta **Salute sistema** per controllare i servizi.

Il sistema verifica automaticamente il formato, il manifest, gli hash dei file e i meccanismi di recupero; effettua anche copie di sicurezza prima dell'aggiornamento. Se una verifica fallisce, l'aggiornamento può essere rifiutato per proteggere la rete.

> **Importante:** non decomprimere manualmente lo ZIP nelle cartelle di sistema; non caricare un archivio sorgenti o uno ZIP che contiene altri ZIP. Non applicare modifiche al firewall su un server remoto senza avere un percorso di recupero.

### Prima installazione su un sistema nuovo

Il file **Native Update non è un installer da zero**: richiede un'installazione IPTM preesistente e non configura autonomamente web server, privilegi, helper e recovery. Il repository non contiene attualmente una procedura di bootstrap completa, verificata e supportata per un host vuoto. Non usare lo ZIP come installer iniziale.

## Struttura del repository

| Percorso | Contenuto |
| --- | --- |
| `loader/` | Punto d'ingresso PHP della console |
| `modules/` | Pagine e logica applicativa |
| `actions/` | Gestione delle azioni autenticate |
| `assets/` | Interfaccia, CSS e JavaScript locali |
| `extensions/` | Moduli operativi e diagnostici Python |
| `runtime/` | Helper e strumenti di sistema |
| `release/` | ZIP installabili tramite aggiornamento web |
| `native-manifest.json` | Versione e hash SHA-256 dei componenti |
| `CHANGELOG.md` | Cronologia delle modifiche |

## Sicurezza e verifiche

L'accesso ai componenti privilegiati è mediato dall'helper di sistema. Le modifiche che possono interrompere la connettività utilizzano controlli automatici e percorsi di recupero. Il manifest SHA-256 verifica l'integrità del pacchetto, **non prova da solo l'identità dell'autore**: scarica gli aggiornamenti soltanto da fonti fidate, preferibilmente via HTTPS.

**Stato dei test:** sintassi e integrità dei pacchetti sottoposte a verifiche locali; la distribuzione non dichiara un collaudo end-to-end su ogni installazione DietPi.

## Licenza

Il repository include la licenza [GNU GPL v3](LICENSE). Verificare separatamente gli avvisi e le licenze degli eventuali componenti esterni.
