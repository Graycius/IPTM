# IPTM — Network Control UI

**Versione:** 5.20.22 · **Piattaforma di riferimento:** DietPi / Debian · **Interfaccia:** PHP, JavaScript e CSS · **Gestione rete:** iptables e componenti locali.

Pannello di gestione della rete con controllo firewall, LAN, DNS, zone IoT, diagnostica, monitoraggio e aggiornamento nativo. La versione 5.20.22 semplifica testi e navigazione e corregge lo sfondo blu delle schede sulla dashboard.

## Struttura

- `loader/` — punto d’ingresso della console PHP
- `modules/` — moduli applicativi e viste
- `actions/` — operazioni server
- `assets/` — CSS e JavaScript locali
- `extensions/` — servizi e funzioni Python
- `runtime/` — helper di sistema
- `native-manifest.json` — manifest dell’aggiornamento con hash SHA-256
- `CHANGELOG.md` — cronologia delle modifiche

## Aggiornamento

Il pacchetto distributivo originale è `IPTM_5_20_22_CLEAN_UI_NATIVE_WEB_UPDATE.zip`, nella cartella `release/` dell’archivio sorgente. È destinato al flusso di aggiornamento web nativo IPTM, **non** va estratto direttamente nelle directory di sistema senza il gestore di aggiornamento.

Le operazioni firewall/DNS comportano rischi di interruzione della rete: eseguire backup e verificare la possibilità di ripristino prima di applicare modifiche su una macchina remota.

**Stato dei test:** sono stati eseguiti controlli sintattici e di integrità sul pacchetto di aggiornamento; non è documentata una prova d’installazione end-to-end su un sistema DietPi reale.

## Pubblicazione

Repository ufficiale IPTM. Il file di distribuzione è disponibile nella cartella `release/` per l’aggiornamento web nativo.

## Licenza

Il repository contiene un file `LICENSE` con il testo GNU GPL versione 3. Verificare le licenze e gli avvisi di copyright delle dipendenze e degli eventuali componenti di terze parti.
