# Revisione automatica del codice IPTM

Le revisioni AI sono consultive. Non sostituiscono i test offline, la verifica sul dispositivo DietPi o una valutazione umana prima dell'applicazione di modifiche di rete.

## Come consultare i risultati

1. Aprire una pull request verso main da un ramo del repository.
2. Consultare la scheda Actions per l'esito dei test e della richiesta Copilot.
3. Consultare Conversation e Files changed nella pull request per i commenti AI.
4. Verificare ogni suggerimento con un caso riproducibile e un test di regressione prima del merge.

## Revisori

- Copilot: il workflow richiede una revisione quando una PR interna non in bozza viene aperta, riaperta, aggiornata o dichiarata pronta. Non esegue il codice della PR. Il servizio richiede un account/repository idoneo e quota disponibile; un errore di richiesta è visibile in Actions. Non vengono abilitate opzioni di fatturazione.
- CodeRabbit: configurazione in .coderabbit.yaml; installare l'app da https://github.com/marketplace/coderabbitai e limitarla a Graycius/IPTM. Le revisioni automatiche sono configurate, ma l'app deve essere autorizzata.
- Qodo: configurazione in .pr_agent.toml; per i progetti open source consultare https://github.com/marketplace/qodo-merge-pro-for-open-source e autorizzare il solo repository IPTM.

## Priorità

Continuità SSH/LAN/VPN, rollback indipendente, preservazione DHCP/Pi-hole, regole IPv4/IPv6 e IoT, sicurezza PHP/helper root, CAKE/IFB, integrità dei pacchetti e compatibilità degli aggiornamenti HTTP. Distinguere integrità da autenticità per gli aggiornamenti non firmati.

CodeQL, Semgrep, Dependabot e i test di regressione restano indipendenti dai revisori AI. Nessun suggerimento AI va considerato una prova di assenza di vulnerabilità.

Usare pull request per le modifiche da sottoporre a revisione: un commit diretto su main non genera una pull request e non attiva questo workflow Copilot.
