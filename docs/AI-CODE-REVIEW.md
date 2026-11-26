# Revisione automatica del codice IPTM

Le revisioni AI sono consultive. Non sostituiscono i controlli CI, la verifica su DietPi o la valutazione umana. Nessun revisore modifica il codice o pubblica release automaticamente.

## Controlli e risultati

Aprire una pull request interna verso main. Nella scheda Actions si trovano i controlli di sintassi e regressione, CodeQL, Semgrep, Dependency Review e i riepiloghi dei revisori AI. I risultati Copilot, se la richiesta è accettata, sono nella pull request. Un workflow completato senza chiamate AI non significa che il codice sia stato revisionato: leggere sempre il riepilogo.

## Copilot

Il workflow richiede una revisione per le PR interne non in bozza. Il token GitHub Actions può essere non idoneo (HTTP 422 ACTOR_INELIGIBLE). Se l'account dispone di Copilot Code Review, creare un fine-grained personal access token limitato a IPTM, con Pull requests: Read and write, scadenza breve. Inserirlo come repository secret IPTM_COPILOT_TOKEN. Non inserirlo nel repository o in chat. In alternativa, abilitare la revisione nativa in Settings se disponibile. Un errore rimane visibile: non viene simulata una revisione riuscita.

## OpenAI, Gemini, Claude (facoltativi)

Aprire Settings > Secrets and variables > Actions. In Secrets aggiungere solo le chiavi dei provider desiderati:

| Provider | Repository secret | Repository variable con modello API |
|---|---|---|
| OpenAI | OPENAI_API_KEY | IPTM_OPENAI_MODEL |
| Google Gemini | GEMINI_API_KEY | IPTM_GEMINI_MODEL |
| Anthropic Claude | ANTHROPIC_API_KEY | IPTM_CLAUDE_MODEL |

Scegliere un identificatore modello disponibile nel proprio account, compatibile con le API chat completions (OpenAI), generateContent (Gemini) o Messages (Claude). Le chiavi API e gli eventuali costi sono separati dagli abbonamenti alle app. Configurare budget e limiti presso ogni provider.

Solo dopo aver accettato l'invio delle modifiche pubbliche ai provider selezionati e i possibili costi, impostare la repository variable IPTM_AI_REVIEW_ENABLED a true. Non serve configurare tutti i provider. Per disabilitare, impostarla a false o rimuoverla. I provider privi di chiave o modello indicano NOT RUN. I problemi di API indicano NOT COMPLETED.

## Sicurezza e limiti

Il workflow usa solo la configurazione del ramo base, non esegue codice delle PR e si limita alle PR interne dell'owner non in bozza verso main. Non concede permessi di scrittura. Analizza patch testuali selezionate tra i primi 50 file, entro 24.000 caratteri per provider, con esclusioni per percorsi e pattern sensibili. Le esclusioni non sono una garanzia di assenza di segreti: non pubblicare segreti o dati privati. L'analisi è parziale, non una certificazione di sicurezza. Nessun output AI viene eseguito o applicato.

Per ogni suggerimento controllare il file, riprodurre il difetto e aggiungere un test prima di decidere una correzione. Prestare particolare attenzione a lockout SSH/LAN, DNS, VPN, QoS e rollback. I test offline non sostituiscono le prove su una rete isolata.

## Riferimenti

- [Copilot code review API](https://docs.github.com/en/rest/pulls/copilot-code-review)
- [OpenAI API](https://platform.openai.com/docs/api-reference/chat)
- [Gemini API](https://ai.google.dev/api/generate-content)
- [Anthropic Messages API](https://docs.anthropic.com/en/api/messages)
