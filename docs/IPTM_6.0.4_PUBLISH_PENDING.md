# IPTM 6.0.4 — preparazione pubblicazione (non ancora rilasciata)

Questo ramo contiene soltanto la procedura di importazione/pubblicazione e il riferimento al pacchetto locale verificato. Non contiene ancora i sorgenti applicativi 6.0.4 né il relativo ZIP. Il ramo main resta alla 5.30.23.

Pacchetto da importare: IPTM_6.0.4_UPDATE.zip (1.017.938 byte).
SHA-256: c0ca2653024d86b6736abbfffe69a1896282e5a1778816f668ce6efe598307db

Il pacchetto è stato verificato localmente. Per completare l'importazione usare il pacchetto di pubblicazione già distribuito, oppure copiare lo ZIP accanto a tools/pubblica_IPTM_6.0.4.py e usare Python, Git e GitHub CLI autenticati su una workstation. Eseguire prima lo script con --verify-only. L'esecuzione normale crea il ramo release, effettua commit/push, crea una PR e procede al merge e alla pre-release soltanto dopo i controlli CI. Non eseguire sul router.

Limiti: il riferimento legacy a iptm-dns-boot-recover.service può ancora impedire la rimozione della 4.3.9. Non rimuovere manualmente tale release. Il collaudo DietPi reale non è concluso. Non considerare questo ramo un aggiornamento installabile.

Per eseguire soltanto commit e push dei sorgenti, usare --commit-only.
