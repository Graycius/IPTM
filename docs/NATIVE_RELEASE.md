# Generazione e pubblicazione dei pacchetti Native Update

Il workflow [Build and publish IPTM Native Update](../.github/workflows/native-release.yml) genera lo ZIP e il checksum dai sorgenti Git, senza caricare manualmente archivi.

Per una nuova versione, aggiornare coerentemente la versione nel manifest e nel loader e le altre costanti di versione del programma, aggiornare il changelog, aggiungere i sorgenti a Git e ricalcolare il manifest con `python3 tools/build_native_update.py --refresh-manifest`. Includere il manifest nel commit. Il workflow parte quando il manifest cambia su main, verifica sintassi e hash, genera un artefatto e pubblica una nuova release soltanto se il tag non esiste. Per una verifica manuale, usare **Actions → Build and publish IPTM Native Update → Run workflow** lasciando Publish disattivato. Non sovrascrive release esistenti.

Il builder include esclusivamente i percorsi nativi tracciati e il manifest. Non include il repository storico, documentazione, chiavi o file di configurazione personali. La firma digitale è facoltativa. Gli aggiornamenti web HTTP continuano a richiedere il checksum esterno per i download via URL. I controlli di sintassi e integrità non sostituiscono il collaudo operativo del firewall.

La release v6.0.8 già esistente non viene modificata.
