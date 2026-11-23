# IPTM 5.30.23 — Accesso da WireGuard ai servizi LAN

L'uscita Internet dal tunnel prova il funzionamento di routing/NAT WAN, non quello dell'accesso ai servizi nella LAN. In IPTM il traffico destinato al DietPi attraversa `INPUT`; quello destinato a dispositivi differenti attraversa `FORWARD`.

## Configurazione in UI

1. Apri **VPN → Regole firewall della VPN**: verifica interfaccia (`wg0` o altro dispositivo reale), porta UDP e stato del server WireGuard. Le opzioni globali «client raggiungono LAN/Internet» e «client raggiungono anche il router» aggiungono `ACCEPT` estesi sull'interfaccia VPN; è preferibile usare le regole per servizio e sorgente nelle aree sottostanti.
2. Apri **Accesso al router e transito** (`?p=router`), **Servizi del router (INPUT)**: abilita una regola `iif=wg0`, `src=<CIDR_VPN>`, `dst=192.168.1.165/32` (se davvero il DietPi ha quell'IP), `proto=tcp`, `ports=22` (o porta SSH effettiva), destinazione corretta. Un'ulteriore regola per la porta della console se serve.
3. In **Regole di transito (FORWARD)** abilita una regola `iif=wg0`, `oif=<interfaccia_LAN_verificata>` (ad es. bond0 solo se vero), `src=<CIDR_VPN>`, `dst=<IP_HA>/32`, `proto=tcp`, `ports=8123`, `ct=NEW,ESTABLISHED` o campo vuoto. Mantieni la regola di ritorno `ESTABLISHED,RELATED` per le connessioni già consentite. Verifica che l'isolamento ospiti/IoT/VLAN non abbia un DROP precedente che ne impedisca il transito.
4. Mantieni la policy `FORWARD DROP`; non aprire tutte le porte di gestione su Internet o da tutte le subnet VPN.
5. **Applica in prova con rollback**: verifica la bozza e, da un secondo client VPN, prova SSH, Home Assistant, DNS e accesso alla UI; conferma manualmente entro la finestra configurata. Altrimenti il watchdog ripristina automaticamente le regole precedenti.

## Rotte

Su client WireGuard split-tunnel, il campo `AllowedIPs` del **peer server sul client** deve comprendere le reti locali da raggiungere, per esempio `192.168.1.0/24, 192.168.10.0/24` e la subnet VPN. In modalità full-tunnel `0.0.0.0/0` include già gli indirizzi privati, ma controlla eventuali route più specifiche verso la LAN locale del client. Nel server, `AllowedIPs` del singolo **peer client** deve restare normalmente l'indirizzo /32 di quel peer e non tutte le LAN del server.

Quando il gateway predefinito dei dispositivi LAN non è il DietPi WireGuard, configura sul router LAN una **rotta statica** verso `<CIDR_VPN>` via `<IP_DIETPI_LAN>` (es. `192.168.1.165` solo se confermato). Oppure prevedi SNAT mirato, se il router non supporta rotte statiche e l'isolamento lo consente, sapendo che nasconde l'IP originale del peer. Verifica anche il firewall host del dispositivo Home Assistant. Non assumere che la subnet `10.19.165.0/24`, presente in vecchie regole, sia quella effettiva di WireGuard.

## Diagnostica in sola lettura su DietPi

```bash
sudo wg show
ip -4 addr show wg0
ip -4 route
sudo iptables -vnL INPUT --line-numbers
sudo iptables -vnL FORWARD --line-numbers
sudo iptables -t nat -vnL POSTROUTING --line-numbers
sudo ss -lntp | grep -E ':(22|8123)\b'
```

Esegui un test dalla VPN verso `192.168.1.165:22` e verso `<IP_HA>:8123`; confronta contatori DROP/ACCEPT nelle rispettive catene e, se necessario, usa `sudo tcpdump -ni wg0 'tcp port 22 or tcp port 8123'` (osservazione del traffico, nessun cambiamento firewall). Controlla che Home Assistant ascolti sulla LAN corretta e che il suo gateway abbia una rotta di risposta.

**Nota:** questa guida non modifica la VPN e non sostituisce test reali su DietPi. Evita un `iptables -F`, `FORWARD ACCEPT`, regole iptables generiche o una nuova attivazione di NAT senza rollback.
