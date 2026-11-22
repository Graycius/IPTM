# IPTM 5.30.9 — Associazione ingresso LAN e anti-spoof IPv4

## Protezione del traffico in ingresso

Le autorizzazioni `INPUT` con sorgente in una subnet LAN attendibile vengono associate a `-i <interfaccia>` se il percorso è verificabile. La stessa limitazione viene applicata ai salti `FORWARD` verso `IPTM-LAN-EGRESS`, alle autorizzazioni `FORWARD` gestite da IPTM e al DNAT DNS IPv4 `nat/PREROUTING` proveniente dalla LAN. Nessuna regola `POSTROUTING` riceve `-i` (opzione non supportata nella chain).

La pagina **WAN, LAN e NAT** permette di associare esplicitamente un CIDR a un ingresso, ad esempio `192.168.10.0/24=bond0.10,10.19.165.0/24=wg0`. La mappatura è ammessa solo quando il CIDR è compreso nelle reti LAN configurate e l'interfaccia esiste, non è la WAN e non è marcata come esterna non fidata. Sono escluse sequenze malevole, CIDR non canonici, duplicati e interfacce arbitrarie. Le impostazioni salvate persistono, e la UI visualizza il risultato per ciascuna subnet senza modificare il firewall attivo.

## Anti-spoofing

Le regole `-i <ingresso esterno> -s <RFC1918> -j DROP` vengono generate in `filter/INPUT` e `filter/FORWARD` solo con un ingresso distinto dalle LAN e identificato con un solo indirizzo IPv4 pubblico. Le interfacce esterne ulteriori sono selezionabili esplicitamente e verificate prima della generazione. Doppio NAT, WAN a indirizzo privato o misto, `single_nic`, LAN/VPN con indirizzi locali e topologie ambigue vengono lasciate senza il blocco automatico, con avviso in bozza e anteprima. I controlli `bogon_wan` invasivi sono inoltre sospesi quando non è verificabile una WAN pubblica dedicata.

## Limiti di sicurezza

Un indirizzo IP sorgente LAN da solo non dimostra l'ingresso su un'interfaccia fidata. Quando non è possibile dimostrare l'ingresso, IPTM mantiene le regole di servizio preesistenti ma segnala le subnet non verificate. Gli eventuali collegamenti L2 tra host sulla stessa rete non possono essere isolati tramite `iptables` sul gateway; servono VLAN/AP isolation. Il blocco RFC1918 su una WAN privata con gateway a monte potrebbe interrompere le risposte lecite: non viene generato automaticamente. La protezione IPv6 richiede regole dedicate e non è automaticamente derivata dal controllo IPv4.

Gli aggiornamenti software non applicano regole al kernel. È necessario rigenerare e verificare la bozza e applicarla con conferma e rollback. I test inclusi coprono casi validi, invalidi, multi-WAN, double NAT, VLAN/VPN, SSH, DoT/DNS, IoT e cambiamenti non consentiti, ma non sostituiscono un collaudo su DietPi reale.
