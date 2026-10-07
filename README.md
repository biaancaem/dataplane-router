# Tema1 - PCom
### Militaru Elena-Bianca, 324CB

---

## Descriere generală

Această temă implementează dataplane-ul unui router în C, acoperind procesul de dirijare IPv4 cu Longest Prefix Match eficient prin Binary Search, protocolul ARP dinamic cu coadă de așteptare pentru pachetele în așteptare și protocolul ICMP cu mesaje de eroare și Echo Reply.
Pentru realizarea temei, am utilizat scheletul laboratorului 4 și am urmat detaliile din enunț privitoare la implementarea fiecărui protocol în parte.
---


## Subiect 1 – Procesul de Dirijare (IPv4 Forwarding)

### Screenshot: `Subiectul1.png`

Screenshot-ul surprinde testarea completă a procesului de dirijare IPv4 între hostul `h-0` și hostul `h-1` , cu ambele routere (`router-0` și `router-1`) pornite și funcționale. În terminalul `h-0` se observă rezultatul comenzii `ping -c 4 h1`, care a transmis cu succes 4 pachete ICMP și a primit 4 răspunsuri, cu 0% packet loss, ceea ce demonstrează că rutarea funcționează corect prin cele două routere.  În terminalul `router-0` din dreapta sus se vad mesajele `We have received a packet` care apar pentru fiecare pachet procesat de router, confirmând că routerul funcționează.

Wireshark capturat pe interfața `h-1` prezintă în detaliu întregul flux de pachete. Primele două pachete sunt ARP: routerul trimite un ARP Request broadcast ("Who has 192.168.1.2? Tell 192.168.1.1") pentru a afla MAC-ul destinației, iar `h-1` răspunde cu un ARP Reply ("192.168.1.2 is at de:ad:be:ef:00:01"). Urmează 4 perechi de pachete ICMP Echo Request și ICMP Echo Reply, toate cu TTL=63, ceea ce confirmă că routerul decrementează corect TTL-ul cu o unitate la fiecare hop. Panoul din dreapta Wireshark (Packet 3) arată detaliile complete ale unui Echo Request.
### Implementare

La primirea fiecărui pachet IP, routerul parcurge o serie de pași în ordine. Mai întâi se verifică integritatea headerului IP prin recalcularea checksum-ului: dacă valoarea obținută nu este zero, pachetul este corupt și se aruncă. Dacă pachetul are ca destinație chiar IP-ul interfeței pe care a sosit, routerul verifică dacă este un ICMP Echo Request și, dacă da, generează un Echo Reply (Type 0) înapoi spre sursă.

Dacă pachetul este destinat altui host, routerul verifică valoarea TTL. Dacă TTL-ul este mai mic sau egal cu 1, înseamnă că pachetul a depășit numărul maxim de hopuri permis și se trimite un mesaj ICMP Time Exceeded  înapoi spre sursă si apoi pachetul este aruncat. Altfel, TTL-ul este decrementat cu o unitate și checksum-ul IP este recalculat. Se calculeaza apoi cea mai buna ruta prin funcția `get_best_route`, iar dacă nu se găsește nicio rută potrivită se trimite ICMP Destination Unreachable. Dacă ruta există, se caută MAC-ul next hop-ului în tabela ARP: dacă nu există, pachetul este pus în coadă și se trimite un ARP Request, altfel se actualizează adresele MAC și pachetul este trimis pe interfața corespunzătoare.

---

## Longest Prefix Match Eficient (Binary Search)

Tabela de rutare este sortată o singură dată la inițializare folosind `qsort` cu o funcție de comparare care sortează intrările crescător după prefix și, la prefixe egale, crescător după mască. Această organizare garantează că intrările cu mască mai specifica pentru același prefix se află spre dreapta în tablou.

Algoritmul `get_best_route` implementează un Binary Search modificat care, atunci când găsește o potrivire la poziția `mij` (adică `ip_dest & mask == prefix`), salvează acea rută ca `best_route` dar continuă căutarea spre dreapta (`left = mij + 1`) în căutarea unei măști mai lungi și mai specifice. La finalul căutării, `best_route` conține întotdeauna ruta cea mai specifica. Complexitatea este O(log n) față de O(n) a căutării liniare.

---

## Subiect 2 – Protocolul ARP

### Screenshot: `Subiectul2.png`

Screenshot-ul arata funcționarea protocolului ARP dinamic. În terminalul `h-0` din centru se observă că a fost executata comanda `ping -c 1 h1` și s-a primit un răspuns complet, 1 pachet transmis, 1 primit și 0% packet loss. Aceasta demonstrează că tabela ARP a fost populată dinamic și pachetul IP a fost livrat corect după rezolvarea adresei MAC. 

In fereastra de Wireshark am folosit filtrul `arp || icmp` pentru a vedea schimbul complet de pachete.
Pachetul 1 este un ARP Request trimis de `de:ad:be:ef:00:00` cu mesajul "Who has 192.168.0.1? Tell 192.168.0.2", adică hostul caută MAC-ul gateway-ului.
Pachetul 2 este ARP Reply de la `de:fe:c8:ed:00:00` confirmând "192.168.0.1 is at de:fe:c8:ed:00:00". 
Pachetul 3 este ICMP Echo Request de la 192.168.0.2 spre 192.168.1.2, trimis imediat după ce MAC-ul a fost aflat și pachetul din coadă a putut fi livrat.
Pachetul 4 arată un nou ARP Request de la router spre h-0 pentru a-i afla MAC-ul la întoarcere, pachetul 5 este reply-ul corespunzător,
Pachetul 6 este ICMP Echo Reply de la 192.168.1.2 înapoi spre 192.168.0.2. 

### Implementare

Când routerul trebuie să trimită un pachet dar nu cunoaște MAC-ul next hop-ului, acesta salvează pachetul într-o coadă (`coada_pachete`) alocând dinamic un buffer cu `malloc` și copiind conținutul, după care trimite un ARP Request. Funcția `send_ARP_request` construiește un pachet ARP cu adresa Ethernet destinație setată la broadcast, MAC-ul și IP-ul propriu ca sursă și IP-ul căutat ca destinație, cu câmpul target MAC completat cu zerouri.

La primirea unui ARP Request, routerul răspunde automat prin `send_ARP_reply`, care inversează câmpurile sursă-destinație din headerele Ethernet și ARP, setează opcode 2 (REPLY) și completează MAC-ul propriu ca sursă. La primirea unui ARP Reply, routerul adaugă perechea IP-MAC în `mac_table` și parcurge întreaga coadă de pachete în așteptare. Pentru fiecare pachet din coadă, recalculează best route și caută din nou MAC-ul în tabela ARP actualizată: dacă MAC-ul există, completează adresele MAC și trimite pachetul, eliberând memoria alocată cu `free`; dacă MAC-ul tot nu există, pachetul este mutat într-o coadă temporară pentru a fi reîncercat ulterior.

---

## Subiect 3 – Protocolul ICMP

### Screenshot: `Subiectul3.png`

Screenshot-ul arata funcționarea protocolului ICMP. În terminalul `h-0` din stânga se observă rularea comenzii `ping -t 1 h1` , care generează 31 de pachete trimise și 0 primite cu succes, toate întorcând "From 192.168.0.1 icmp_seq=X Time to live exceeded". Aceasta confirmă că router-0 detectează corect TTL-ul expirat și generează mesajul ICMP corespunzător înainte de a arunca pachetul. Terminalul `router-0` din dreapta sus afișează continuu `We have received a packet`, confirmând că routerul procesează activ fiecare pachet primit.

Wireshark capturat pe `h-0` prezintă alternând două tipuri de pachete. Pachetele impare sunt ICMP Echo Request trimise de `192.168.0.2` spre `192.168.1.2` cu `ttl=1`, în timp ce pachetele pare sunt ICMP Time-to-live exceeded trimise înapoi. De asemenea, la pachetele 11 și 12 apar schimburi ARP intercalate, ceea ce arată că routerul face refresh ARP în mod normal în paralel cu procesarea pachetelor ICMP. Panoul inferior stâng Wireshark detaliază structura unui mesaj ICMP Time Exceeded.
### Implementare

Funcția `send_icmp(buf, interface, type, code)` construiește și trimite mesaje ICMP folosind același buffer primit ca parametru. Structura finală a pachetului construit este header Ethernet, urmat de header IP nou, urmat de header ICMP, urmat de headerul IP original și primii 8 bytes din datele originale.

Primul pas este salvarea headerului IP original împreună cu primii 8 bytes de date într-un buffer temporar `ip_vechi_si_date`, înainte ca headerul să fie suprascris.
Apoi se inversează adresele MAC din headerul Ethernet, sursa devenind destinație și invers.
La nivelul IP, adresa destinație este setată la adresa sursă originală pentru a trimite mesajul înapoi spre expeditor, iar adresa sursă este setată la IP-ul interfeței pe care a sosit pachetul (`inet_addr(get_interface_ip(interface))`), deoarece routerul este cel care generează eroarea.
Se setează protocolul la 1 (ICMP), TTL la 64 și se recalculează checksum-ul IP. Câmpurile ICMP (`mtype`, `mcode`) sunt completate cu valorile primite ca parametri, checksum-ul ICMP este calculat pe întreaga lungime a mesajului ICMP incluzând payload-ul cu datele originale, iar în final pachetul complet este trimis pe interfața pe care a venit.

