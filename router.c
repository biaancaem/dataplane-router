#include<string.h>
#include <arpa/inet.h>
#include<stdlib.h>
#include<stdio.h>
#include <stdint.h>
#include "protocols.h"
#include "queue.h"
#include "lib.h"

#define ARP_TYPE 0x0806
#define IP_TYPE 0x0800
#define ARP_REQUEST 1
#define ARP_REPLY 2
#define ARP_HW_ETHERNET 1

queue coada_pachete;

struct route_table_entry *rtable;
int rtable_len;

struct arp_table_entry *mac_table;
int mac_table_len;

//ARP REQUEST - face broadcast cautand cine are un anumit ip si astepta mac-ul ip-ului respectiv
//			  - doar cel care are ip-ul cautat raspunde
//ARP REPLY - ip-ul cautat trimite raspuns catre router, mac-ul destinatie o sa fie cel al routerului care a intrebat
// cand primim ARP REPLY adaugam in mac_table ip-ul si mac-ul celui care a raspuns

void send_ARP_request(uint32_t ip_dest,int interface) {
	char buf[MAX_PACKET_LEN];
	memset(buf, 0, sizeof(buf));

	struct ether_hdr *eth_hdr = (struct ether_hdr *)buf;
	eth_hdr->ethr_type = htons(ARP_TYPE);
	get_interface_mac(interface, eth_hdr->ethr_shost);
	memset(eth_hdr->ethr_dhost, 0xFF, 6);
	struct arp_hdr *arp_hdr = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));
	arp_hdr->proto_type = htons(IP_TYPE); //protocol ip
	arp_hdr->hw_type = htons(ARP_HW_ETHERNET); // hw type - ethernet
	arp_hdr->hw_len = 6; // lungime adresa mac
	arp_hdr->proto_len = 4; //lungime adresa ip
	arp_hdr->opcode = htons(ARP_REQUEST);
	get_interface_mac(interface, arp_hdr->shwa);
	inet_pton(AF_INET, get_interface_ip(interface), &arp_hdr->sprotoa); // convertim ip-ul in forma binara
	memset(arp_hdr->thwa,0, 6);
	arp_hdr->tprotoa = ip_dest;
	send_to_link(sizeof(struct ether_hdr) + sizeof(struct arp_hdr),buf,interface);

}

void send_ARP_reply(char *buf, int interface) {
	//interface = interfata routerului la care e packetul acum
	//interfata sursa din buffer = interfata care trebuie sa fie destinatie
	struct ether_hdr *eth_hdr = (struct ether_hdr *)buf;
	memcpy(eth_hdr->ethr_dhost,eth_hdr->ethr_shost,6);
	get_interface_mac(interface, eth_hdr->ethr_shost);

	struct arp_hdr *arp_hdr = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));
	arp_hdr->proto_type = htons(IP_TYPE);
	arp_hdr->hw_type = htons(ARP_HW_ETHERNET);
	arp_hdr->hw_len = 6;
	arp_hdr->proto_len = 4;
	arp_hdr->opcode = htons(ARP_REPLY);
	memcpy(arp_hdr->thwa,arp_hdr->shwa,6);
	arp_hdr->tprotoa = arp_hdr->sprotoa;//setam destinatia ca find sursa de unde a venit pachetu;
	get_interface_mac(interface, arp_hdr->shwa); //macul nostru ca sursa
	inet_pton(AF_INET, get_interface_ip(interface), &arp_hdr->sprotoa);
	send_to_link(sizeof(struct ether_hdr) + sizeof(struct arp_hdr),buf,interface);

}


//STRUCTURA BUF
//1. Ethernet (14 bytes)
//2. IP Nou (20 bytes)
//3. ICMP Header (8 bytes)
//4. Copia IP Vechi (20 bytes)
//5. 8 bytes date vechi (8 bytes)
void send_icmp(char *buf,int interface,int type,int code) {
	//[ether_hdr [ip_nou [icmp [ip_vechi]]]]
	struct ether_hdr *eth_hdr = (struct ether_hdr *)buf;
    struct ip_hdr *ip_hdr = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));
	struct icmp_hdr *icmp = (struct icmp_hdr *)(buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));

	//daca este un mesaj de eroare
	if (type != 0) {
		//copiem vechile date si vechiul header ip
		char ip_vechi_si_date[sizeof(struct ip_hdr) + 8];
		memcpy(ip_vechi_si_date, ip_hdr, sizeof(struct ip_hdr) + 8);
		ip_hdr->tot_len = htons(sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + sizeof(ip_vechi_si_date));
		memset(&icmp->un_t, 0, sizeof(icmp->un_t));
		memcpy((char *)icmp + sizeof(struct icmp_hdr), ip_vechi_si_date, sizeof(ip_vechi_si_date));
	}

	//inversare adrese mac
	uint8_t mac_aux[6];
	memcpy(mac_aux,eth_hdr->ethr_dhost,6);
	memcpy(eth_hdr->ethr_dhost,eth_hdr->ethr_shost,6);
	memcpy(eth_hdr->ethr_shost,mac_aux,6);

	//inversare ip;
	ip_hdr->dest_addr = ip_hdr->source_addr;
	inet_pton(AF_INET, get_interface_ip(interface), &ip_hdr->source_addr);
	//modificare header_ip
	ip_hdr->proto = 1;//pt icmp
	ip_hdr->checksum = 0;
	ip_hdr->ttl = 64;
	ip_hdr->checksum = htons(checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr))) ;

	//setam campurile pt icmp
	icmp->mtype = type;
	icmp->mcode = code;
	icmp->check = 0;
	// calculam lungimea icmp
	int lungime_icmp = ntohs(ip_hdr->tot_len) - sizeof(struct ip_hdr);
	icmp->check = htons(checksum((uint16_t *)icmp,lungime_icmp));
	send_to_link(sizeof(struct ether_hdr) + ntohs(ip_hdr->tot_len),buf,interface);
}

int cmp(const void *a,const void *b) {
	struct route_table_entry *entry_a = (struct route_table_entry *)a;
	struct route_table_entry *entry_b = (struct route_table_entry *)b;
	if (ntohl(entry_a->prefix) <  ntohl(entry_b->prefix) ) {
		return -1;
	} else if (ntohl(entry_a->prefix) > ntohl(entry_b->prefix)) {
		return 1;
	} else {
		if (ntohl(entry_a->mask) < ntohl(entry_b->mask)) {
			return -1;
		} else if (ntohl(entry_a->mask) > ntohl(entry_b->mask)) {
			return 1;
		}else
			return 0;
	}
}

// struct route_table_entry *get_best_route(uint32_t ip_dest) {
//
// 	struct route_table_entry *best_route = NULL;
// 	for (int i = 0; i < rtable_len; i++) {
// 		if ((ip_dest & rtable[i].mask) == rtable[i].prefix) {
// 			if (best_route == NULL || ntohl(rtable[i].mask) > ntohl(best_route->mask)) {
// 				best_route = &rtable[i];
// 			}
// 		}
// 	}
// 	return best_route;
// }

struct route_table_entry *get_best_route(uint32_t ip_dest) {
	struct route_table_entry *best_route = NULL;
	int left = 0;
	int right = rtable_len - 1;

	while (left <= right) {
		int mij = left + (right - left) / 2;
		if ((ip_dest & rtable[mij].mask) == rtable[mij].prefix){
			//daca adresa ip se potriveste salvam ruta dar cautam in continuare
			//o masca mai specifica,mai in dreapta
			best_route = &rtable[mij];
			left = mij + 1;
		}
		else if (ntohl(ip_dest) < ntohl(rtable[mij].prefix)) {
			right = mij - 1;
		} else {
			left = mij + 1;
		}
	}
	return best_route;
}

struct arp_table_entry *get_arp_entry(uint32_t given_ip) {
	for (int i = 0; i < mac_table_len; i++) {
		if (given_ip == mac_table[i].ip) {
			return &mac_table[i];
		}
	}
	return NULL;
}
//functie pentru trimiterea pachetului din coada
int procesare_pachet(char *pachet) {
	struct ether_hdr *eth_hdr = (struct ether_hdr *)pachet;
			struct ip_hdr *ip_hdr = (struct ip_hdr *)(pachet + sizeof(struct ether_hdr));
			//size_t pkt_len = sizeof(struct ether_hdr) + ntohs(ip_h->tot_len);
			struct route_table_entry *best_route = get_best_route(ip_hdr->dest_addr);
			struct arp_table_entry *destination_mac = get_arp_entry(best_route->next_hop);
			if (destination_mac == NULL) {
				//daca nu avem mac il punem in coada temporala pt retrimitere
				return 0;
			}
			get_interface_mac(best_route->interface, eth_hdr->ethr_shost);
			memcpy(eth_hdr->ethr_dhost, destination_mac->mac, 6);
			send_to_link(sizeof(struct ether_hdr) + ntohs(ip_hdr->tot_len), pachet, best_route->interface);
			free(pachet);
			return 1;
}

void send_ARP_reply_logic(char *buf, int interface) {
	struct arp_hdr *arp_hdr = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));
	if (ntohs(arp_hdr->opcode) == ARP_REQUEST) {
		//daca am primit un
		send_ARP_reply(buf, interface);
	} else if (ntohs(arp_hdr->opcode) == ARP_REPLY) {
		//adaugam intrarea in tabel
		mac_table[mac_table_len].ip =arp_hdr->sprotoa;
		memcpy(mac_table[mac_table_len].mac, arp_hdr->shwa, 6);
		mac_table_len++;

		queue coada_netrimise = create_queue();
		//cat timp coada de pachete nu e goala
		while (queue_empty(coada_pachete) != 1) {
			//extragem cate un pachet si verificam daca exista adresa mac pt unde vrea sa ajunga
			char *pachet = (char *)queue_deq(coada_pachete);
			if (procesare_pachet(pachet) == 0)
				queue_enq(coada_netrimise, pachet );
		}
		coada_pachete = coada_netrimise;
	}
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];
	coada_pachete = create_queue(); //coada pentru pachetele care asteapta sa afle MAC pt next hop


	// Do not modify this line
	init(argv + 2, argc - 2);

	rtable = malloc(sizeof(struct route_table_entry) * 800000);
	/* DIE is a macro for sanity checks */
	DIE(rtable == NULL, "memory");

	mac_table = malloc(sizeof(struct arp_table_entry) * 100);
	DIE(mac_table == NULL, "memory");

	/* Read the static routing table and the MAC table */
	rtable_len = read_rtable(argv[1], rtable);
	//mac_table_len = parse_arp_table("arp_table.txt", mac_table);
	mac_table_len = 0;

	//sortam tabela de routare
	qsort(rtable, rtable_len, sizeof(struct route_table_entry), cmp);

	while (1) {

		size_t len;

		int interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "get_message");
		printf("We have received a packet\n");

    // TODO: Implement the router forwarding logic

    /* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */
		struct ether_hdr *eth_hdr = (struct ether_hdr *) buf;

		if (ntohs(eth_hdr->ethr_type) == ARP_TYPE) {
			send_ARP_reply_logic(buf,interface);
			continue;
		}

		struct ip_hdr *ip_header = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));
		if (checksum((uint16_t *)ip_header, sizeof(struct ip_hdr)) != 0) {
			printf("Ignored packet with invalid checksum\n");
			continue;
		}
		uint32_t router_ip = inet_addr(get_interface_ip(interface));

		if (ip_header->dest_addr == router_ip) {
			//daca e ICMP Echo Request, trimitem ICMP Echo Reply
			struct icmp_hdr *icmp = (struct icmp_hdr *)(buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
			if (ip_header->proto == 1 && icmp->mtype == 8) {
				 send_icmp(buf,interface,0,0);
				continue;
			}
		}

		if (ip_header->ttl <= 1) {
			//ICMP Time Exceeded
			send_icmp(buf, interface, 11, 0);
			continue;
		}
		ip_header->ttl -= 1;

		struct route_table_entry *best_route = get_best_route(ip_header->dest_addr);
		if (best_route == NULL) {
			//ICMP Dest Unreachable
			send_icmp(buf, interface, 3, 0);
			continue;
		}
		ip_header->checksum = 0; //resetam campul inainte sa recalculam
		ip_header->checksum = htons(checksum((uint16_t *)ip_header, sizeof(struct ip_hdr))) ;

		struct arp_table_entry *destination_mac = get_arp_entry(best_route->next_hop);
		//daca ip-ul up next_hop-ului nu s-a gasit in mac_table trimit un arp request pt a afla mac-ul destinatie
		if (destination_mac == NULL) {
			char *pachet = malloc(len);
    		memcpy(pachet, buf, len);
    		queue_enq(coada_pachete, pachet);
    		send_ARP_request(best_route->next_hop, best_route->interface);
    		continue;
		}
		//avem mac-ul destinatiei si trimitem pachetul
		get_interface_mac(best_route->interface, eth_hdr->ethr_shost);
		memcpy(eth_hdr->ethr_dhost, destination_mac->mac, 6);
		send_to_link(len, buf, best_route->interface);

	}
	return 0;
}