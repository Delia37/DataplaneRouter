#include <netinet/in.h>
//#include <netinet/ether.h> eroare din cauza struct ether_header
#include <arpa/inet.h>
//#include <netinet/ip_icmp.h>

#include <string.h>

#include "queue.h"
#include "list.h"
#include "lib.h"
#include "protocols.h"

#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806
#define ARP_REQ 1 
#define ARP_REPLY 2
#define ICMP_ECHO 8
#define ICMP_ECHOREPLY 0
#define ICMP_TIME_EXCEEDED 11
#define ICMP_EXC_TTL 0
#define ICMP_DEST_UNREACH 3
#define ICMP_NET_UNREACH 0
#define ARPHRD_ETHER 1
#define IP_STRING 16

struct packet {
	char msg[MAX_PACKET_LEN];
	uint32_t daddr; 
	int interface;
	int len;
};

int check_broadcast(uint8_t* mac)
{
	for (int i = 0; i < 6; i++)
		if (mac[i] != 0xFF)
			return 0;
	return 1;
}

int match_array(uint8_t* arr, uint8_t* vec, int n)
{
	if (!arr || !vec || n <= 0)
		return 0;
	for (int i = 0; i < n; i++)
		if (arr[i] != vec[i])
			return 0;

	return 1;
}

struct cell* find(struct cell* list, uint32_t ip)
{
	if (list == NULL) {
		//printf("Lista e null\n");
		return NULL;
	}

	struct cell* p = list;
	while (p) {
		struct arp_table_entry* data = (struct arp_table_entry*)(p->element);
		if (data->ip == ip) {
			return p;
		}
		p = p->next;
	}
	//printf(" nu gaseste acest ip\n");
	return NULL;
}

int bit_count(uint32_t n) 
{
    int ret = 0;
    while (n) 
    {
        if (n & 1)
			ret++;
        n >>= 1;
    }
    return ret;
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	struct route_table_entry* rtable = malloc(sizeof(struct route_table_entry) * 80000);
	int rtable_entries = read_rtable(argv[1], rtable);

	// incerc sa folosesc structura data pentru tabela dinamica de ARP
	struct cell* ARP_table = NULL;
	struct queue* waiting_packets = queue_create();

	int icmp_size =  sizeof(struct iphdr) 
		 		   + sizeof(struct icmphdr)
				   + sizeof(struct ether_header);

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		uint8_t router_if_MAC[6];
		get_interface_mac(interface, router_if_MAC);
		char my_ip_addr[IP_STRING];
		strcpy(my_ip_addr, get_interface_ip(interface));

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		uint16_t ether_type = ntohs(eth_hdr->ether_type);

		// trebuie verificat daca pachetul este pentru mine
		int for_me = 0;
		int broadcast = 0;
		if (check_broadcast(eth_hdr->ether_dhost))
			broadcast = 1;
		else if (match_array(eth_hdr->ether_dhost, router_if_MAC, 6))
			for_me = 1;

		if (!for_me && !broadcast)
			continue;

		if (ether_type == ETHERTYPE_ARP)
		{
			struct arp_header* arp_content = (struct arp_header*)
										   (buf + sizeof(struct ether_header));
			// vedem daca este request sau reply
			if (ntohs(arp_content->op) == ARP_REQ)
			{
				struct arp_header arp_reply;
				memset(&arp_reply, 0, sizeof(struct arp_header));

				arp_reply.htype = htons(1); // pentru ethernet
				arp_reply.ptype = htons(ETHERTYPE_IP);
				arp_reply.hlen = 6; // 6 grupe de perechi hexa
				arp_reply.plen = 4; // 4 grupuri numere 0-255 de IP
				arp_reply.op = htons(ARP_REPLY);

				memcpy(arp_reply.sha, router_if_MAC, 6); 

				arp_reply.spa = inet_addr(my_ip_addr);
				// merge inapoi de unde a venit
				memcpy(arp_reply.tha, arp_content->sha, 6);
				// la fel si pentru IP
				arp_reply.tpa = arp_content->spa;

				// trebuie incapsulat intr-un frame de ethernet
				struct ether_header reply_ethr_hdr;
				memcpy(reply_ethr_hdr.ether_dhost, arp_content->sha, 6);
				memcpy(reply_ethr_hdr.ether_shost, router_if_MAC, 6);
				reply_ethr_hdr.ether_type = htons(ETHERTYPE_ARP);

				char reply_buf[MAX_PACKET_LEN];
				memcpy(reply_buf, &reply_ethr_hdr, sizeof(struct ether_header));
				memcpy(reply_buf + sizeof(struct ether_header), &arp_reply,
							 			sizeof(struct arp_header));

				// trimit cu acceasi lungime cu care a venit
				send_to_link(interface, reply_buf, len);

				// ar trebui bagat si un update la ARP table aici - daca nu il am deja
				struct arp_table_entry* nou = malloc(sizeof(struct arp_table_entry));
				nou->ip = arp_content->spa;
				memcpy(nou->mac, arp_content->sha, 6);
				ARP_table = cons(nou, ARP_table);
			}
			else if (ntohs(arp_content->op) == ARP_REPLY)
			{
				uint32_t ip = arp_content->spa;
				struct arp_table_entry* nou = malloc(sizeof(struct arp_table_entry));
				nou->ip = ip;
				memcpy(nou->mac, arp_content->sha, 6);
				ARP_table = cons(nou, ARP_table);

				struct queue* aux_queue = queue_create();
				while (!queue_empty(waiting_packets))
				{
					struct packet* pm = queue_deq(waiting_packets);
					if (ip == pm->daddr)
					{
						// acum stiu la ce MAC sa trimit
						struct ether_header *send_eth_hdr = (struct ether_header *)(pm->msg);
						memcpy(send_eth_hdr->ether_dhost, arp_content->sha, 6);
						
						send_to_link(pm->interface, pm->msg, pm->len);
					}
					//bag in alta coada altfel va merge la nesfarsit
					else
						queue_enq(aux_queue, pm);
				}
				waiting_packets = aux_queue;
			}							   

		}
		else if (ether_type == ETHERTYPE_IP)
		{
			struct iphdr* ip_content = (struct iphdr*)
										(buf + sizeof(struct ether_header));

			// verificam daca este un pachet valid
			uint16_t old_checksum = ntohs(ip_content->check);
			ip_content->check = 0;
			uint16_t new_checksum = checksum((uint16_t*)ip_content, sizeof(struct iphdr));
			if (new_checksum != old_checksum) {
				//printf("Are probleme cu checksum\n");
				continue;
			}
			// il refac
			ip_content->check = htons(old_checksum);

			// verific TTL
			if (ip_content->ttl <= 1)
			{
				//printf("Probleme cu TTL\n");
				char reply_buf[MAX_PACKET_LEN];
				memset(reply_buf, 0, MAX_PACKET_LEN);
																	
				struct icmphdr* reply_icmp = (struct icmphdr*)(reply_buf 
												+ sizeof(struct ether_header)
												+ sizeof(struct iphdr));
				reply_icmp->type = ICMP_TIME_EXCEEDED;
    			reply_icmp->code = ICMP_EXC_TTL;
    			reply_icmp->checksum = 0;
    			reply_icmp->un.echo.id = 1488;
    			reply_icmp->un.echo.sequence = 0;
    			reply_icmp->checksum = htons(checksum((uint16_t *)reply_icmp, sizeof(struct icmphdr)));

    			struct iphdr* reply_ip_hdr = (struct iphdr*)(reply_buf
												+ sizeof(struct ether_header));
 
				reply_ip_hdr->ihl = 5;
    			reply_ip_hdr->version = 4;
    			reply_ip_hdr->tos = 0;
    			reply_ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
    			reply_ip_hdr->id = ip_content->id;
    			reply_ip_hdr->frag_off = 0;
    			reply_ip_hdr->protocol = IPPROTO_ICMP;

    			reply_ip_hdr->daddr = ip_content->saddr;
    			reply_ip_hdr->saddr = inet_addr(my_ip_addr);
				reply_ip_hdr->ttl = 64;
				reply_ip_hdr->check = 0;
				reply_ip_hdr->check = htons(checksum((uint16_t*)reply_ip_hdr, sizeof(struct iphdr)));

				struct ether_header* reply_ethr_hdr = (struct ether_header*)reply_buf;
				reply_ethr_hdr->ether_type = htons(ETHERTYPE_IP);
                memcpy(reply_ethr_hdr->ether_dhost, eth_hdr->ether_shost, 6); 
                memcpy(reply_ethr_hdr->ether_shost, eth_hdr->ether_dhost, 6);
				
                send_to_link(interface, reply_buf, icmp_size);

                continue; //sfarsit
			}

			struct in_addr packet_sender_ipaddr; // ptr printari debug
			packet_sender_ipaddr.s_addr = ip_content->saddr; // ptr printari debug
			struct in_addr packet_dest_ipaddr;
			packet_dest_ipaddr.s_addr = ip_content->daddr;

			char dest_ip_string[IP_STRING];
		    char sender_ip_string[IP_STRING];
		    inet_ntop(AF_INET, &packet_dest_ipaddr, dest_ip_string, IP_STRING);
		    inet_ntop(AF_INET, &packet_sender_ipaddr, sender_ip_string, IP_STRING);

		    //printf("Pachetul este de la %s pentru %s\n", sender_ip_string, dest_ip_string);

		    struct icmphdr* icmp_content = (struct icmphdr*)(buf 
												+ sizeof(struct ether_header)
												+ sizeof(struct iphdr));

			// verific daca eu sunt destinatia
			if (strcmp(my_ip_addr, dest_ip_string) == 0)
			{
				if (ip_content->protocol == IPPROTO_ICMP)
				{
					

					if (icmp_content->type == ICMP_ECHO && icmp_content->code == 0)
					{
						char reply_buf[MAX_PACKET_LEN];
						memset(reply_buf, 0, MAX_PACKET_LEN);
																	
						struct icmphdr* reply_icmp = (struct icmphdr*)(reply_buf 
												+ sizeof(struct ether_header)
												+ sizeof(struct iphdr));

						reply_icmp->type = ICMP_ECHOREPLY;
    					reply_icmp->code = 0;
    					reply_icmp->checksum = 0;
    					reply_icmp->un.echo.id = icmp_content->un.echo.id;
    					reply_icmp->un.echo.sequence = icmp_content->un.echo.sequence;// 0?

    					reply_icmp->checksum = htons(checksum((uint16_t *)reply_icmp, sizeof(struct icmphdr)));

    					struct iphdr* reply_ip_hdr = (struct iphdr*)(reply_buf
												+ sizeof(struct ether_header));

    					// daca nu merge asa le iau cu memcpy din pachetul primit 
    					reply_ip_hdr->ihl = 5;
    					reply_ip_hdr->version = 4;
    					reply_ip_hdr->tos = 0;
    					reply_ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
    					reply_ip_hdr->id = ip_content->id;
    					reply_ip_hdr->frag_off = 0;
    					reply_ip_hdr->protocol = 1;

    					reply_ip_hdr->daddr = ip_content->saddr;
    					reply_ip_hdr->saddr = ip_content->daddr;
						reply_ip_hdr->ttl = 64;
						reply_ip_hdr->check = 0;
						reply_ip_hdr->check = checksum((uint16_t*)reply_ip_hdr, sizeof(struct iphdr));    					

    					struct ether_header* reply_ethr_hdr = (struct ether_header*)reply_buf;
                        memcpy(reply_ethr_hdr->ether_dhost, eth_hdr->ether_shost, 6); 
                        memcpy(reply_ethr_hdr->ether_shost, eth_hdr->ether_dhost, 6);
                        reply_ethr_hdr->ether_type = htons(ETHERTYPE_IP);

                        send_to_link(interface, reply_buf, icmp_size);
					}
				}

				continue; // daca nu e ICMP nu analizez
			}
			// am un pachet care trebuie rutat
			else
			{
				ip_content->ttl--;

				// ma uit in tabela de rutare dupa adresa IP destinatie la care trebuie sa ajunga
				int next_hop = -1;
				int next_interface = -1;

				int first = 0;
				int max_val = -1;
				int max_index = -1;
				for (int i = 0; i < rtable_entries; i++)
				{
					
					uint32_t dest_network = (ip_content->daddr & rtable[i].mask);
					if (dest_network  == rtable[i].prefix) {
						//print_ip(ntohl(rtable[i].prefix));
						//printf("<<a facut match\n");
						if (first == 0)
						{
							max_index = i;
							max_val = bit_count(rtable[i].mask);
							first = 1;
						}
						else if (bit_count(rtable[i].mask) > max_val)
						{
							max_index = i;
							max_val = bit_count(rtable[i].mask);
						}


					}
				}
				if (first)
					next_hop = max_index;

				// daca trebuie sa trimit catre o alta retea
				if (next_hop > -1)
				{
					next_interface = rtable[next_hop].interface;

					//char reply_buf[MAX_PACKET_LEN] = {0};

					ip_content->check = 0;
					ip_content->check = htons(checksum((uint16_t*)ip_content,
														sizeof(struct iphdr)));

					uint8_t next_if_MAC[6];
					get_interface_mac(next_interface, next_if_MAC);
					memcpy(eth_hdr->ether_shost, next_if_MAC, 6);

					char next_ip_addr[IP_STRING];
					strcpy(next_ip_addr, get_interface_ip(next_interface));

					//memcpy(reply_buf, buf, MAX_PACKET_LEN);
					
					struct cell* next_hop_node = find(ARP_table, rtable[next_hop].next_hop);

					if (next_hop_node)
					{
						//printf("Stiu la ce MAC sa-l trimit\n");

						memcpy(eth_hdr->ether_dhost, ((struct arp_table_entry*)(next_hop_node->element))->mac, 6);

						send_to_link(next_interface, buf, len);
						continue;
					}
					else
					{
						// sa ma bag pe mine la sender -sunt deja bagat?
						memcpy(eth_hdr->ether_shost, next_if_MAC, 6);

						struct packet* wm = malloc(sizeof(struct packet));
						memcpy(wm->msg, buf, len);
						wm->daddr = rtable[next_hop].next_hop;
						wm->interface = next_interface;
						wm->len = len;
						queue_enq(waiting_packets, wm);

						struct arp_header arp_request;
						memset(&arp_request, 0, sizeof(struct arp_header));

						arp_request.htype = htons(ARPHRD_ETHER);
						arp_request.ptype = htons(ETHERTYPE_IP);
						arp_request.hlen = 6; // 6 grupe de perechi hexa
						arp_request.plen = 4; // 4 grupuri numere 0-255 de IP
						arp_request.op = htons(ARP_REQ);

						memcpy(arp_request.sha, next_if_MAC, 6);
						arp_request.spa = inet_addr(next_ip_addr);
						memset(arp_request.tha, 0, 6);
						arp_request.tpa = rtable[next_hop].next_hop;

						struct ether_header reply_ethr_hdr;
						reply_ethr_hdr.ether_type = htons(ETHERTYPE_ARP);
						memset(reply_ethr_hdr.ether_dhost, 0xFF, 6);
						memcpy(reply_ethr_hdr.ether_shost, next_if_MAC, 6);

						char reply_buf[MAX_PACKET_LEN] = {0};
						memcpy(reply_buf, &reply_ethr_hdr, sizeof(struct ether_header));
						memcpy(reply_buf + sizeof(struct ether_header), &arp_request,
						 									sizeof(struct arp_header));

						int arp_len = sizeof(struct arp_header) 
									  + sizeof(struct ether_header);

						send_to_link(next_interface, reply_buf, arp_len); 											
					}
				}
				// trimit un ICMP destination unreachable
				else
				{
					char reply_buf[MAX_PACKET_LEN];
					memset(reply_buf, 0, MAX_PACKET_LEN);
																	
					struct icmphdr* reply_icmp = (struct icmphdr*)(reply_buf 
												+ sizeof(struct ether_header)
												+ sizeof(struct iphdr));

					reply_icmp->type = ICMP_DEST_UNREACH;
    				reply_icmp->code = ICMP_NET_UNREACH;
    				reply_icmp->checksum = 0;
    				reply_icmp->un.echo.id = icmp_content->un.echo.id;
    				reply_icmp->un.echo.sequence = icmp_content->un.echo.sequence;// 0?

    				reply_icmp->checksum = htons(checksum((uint16_t *)reply_icmp, sizeof(struct icmphdr)));

    				struct iphdr* reply_ip_hdr = (struct iphdr*)(reply_buf
												+ sizeof(struct ether_header));

    				reply_ip_hdr->ihl = 5;
    				reply_ip_hdr->version = 4;
    				reply_ip_hdr->tos = 0;
    				reply_ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
    				reply_ip_hdr->id = ip_content->id;
    				reply_ip_hdr->frag_off = 0;
    				reply_ip_hdr->protocol = IPPROTO_ICMP;

    				reply_ip_hdr->daddr = ip_content->saddr;
    				reply_ip_hdr->saddr = inet_addr(my_ip_addr);
					reply_ip_hdr->ttl = 64;
					reply_ip_hdr->check = 0;
					reply_ip_hdr->check = checksum((uint16_t*)reply_ip_hdr, sizeof(struct iphdr));

					struct ether_header* reply_ethr_hdr = (struct ether_header*)reply_buf;
					reply_ethr_hdr->ether_type = htons(ETHERTYPE_IP); 
                    memcpy(reply_ethr_hdr->ether_dhost, eth_hdr->ether_shost, 6); 
                    memcpy(reply_ethr_hdr->ether_shost, router_if_MAC, 6);
                        
					int send_len =  sizeof(struct icmphdr) + sizeof(struct iphdr) + sizeof(struct ether_header);
					send_to_link(interface, reply_buf, send_len);
				}
			}

		}
		else
		{
			; // print sau decartez
		}
	}

	// de eliberat alea doua tabele
	free(rtable);
	if (ARP_table)
		cdr_and_free(ARP_table);

	return 0;
}