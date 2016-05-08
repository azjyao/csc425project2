/*

Implementing an arp_cache

*/
#include "sr_router.h"
#include "sr_arp_cache.h"

void arp_cache_init(struct sr_arp_cache* arp_cache){
	memset(arp_cache->cache, 0, sizeof(arp_cache->cache));
}

void arp_cache_refresh(struct sr_arp_cache* arp_cache){
	struct timeval current_time;
	memset(&current_time, 0, sizeof(current_time));
	gettimeofday(&current_time, NULL);
	int curr_sec = current_time.tv_sec;
	int i;
	for(i = 0; i < MAX_SIZE; i++){
		if(arp_cache->cache[i].ip_addr != 0){
			if((curr_sec - arp_cache->cache[i].init_time) > ENTRY_LIFETIME){
				memset(&(arp_cache->cache[i]), 0, sizeof(struct arp_cache_entry));
			}
		}
	}
}

int arp_cache_insert(struct sr_arp_cache* arp_cache, uint32_t ip, unsigned char* hardware){
	int not_full = 0;
	struct timeval current_time;
	memset(&current_time, 0, sizeof(current_time));
	gettimeofday(&current_time, NULL);
	int curr_sec = current_time.tv_sec;
	int i;
	for(i = 0; i < MAX_SIZE; i++){
		if(arp_cache->cache[i].ip_addr == 0){
			arp_cache->cache[i].ip_addr = ip;
			memcpy(arp_cache->cache[i].hardware_addr, hardware, sizeof(unsigned char)*ETHER_ADDR_LEN);
			arp_cache->cache[i].init_time = curr_sec;
			not_full = 1;
			break;
		}
	}
	return not_full;
}

int arp_cache_lookup(struct sr_arp_cache* arp_cache, uint32_t ip, unsigned char* hardware){
	arp_cache_refresh(arp_cache);
	int found = 0;
	int i;
	struct timeval current_time;
	memset(&current_time, 0, sizeof(current_time));
	gettimeofday(&current_time, NULL);
	int curr_sec = current_time.tv_sec;
	for(i = 0; i < MAX_SIZE; i++){
		if(arp_cache->cache[i].ip_addr == ip){
			memcpy(hardware, arp_cache->cache[i].hardware_addr, sizeof(unsigned char)*ETHER_ADDR_LEN);
			found = 1;
			arp_cache->cache[i].init_time = curr_sec;
			break;
		}
	}
	return found;
}

int insert_packet(struct ip_packet_queue* head, uint32_t dest, uint8_t* pkt, unsigned int length, char* iface){
	struct ip_packet_queue * insert = (struct ip_packet_queue *) malloc(sizeof(struct ip_packet_queue));
	insert->dest_ip = dest;
	insert->packet = pkt;
	insert->len = length;
	insert->interface = iface;
	insert->next = NULL;

	struct ip_packet_queue * current = head;
	while(current->next != NULL){
		current = current->next;
	}
	current->next = insert;
}

