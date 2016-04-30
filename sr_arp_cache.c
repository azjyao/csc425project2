#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
#include "sr_protocol.h"

#define MAX_SIZE 32
#define ENTRY_LIFETIME 15

struct arp_cache_entry {
	unsigned char	hardware_addr[ETHER_ADDR_LEN];
	uint32_t		ip_addr;
	int				init_time;
};

struct sr_arp_cache {
	struct arp_cache_entry cache[MAX_SIZE];
};

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