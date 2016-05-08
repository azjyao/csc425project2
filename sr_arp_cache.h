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

void arp_cache_init(struct sr_arp_cache*);
void arp_cache_refresh(struct sr_arp_cache*);
int arp_cache_insert(struct sr_arp_cache*, uint32_t, unsigned char*);
int arp_cache_lookup(struct sr_arp_cache*, uint32_t, unsigned char*);