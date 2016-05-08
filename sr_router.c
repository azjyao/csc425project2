/**********************************************************************
 * file:  sr_router.c 
 * date:  Mon Feb 18 12:50:42 PST 2002  
 * Contact: casado@stanford.edu 
 *
 * Description:
 * 
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing. 11
 * 90904102
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <netinet/in.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "vnscommand.h"

 void send_arp_reply(struct sr_instance*, struct sr_arphdr*, char*);
 void process_ip_packet(struct sr_instance*, struct ip*, char*, int);
 u_short cksum(u_short*, int);
 struct sr_rt* get_nexthop(struct sr_rt*, struct in_addr*);
 int arp_cache_lookup(struct sr_arp_cache*, uint32_t, unsigned char*);
/*--------------------------------------------------------------------- 
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 * 
 *---------------------------------------------------------------------*/

 void sr_init(struct sr_instance* sr) 
 {
    /* REQUIRES */
    assert(sr);

    printf("\n*******Before arp_cache_init\n");
    /* Add initialization code here! */
    arp_cache_init(sr->arp_cache);
    printf("\n*******After arp_cache_init\n");


} /* -- sr_init -- */



/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

 void sr_handlepacket(struct sr_instance* sr, 
        uint8_t * packet/* lent */,
    unsigned int len,
        char* interface/* lent */)
    {
    /* REQUIRES */
        assert(sr);
        assert(packet);
        assert(interface);

        struct sr_ethernet_hdr *ehdr;

        ehdr = (struct sr_ethernet_hdr *)packet;
        if (ntohs(ehdr->ether_type) == ETHERTYPE_ARP) {
        /* Process the ARP packet */
            struct sr_arphdr *ahdr;
            ahdr = (struct sr_arphdr *) (packet + sizeof(struct sr_ethernet_hdr));
            send_arp_reply(sr, ahdr, interface);


        } else if(ntohs(ehdr->ether_type) == ETHERTYPE_IP) {
        /* Process the IP packet */
            struct ip *ip_hdr;
            ip_hdr = (struct ip *) (packet + sizeof(struct sr_ethernet_hdr));
            printf("We got an IP packet\n");
            process_ip_packet(sr, ip_hdr, interface, len);
        } else {
            printf("In else statement\n");
        }

        printf("*** -> Receiving packet type is: %x", ntohs(ehdr->ether_type));
        printf("*** -> Receiving interface is: %s",interface);
        /*printf("*** -> Interface ethernet addr is: ");
        struct sr_if* rec_if = sr_get_interface(sr, interface);
        int pos2 = 0;
        uint8_t curr1;
        for (; pos2 < ETHER_ADDR_LEN; pos2++) {
            curr1 = (rec_if->addr)[pos2];
            if (pos2 > 0)
              fprintf(stderr, ":");
          fprintf(stderr, "%02X", curr1);
      }*/
      printf("*** -> Received packet of length %d \n",len);

}/* end sr_ForwardPacket */


/*--------------------------------------------------------------------- 
 * Method: send_arp_reply()
 *
 *---------------------------------------------------------------------*/

 void send_arp_reply(struct sr_instance* sr, struct sr_arphdr * arp_header, char* interface){
    /* Build the ARP header for the reply message
    */
    struct sr_arphdr reply_arphdr;
    struct sr_if* sr_if = sr_get_interface(sr, interface);
    if(sr_if->ip != arp_header->ar_tip){
        return;
    }
    
    reply_arphdr.ar_hrd = htons(0x0001);
    reply_arphdr.ar_pro = htons(0x0800);
    reply_arphdr.ar_hln = ETHER_ADDR_LEN;
    reply_arphdr.ar_pln = sizeof(uint32_t);
    reply_arphdr.ar_op = htons(ARP_REPLY);
    memcpy(reply_arphdr.ar_sha, sr_if->addr, ETHER_ADDR_LEN);
    reply_arphdr.ar_sip = sr_if->ip;
    memcpy(reply_arphdr.ar_tha, arp_header->ar_sha, ETHER_ADDR_LEN);
    reply_arphdr.ar_tip = arp_header->ar_sip;

    /* Build the ethernet header for the reply message */
    struct sr_ethernet_hdr reply_ethhdr;
    reply_ethhdr.ether_type = htons(ETHERTYPE_ARP);
    memcpy(reply_ethhdr.ether_dhost, arp_header->ar_sha, ETHER_ADDR_LEN);
    memcpy(reply_ethhdr.ether_shost, sr_if->addr, ETHER_ADDR_LEN);

    unsigned int reply_ethpacket_len = sizeof(struct sr_arphdr) + sizeof(reply_ethhdr);
    uint8_t * reply_ethpacket = malloc(reply_ethpacket_len);
    memcpy(reply_ethpacket, &reply_ethhdr, sizeof(reply_ethhdr));
    memcpy(reply_ethpacket + sizeof(reply_ethhdr), &reply_arphdr, sizeof(reply_arphdr));
    sr_send_packet(sr, reply_ethpacket, reply_ethpacket_len, interface);

}

void process_ip_packet(struct sr_instance* sr, struct ip * ip_hdr, char* interface, int len){
    uint32_t dst_addr = (ip_hdr->ip_dst).s_addr;
    printf("*** -> Destination Address is: %d\n", dst_addr);
    struct sr_if* sr_if = sr_get_interface(sr, interface);
    printf("*** -> (in process_ip_packet) Interface address: %d", sr_if->ip);

    /* 
    Check if destination is us
    */
    if(sr_if->ip == dst_addr){
        printf("Destination address is ourselves, drop the packet\n");
        return;
    }

    /*
    TTL and Checksum
    */
    int iphdr_len_cksum = sizeof(struct ip)/2;
    // printf("*** -> Received checksum: %d", ip_hdr->ip_sum);
    ip_hdr->ip_sum = 0;
    // printf("*** -> Calculated checksum of Packet: %d", cksum(ip_hdr, iphdr_len_cksum));

    // printf("*** -> Old TTL of packet: %d", ip_hdr->ip_ttl);
    ip_hdr->ip_ttl--;
    // printf("*** -> New TTL of packet: %d", ip_hdr->ip_ttl);
    if(ip_hdr->ip_ttl == 0){
        printf("TTL is 0, drop the packet\n");
        return;
    }

    ip_hdr->ip_sum = (uint16_t) cksum(ip_hdr, iphdr_len_cksum);
    printf("*** -> New Checksum of Packet: %d", ip_hdr->ip_sum);

    /* Find ip address of next hop */
    struct sr_rt* nexthop_rt_entry = get_nexthop(sr->routing_table, &(ip_hdr->ip_dst));
    printf("interface of next hop: %s\n", nexthop_rt_entry->interface);


    unsigned char* nexthop_hdw_addr = malloc(ETHER_ADDR_LEN*sizeof(unsigned char));
    if(arp_cache_lookup(sr->arp_cache, nexthop_rt_entry->dest.s_addr, nexthop_hdw_addr) == 0){
        // Not in arp_cache
        //send arp request
    }
    else{
        printf("Next hop hardware_addr:");
        int pos2 = 0;
        uint8_t curr1;
        for (; pos2 < ETHER_ADDR_LEN; pos2++) {
            curr1 = (nexthop_hdw_addr)[pos2];
            if (pos2 > 0)
              fprintf(stderr, ":");
          fprintf(stderr, "%02X", curr1);
      }
    }

    return;
}

u_short cksum(u_short *buf, int count)
{
    register u_long sum = 0;
    while (count--)
    {
        sum += *buf++;
        if (sum & 0xFFFF0000)
        {
/* carry occurred,
so wrap around */
            sum &= 0xFFFF;
            sum++;
        }
    }
    return ~(sum & 0xFFFF);
}

struct sr_rt* get_nexthop(struct sr_rt* routing_table, struct in_addr* ip_dst){
    uint32_t dst_addr = ip_dst->s_addr;
    struct sr_rt* table_entry = routing_table;
    uint32_t best_match_mask = 0;
    struct sr_rt* best_match = 0;

    while(table_entry != 0){
        /*
        Check is the table entry is a match, and then check if it a longer match
        */
        if((table_entry->mask.s_addr & table_entry->dest.s_addr) == (dst_addr & table_entry->mask.s_addr)){

            if(table_entry->mask.s_addr > best_match_mask){
                best_match_mask = table_entry->mask.s_addr;
                best_match = table_entry;
            }
            
        }
        table_entry = table_entry->next;
    }

    return best_match;
}
