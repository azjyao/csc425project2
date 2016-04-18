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


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "vnscommand.h"
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

    /* Add initialization code here! */

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
        ahdr = (struct sr_arphdr *) (packet + sizeof(struct sr_ethernet_hdr));;
        printf("Hardware addr format: %d\n", ntohs(ahdr->ar_hrd));
	printf("Protocol addr format: %d\n", ntohs(ahdr->ar_pro));
	printf("Hardware addr length: %d\n", ntohs(ahdr->ar_hln));
	printf("Protocol addr length: %d\n", ntohs(ahdr->ar_pln));
       	printf("ARP_opcode: %d\n", ntohs(ahdr->ar_op));
	int pos = 0;
  	uint8_t cur;
  	for (; pos < ETHER_ADDR_LEN; pos++) {
    		cur = (ahdr->ar_sha)[pos];
    		if (pos > 0)
      			fprintf(stderr, ":");
    		fprintf(stderr, "%02X", cur);
  	}
  	fprintf(stderr, "\n");
	uint32_t ip = ntohl(ahdr->ar_sip);
	uint32_t curOctet = ip >> 24;
  	fprintf(stderr, "%d.", curOctet);
  	curOctet = (ip << 8) >> 24;
  	fprintf(stderr, "%d.", curOctet);
  	curOctet = (ip << 16) >> 24;
  	fprintf(stderr, "%d.", curOctet);
  	curOctet = (ip << 24) >> 24;
  	fprintf(stderr, "%d\n", curOctet);
  	int pos1 = 0;
  	uint8_t curr;
	for (; pos1 < ETHER_ADDR_LEN; pos1++) {
    		curr = (ahdr->ar_tha)[pos1];
    		if (pos1 > 0)
 	     		fprintf(stderr, ":");
	     	fprintf(stderr, "%02X", curr);
	}
	fprintf(stderr, "\n");
  ip = ntohl(ahdr->ar_tip);
  uint32_t curOctet1 = ip >> 24;
  fprintf(stderr, "%d.", curOctet1);
  curOctet1 = (ip << 8) >> 24;
  fprintf(stderr, "%d.", curOctet1);
  curOctet1 = (ip << 16) >> 24;
  fprintf(stderr, "%d.", curOctet1);
  curOctet1 = (ip << 24) >> 24;
  fprintf(stderr, "%d\n", curOctet1);
    } else {
        printf("In else statement\n");
    }
    printf("*** -> Receiving packet type is: %x", ntohs(ehdr->ether_type));
    printf("*** -> Receiving interface is: %s",interface);
    printf("*** -> Interface ethernet addr is: ");
    struct sr_if* rec_if = sr_get_interface(sr, interface);
    int pos2 = 0;
    uint8_t curr1;
  for (; pos2 < ETHER_ADDR_LEN; pos2++) {
        curr1 = (rec_if->addr)[pos2];
        if (pos2 > 0)
          printf(stderr, ":");
        printf(stderr, "%02X", curr1);
  }
    printf("*** -> Received packet of length %d \n",len);


}/* end sr_ForwardPacket */


/*--------------------------------------------------------------------- 
 * Method: 
 *
 *---------------------------------------------------------------------*/
