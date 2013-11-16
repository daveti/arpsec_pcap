/*
 * AsNet.h
 * Header file for AsNet
 * Nov 15, 2013
 * root@davejingtian.org
 * http://davejingtian.org
 */

#ifndef AsNet_INCLUDE
#define AsNet_INCLUDE

#include <netinet/if_ether.h>

#define LL_ADDR_LEN 6

struct  fixed_ether_arp {
  struct  arphdr ea_hdr;          //fixed-size header 
  u_int8_t arp_sha[ETH_ALEN];    //sender hardware address 
  u_int8_t arp_spa[4];           // sender protocol address 
  u_int8_t arp_tha[ETH_ALEN];    //target hardware address 
  u_int8_t arp_tpa[4];            //target protocol address 
};

/* Ethernet header */
struct sniff_ethernet {
  u_char  ether_dhost[ETHER_ADDR_LEN];    /* Destination host address */
  u_char  ether_shost[ETHER_ADDR_LEN];    /* Source host address */
  u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* Methods */
libnet_t * init_packet_injection(char *device,char *errbuf);
int send_arp_packet(libnet_t *l,struct libnet_arp_hdr *arp,unsigned char *payload,int paylen);
int get_ip(libnet_t *l);
char * get_mac(libnet_t *l);
u_int32_t str2ip(const char *ip);
char * ip2str(u_int32_t ip);
unsigned char * str2mac(const u_char *ll_addr);
char * mac2str(const u_char * mac);

#endif
