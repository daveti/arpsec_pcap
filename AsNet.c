/*
 * AsNet.c
 * Source file for AsNet
 * Nov 15, 2013
 * root@davejingtian.org
 * http://davejingtian.org
 */

#include <libnet.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>

#include "AsTime.h"
#include "AsNet.h"


libnet_t * init_packet_injection(char *device,char *errbuf) 
{
  libnet_t *l;

  l = libnet_init(LIBNET_LINK_ADV,device,errbuf);                              
  return l;
}


int send_arp_packet(libnet_t *l,struct libnet_arp_hdr *arp,unsigned char *payload,int paylen) {

    int c;
    libnet_ptag_t t;
    struct fixed_ether_arp *earp;
    
    u_int8_t *packet;
    u_int32_t packet_s;
    
    //wl_uint64_t t1,t2,t3,t4,t5,t6,diff1,diff2,diff3,diff4;
    //wl_current_time(&t1);

    earp = (struct fixed_ether_arp *)arp;

    t = libnet_build_arp(
	  ntohs(arp->ar_hrd),                     /* hardware addr */
	  ntohs(arp->ar_pro),                     /* protocol addr */
	  arp->ar_hln,                            /* hardware addr size */
	  arp->ar_pln,                            /* protocol addr size */
	  ntohs(arp->ar_op),                      /* operation type */
	  earp->arp_sha,                          /* sender hardware addr */
	  earp->arp_spa,                          /* sender protocol addr */
	  earp->arp_tha,                          /* target hardware addr */
	  earp->arp_tpa,                          /* target protocol addr */
	  payload,                                   /* payload */
	  paylen,                                      /* payload size */
	  l,                                      /* libnet handle */
	  0);                                     /* libnet id */

    //wl_current_time(&t5);
    //diff4 = t5-t1;

    if (t == -1) {
        error_msg(libnet_geterror(l));
    }

    t = libnet_build_ethernet  	(earp->arp_tha,
				 earp->arp_sha,
				 ETHERTYPE_ARP,           //ARP packet
				 NULL,
				 0,
				 l,
				 0);  	

    if (t == -1) {
      error_msg(libnet_geterror(l));
    }

    //wl_current_time(&t2);
    //diff1 = t2-t5;

    c = libnet_write(l);

    //wl_current_time(&t3);
    //diff2 = t3-t2;

    if (c == -1) {
      error_msg(libnet_geterror(l));
    }
    libnet_clear_packet(l);
    //wl_current_time(&t4);
    //diff3 = t4-t3;
    //printf("build arp %llu\n",diff4);
    //printf("build ethernet  %llu\n",diff1);
    //printf("write %llu \n",diff2);
    //printf("Rest of arp send %llu\n",diff3);
    return c;
}

int get_ip(libnet_t *l) {
  int myip;
  myip = libnet_get_ipaddr4(l);
  return myip;
}


char * get_mac(libnet_t *l)
{
  static char ll_addr[LL_ADDR_LEN];
  struct libnet_ether_addr *src;
  char errbuf[LIBNET_ERRBUF_SIZE];
 
  src = libnet_get_hwaddr(l);
  if (src == NULL) {
    perror("libnet_get_hwaddr");
    exit(1);
  }
  memcpy(ll_addr, src->ether_addr_octet, LL_ADDR_LEN);
  return ll_addr;
}

u_int32_t str2ip(const char *ip)
{
   return inet_addr(ip);
}

char * ip2str(u_int32_t ip)
{
  /* there are some problems with this function */
  /* multiple consecutive calls will return the same memeory address causing 
     all previous calls to have
     same value as the last call 
  */
  struct in_addr addr;
  char *net;

  addr.s_addr = ip;
  net = inet_ntoa(addr);
  return net;
}

unsigned char * str2mac(const u_char *ll_addr)
{
   static unsigned char network[6];
   int m1,m2,m3,m4,m5,m6;

   if (sscanf((char *)ll_addr, "%02X:%02X:%02X:%02X:%02X:%02X", &m1, &m2, &m3, 
                           &m4, &m5, &m6) != 6)
      return NULL;
   
   network[0] = (char) m1;
   network[1] = (char) m2;
   network[2] = (char) m3;
   network[3] = (char) m4;
   network[4] = (char) m5;
   network[5] = (char) m6;
   
   return network;
}

char * mac2str(const u_char * mac)
{
 
  static char strmac[18];
 
  sprintf(strmac, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4]
	  ,mac[5]);
  strmac[17] = '\0';
  return strmac;

}

