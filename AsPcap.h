/*
 * AsPcap.h
 * Header file for AsPcap
 * Nov 14, 2013
 * root@davejingtian.org
 * http://davejingtian.org
 */

#ifndef AsPcap_INCLUDE
#define AsPcap_INCLUDE

/* Defines */
#define PCAP_IFACE "any"
#define PCAP_FILTER "arp"
#define PCAP_PROMISC_FALSE 0
#define PCAP_TIMEOUT 0
#define PCAP_OPTIMIZE 1 
#define PCAP_BUFSIZ 1550

/* Methods */
pcap_t * init_capture();
void close_capture(pcap_t *descr);
void start_capture(pcap_t *descr, pcap_handler process_packet);

#endif
