/*
 * AsPcap.c
 * Source file for AsPcap
 * Nov 15, 2013
 * root@davejingtian.org
 * http://davejingtian.org
 */

#include <pcap.h>
#include "AsPcap.h"
#include "AsLog.h"

/*
 *  init_capture 
 *  initializes the capture library (pcap). return a device and descriptor 
 *  that can be used to capture packets, all parameters are updated by the fucnction.
 */
pcap_t * init_capture() {

  bpf_u_int32 netp;
  bpf_u_int32 maskp;
  char errbuf[PCAP_ERRBUF_SIZE];  /* Error buffer */
  char *dev;
  pcap_t *descr;
  struct bpf_program bpf_prog;          

 
  /* Open the device for capture*/
  descr = pcap_open_live(PCAP_IFACE, PCAP_BUFSIZ, PCAP_PROMISC_FALSE, PCAP_TIMEOUT, errbuf);
  if (descr == NULL) {
    error_msg(errbuf);
  }

  if (pcap_lookupnet(PCAP_IFACE, &netp, &maskp, errbuf) == -1) {
    error_msg(errbuf);
  }

  if (pcap_compile(descr, &bpf_prog, PCAP_FILTER, PCAP_OPTIMIZE, netp) == -1) {
    error_msg("pcap_compile error\n");
  }

  if (pcap_setfilter(descr, &bpf_prog) == -1) {
    error_msg("pcap_setfilter error\n");
  }

  return descr;

}

void close_capture(pcap_t *descr) {

  pcap_close(descr);
   
}

void start_capture(pcap_t *descr, pcap_handler process_packet) {

  pcap_loop(descr, -1, process_packet, NULL);

}

