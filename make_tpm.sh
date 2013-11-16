#!/bin/sh

# Make a arpsecd_pcap_tpm quick

gcc -g -pg arpsecd.c AsLog.c AsLogic.c AsTMeasure.c AsKrnRelay.c AsNetlink.c AsTpmDB.c AsWhiteList.c AT.c tpmw.c timer_queue.c timer_thread.c AsPcap.c AsKrnProc.c AsNet.c AsNeighbor.c AsControl_tpm.c -lgcrypt -ltspi -lpthread -lpcap -lnet -lnetlink -o arpsecd_pcap_tpm -I/usr/local/gprolog-1.4.2/include
