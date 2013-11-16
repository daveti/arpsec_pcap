#!/bin/sh

# Make a arpsecd_pcap_nologic quick

gcc -g -pg arpsecd.c AsLog.c AsLogic.c AsTMeasure.c AsKrnRelay.c AsNetlink.c AsTpmDB.c AsWhiteList.c AT.c tpmw.c timer_queue.c timer_thread.c AsPcap.c AsKrnProc.c AsNet.c AsNeighbor.c AsControl_nologic.c -lgcrypt -ltspi -lpthread -lpcap -lnet -lnetlink -o arpsecd_pcap_nologic -I/usr/local/gprolog-1.4.2/include
