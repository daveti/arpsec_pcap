# Make for arpsec pcap kernel module
# Nov 15, 2013
# daveti@cs.uoregon.edu
# Oct 15, 2013
# Replace CFLAGS with ccflags-y
# root@davejingtian.org
# http://davejingtian.org

INSTALL = install

KVER    := $(shell uname -r)
ARP_PACKET_TYPE_ADDR :=$(shell grep -w arp_packet_type /boot/System.map-$(KVER) | awk {'print "0x"$$1'})
#CFLAGS += -DARP_PACKET_TYPE_ADDR=$(ARP_PACKET_TYPE_ADDR)
ccflags-y += -DARP_PACKET_TYPE_ADDR=$(ARP_PACKET_TYPE_ADDR)

ifneq ($(KERNELRELEASE),) 
obj-m	:= arpsec_mod.o

else
KDIR	:= /lib/modules/$(shell uname -r)/build
PWD	:= $(shell pwd)

default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
endif


install:
	$(INSTALL) -d /lib/modules/`uname -r`/kernel/net/ipv4
	$(INSTALL) -m 744 arpsec_mod.ko /lib/modules/`uname -r`/kernel/net/ipv4

clean:
	rm *.o *.ko *~
