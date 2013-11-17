/*
 * AsNeighbor.c
 * Source file for AsNeighbor
 * Nov 15, 2013
 * root@davejingtian.org
 * http://davejingtian.org
 */

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <asm/types.h>
#include <libnetlink.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include "AsNeighbor.h"

int get_integer(int *val, char *arg, int base)
{
	long res;
	char *ptr;

	if (!arg || !*arg)
		return -1;
	res = strtol(arg, &ptr, base);
	if (!ptr || ptr == arg || *ptr || res > INT_MAX || res < INT_MIN)
		return -1;
	*val = res;
	return 0;
}

int get_addr_1(inet_prefix *addr, char *name, int family)
{
	char *cp;
	unsigned char *ap = (unsigned char*)addr->data;
	int i;

	memset(addr, 0, sizeof(*addr));

	if (strcmp(name, "default") == 0 ||
	    strcmp(name, "all") == 0 ||
	    strcmp(name, "any") == 0) {
		if (family == AF_DECnet)
			return -1;
		addr->family = family;
		addr->bytelen = (family == AF_INET6 ? 16 : 4);
		addr->bitlen = -1;
		return 0;
	}

	if (strchr(name, ':')) {
		addr->family = AF_INET6;
		if (family != AF_UNSPEC && family != AF_INET6)
			return -1;
		if (inet_pton(AF_INET6, name, addr->data) <= 0)
			return -1;
		addr->bytelen = 16;
		addr->bitlen = -1;
		return 0;
	}

	/*	if (family == AF_DECnet) {
		struct dn_naddr dna;
		addr->family = AF_DECnet;
		if (dnet_pton(AF_DECnet, name, &dna) <= 0)
			return -1;
		memcpy(addr->data, dna.a_addr, 2);
		addr->bytelen = 2;
		addr->bitlen = -1;
		return 0;
	}
	*/
	addr->family = AF_INET;
	if (family != AF_UNSPEC && family != AF_INET)
		return -1;
	addr->bytelen = 4;
	addr->bitlen = -1;
	for (cp=name, i=0; *cp; cp++) {
		if (*cp <= '9' && *cp >= '0') {
			ap[i] = 10*ap[i] + (*cp-'0');
			continue;
		}
		if (*cp == '.' && ++i <= 3)
			continue;
		return -1;
	}
	return 0;
}

int get_prefix_1(inet_prefix *dst, char *arg, int family)
{
	int err;
	unsigned plen;
	char *slash;

	memset(dst, 0, sizeof(*dst));

	if (strcmp(arg, "default") == 0 || strcmp(arg, "any") == 0) {
		if (family == AF_DECnet)
			return -1;
		dst->family = family;
		dst->bytelen = 0;
		dst->bitlen = 0;
		return 0;
	}

	slash = strchr(arg, '/');
	if (slash)
		*slash = 0;
	err = get_addr_1(dst, arg, family);
	if (err == 0) {
		switch(dst->family) {
			case AF_INET6:
				dst->bitlen = 128;
				break;
			case AF_DECnet:
				dst->bitlen = 16;
				break;
			default:
			case AF_INET:
				dst->bitlen = 32;
		}
		if (slash) {
		  if (get_integer((int *)&plen, slash+1, 0) || plen > dst->bitlen) {
				err = -1;
				goto done;
			}
			dst->bitlen = plen;
		}
	}
done:
	if (slash)
		*slash = '/';
	return err;
}

int get_addr(inet_prefix *dst, char *arg, int family)
{
	if (family == AF_PACKET) {
		fprintf(stderr, "Error: \"%s\" may be inet address, but it is not allowed in this context.\n", arg);
		exit(1);
	}
	if (get_addr_1(dst, arg, family)) {
		fprintf(stderr, "Error: an inet address is expected rather than \"%s\".\n", arg);
		exit(1);
	}
	return 0;
}



/*
 * add an entry in the neighbor table.
 * if it already exist, replace it.
 * ll_addr and ip must be in network order
 */

void neigh_add(char *ll_addr, u_int32_t ip, char *iface, int nud)
{
  //DEBUG_MSG("neigh add %s %s %s", ha_ntoa(ll_addr), inet_ntoa(*(struct in_addr *)&ip),
  //                 iface);
   
   ipneigh_modify(RTM_NEWNEIGH, NLM_F_CREATE|NLM_F_REPLACE, nud, 
                   ll_addr, ip, iface);
}

/*
 * remove an entry from the table
 * ll_addr and ip must be in network order
 */

void neigh_remove(char *ll_addr, u_int32_t ip, char *iface)
{
  // DEBUG_MSG("neigh remove %s %s %s", ha_ntoa(ll_addr), 
  //                 inet_ntoa(*(struct in_addr *)&ip), iface);
   
   ipneigh_modify(RTM_DELNEIGH, 0, 0, ll_addr, ip, iface);
}


/*
 * netlink manipulation
 */

int ipneigh_modify(int cmd, int flags, int nud, char *ll_addr, u_int32_t ip, char *iface)
{
	struct rtnl_handle rth;
	struct {
		struct nlmsghdr 	n;
		struct ndmsg 		ndm;
		char   			   buf[256];
	} req;
   
	inet_prefix dst;
	

	memset(&req, 0, sizeof(req));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST | flags;
	req.n.nlmsg_type = cmd;
	req.ndm.ndm_family = AF_INET;
	
   /* 
    * the state of the entries 
    * SARP messages can nevere expire since they are 
    * authenticated. they will be replaced if a new
    * SARP message is received
    */
   
   req.ndm.ndm_state = nud;

   /* add the IP */
   
   get_addr(&dst, inet_ntoa(*(struct in_addr *)&ip), AF_INET);
	addattr_l(&req.n, sizeof(req), NDA_DST, &dst.data, dst.bytelen);

   /* add the link layer address */
   
	addattr_l(&req.n, sizeof(req), NDA_LLADDR, ll_addr, LL_ADDR_LEN);

   /* open the netlink socket */
   
	if (rtnl_open(&rth, 0) < 0)
	  		printf("rtnl_open()");

	ll_init_map(&rth);

   /* find the iface index */
   
	if ((req.ndm.ndm_ifindex = ll_name_to_index(iface)) == 0) 
	    printf("ll_name_to_index()");

   /* send data */
   
	if (rtnl_talk(&rth, &req.n, 0, 0, NULL, NULL, NULL) < 0)
	  	printf("rtnl_talk()");

   /* Close the netlink socket opened by the libnetlink - daveti */
   rtnl_close(&rth);
 
   return 0;
}

