/*
 * AsNeighbor.h
 * Header file for AsNeighbor
 * Nov 15, 2013
 * root@davejingtian.org
 * http://davejingtian.org
 */

#ifndef AsNeighbor_INCLUDE
#define AsNeighbor_INCLUDE

#define LL_ADDR_LEN 6

typedef struct
{
	__u8 family;
	__u8 bytelen;
	__s16 bitlen;
	__u32 data[4];
} inet_prefix;


int get_integer(int *val, char *arg, int base);
int get_addr_1(inet_prefix *addr, char *name, int family);
int get_prefix_1(inet_prefix *dst, char *arg, int family);
int get_addr(inet_prefix *dst, char *arg, int family);

void neigh_add(char *ll_addr, u_int32_t ip, char *iface, int nud);
void neigh_remove(char *ll_addr, u_int32_t ip, char *iface);
int ipneigh_modify(int cmd, int flags, int nud, char *ll_addr, u_int32_t ip, char *iface);

#endif
