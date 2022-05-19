#ifndef P6_ETHER
#define P6_ETHER

#include <stdint.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/ethernet.h>

extern uint8_t *datagram;
extern uint32_t datagram_len;
extern struct ether_header eth_hdr;

int p6_dg_init();
int p6_ether_set_src( char *string);
int p6_ether_set_dst( char *string);
int p6_ether_set_type( uint16_t type);
int p6_dg_copy_ether();
int p6_dg_copy( void *addr, int len );
int p6_dg_send( char *iface);
int p6_dg_free();
uint16_t p6_ether_typestr( char *str );

#endif
