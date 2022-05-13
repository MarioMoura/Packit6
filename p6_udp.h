#ifndef P6_UDP
#define P6_UDP

#include "p6_ip.h"
#include <netinet/udp.h>
#include <stdint.h>

#define UDP_HDRLEN  8         // UDP header length, excludes data
#define UDP6_PSDHDRLEN 40
	
struct udpv6_psdhdr{
    struct in6_addr src;
    struct in6_addr dst;
	uint32_t ulpl;
	uint8_t zero[3];
	uint8_t nxthdr;
} __attribute__ ((packed));

extern struct udphdr udphdr;

int p6_udp_data( void *addr, int len);
int p6_udp_sport( uint16_t sport);
int p6_udp_dport( uint16_t dport);
int p6_udp_len( uint16_t len);
int p6_udp_checksum( uint16_t cksum);
void p6_udp_calc_cksum();
void p6_dg_cp_udp();

#endif
