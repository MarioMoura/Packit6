#ifndef P6_TCP
#define P6_TCP

#include "p6_ether.h"
#include "p6_ip.h"

#define TCP_HDRLEN 20
#define TCP6_PSDHDRLEN 40

struct tcpv6_psdhdr{
    struct in6_addr src;
    struct in6_addr dst;
	uint32_t ulpl;
	uint8_t zero[3];
	uint8_t nxthdr;
} __attribute__ ((packed));

struct tcp_header{
	uint16_t sport;
	uint16_t dport;
	uint32_t seq;
	uint32_t ack;
	uint8_t doff;
	struct flags {
		uint8_t fin: 1;
		uint8_t syn: 1;
		uint8_t rst: 1;
		uint8_t psh: 1;
		uint8_t ack: 1;
		uint8_t urg: 1;
		uint8_t ece: 1;
		uint8_t crw: 1;
	} flags;
	uint16_t win;
	uint16_t cksum;
	uint16_t urg;
} __attribute__ ((packed));

extern struct tcp_header tcphdr;

void p6_tcp_sport( uint16_t sport );
void p6_tcp_dport( uint16_t dport );
void p6_tcp_seq( uint32_t seq );
void p6_tcp_ack( uint32_t ack );
void p6_tcp_doff( uint8_t doff );
void p6_tcp_fns( char flag );
void p6_tcp_fcwr( char flag );
void p6_tcp_fece( char flag );
void p6_tcp_furg( char flag );
void p6_tcp_fack( char flag );
void p6_tcp_fpsh( char flag );
void p6_tcp_frst( char flag );
void p6_tcp_fsyn( char flag );
void p6_tcp_ffin( char flag );
void p6_tcp_win( uint16_t win );
void p6_tcp_cksum( uint16_t cksum );
void p6_tcp_urg( uint16_t urg );
void p6_tcp_calc_cksum();
void p6_tcp_data( void *addr, int len );
void p6_dg_cp_tcp();

#endif
