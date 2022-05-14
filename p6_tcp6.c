#include "p6_tcp6.h"
#include <string.h>
#include <stdlib.h>

struct tcp_header tcphdr;
void *tcpdata;
int tcpdatalen = 0;

struct tcpv6_psdhdr psdhdr_preamble;
uint8_t *psdhdr;
int psdhdrlen;

uint16_t checksum (uint16_t *addr, int len) {
  int count = len;
  register uint32_t sum = 0;
  uint16_t answer = 0;
  // Sum up 2-byte values until none or only one byte left.
  while (count > 1) {
    sum += *(addr++);
    count -= 2;
  }
  // Add left-over byte, if any.
  if (count > 0) {
    sum += *(uint8_t *) addr;
  }
  // Fold 32-bit sum into 16 bits; we lose information by doing this,
  // increasing the chances of a collision.
  // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }
  // Checksum is one's compliment of sum.
  answer = ~sum;

  return (answer);
}

void p6_tcp_sport( uint16_t sport ){
	tcphdr.sport = htons( sport );
}
void p6_tcp_dport( uint16_t dport ){
	tcphdr.dport = htons( dport );
}
void p6_tcp_seq( uint32_t seq ){
	tcphdr.seq = htonl( seq );
}
void p6_tcp_ack( uint32_t ack ){
	tcphdr.ack = htonl( ack );
}
void p6_tcp_doff( uint8_t doff ){
	tcphdr.doff = ( doff << 4 );
}
void p6_tcp_fns( char flag ){
	if(flag)
		tcphdr.doff = tcphdr.doff | 1;
	else
		tcphdr.doff = tcphdr.doff | 0;
}
void p6_tcp_fcwr( char flag ){
	if(flag)
		tcphdr.flags.crw = 1;
	else
		tcphdr.flags.crw = 0;
}

void p6_tcp_fece( char flag ){
	if(flag)
		tcphdr.flags.ece = 1;
	else
		tcphdr.flags.ece = 0;
}

void p6_tcp_furg( char flag ){
	if(flag)
		tcphdr.flags.urg = 1;
	else
		tcphdr.flags.urg = 0;
}
void p6_tcp_fack( char flag ){
	if(flag)
		tcphdr.flags.ack = 1;
	else
		tcphdr.flags.ack = 0;
}
void p6_tcp_fpsh( char flag ){
	if(flag)
		tcphdr.flags.psh = 1;
	else
		tcphdr.flags.psh = 0;
}
void p6_tcp_frst( char flag ){
	if(flag)
		tcphdr.flags.rst = 1;
	else
		tcphdr.flags.rst = 0;
}
void p6_tcp_fsyn( char flag ){
	if(flag)
		tcphdr.flags.syn = 1;
	else
		tcphdr.flags.syn = 0;
}
void p6_tcp_ffin( char flag ){
	if(flag)
		tcphdr.flags.fin = 1;
	else
		tcphdr.flags.fin = 0;
}
void p6_tcp_win( uint16_t win ){
	tcphdr.win = htons( win );
}
void p6_tcp_cksum( uint16_t cksum ){
	tcphdr.cksum = htons( cksum );
}
void p6_tcp_calc_cksum(){
	p6_tcp_cksum( 0 );
	psdhdrlen = TCP_HDRLEN + TCP6_PSDHDRLEN + tcpdatalen;
	psdhdr = malloc( psdhdrlen * sizeof( uint8_t ));

	memcpy(&(psdhdr_preamble.dst), &(ip_hdr.dst), sizeof( struct in6_addr));
	memcpy(&(psdhdr_preamble.src), &(ip_hdr.src), sizeof( struct in6_addr));

	psdhdr_preamble.ulpl = htonl( TCP_HDRLEN + tcpdatalen );
	psdhdr_preamble.nxthdr = P_TCP;

	memcpy( psdhdr, &psdhdr_preamble, TCP6_PSDHDRLEN);
	memcpy( psdhdr + TCP6_PSDHDRLEN, &(tcphdr), TCP_HDRLEN);
	memcpy( psdhdr + TCP6_PSDHDRLEN + TCP_HDRLEN, tcpdata, tcpdatalen);
	tcphdr.cksum = checksum((uint16_t *) psdhdr, psdhdrlen);;

	free(psdhdr);
}
void p6_tcp_urg( uint16_t urg ){
	tcphdr.urg = htons( urg );
}
void p6_tcp_data( void *addr, int len ){
	tcpdata = addr;
	tcpdatalen = len;
}
void p6_dg_cp_tcp(){
	p6_dg_copy(&(tcphdr), TCP_HDRLEN );
	if(tcpdatalen){
		p6_dg_copy( tcpdata, tcpdatalen);
	}
}
