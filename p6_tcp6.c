#include "p6_tcp6.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

struct tcp_header tcphdr;
void *tcpdata;
int tcpdatalen = 0;

struct tcpv6_psdhdr psdhdr_preamble;
uint8_t *psdhdr;
int psdhdrlen;

uint8_t *tcpoptions = NULL;
int tcpoptions_counter;
int tcp_options_len;
int tcpoptions_words;
struct mss_struct mss;
char mss_set = 0;
struct wsf_struct wsf;
char wsf_set = 0;
struct sap_struct sap;
char sap_set = 0;
struct tstmp_struct tstmp;
char tstmp_set = 0;

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
void p6_tcp_calc_doff(){
	p6_ip_pl( TCP_HDRLEN + ( tcpoptions_words * 4 ) + tcpdatalen );
	printf("pl = %d\n", TCP_HDRLEN + ( tcpoptions_words * 4 ) + tcpdatalen );
	p6_tcp_doff( MIN_DOFF + tcpoptions_words);
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
	printf("tcpoptions_words = %d\n", tcpoptions_words);
	uint8_t *psdhdr_ptr;
	p6_tcp_cksum( 0 );
	psdhdrlen = TCP_HDRLEN + TCP6_PSDHDRLEN + (tcpoptions_words * sizeof(uint32_t)) + tcpdatalen;
	psdhdr = malloc( psdhdrlen * sizeof( uint8_t ));
	psdhdr_ptr = psdhdr;

	memcpy(&(psdhdr_preamble.dst), &(ip_hdr.dst), sizeof( struct in6_addr));
	memcpy(&(psdhdr_preamble.src), &(ip_hdr.src), sizeof( struct in6_addr));

	psdhdr_preamble.ulpl = htonl( TCP_HDRLEN +(tcpoptions_words * sizeof(uint32_t))+ tcpdatalen );
	psdhdr_preamble.nxthdr = P_TCP;

	memcpy( psdhdr_ptr , &psdhdr_preamble, TCP6_PSDHDRLEN);
	psdhdr_ptr += TCP6_PSDHDRLEN;
	memcpy( psdhdr_ptr , &(tcphdr), TCP_HDRLEN);
	psdhdr_ptr += TCP_HDRLEN;
	if(tcpoptions){
		memcpy( psdhdr_ptr, tcpoptions, tcpoptions_words * sizeof( uint32_t));
		psdhdr_ptr +=  tcpoptions_words * sizeof( uint32_t);
	}
	if(tcpdatalen){
		memcpy( psdhdr_ptr, tcpdata, tcpdatalen);
		psdhdr_ptr +=  tcpdatalen;
	}
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
	if(tcpoptions){
		p6_dg_copy( tcpoptions, tcpoptions_words * sizeof( uint32_t ));
		free(tcpoptions);
	}
	if(tcpdatalen){
		p6_dg_copy( tcpdata, tcpdatalen);
	}
}
void p6_tcp_mkops(){
	int rest = ( tcp_options_len % 4 );
	if( rest )
		rest = 4 - rest;
	else
		rest = 0;

	tcpoptions = malloc( (tcpoptions_words) * sizeof( uint32_t));
	if(mss_set){
		memcpy(tcpoptions + tcpoptions_counter, &(mss), sizeof( struct mss_struct ));
		tcpoptions_counter += sizeof( struct mss_struct );
	}
	if(wsf_set){
		memcpy(tcpoptions + tcpoptions_counter, &(wsf), sizeof( struct wsf_struct ));
		tcpoptions_counter += sizeof( struct wsf_struct );
	}
	if(sap_set){
		memcpy( tcpoptions + tcpoptions_counter, &(sap), sizeof( struct sap_struct));
		tcpoptions_counter += sizeof( struct sap_struct);
	}
	if(tstmp_set){
		memcpy( tcpoptions + tcpoptions_counter, &(tstmp), sizeof( struct tstmp_struct));
		tcpoptions_counter += sizeof( struct tstmp_struct);
	}
	if(rest)
		memset( tcpoptions + tcpoptions_counter, 1, rest);
}
void p6_tcp_mss( uint16_t mss_value ){
	mss_set = 1;
	mss.type = 2;
	mss.size = 4;
	mss.mss = htons(mss_value);
	
	tcp_options_len += 4;
	tcpoptions_words = (tcp_options_len / 4);
	if( tcp_options_len % 4)
		tcpoptions_words++;
}
void p6_tcp_wsf( uint8_t wsf_value ){
	wsf_set = 1;
	wsf.type = 3;
	wsf.size = 3;
	wsf.wsf = wsf_value;
	
	tcp_options_len += 3;
	tcpoptions_words = (tcp_options_len / 4);
	if( tcp_options_len % 4)
		tcpoptions_words++;
}
void p6_tcp_sap(){
	sap_set = 1;
	sap.type = 4;
	sap.size = 2;

	tcp_options_len += 2;
	tcpoptions_words = (tcp_options_len / 4);
	if( tcp_options_len % 4)
		tcpoptions_words++;
}
void p6_tcp_tstmp( uint32_t sstmp, uint32_t rstmp){
	tstmp_set = 1;
	tstmp.type = 8;
	tstmp.size = 10;
	tstmp.ststmp = htonl( sstmp );
	tstmp.rtstmp = htonl( rstmp );

	tcp_options_len += 10;
	tcpoptions_words = (tcp_options_len / 4);
	if( tcp_options_len % 4)
		tcpoptions_words++;
}
	

