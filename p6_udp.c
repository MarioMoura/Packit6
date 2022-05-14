#include "p6_udp.h"
#include "p6_ether.h"
#include <stdlib.h>
#include <string.h>


struct udphdr udphdr;
struct udpv6_psdhdr psdhdr_preamble;
uint8_t *psdhdr;
void *udpdata;
int udpdatalen;

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
int p6_udp_data( void *addr, int len){
	udpdata = addr;
	udpdatalen = len;
	return 0;
}
int p6_udp_sport( uint16_t sport){
	udphdr.source = htons(sport);
	return 0;
}
int p6_udp_dport( uint16_t dport){
	udphdr.dest = htons(dport);
	return 0;
}
int p6_udp_len( uint16_t len){
	udphdr.len = htons(len);
	return 0;
}
int p6_udp_checksum( uint16_t cksum){
	udphdr.check = htons( cksum );
	return 0;
}
void p6_udp_calc_cksum(){
	p6_udp_checksum( 0 );
	int psdhdrlen = UDP6_PSDHDRLEN + UDP_HDRLEN + udpdatalen;
	psdhdr = malloc( psdhdrlen * sizeof( uint8_t));

	memcpy(&(psdhdr_preamble.dst), &(ip_hdr.dst), sizeof( struct in6_addr));
	memcpy(&(psdhdr_preamble.src), &(ip_hdr.src), sizeof( struct in6_addr));
	psdhdr_preamble.ulpl = htonl( UDP_HDRLEN + udpdatalen );
	psdhdr_preamble.nxthdr = P_UDP;

	memcpy( psdhdr, &psdhdr_preamble, UDP6_PSDHDRLEN);
	memcpy( psdhdr + UDP6_PSDHDRLEN, &(udphdr), UDP_HDRLEN);
	memcpy( psdhdr + UDP6_PSDHDRLEN + UDP_HDRLEN, udpdata, udpdatalen);
	udphdr.check = checksum((uint16_t *) psdhdr, psdhdrlen);;

	free(psdhdr);
}
void p6_dg_cp_udp(){
	p6_dg_copy(&(udphdr), UDP_HDRLEN);
	if(udpdatalen){
		p6_dg_copy( udpdata, udpdatalen);
	}
}

