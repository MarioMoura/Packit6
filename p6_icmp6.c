#include "p6_icmp6.h"
#include <stdlib.h>
#include <string.h>

struct icmpv6_header icmp6_hdr;
struct icmpv6_psdhdr psdhdr_preamble;
uint8_t *psdhdr;

void *icmp6_data;
int icmp6_datalen;

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

int p6_icmp6_data( void *addr, int len ){
	icmp6_data = addr;
	icmp6_datalen = len;
	return 0;
}

int p6_icmp6_type( uint8_t type){
	icmp6_hdr.type = type;
	return 0;
}
int p6_icmp6_code( uint8_t code){
	icmp6_hdr.code = code;
	return 0;
}
int p6_icmp6_checksum( uint16_t cksum ){
	icmp6_hdr.chksum = htons( cksum );
	return 0;
}

int p6_icmp6_calc_cksum(){
	p6_icmp6_checksum( 0 );
	int psdhdrlen = ICMP6_PSDHDRLEN + ICMP6_HDRLEN_ECRQT + icmp6_datalen;
	psdhdr = malloc( psdhdrlen * sizeof( uint8_t));

	memcpy(&(psdhdr_preamble.dst), &(ip_hdr.dst), sizeof( struct in6_addr));
	memcpy(&(psdhdr_preamble.src), &(ip_hdr.src), sizeof( struct in6_addr));
	psdhdr_preamble.ulpl = htonl( ICMP6_HDRLEN_ECRQT + icmp6_datalen );
	psdhdr_preamble.nxthdr = P_ICMPV6;

	memcpy( psdhdr, &psdhdr_preamble, ICMP6_PSDHDRLEN);
	memcpy( psdhdr + ICMP6_PSDHDRLEN, &(icmp6_hdr), ICMP6_HDRLEN_ECRQT);
	memcpy( psdhdr + ICMP6_PSDHDRLEN + ICMP6_HDRLEN_ECRQT, icmp6_data, icmp6_datalen);
	icmp6_hdr.chksum = checksum((uint16_t *) psdhdr, psdhdrlen);;

	free(psdhdr);
	return 0;
}
int p6_icmp6_id( uint16_t id){
	icmp6_hdr.id = htons( id );
	return 0;
}
int p6_icmp6_seq( uint16_t seq ){
	icmp6_hdr.seq = htons( seq );
	return 0;
}
int p6_dg_cp_icmp6(){
	p6_dg_copy( &(icmp6_hdr), ICMP6_HDRLEN_ECRQT);
	p6_dg_copy( icmp6_data, icmp6_datalen);
	return 0;
}