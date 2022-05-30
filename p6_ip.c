
#include "p6_utils.h"
#include "p6_ether.h"
#include "p6_ip.h"

#include <stdio.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

struct psdhdr_struct psdhdr_preamble;
uint8_t *psdhdr;

struct ipv6_hdr ip_hdr; 
uint16_t ipv6_pl = 0;

uint8_t *ext_hdr = NULL;
uint32_t ext_len = 0;


int p6_ip_vs( uint8_t version ){
	if( version > 16){
		fprintf(stderr, "Error: version out of range, setting to 6\n");
		ip_hdr.version = 6 << 4;
		return 1;
	}
	ip_hdr.version = version << 4;
	return 0;
}
int p6_ip_tc( uint8_t trafficclass ){
	uint32_t tmp;
	uint32_t tfc = (uint32_t) trafficclass;
	tmp = ip_hdr.line | htonl( ( tfc << 20 )) ;
	ip_hdr.line = tmp;
	return 0;
}
int p6_ip_fl( uint32_t flow_label ){
	if(flow_label > (BIT20_MAX)){ // Max value for 20 bits
		fprintf(stderr, "Error: Flow label out of range, setting to 0\n");
		return 1;
	}
	uint32_t tmp;
	tmp = ip_hdr.line | htonl( ( flow_label )) ;
	ip_hdr.line = tmp;
	return 0;
}
int p6_ip_pl( uint16_t length ){
	if( length > UINT16_MAX ){
		fprintf(stderr, "ERROR: IP Header payload length too big!\n");
		ip_hdr.length = htons(0);
	}
	ip_hdr.length = htons( length );
	return 0;
}
void p6_ip_nh( uint8_t next_header ){
	ip_hdr.next_header = next_header;
}
void p6_ip_hl( uint8_t hop_limit ){
	ip_hdr.hop_limit = hop_limit;
}
int p6_ip_src( char *string_src ){
	int status;
	if ((status = inet_pton (AF_INET6, string_src, &(ip_hdr.src))) != 1) {
		fprintf (stderr, "Error while parsing the ip source address\n" );
		return EXIT_FAILURE;
	}
	return 0;
}
int p6_ip_dst( char *string_dst ){
	int status;
	if ((status = inet_pton (AF_INET6, string_dst, &(ip_hdr.dst))) != 1) {
		fprintf (stderr, "Error while parsing the ip destination address\n" );
		return EXIT_FAILURE;
	}
	return 0;
}
int p6_dg_copy_ip(){
	p6_dg_copy( &(ip_hdr), IPV6_HDRLEN);
	if(ext_hdr){
		p6_dg_copy( ext_hdr, ext_len);
		free(ext_hdr);
	}
	return 0;
}
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
void p6_cp_ext( void *addr, int len){
	ext_hdr = realloc( ext_hdr, ext_len + len);
	memcpy(ext_hdr + ext_len, addr, len);
	ext_len += len;
	hexDump( "Ext Header", ext_hdr, ext_len, 16);
}
int hexstr2intarr(char *str, int len, uint8_t *mem){
	memset( mem , 0, len );
	if(str == NULL){
		return 0;
	}
	int byte_len = 0;
	int str_len = strlen(str);
	if(str_len < 3)
		return 1;
	if(str[0] == '0' && str[1] == 'x')
		byte_len = (str_len - 2) / 2;	
	char *pos = str + str_len - 2;
	unsigned char n;
	for (int i = 0; i < byte_len; ++i) {
		sscanf( pos, "%2hhx", &n);
		pos -= 2;
		mem[len - 1 - i] = n;
	}
	return 0;
}
void p6_ip_hph_add(char *str){
	uint8_t *hbh_hdr = NULL;
	uint32_t hbh_len = 2;

	char *delim = ",";
	char *token = strtok(str,delim);

	uint8_t nh;
	uint8_t hlen;
	char lenset = 0;

	int byte_rest = 0;

	uint8_t t,l;
	uint8_t *v;
	char *v_value;
	hbh_hdr	= malloc( hbh_len * sizeof(uint8_t));
	if( sscanf(token,"%hhd %hhd", &nh, &hlen) > 1){
		hbh_hdr[1] = hlen;
		lenset = 1;
	}
	hbh_hdr[0] = nh;

	token = strtok(NULL,delim);
	while( token ){
		printf(" = %d\n",
		sscanf( token,"%hhd:%hhd:%ms",&t,&l,&v_value) // Scan token values
		);
		hbh_hdr = realloc( hbh_hdr, hbh_len + l + 2); // prepare header mem
		v = malloc( l * sizeof(uint8_t));
		hexstr2intarr( v_value, l, v);
		free(v_value);
		memcpy(hbh_hdr + hbh_len, &t, sizeof(uint8_t));
		memcpy(hbh_hdr + hbh_len + 1, &l, sizeof(uint8_t));
		memcpy(hbh_hdr + hbh_len + 2, v, l * sizeof(uint8_t));
		free(v);
		token = strtok(NULL,delim);
		hbh_len += l + 2;
	}
	if(hbh_len % 8)
		byte_rest = 8 - (hbh_len % 8);
	hbh_hdr	= realloc(hbh_hdr, hbh_len + byte_rest);
	if(byte_rest == 1){
		hbh_hdr[ hbh_len + 1] = 0;
	}else if(byte_rest > 1){
		hbh_hdr[ hbh_len + 0] = 1;
		hbh_hdr[ hbh_len + 1] = byte_rest - 2;
	}
	hbh_len += byte_rest;
	if(!lenset)
		hbh_hdr[1] = (hbh_len / 8) - 1;
	if(hbh_hdr){ // copy to ext header
		p6_cp_ext(hbh_hdr, hbh_len);
		p6_ip_add_len( hbh_len);
		free(hbh_hdr);
	}
}
void p6_ip_add_len(uint16_t len){
	ipv6_pl += len;
}
void p6_ip_autolen(){
	p6_ip_pl(ipv6_pl);
}
