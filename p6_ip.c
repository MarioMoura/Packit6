
#include "p6_ether.h"
#include "p6_ip.h"

#include <stdio.h>
#include <arpa/inet.h>
#include <stdlib.h>

struct ipv6_hdr ip_hdr; 


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
	if(flow_label > (1048576)){ // Max value for 20 bits
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
