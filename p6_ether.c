
#include "p6_ether.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/if.h>

struct sockaddr_ll device;
int sd;
uint8_t *datagram;		// datagram pointer
uint32_t datagram_len = 0;	// datagram filled length
struct ether_header eth_hdr;

int p6_dg_init(){
	void *status;

	status = (uint8_t*) malloc( IP_MAXPACKET * sizeof(uint8_t));

	if(status == NULL){
		fprintf(stderr, "Error in allocatin base memory for packet.\n");
		exit(EXIT_FAILURE);
	}
	datagram = status;
	memset(datagram,0, IP_MAXPACKET * sizeof(uint8_t));

	return 1;
}
int p6_ether_set_src( char *string){
	int bytes[6];
	int i;
	if( 6 == sscanf( string, "%x:%x:%x:%x:%x:%x%*c",
				&bytes[0], &bytes[1], &bytes[2],
				&bytes[3], &bytes[4], &bytes[5] ) ) {
		for( i = 0; i < 6; ++i )
			eth_hdr.ether_shost[i] = (uint8_t) bytes[i];
	}

	return 0;
}
int p6_ether_set_dst( char *string){
	int bytes[6];
	int i;
	if( 6 == sscanf( string, "%x:%x:%x:%x:%x:%x%*c",
				&bytes[0], &bytes[1], &bytes[2],
				&bytes[3], &bytes[4], &bytes[5] ) ) {
		for( i = 0; i < 6; ++i )
			eth_hdr.ether_dhost[i] = (uint8_t) bytes[i];
	}

	return 0;
}
int p6_ether_set_type( uint16_t type){
	eth_hdr.ether_type = htons( type );
	return 0;
}
int p6_dg_copy( void *addr, int len ){
	memcpy( datagram + datagram_len, addr, len );
	datagram_len += len;
	return 0;
}
int p6_dg_copy_ether(){
	memcpy( datagram + datagram_len, &(eth_hdr), ETHER_HDR_LEN); 
	datagram_len += ETHER_HDR_LEN;
	return 0;
}
int p6_dg_send( char *interface){
	int bytes = 0;
	sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	/*sd = socket(AF_INET6, SOCK_RAW, htons(ETH_P_ALL));*/
	if (sd < 0) {
		fprintf(stderr, "Cannot create raw socket: %s\n", strerror(errno));
		abort();
	}
	memset (&device, 0, sizeof (device));
	if ((device.sll_ifindex = if_nametoindex(interface)) == 0) {
		perror ("if_nametoindex() failed to obtain interface index ");
		exit (EXIT_FAILURE);
	}
	printf ("Index for interface %s is %i\n", interface, device.sll_ifindex);
	// Fill out sockaddr_ll.
	device.sll_family = AF_PACKET;
	memcpy (device.sll_addr, eth_hdr.ether_shost , ETHER_ADDR_LEN);
	device.sll_halen = ETHER_ADDR_LEN;

	if ((bytes = sendto (sd, datagram, datagram_len, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) {
		perror ("sendto() failed");
		exit (EXIT_FAILURE);
	}
	close(sd);
	return 0;
}
int p6_dg_free(){
	free(datagram);
	return 0;
}
