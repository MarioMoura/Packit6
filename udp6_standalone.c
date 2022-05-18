
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "p6_ether.h"
#include "p6_ip.h"
#include "p6_udp.h"
#include "p6_utils.h"

int main(int argc, char **argv){
	char *data = "Test";
	int datalen= strlen( data );
	p6_dg_init();

	// Ethernet Header
	p6_ether_set_src("f0:00:00:00:00:00");
	p6_ether_set_dst("00:00:00:00:00:00");
	/*p6_ether_set_type(ETHERTYPE_LOOPBACK);*/
	p6_ether_set_type(ETHERTYPE_IPV6);
	p6_dg_copy_ether();

	// IP6 Header
	p6_ip_vs( 6 );
	p6_ip_tc( 8 );
	p6_ip_fl( 0x1 );
	p6_ip_pl( 8 + datalen );
	p6_ip_nh( P_UDP );
	p6_ip_hl( 64 );
	p6_ip_src("::1");
	p6_ip_dst("::1");

	p6_dg_copy_ip();

	p6_udp_data( data, datalen);
	p6_udp_sport( 3500 );
	p6_udp_dport( 3500 );
	p6_udp_len( UDP_HDRLEN + datalen); 
	/*p6_udp_checksum( 0x1ca3 );*/
	p6_udp_calc_cksum();

	p6_dg_cp_udp();


	hexDump( "Data", (void*) datagram,
			54 
			, 16);
	p6_dg_send( "lo" );
	p6_dg_free();

	return 0;
}
