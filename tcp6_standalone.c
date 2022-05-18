#include "p6_ether.h"
#include "p6_ip.h"
#include "p6_tcp6.h"
#include "p6_utils.h"

#include <string.h>
#include <stdio.h>
#include <stdint.h>

int main(void){
	char *data = "Test";
	int datalen= strlen( data );
	p6_dg_init();

	/*Ethernet Header*/
	p6_ether_set_src("f0:00:00:00:00:00");
	p6_ether_set_dst("00:00:00:00:00:00");
	p6_ether_set_type(ETHERTYPE_LOOPBACK);
	p6_ether_set_type(ETHERTYPE_IPV6);
	p6_dg_copy_ether();

	/*IP6 Header*/
	p6_ip_vs( 6 );
	p6_ip_tc( 8 );
	p6_ip_fl( 0x1 );
	p6_ip_pl( 20 + datalen);
	p6_ip_nh( P_TCP );
	p6_ip_hl( 64 );
	p6_ip_src("::1");
	p6_ip_dst("::1");


	/*TCP Header*/
	p6_tcp_sport( 3900 );
	p6_tcp_dport( 3500 );
	/*p6_tcp_doff( 5 );*/
	p6_tcp_seq( 1 );
	p6_tcp_ack( 150 );
	/*p6_tcp_fns( 1 );*/
	/*p6_tcp_fcwr( 1 );*/
	/*p6_tcp_frst( 1 );*/
	/*p6_tcp_fack( 1 );*/
	/*p6_tcp_ffin( 1 );*/
	p6_tcp_fpsh( 1 );
	/*p6_tcp_fece( 1 );*/
	/*p6_tcp_furg( 1 );*/
	p6_tcp_fsyn( 1 );
	p6_tcp_win( 150 );
	/*p6_tcp_cksum( 0xc9e6 );*/
	p6_tcp_mss( 35000 );
	p6_tcp_wsf( 10 );
	p6_tcp_sap();
	p6_tcp_tstmp( 1 , 1 );

	p6_tcp_data( data, datalen);
	p6_tcp_calc_doff();
	p6_tcp_mkops();
	p6_tcp_calc_cksum();
	p6_dg_copy_ip();
	p6_dg_cp_tcp();

	hexDump( "Data", (void*) datagram,
		98
			, 16);
	p6_dg_send( "lo" );
	p6_dg_free();

	return 0;
}
