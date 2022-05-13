
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "p6_ether.h"
#include "p6_ip.h"
#include "p6_icmp6.h"

void hexDump ( const char * desc, const void * addr, const int len, int perLine) {
    // Silently ignore silly per-line values.

    if (perLine < 4 || perLine > 64) perLine = 16;

    int i;
    unsigned char buff[perLine+1];
    const unsigned char * pc = (const unsigned char *)addr;

    // Output description if given.

    if (desc != NULL) printf ("%s:\n", desc);

    // Length checks.

    if (len == 0) {
        printf("  ZERO LENGTH\n");
        return;
    }
    if (len < 0) {
        printf("  NEGATIVE LENGTH: %d\n", len);
        return;
    }

    // Process every byte in the data.

    for (i = 0; i < len; i++) {
        // Multiple of perLine means new or first line (with line offset).

        if ((i % perLine) == 0) {
            // Only print previous-line ASCII buffer for lines beyond first.

            if (i != 0) printf ("  %s\n", buff);

            // Output the offset of current line.

            printf ("  %04x ", i);
        }

        // Now the hex code for the specific character.

        printf (" %02x", pc[i]);

        // And buffer a printable ASCII character for later.

        if ((pc[i] < 0x20) || (pc[i] > 0x7e)) // isprint() may be better.
            buff[i % perLine] = '.';
        else
            buff[i % perLine] = pc[i];
        buff[(i % perLine) + 1] = '\0';
    }

    // Pad out last line if not exactly perLine characters.

    while ((i % perLine) != 0) {
        printf ("   ");
        i++;
    }

    // And print the final ASCII buffer.

    printf ("  %s\n", buff);
}

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
	p6_ip_fl( 0xad7b3 );
	p6_ip_pl( 8 + datalen );
	p6_ip_nh( P_ICMPV6 );
	p6_ip_hl( 64 );
	p6_ip_src("::1");
	p6_ip_dst("::1");

	p6_dg_copy_ip();

	p6_icmp6_data( data , datalen );
	p6_icmp6_type( 3 );
	p6_icmp6_code( 1 );
	p6_icmp6_checksum( 0 );
	p6_icmp6_id(1);
	p6_icmp6_seq( 1 );
	p6_icmp6_calc_cksum();

	p6_dg_cp_icmp6();

	hexDump( "Data", (void*) datagram,
			54 +
			ICMP6_HDRLEN_ECRQT +
			datalen
			, 16);
	p6_dg_send( "lo" );
	p6_dg_free();

	return 0;
}
