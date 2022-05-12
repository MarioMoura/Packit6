#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           
#include <string.h>           

#include <netdb.h>            
#include <sys/types.h>       
#include <sys/socket.h>       
#include <netinet/in.h>     
#include <netinet/ip.h>       
#include <netinet/ip6.h>      
#include <netinet/udp.h>      
#include <arpa/inet.h>        
#include <sys/ioctl.h>        
#include <bits/ioctls.h>   
#include <net/if.h>           
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>

#include <errno.h>            

// Flags
char *protocol;

int main( int argc, char **argv){

	// Parsing of command line arguments
	for (int i = 0; i < argc; ++i) {
		if(!strcmp(argv[i],"-t"))
			protocol = argv[++i];
	}
	// Protocols
	if(!strcmp(protocol,"icmp") || !strcmp(protocol,"ICMP")){

	} else if(!strcmp(protocol,"udp") || !strcmp(protocol,"UDP")){

	} else if(!strcmp(protocol,"tcp") || !strcmp(protocol,"TCP")){

	} else {
		fprintf(stderr, "ERROR: No Valid Protocol Chosen\n");
	}
	return 0;
}

