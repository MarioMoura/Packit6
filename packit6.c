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
#include <getopt.h>
#include <errno.h>            

#include "p6_ether.h"
#include "p6_ip.h"
#include "p6_udp.h"
#include "p6_icmp6.h"
#include "p6_tcp6.h"
#include "p6_utils.h"

// Defaults
#define ETHER_DFT_ADDR "00:00:00:00:00:00"
#define IPV6_DFT_ADDR "::1"

#define ICMP 1
#define UDP 2
#define TCP 3

#define PAYLOAD 1000
#define ETHERTYPE 1001
#define IP_VERSION 1002
#define IP_TC 1003
#define IP_FL 1004
#define IP_PL 1005
#define IP_NH 1006
#define IP_HL 1007

#define IC_T 1008
#define IC_C 1009
#define IC_CKS 1010
#define IC_ID 1011
#define IC_SQ 1012

// Usage
char *usage= "Usage: [-m mode] [-t protocol] [-ab] [-c cvalue]\n";

// Options variables
char *protocol = NULL;
char *payload = NULL;
int payload_len = 0;

// Ethernet
char *ether_src = NULL;
char *ether_dst = NULL;
uint16_t ether_type = ETHERTYPE_IPV6;

// IPv6
char *ip_src = NULL;
char *ip_dst = NULL;
char ip_v = 6;
uint8_t ip_tc = 0;
uint32_t ip_fl = 0;
uint8_t ip_pl = 0;
uint8_t ip_nh = 0;
uint8_t ip_hl = 64;

// ICMPv6
uint8_t ic_t = 128;
uint8_t ic_c = 0;
uint16_t ic_cks = 0;
uint16_t ic_id = 1;
uint16_t ic_sq = 1;

// Long options
static struct option long_options[] =
{
    {"payload", required_argument, NULL, PAYLOAD},
    {"eT", required_argument, NULL, ETHERTYPE},
    {"ipV", required_argument, NULL, IP_VERSION},
    {"ipTC", required_argument, NULL, IP_TC},
    {"ipFL", required_argument, NULL, IP_FL},
    {"ipPL", required_argument, NULL, IP_PL},
    {"ipNH", required_argument, NULL, IP_NH},
    {"ipHL", required_argument, NULL, IP_HL},
    {"icT", required_argument, NULL, IC_T},
    {"icC", required_argument, NULL, IC_C},
    {"icCKS", required_argument, NULL, IC_CKS},
    {"icID", required_argument, NULL, IC_ID},
    {"icSQ", required_argument, NULL, IC_SQ},
    {NULL, 0, NULL, 0}
};


int main( int argc, char **argv){
	int opt;
	if( argc < 2 ){
		fprintf(stderr, "Error: Nothing to do!\n");
		return 1;
	}

	// Parsing of command line arguments
	while ((opt = getopt_long(argc, argv, "e:E:t:s:d:p:K:C:N:Q:",long_options,NULL)) != -1) {
        switch (opt) {
        case 't': protocol = optarg; break; // Protocol
        case 'e': ether_src = optarg; break; // Ether Src
        case 'E': ether_dst = optarg; break; // Ether Dst
        case ETHERTYPE : ether_type = p6_ether_typestr(optarg); break;
        case IP_VERSION : ip_v = atoi(optarg) ; break;
        case IP_TC : ip_tc = atoi(optarg) ; break;
        case IP_FL : ip_fl = atoi(optarg) ; break;
        case IP_PL : ip_pl = atoi(optarg) ; break;
        case IP_NH : ip_nh = atoi(optarg) ; break;
        case IP_HL : ip_hl = atoi(optarg) ; break;
		case 's': ip_src = optarg; break; // IP Src
		case 'd': ip_dst = optarg; break; // IP Dst
		case IC_T: ic_t = atoi(optarg); break;
		case 'K': ic_t = atoi(optarg); break;
		case IC_C: ic_c = atoi(optarg); break;
		case 'C': ic_c = atoi(optarg); break;
		case IC_CKS: ic_cks = atoi(optarg); break;
		case IC_ID: ic_id = atoi(optarg); break;
		case 'N': ic_id = atoi(optarg); break;
		case IC_SQ: ic_sq = atoi(optarg); break;
		case 'Q': ic_sq = atoi(optarg); break;
        case PAYLOAD: payload = optarg; break;
        case 'p': payload = optarg; break;
        default:
            fprintf(stderr, usage , argv[0]);
            exit(EXIT_FAILURE);
        }
    }
	if(!protocol){ // Default Protocol
		protocol = "icmp";
	}
	if(payload){
		payload_len = strlen(payload);
	}

	// Initiate Datagram
	p6_dg_init();

	if(ether_src) // Ethernet Source
		p6_ether_set_src(ether_src);
	else
		p6_ether_set_src(ETHER_DFT_ADDR);

	if(ether_dst) // Ethernet Destination
		p6_ether_set_dst(ether_dst);
	else
		p6_ether_set_dst(ETHER_DFT_ADDR);

	if(ether_type) // Ethernet Type
		p6_ether_set_type(ether_type);
	else
		p6_ether_set_type(ETHERTYPE_IPV6);

	// IP Header
	p6_ip_vs(ip_v);
	p6_ip_tc(ip_tc);
	p6_ip_fl(ip_fl);

	if(ip_nh)
		p6_ip_nh(ip_nh);
	else
		if(!strcasecmp(protocol,"icmp"))
			p6_ip_nh(P_ICMPV6);
		else if(!strcasecmp(protocol,"tcp"))
			p6_ip_nh(P_TCP);
		else if(!strcasecmp(protocol,"udp"))
			p6_ip_nh(P_UDP);

	p6_ip_hl(ip_hl);

	if(ip_src)
		p6_ip_src(ip_src);
	else
		p6_ip_src(IPV6_DFT_ADDR);

	if(ip_dst)
		p6_ip_dst(ip_dst);
	else
		p6_ip_dst(IPV6_DFT_ADDR);

	// Protocols Headers
	
	// ICMP Header
	if(!strcasecmp(protocol,"icmp")){
		// Set IP payload length
		p6_ip_pl( ICMP6_HDRLEN_ECRQT + payload_len );
		if(payload)
			p6_icmp6_data( payload , payload_len );
		p6_icmp6_type(ic_t);
		p6_icmp6_code(ic_c);
		p6_icmp6_id(ic_id);
		p6_icmp6_seq(ic_sq);
		if(ic_cks)
			p6_icmp6_checksum(ic_cks);
		else{
			p6_icmp6_checksum(0);
			p6_icmp6_calc_cksum();
		}
	}else if(!strcasecmp(protocol,"tcp")){

	}else if(!strcasecmp(protocol,"udp")){

	}

	p6_dg_copy_ether();
	if(ip_pl)
		p6_ip_pl(ip_pl);
	p6_dg_copy_ip();
	if(!strcasecmp(protocol,"icmp"))
		p6_dg_cp_icmp6();
	else if(!strcasecmp(protocol,"tcp"))
		p6_dg_cp_tcp();
	else if(!strcasecmp(protocol,"udp"))
		p6_dg_cp_udp();
	hexDump( "Datagram", datagram, datagram_len, 16);
	p6_dg_send( "lo" );
	p6_dg_free();
	return 0;
}

