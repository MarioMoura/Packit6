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

//      Defaults
#define ETHER_DFT_ADDR "00:00:00:00:00:00"
#define IPV6_DFT_ADDR  "::1"

#define ICMP       1
#define UDP        2
#define TCP        3

#define HELP       998
#define DUMP       999
#define PAYLOAD    1000
#define ETHERTYPE  1001

#define IP_VERSION 1002
#define IP_TC      1003
#define IP_FL      1004
#define IP_PL      1005
#define IP_NH      1006
#define IP_HL      1007
#define IP_HBH     1021
#define IP_DOH     1022

#define IC_T       1008
#define IC_C       1009
#define IC_CKS     1010
#define IC_ID      1011
#define IC_SQ      1012

#define UDP_L      1013
#define UDP_CKS    1014

#define TCP_CKS    1015
#define TCP_DOFF   1016
#define TCP_MSS    1017
#define TCP_WSF    1018
#define TCP_SAP    1019
#define TCP_STMP   1020

// Usage
char *usage= "Usage:\n"
             "packit [-t protocol] [options]\n\n"
			 "Options:\n"
			 "        -t [icmp|upc|tcp]                               Set protocol\n"
			 "        --help\n"
			 "        --dump\n"
			 "        -p, --payload <payload>                         Set the payload\n"
			 "\n"
			 "        ETHERNET\n"
			 "            -e <source_mac>                             Ethernet Source address\n"
			 "            -E <destination_mac>                        Ethernet Destination address\n"
			 "                --eT <ethernet_type>                    Ethernet Protocol type\n"
			 "\n"
			 "        IP\n"
			 "            -s <source_address>                         IP Source address\n"
			 "            -d <destination_address                     IP Destination address\n"
			 "            -n, --ipFL <label>                          IP FlowLabel\n"
			 "                --ipV <version>                         IP version\n"
			 "                --ipTC <tc>                             IP Traffic class\n"
			 "                --ipPL <pl>                             IP Payload length\n"
			 "                --ipNH <nh>                             IP Next Header\n"
			 "                --ipHL <hl>                             IP Hop limit (TTL)\n"
			 "                --ipHBH \"nh [len],t:l:v[,t:l:v...]\"     IP Hop-by-Hop Header\n"
			 "                --ipDOH \"nh [len],t:l:v[,t:l:v...]\"     IP Destination Options Header\n"
			 "\n"
			 "        ICMPv6\n"
			 "            -K, --icT <type>                            ICMP type\n"
			 "            -C, --icC <code>                            ICMP code\n"
			 "            -N, --icID <id>                             ICMP id\n"
			 "            -Q, --icSQ <sq>                             ICMP sequence number\n"
			 "                --icCKS <checksum>                      ICMP Checksum\n"
			 "\n"
			 "        UDP\n"
			 "            -S <port>                                   UDP Source port\n"
			 "            -D <port>                                   UDP Destination port\n"
			 "                --udpL <len>                            UDP length\n"
			 "                --udpCKS <checksum>                     UDP Checksum\n"
			 "\n"
			 "        TCP\n"
			 "            -S <port>                                   TCP Source port\n"
			 "            -D <port>                                   TCP Destination port\n"
			 "            -F [SFAPURN]                                TCP Flags\n"
			 "            -q <sq_no>                                  TCP Sequence number\n"
			 "            -a <ack_no>                                 TCP Acknowledgment number\n"
			 "            -W <winz_no>                                TCP Window size\n"
			 "            -u <urg_ptr>                                TCP Urgent pointer\n"
			 "                --tcpCKS <checksum>                     TCP Checksum\n"
			 "                --tcpOFF <doff>                         TCP Data offset\n"
			 "                --tcpMSS <mss>                          TCP Maximum segment size\n"
			 "                --tcpWSF <wsf>                          TCP Window scaling\n"
			 "                --tcpSAP                                TCP SAP\n"
			 "                --tcpSTMP <no,no>                       TCP Timestamp\n"
			 "\n"
;

char fdump = 0;

char *protocol       = NULL;
char *payload        = NULL;
int  payload_len     = 0   ;
void (*cp_fun)(void);

//       Ethernet
char     *ether_src = NULL          ;
char     *ether_dst = NULL          ;
uint16_t ether_type = ETHERTYPE_IPV6;

//       IPv6
char     *ip_src = NULL;
char     *ip_dst = NULL;
char     ip_v    = 6   ;
uint8_t  ip_tc   = 0   ;
uint32_t ip_fl   = 0   ;
uint8_t  ip_pl   = 0   ;
uint8_t  ip_nh   = 0   ; char fip_nh = 0;
uint8_t  ip_hl   = 64  ;

//       ICMPv6
uint8_t  ic_t   = 128;
uint8_t  ic_c   = 0  ;
uint16_t ic_cks = 0  ;
uint16_t ic_id  = 1  ;
uint16_t ic_sq  = 1  ;

// UDP && TCP
uint16_t sport;
uint16_t dport;

//       UDP
uint16_t udp_l   = 0; char fudp_l   = 0;
uint16_t udp_cks = 0; char fudp_cks = 0;

// TCP
char    *tcp_flags;
uint8_t  tcp_doff ; char ftcp_doff = 0;
uint32_t tcp_sq   ;
uint32_t tcp_ack  ;
uint16_t tcp_win  ;
uint16_t tcp_cks  ; char ftcp_cks  = 0;
uint16_t tcp_urg  ;

// TCP Options
uint16_t tcp_mss ; char ftcp_mss  = 0;
uint16_t tcp_wsf ; char ftcp_wsf  = 0;
                   char ftcp_sap  = 0;
char    *tcp_stmp; char ftcp_stmp = 0;


// Long options
static struct option long_options[] =
{
	{"dump"    , no_argument       , NULL , DUMP}       ,
	{"help"    , no_argument       , NULL , HELP}       ,
	{"payload" , required_argument , NULL , PAYLOAD}    ,
    {"eT"      , required_argument , NULL , ETHERTYPE}  ,
    {"ipV"     , required_argument , NULL , IP_VERSION} ,
    {"ipTC"    , required_argument , NULL , IP_TC}      ,
    {"ipFL"    , required_argument , NULL , IP_FL}      ,
    {"ipPL"    , required_argument , NULL , IP_PL}      ,
    {"ipNH"    , required_argument , NULL , IP_NH}      ,
    {"ipHL"    , required_argument , NULL , IP_HL}      ,
    {"ipHBH"   , required_argument , NULL , IP_HBH}     ,
    {"ipDOH"   , required_argument , NULL , IP_DOH}     ,
    {"icT"     , required_argument , NULL , IC_T}       ,
    {"icC"     , required_argument , NULL , IC_C}       ,
    {"icCKS"   , required_argument , NULL , IC_CKS}     ,
    {"icID"    , required_argument , NULL , IC_ID}      ,
    {"icSQ"    , required_argument , NULL , IC_SQ}      ,
    {"udpL"    , required_argument , NULL , UDP_L}      ,
    {"udpCKS"  , required_argument , NULL , UDP_CKS}    ,
    {"tcpCKS"  , required_argument , NULL , TCP_CKS}    ,
    {"tcpOFF"  , required_argument , NULL , TCP_DOFF}   ,
    {"tcpMSS"  , required_argument , NULL , TCP_MSS}    ,
    {"tcpWSF"  , required_argument , NULL , TCP_WSF}    ,
    {"tcpSAP"  , no_argument       , NULL , TCP_SAP}    ,
    {"tcpSTMP" , required_argument , NULL , TCP_STMP}   ,
    {NULL      , 0                 , NULL , 0}
};


int main( int argc, char **argv){
	int opt;
	if( argc < 2 ){
		fprintf(stderr, "Error: Nothing to do!\n");
		return 1;
	}

	// Parsing of command line arguments
	while ((opt = getopt_long(argc, argv, "e:E:t:s:d:n:p:K:C:N:Q:S:D:fF:q:a:W:u:",long_options,NULL)) != -1) {
        switch (opt) {
			case HELP       : puts(usage)                                              ; exit(0);       break;
			case DUMP       : fdump                         = 1                        ;                break;
			case 't'        : protocol                      = optarg                   ;                break;
			case 'e'        : ether_src                     = optarg                   ;                break;
			case 'E'        : ether_dst                     = optarg                   ;                break;
			case ETHERTYPE  : ether_type                    = p6_ether_typestr(optarg) ;                break;
			case IP_VERSION : ip_v                          = atoi(optarg)             ;                break;
			case IP_TC      : ip_tc                         = atoi(optarg)             ;                break;
			case IP_FL      : ip_fl                         = atoi(optarg)             ;                break;
			case 'n'        : ip_fl                         = atoi(optarg)             ;                break;
			case IP_PL      : ip_pl                         = atoi(optarg)             ;                break;
			case IP_NH      : ip_nh                         = atoi(optarg)             ; fip_nh=1;      break;
			case IP_HL      : ip_hl                         = atoi(optarg)             ;                break;
			case 's'        : ip_src                        = optarg                   ;                break;
			case 'd'        : ip_dst                        = optarg                   ;                break;
			case IP_HBH     : p6_ip_hph_add(optarg)                                    ;                break;
			case IP_DOH     : p6_ip_hph_add(optarg)                                    ;                break;
			case IC_T       : ic_t                          = atoi(optarg)             ;                break;
			case 'K'        : ic_t                          = atoi(optarg)             ;                break;
			case IC_C       : ic_c                          = atoi(optarg)             ;                break;
			case 'C'        : ic_c                          = atoi(optarg)             ;                break;
			case IC_CKS     : ic_cks                        = atoi(optarg)             ;                break;
			case IC_ID      : ic_id                         = atoi(optarg)             ;                break;
			case 'N'        : ic_id                         = atoi(optarg)             ;                break;
			case IC_SQ      : ic_sq                         = atoi(optarg)             ;                break;
			case 'Q'        : ic_sq                         = atoi(optarg)             ;                break;
			case PAYLOAD    : payload                       = optarg                   ;                break;
			case 'p'        : payload                       = optarg                   ;                break;
			case 'S'        : sport                         = atoi(optarg)             ;                break;
			case 'D'        : dport                         = atoi(optarg)             ;                break;
			case UDP_L      : udp_l                         = atoi(optarg)             ; fudp_l=1;      break;
			case UDP_CKS    : udp_cks                       = atoi(optarg)             ; fudp_cks=1;    break;
			case 'q'        : tcp_sq                        = atoi(optarg)             ;                break;
			case 'a'        : tcp_ack                       = atoi(optarg)             ;                break;
			case 'W'        : tcp_win                       = atoi(optarg)             ;                break;
			case 'u'        : tcp_urg                       = atoi(optarg)             ;                break;
			case TCP_DOFF   : tcp_doff                      = atoi(optarg)             ; ftcp_doff = 1; break;
			case TCP_CKS    : tcp_cks                       = atoi(optarg)             ; ftcp_cks = 1;  break;
			case 'F'        : tcp_flags                     = optarg                   ;                break;
			case 'f'        :                                                          ;                break;
			case TCP_MSS    : tcp_mss                       = atoi(optarg)             ; ftcp_mss = 1;  break;
			case TCP_WSF    : tcp_wsf                       = atoi(optarg)             ; ftcp_wsf = 1;  break;
			case TCP_SAP    : ftcp_sap                      = 1                        ;                break;
			case TCP_STMP   : tcp_stmp                      = optarg                   ; ftcp_stmp = 1; break;
			default         :
						   fprintf(stderr, usage , argv[0]);
						   exit(EXIT_FAILURE);
		}
    }
	if(!protocol){
		fprintf(stderr, "Error: option -t <protocol> needed!\n");
		return 1;
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
	p6_ip_vs(ip_v);  // Version
	p6_ip_tc(ip_tc); // Traffic Class
	p6_ip_fl(ip_fl); // Flow Label

	// Next Header
	if(fip_nh)
		p6_ip_nh(ip_nh);
	else
		if(!strcasecmp(protocol,"icmp"))
			p6_ip_nh(P_ICMPV6);
		else if(!strcasecmp(protocol,"tcp"))
			p6_ip_nh(P_TCP);
		else if(!strcasecmp(protocol,"udp"))
			p6_ip_nh(P_UDP);

	p6_ip_hl(ip_hl); // Hop Limit

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
		/*p6_ip_pl( ICMP6_HDRLEN_ECRQT + payload_len );*/
		p6_ip_add_len( ICMP6_HDRLEN_ECRQT + payload_len);
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
		cp_fun = &p6_dg_cp_icmp6;
	}else if(!strcasecmp(protocol,"udp")){
		// Set IP payload length
		/*p6_ip_pl( UDP_HDRLEN + payload_len );*/
		p6_ip_add_len( UDP_HDRLEN + payload_len);
		if(payload)
			p6_udp_data( payload , payload_len );

		p6_udp_sport(sport);
		p6_udp_dport(dport);
		if(fudp_l)
			p6_udp_len(udp_l); 
		else
			p6_udp_len( UDP_HDRLEN + payload_len); 

		if(fudp_cks)
			p6_udp_checksum( udp_cks);
		else
			p6_udp_calc_cksum();

		cp_fun = &p6_dg_cp_udp;
	}else if(!strcasecmp(protocol,"tcp")){

		if(payload)
			p6_tcp_data( payload, payload_len);
		p6_tcp_sport(sport);
		p6_tcp_dport(dport);
		p6_tcp_seq(tcp_sq);
		p6_tcp_ack(tcp_ack);
		p6_tcp_win(tcp_win);
		p6_tcp_urg(tcp_urg);
		if(tcp_flags)
			p6_tcp_flags(tcp_flags);
		if(ftcp_mss)
			p6_tcp_mss(tcp_mss);
		if(ftcp_wsf)
			p6_tcp_wsf(tcp_wsf);
		if(ftcp_sap)
			p6_tcp_sap();
		if(ftcp_stmp)
			p6_tcp_timestamp(tcp_stmp);

		p6_tcp_calc_doff();
		if(ftcp_doff)
			p6_tcp_doff(tcp_doff);

		p6_tcp_mkops();
		if(ftcp_cks)
			p6_tcp_cksum(tcp_cks);
		else
			p6_tcp_calc_cksum();

		cp_fun = &p6_dg_cp_tcp;
	}

	p6_dg_copy_ether();
	if(ip_pl)
		p6_ip_pl(ip_pl);
	else
		p6_ip_autolen();
	p6_dg_copy_ip();
	(*cp_fun)();
	if(fdump)
		hexDump( "Datagram", datagram, datagram_len, 16);
	else
		p6_dg_send( "lo" );
	p6_dg_free();
	return 0;
}

