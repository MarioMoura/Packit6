#ifndef P6_IP
#define P6_IP

#include <stdint.h>
#include <netinet/in.h>

#define IPV6_HDRLEN 40

#define BIT20_MAX 1048576

// IPV4
#define P_IP		IPPROTO_IP /* Dummy protocol for TCP.  */
#define P_ICMP		IPPROTO_ICMP /* Internet Control Message Protocol.  */
#define P_IGMP		IPPROTO_IGMP /* Internet Group Management Protocol. */
#define P_IPIP		IPPROTO_IPIP /* IPIP tunnels (older KA9Q tunnels use 94).  */
#define P_TCP		IPPROTO_TCP /* Transmission Control Protocol.  */
#define P_EGP		IPPROTO_EGP /* Exterior Gateway Protocol.  */
#define P_PUP		IPPROTO_PUP /* PUP protocol.  */
#define P_UDP		IPPROTO_UDP /* User Datagram Protocol.  */
#define P_IDP		IPPROTO_IDP /* XNS IDP protocol.  */
#define P_TP		IPPROTO_TP /* SO Transport Protocol Class 4.  */
#define P_DCCP		IPPROTO_DCCP /* Datagram Congestion Control Protocol.  */
#define P_IPV6		IPPROTO_IPV6 /* IPv6 header.  */
#define P_RSVP		IPPROTO_RSVP /* Reservation Protocol.  */
#define P_GRE		IPPROTO_GRE /* General Routing Encapsulation.  */
#define P_ESP		IPPROTO_ESP /* encapsulating security payload.  */
#define P_AH		IPPROTO_AH /* authentication header.  */
#define P_MTP		IPPROTO_MTP /* Multicast Transport Protocol.  */
#define P_BEETPH		IPPROTO_BEETPH /* IP option pseudo header for BEET.  */
#define P_ENCAP		IPPROTO_ENCAP /* Encapsulation Header.  */
#define P_PIM		IPPROTO_PIM /* Protocol Independent Multicast.  */
#define P_COMP		IPPROTO_COMP /* Compression Header Protocol.  */
#define P_SCTP		IPPROTO_SCTP /* Stream Control Transmission Protocol.  */
#define P_UDPLITE		IPPROTO_UDPLITE /* UDP-Lite protocol.  */
#define P_MPLS		IPPROTO_MPLS /* MPLS in IP.  */
#define P_ETHERNET	IPPROTO_ETHERNET /* Ethernet-within-IPv6 Encapsulation.  */
#define P_RAW		IPPROTO_RAW /* Raw IP packets.  */
#define P_MPTCP		IPPROTO_MPTCP /* Multipath TCP connection.  */

// IPV6
#define P_HOPOPTS		IPPROTO_HOPOPTS /* IPv6 Hop-by-Hop options.  */
#define P_ROUTING		IPPROTO_ROUTING /* IPv6 routing header.  */
#define P_FRAGMENT	IPPROTO_FRAGMENT /* IPv6 fragmentation header.  */
#define P_ICMPV6		IPPROTO_ICMPV6 /* ICMPv6.  */
#define P_NONE		IPPROTO_NONE /* IPv6 no next header.  */
#define P_DSTOPTS		IPPROTO_DSTOPTS /* IPv6 destination options.  */
#define P_MH		IPPROTO_MH /* IPv6 mobility header.  */

struct psdhdr_struct {
    struct in6_addr src;
    struct in6_addr dst;
	uint32_t ulpl;
	uint8_t zero[3];
	uint8_t nxthdr;
} __attribute__ ((packed));

struct ipv6_hdr {
	union {
		uint8_t version;
		uint32_t line;
	};
    uint16_t length;
    uint8_t  next_header;
    uint8_t  hop_limit;
    struct in6_addr src;
    struct in6_addr dst;
} __attribute__ ((packed));

extern struct ipv6_hdr ip_hdr; 
extern uint16_t ipv6_pl;

extern struct psdhdr_struct psdhdr_preamble;
extern uint8_t *psdhdr;

int p6_ip_vs( uint8_t version );
int p6_ip_tc( uint8_t trafficclass );
int p6_ip_fl( uint32_t flow_label );
int p6_ip_pl( uint16_t length );
void p6_ip_nh( uint8_t next_header );
void p6_ip_hl( uint8_t hop_limit );
int p6_ip_src( char *string_src );
int p6_ip_dst( char *string_dst );
int p6_dg_copy_ip();
uint16_t checksum (uint16_t *addr, int len);

void p6_ip_hph_add(char *str);

void p6_ip_add_len(uint16_t len);
void p6_ip_autolen();

#endif
