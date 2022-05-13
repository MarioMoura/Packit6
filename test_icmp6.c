#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <getopt.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <linux/if_packet.h> // struct sockaddr_ll (see man 7 packet)
#define __FAVOR_BSD
#include <netinet/udp.h>

#define MSGSIZE 64
#define PORT 42
#define TTL 23
#define ETH_HDRLEN 14  // Ethernet header length
#define ICMP_HDRLEN 8  // ICMP header length for echo request, excludes data
#define IPV6_HDRLEN 40
#define ICMPV6_PSDHDRLEN 40

/* No constant for UDP on NetBSD */
#ifndef SOL_UDP
#define SOL_UDP 17
#endif

uint8_t * allocate_ustrmem (int len) {

  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_ustrmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (uint8_t *) malloc (len * sizeof (uint8_t));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (uint8_t));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_ustrmem().\n");
    exit (EXIT_FAILURE);
  }
}
struct ipv6_hdr {
	/*unsigned int*/
		/*version : 4,*/
		/*traffic_class : 8,*/
		/*flow_label : 20;*/
	/*uint8_t l1;*/
	/*uint8_t l2;*/
	/*uint8_t l3;*/
	/*uint8_t l4;*/
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

struct icmpv6_hdr {
  uint8_t type, icode;
  uint16_t icmpchksum;
  uint16_t id, seqno;
} __attribute__ ((packed));

struct icmpv6_psdhdr{
    struct in6_addr src;
    struct in6_addr dst;
	uint32_t ulpl;
	uint8_t zero[3];
	uint8_t nxthdr;
} __attribute__ ((packed));

struct pckt6_icmp {
	struct ether_header eth;
    struct ipv6_hdr  ip;
	struct icmpv6_hdr icmp;
    /*char   payload[MSGSIZE];*/
} __attribute__ ((packed));

uint16_t checksum (uint16_t *, int);

void usage() { puts("dummy"); }

// return the text form of and sockaddr address
char *text_of(struct sockaddr *address) {
    char           *text = malloc(INET6_ADDRSTRLEN);
    struct sockaddr_in *address_v4;
    struct sockaddr_in6 *address_v6;
    if (address->sa_family == AF_INET) {
        address_v4 = (struct sockaddr_in *) address;
        inet_ntop(AF_INET, &address_v4->sin_addr, text, INET_ADDRSTRLEN);
    } else if (address->sa_family == AF_INET6) {
        address_v6 = (struct sockaddr_in6 *) address;
        inet_ntop(AF_INET6, &address_v6->sin6_addr, text, INET6_ADDRSTRLEN);
    } else {
        strcpy(text, "Unknown address family");
    }
    return text;
}

// Allocate memory for an array of chars.
char *
allocate_strmem (int len) {

  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_strmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (char *) malloc (len * sizeof (char));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (char));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_strmem().\n");
    exit (EXIT_FAILURE);
  }
}

static char     source_addr[INET6_ADDRSTRLEN];

int main(int argc, char **argv){

	int full_frame_len, bytes;
	struct sockaddr_ll device;
    struct pckt6_icmp op6;
    struct sockaddr_in6 *sockaddr6;
	struct icmpv6_psdhdr psdhdr_top;
    char message[MSGSIZE];
    int status;
    int sd;         /* Socket Descriptor */
	char *interface, *target, *src_ip, *dst_ip;
	uint8_t *data, *src_mac, *dst_mac, *ether_frame;
	uint32_t datalen;
	uint8_t *psdhdr;

    strcpy(message, "text");
	data = message;
	datalen = strlen( message );
	int psdhdrlen = 40 + ICMP_HDRLEN + datalen;
	src_mac = allocate_ustrmem (6);
	dst_mac = allocate_ustrmem (6);
	src_ip = allocate_strmem (INET6_ADDRSTRLEN);
	dst_ip = allocate_strmem (INET6_ADDRSTRLEN);
	interface = allocate_strmem (INET6_ADDRSTRLEN);
	ether_frame = allocate_ustrmem (IP_MAXPACKET);
	psdhdr = allocate_ustrmem (psdhdrlen);

	strcpy (interface, "lo");

	dst_mac[0] = 0x00;
	dst_mac[1] = 0x00;
	dst_mac[2] = 0x00;
	dst_mac[3] = 0x00;
	dst_mac[4] = 0x00;
	dst_mac[5] = 0x00;

	src_mac[0] = 0x00;
	src_mac[1] = 0x00;
	src_mac[2] = 0x00;
	src_mac[3] = 0x00;
	src_mac[4] = 0x00;
	src_mac[5] = 0x00;

	memcpy (op6.eth.ether_dhost, dst_mac, 6);
	memcpy (op6.eth.ether_shost, src_mac, 6);
	op6.eth.ether_type = htons(ETHERTYPE_IPV6);

	strcpy (src_ip, "::1");
	strcpy (dst_ip, "::1");

	memset( &op6.ip, 0 , 4);
	/*op6.ip.traffic_class = 0;*/
	op6.ip.version =  6 << 4;
	op6.ip.length = htons( ICMP_HDRLEN + strlen(message));
	/*op6.ip.next_header = 58;*/
	op6.ip.next_header = IPPROTO_ICMPV6;
	op6.ip.hop_limit = 255;

	if ((status = inet_pton (AF_INET6, src_ip, &(op6.ip.src))) != 1) {
		fprintf (stderr, "inet_pton() failed for source address.\nError message: %s", strerror (status));
		exit (EXIT_FAILURE);
	}

	if ((status = inet_pton (AF_INET6, dst_ip, &(op6.ip.dst))) != 1) {
		fprintf (stderr, "inet_pton() failed for destination address.\nError message: %s", strerror (status));
		exit (EXIT_FAILURE);
	}
	// =============
	op6.icmp.type = 128;
	op6.icmp.icode = 0;
	op6.icmp.icmpchksum = 0;
	op6.icmp.id = htons(5);
	op6.icmp.seqno = htons(300);
	// pseudo header
	memcpy(&(psdhdr_top.dst), &(op6.ip.dst), sizeof( struct in6_addr));
	memcpy(&(psdhdr_top.src), &(op6.ip.src), sizeof( struct in6_addr));
	psdhdr_top.ulpl = htonl( ICMP_HDRLEN + datalen );
	psdhdr_top.nxthdr = IPPROTO_ICMPV6;
	memcpy( psdhdr, &psdhdr_top, ICMPV6_PSDHDRLEN);
	memcpy( psdhdr + ICMPV6_PSDHDRLEN, &(op6.icmp), ICMP_HDRLEN);
	memcpy( psdhdr + ICMPV6_PSDHDRLEN + ICMP_HDRLEN, data, datalen);
	op6.icmp.icmpchksum = checksum((uint16_t *) psdhdr, psdhdrlen);;
	// ===============================
	// device
	memset (&device, 0, sizeof (device));
	if ((device.sll_ifindex = if_nametoindex(interface)) == 0) {
		perror ("if_nametoindex() failed to obtain interface index ");
		exit (EXIT_FAILURE);
	}
	printf ("Index for interface %s is %i\n", interface, device.sll_ifindex);
	// Fill out sockaddr_ll.
	device.sll_family = AF_PACKET;
	memcpy (device.sll_addr, src_mac, 6);
	device.sll_halen = 6;

	// ===============================
	//
	sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	/*sd = socket(AF_INET6, SOCK_RAW, htons(ETH_P_ALL));*/
	if (sd < 0) {
		fprintf(stderr, "Cannot create raw socket: %s\n", strerror(errno));
		abort();
	}

	full_frame_len = ETH_HDRLEN + IPV6_HDRLEN + ICMP_HDRLEN + strlen(message);

	memcpy( ether_frame, &op6, sizeof( struct pckt6_icmp ));
	memcpy( ether_frame + sizeof( struct pckt6_icmp ), message, strlen(message));

	printf("dlakdalk = %d\n", datalen );
	

	// Send ethernet frame to socket.
	if ((bytes = sendto (sd, ether_frame, full_frame_len, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) {
		perror ("sendto() failed");
		exit (EXIT_FAILURE);
	}

	return 0;
}

// Computing the internet checksum (RFC 1071).
// Note that the internet checksum is not guaranteed to preclude collisions.
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

