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

#define IP6_HDRLEN 40         
#define UDP_HDRLEN  8         

uint16_t checksum (uint16_t *addr, int len);
uint16_t udp6_checksum (struct ip6_hdr, struct udphdr, uint8_t *, int);
char *allocate_strmem (int);
uint8_t *allocate_ustrmem (int);

int
main (int argc, char **argv) {

  int i, status, datalen, frame_length, sd, bytes;
  char *interface, *target, *src_ip, *dst_ip;
  struct ip6_hdr iphdr;
  struct udphdr udphdr;
  uint8_t *data, *src_mac, *dst_mac, *ether_frame;
  struct addrinfo hints, *res;
  struct sockaddr_in6 *ipv6;
  struct sockaddr_ll device;
  struct ifreq ifr;
  void *tmp;

  src_mac = allocate_ustrmem (6);
  dst_mac = allocate_ustrmem (6);
  data = allocate_ustrmem (IP_MAXPACKET);
  ether_frame = allocate_ustrmem (IP_MAXPACKET);
  interface = allocate_strmem (INET6_ADDRSTRLEN);
  target = allocate_strmem (INET6_ADDRSTRLEN);
  src_ip = allocate_strmem (INET6_ADDRSTRLEN);
  dst_ip = allocate_strmem (INET6_ADDRSTRLEN);

  strcpy (interface, "lo");

  if ((sd = socket (PF_PACKET, SOCK_DGRAM, IPPROTO_RAW)) < 0) {
    perror ("socket() failed to get socket descriptor for using ioctl() ");
    exit (EXIT_FAILURE);
  }

  memset (&ifr, 0, sizeof (ifr));
  snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
  if (ioctl (sd, SIOCGIFHWADDR, &ifr) < 0) {
    perror ("ioctl() failed to get source MAC address ");
    return (EXIT_FAILURE);
  }
  close (sd);

  memcpy (src_mac, ifr.ifr_hwaddr.sa_data, 6 * sizeof (uint8_t));

  printf ("MAC address for interface %s is ", interface);
  for (i=0; i<5; i++) {
    printf ("%02x:", src_mac[i]);
  }
  printf ("%02x\n", src_mac[5]);

  memset (&device, 0, sizeof (device));
  if ((device.sll_ifindex = if_nametoindex (interface)) == 0) {
    perror ("if_nametoindex() failed to obtain interface index ");
    exit (EXIT_FAILURE);
  }
  printf ("Index for interface %s is %i\n", interface, device.sll_ifindex);

  dst_mac[0] = 0xff;
  dst_mac[1] = 0xff;
  dst_mac[2] = 0xff;
  dst_mac[3] = 0xff;
  dst_mac[4] = 0xff;
  dst_mac[5] = 0xff;

  /*strcpy (src_ip, "2001:db8::214:51ff:fe2f:1556");*/
  strcpy (src_ip, "::1");

  /*strcpy (target, "ipv6.google.com");*/
  strcpy (target, "::1");

  memset (&hints, 0, sizeof (hints));
  hints.ai_family = AF_INET6;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = hints.ai_flags | AI_CANONNAME;

  if ((status = getaddrinfo (target, NULL, &hints, &res)) != 0) {
    fprintf (stderr, "getaddrinfo() failed for target: %s\n", gai_strerror (status));
    exit (EXIT_FAILURE);
  }
  ipv6 = (struct sockaddr_in6 *) res->ai_addr;
  tmp = &(ipv6->sin6_addr);
  if (inet_ntop (AF_INET6, tmp, dst_ip, INET6_ADDRSTRLEN) == NULL) {
    status = errno;
    fprintf (stderr, "inet_ntop() failed for target.\nError message: %s", strerror (status));
    exit (EXIT_FAILURE);
  }
  freeaddrinfo (res);

  device.sll_family = AF_PACKET;
  device.sll_protocol = htons (ETH_P_IPV6);
  memcpy (device.sll_addr, dst_mac, 6 * sizeof (uint8_t));
  device.sll_halen = 6;

  // UDP data
  datalen = 6;
  data[0] = 'T';
  data[1] = 'e';
  data[2] = 's';
  data[3] = 't';
  data[4] = 'e';
  data[5] = 'x';


  iphdr.ip6_flow = htonl ((6 << 28) | (0 << 20) | 0);

  iphdr.ip6_plen = htons (UDP_HDRLEN + datalen);

  iphdr.ip6_nxt = IPPROTO_UDP;

  iphdr.ip6_hops = 255;

  if ((status = inet_pton (AF_INET6, src_ip, &(iphdr.ip6_src))) != 1) {
    fprintf (stderr, "inet_pton() failed for source address.\nError message: %s", strerror (status));
    exit (EXIT_FAILURE);
  }

  if ((status = inet_pton (AF_INET6, dst_ip, &(iphdr.ip6_dst))) != 1) {
    fprintf (stderr, "inet_pton() failed for destination address.\nError message: %s", strerror (status));
    exit (EXIT_FAILURE);
  }


  udphdr.source = htons (4950);

  udphdr.dest = htons (4950);

  udphdr.len = htons (UDP_HDRLEN + datalen);

  udphdr.check = udp6_checksum (iphdr, udphdr, data, datalen);


  frame_length = IP6_HDRLEN + UDP_HDRLEN + datalen;

  memcpy (ether_frame, &iphdr, IP6_HDRLEN * sizeof (uint8_t));

  memcpy (ether_frame + IP6_HDRLEN, &udphdr, UDP_HDRLEN * sizeof (uint8_t));

  memcpy (ether_frame + IP6_HDRLEN + UDP_HDRLEN, data, datalen * sizeof (uint8_t));

  if ((sd = socket (PF_PACKET, SOCK_DGRAM, htons (ETH_P_ALL))) < 0) {
    perror ("socket() failed ");
    exit (EXIT_FAILURE);
  }

  if ((bytes = sendto (sd, ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) {
    perror ("sendto() failed");
    exit (EXIT_FAILURE);
  }

  close (sd);

  free (src_mac);
  free (dst_mac);
  free (data);
  free (ether_frame);
  free (interface);
  free (target);
  free (src_ip);
  free (dst_ip);

  return (EXIT_SUCCESS);
}

uint16_t
checksum (uint16_t *addr, int len) {

  int count = len;
  register uint32_t sum = 0;
  uint16_t answer = 0;

  while (count > 1) {
    sum += *(addr++);
    count -= 2;
  }

  if (count > 0) {
    sum += *(uint8_t *) addr;
  }

  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  answer = ~sum;

  return (answer);
}

uint16_t
udp6_checksum (struct ip6_hdr iphdr, struct udphdr udphdr, uint8_t *payload, int payloadlen) {

  char buf[IP_MAXPACKET];
  char *ptr;
  int chksumlen = 0;
  int i;

  ptr = &buf[0];  // ptr points to beginning of buffer buf

  // Copy source IP address into buf (128 bits)
  memcpy (ptr, &iphdr.ip6_src.s6_addr, sizeof (iphdr.ip6_src.s6_addr));
  ptr += sizeof (iphdr.ip6_src.s6_addr);
  chksumlen += sizeof (iphdr.ip6_src.s6_addr);

  // Copy destination IP address into buf (128 bits)
  memcpy (ptr, &iphdr.ip6_dst.s6_addr, sizeof (iphdr.ip6_dst.s6_addr));
  ptr += sizeof (iphdr.ip6_dst.s6_addr);
  chksumlen += sizeof (iphdr.ip6_dst.s6_addr);

  // Copy UDP length into buf (32 bits)
  memcpy (ptr, &udphdr.len, sizeof (udphdr.len));
  ptr += sizeof (udphdr.len);
  chksumlen += sizeof (udphdr.len);

  // Copy zero field to buf (24 bits)
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 3;

  // Copy next header field to buf (8 bits)
  memcpy (ptr, &iphdr.ip6_nxt, sizeof (iphdr.ip6_nxt));
  ptr += sizeof (iphdr.ip6_nxt);
  chksumlen += sizeof (iphdr.ip6_nxt);

  // Copy UDP source port to buf (16 bits)
  memcpy (ptr, &udphdr.source, sizeof (udphdr.source));
  ptr += sizeof (udphdr.source);
  chksumlen += sizeof (udphdr.source);

  // Copy UDP destination port to buf (16 bits)
  memcpy (ptr, &udphdr.dest, sizeof (udphdr.dest));
  ptr += sizeof (udphdr.dest);
  chksumlen += sizeof (udphdr.dest);

  // Copy UDP length again to buf (16 bits)
  memcpy (ptr, &udphdr.len, sizeof (udphdr.len));
  ptr += sizeof (udphdr.len);
  chksumlen += sizeof (udphdr.len);

  // Copy UDP checksum to buf (16 bits)
  // Zero, since we don't know it yet
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 2;

  // Copy payload to buf
  memcpy (ptr, payload, payloadlen * sizeof (uint8_t));
  ptr += payloadlen;
  chksumlen += payloadlen;

  // Pad to the next 16-bit boundary
  for (i=0; i<payloadlen%2; i++, ptr++) {
    *ptr = 0;
    ptr++;
    chksumlen++;
  }

  return checksum ((uint16_t *) buf, chksumlen);
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

// Allocate memory for an array of unsigned chars.
uint8_t *
allocate_ustrmem (int len) {

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
