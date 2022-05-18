#ifndef P6_ICMP6
#define P6_ICMP6

#include "p6_ether.h"
#include "p6_ip.h"

#define ICMP6_HDRLEN_ECRQT 8  // ICMP header length for echo request, excludes data
#define ICMP6_PSDHDRLEN 40

struct icmpv6_header {
  uint8_t type, code;
  uint16_t chksum;
  uint16_t id, seq;
} __attribute__ ((packed));

int p6_icmp6_data( void *addr, int len );
int p6_icmp6_type( uint8_t type);
int p6_icmp6_code( uint8_t code);
int p6_icmp6_checksum( uint16_t cksum );
int p6_icmp6_calc_cksum();
int p6_icmp6_id( uint16_t id);
int p6_icmp6_seq( uint16_t seq );
int p6_dg_cp_icmp6();

extern struct icmpv6_header icmp6_hdr; 

#endif
