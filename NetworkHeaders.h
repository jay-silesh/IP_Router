//Ethernet, IP header, ICMP, ARP - rest headers

#pragma once

#include <linux/icmp.h>
#include <net/ethernet.h>
#include <netinet/in.h>       // IPPROTO_RAW, INET_ADDRSTRLEN
#include <netinet/ip.h> 



typedef struct ether_header ethernetHeader;
typedef struct icmphdr icmpHeader;
typedef struct iphdr ipHeader;

typedef struct _arp_hdr {
  uint16_t htype;
  uint16_t ptype;
  uint8_t hlen;
  uint8_t plen;
  uint16_t opcode;
  uint8_t sender_mac[6];
  uint8_t sender_ip[4];
  uint8_t target_mac[6];
  uint8_t target_ip[4];
}arp_hdr;