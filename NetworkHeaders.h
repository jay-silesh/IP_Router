//Ethernet, IP header, ICMP, ARP - rest headers

#pragma once

#include<linux/icmp.h>
#include<net/ethernet.h>
#include <netinet/in.h>       // IPPROTO_RAW, INET_ADDRSTRLEN
#include <netinet/ip.h> 



typedef struct ether_header ethernetHeader;
typedef struct icmphdr icmpHeader;
typedef struct iphdr ipHeader;


