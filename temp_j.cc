#include"Functions.h"




char* uint8_to_char(uint8_t *a)
{
	char temp_mac[6];
	snprintf(temp_mac,6,"%02x%02x%02x%02x%02x%02x",a[6],a[7],a[8],a[9],a[10],a[11]);
	return temp_mac;
}



char* receive_arp_packet()
{
  int i, sd, status;
  uint8_t *ether_frame;
  arp_hdr *arphdr;

  ether_frame = allocate_ustrmem (IP_MAXPACKET);

  if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
    perror ("socket() failed ");
    exit (EXIT_FAILURE);
  }

  arphdr = (arp_hdr *) (ether_frame + 6 + 6 + 2);
  while (((((ether_frame[12]) << 8) + ether_frame[13]) != ETH_P_ARP) || (ntohs (arphdr->opcode) != ARPOP_REPLY)) {
    if ((status = recv (sd, ether_frame, IP_MAXPACKET, 0)) < 0) {
      if (errno == EINTR) {
        memset (ether_frame, 0, IP_MAXPACKET * sizeof (uint8_t));
        continue;  // Something weird happened, but let's try again.
      } else {
        perror ("recv() failed:");
        exit (EXIT_FAILURE);
      }
    }
  }
  close (sd);
  char *temp_mac_addr=uint8_to_char(ether_frame);
  return temp_mac_addr;
}

void SendArpRequestFrame(char *iface, char *source_ip, char *next_hop_ip)
{
  int i, status, frame_length, sd, bytes;
  char *interface, *target, *src_ip;
  arp_hdr arphdr;
  uint8_t *src_mac, *dst_mac, *ether_frame;
  struct addrinfo hints, *res;
  struct sockaddr_in *ipv4;
  struct sockaddr_ll device;
  struct ifreq ifr;

  // Allocate memory for various arrays.
  src_mac = allocate_ustrmem (6);
  dst_mac = allocate_ustrmem (6);
  ether_frame = allocate_ustrmem (IP_MAXPACKET);
  interface = allocate_strmem (40);
  target = allocate_strmem (40);
  src_ip = allocate_strmem (INET_ADDRSTRLEN);

  // Interface to send packet through.
  strcpy (interface, iface);

  // Submit request for a socket descriptor to look up interface.
  if ((sd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
    perror ("socket() failed to get socket descriptor for using ioctl() ");
    exit (EXIT_FAILURE);
  }

  // Use ioctl() to look up interface name and get its MAC address.
  memset (&ifr, 0, sizeof (ifr));
  snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
  if (ioctl (sd, SIOCGIFHWADDR, &ifr) < 0) {
    perror ("ioctl() failed to get source MAC address ");
    return (EXIT_FAILURE);
  }
  close (sd);

  // Copy source MAC address.
  memcpy (src_mac, ifr.ifr_hwaddr.sa_data, 6 * sizeof (uint8_t));

  // Report source MAC address to stdout.
  printf ("MAC address for interface %s is ", interface);
  for (i=0; i<5; i++) {
    printf ("%02x:", src_mac[i]);
  }
  printf ("%02x\n", src_mac[5]);

  // Find interface index from interface name and store index in
  // struct sockaddr_ll device, which will be used as an argument of sendto().
  if ((device.sll_ifindex = if_nametoindex (interface)) == 0) {
    perror ("if_nametoindex() failed to obtain interface index ");
    exit (EXIT_FAILURE);
  }
  printf ("Index for interface %s is %i\n", interface, device.sll_ifindex);

  // Set destination MAC address: broadcast address
  memset (dst_mac, 0xff, 6 * sizeof (uint8_t));

  // Source IPv4 address:  you need to fill this out
  strcpy (src_ip, source_ip);

  // Destination URL or IPv4 address (must be a link-local node): you need to fill this out
  strcpy (target, next_hop_ip);

  // Fill out hints for getaddrinfo().
  memset (&hints, 0, sizeof (struct addrinfo));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = hints.ai_flags | AI_CANONNAME;

  // Resolve source using getaddrinfo().
  if ((status = getaddrinfo (src_ip, NULL, &hints, &res)) != 0) {
    fprintf (stderr, "getaddrinfo() failed: %s\n", gai_strerror (status));
    exit (EXIT_FAILURE);
  }
  ipv4 = (struct sockaddr_in *) res->ai_addr;
  memcpy (&arphdr.sender_ip, &ipv4->sin_addr, 4 * sizeof (uint8_t));
  freeaddrinfo (res);

  // Resolve target using getaddrinfo().
  if ((status = getaddrinfo (target, NULL, &hints, &res)) != 0) {
    fprintf (stderr, "getaddrinfo() failed: %s\n", gai_strerror (status));
    exit (EXIT_FAILURE);
  }
  ipv4 = (struct sockaddr_in *) res->ai_addr;
  memcpy (&arphdr.target_ip, &ipv4->sin_addr, 4 * sizeof (uint8_t));
  freeaddrinfo (res);

  // Fill out sockaddr_ll.
  device.sll_family = AF_PACKET;
  memcpy (device.sll_addr, src_mac, 6 * sizeof (uint8_t));
  device.sll_halen = htons (6);

  // ARP header

  // Hardware type (16 bits): 1 for ethernet
  arphdr.htype = htons (1);

  // Protocol type (16 bits): 2048 for IP
  arphdr.ptype = htons (ETH_P_IP);

  // Hardware address length (8 bits): 6 bytes for MAC address
  arphdr.hlen = 6;

  // Protocol address length (8 bits): 4 bytes for IPv4 address
  arphdr.plen = 4;

  // OpCode: 1 for ARP request
  arphdr.opcode = htons (ARPOP_REQUEST);

  // Sender hardware address (48 bits): MAC address
  memcpy (&arphdr.sender_mac, src_mac, 6 * sizeof (uint8_t));

  // Sender protocol address (32 bits)
  // See getaddrinfo() resolution of src_ip.

  // Target hardware address (48 bits): zero, since we don't know it yet.
  memset (&arphdr.target_mac, 0, 6 * sizeof (uint8_t));

  // Target protocol address (32 bits)
  // See getaddrinfo() resolution of target.

  // Fill out ethernet frame header.

  // Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (ARP header)
  frame_length = 6 + 6 + 2 + ARP_HDRLEN;

  // Destination and Source MAC addresses
  memcpy (ether_frame, dst_mac, 6 * sizeof (uint8_t));
  memcpy (ether_frame + 6, src_mac, 6 * sizeof (uint8_t));

  // Next is ethernet type code (ETH_P_ARP for ARP).
  // http://www.iana.org/assignments/ethernet-numbers
  ether_frame[12] = ETH_P_ARP / 256;
  ether_frame[13] = ETH_P_ARP % 256;

  // Next is ethernet frame data (ARP header).

  // ARP header
  memcpy (ether_frame + ETH_HDRLEN, &arphdr, ARP_HDRLEN * sizeof (uint8_t));

  // Submit request for a raw socket descriptor.
  if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
    perror ("socket() failed ");
    exit (EXIT_FAILURE);
  }

  // Send ethernet frame to socket.
  if ((bytes = sendto (sd, ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) {
    perror ("sendto() failed");
    exit (EXIT_FAILURE);
  }

  // Close socket descriptor.
  close (sd);

  // Free allocated memory.
  free (src_mac);
  free (dst_mac);
  free (ether_frame);
  free (interface);
  free (target);
  free (src_ip);
}




char* get_mac_nexthop(char *iface, char *source_ip, char *next_hop_ip)
{
	SendArpRequestFrame(iface,source_ip,next_hop_ip );
	return (receive_arp_packet());
}



bool init(char* interface1, char* interface2)
{

	Get_All_Mac_Address();

	forwarding_address * entries[2];
		
	int mask[2]={29,23};

	char *mac1=get_mac_nexthop(interface2,"10.99.0.3","10.99.0.1");
	char *mac2=get_mac_nexthop(interface2,"10.99.0.3","10.99.0.2");
	entries[0]= create_forward_structure( ip_to_long_ip("10.99.0.1"),ip_to_long_ip("10.1.0.0"), mac1,interface2);
	entries[1]= create_forward_structure( ip_to_long_ip("10.99.0.2"),ip_to_long_ip("10.1.2.0"),mac2,interface2);

	for(int i=0;i<2;i++)
		routing_table.insert(pair<uint32_t,forwarding_address *>(mask_to_int(mask[i]),entries[i]));


	//Here get the mac address using arp code and store the mac address into the routing table

	if ((arpRawSocket = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
		perror ("socket() failed to create RAW socket for sending ARP request ");
		exit (EXIT_FAILURE);
	  }

}

uint8_t* GetMACAddressFromInterface(char* interface)
{

	uint8_t *mac = (uint8_t*)allocate_ustrmem(6);	
	struct ifreq ifr;
	memset (&ifr, 0, sizeof (ifr));
	snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
	if (ioctl (arpRawSocket, SIOCGIFHWADDR, &ifr) < 0) {
		perror ("ioctl() failed to get source MAC address ");
		return NULL;
	}
	memcpy (mac, ifr.ifr_hwaddr.sa_data, 6 * sizeof (uint8_t));

	return mac;
}

void start(char* interface1, char* interface2)
{

	// start two threads for pcap

	// start frame processing thread

}


void callback(u_char *args, const struct pcap_pkthdr *header, const u_char* frame)
{
	waitQueueEntry *entry = (waitQueueEntry*)malloc(sizeof(waitQueueEntry));

	//copy the const frame to new memory
	
	

	

	
	
	waitQueueEntry *entry = (waitQueueEntry*)malloc(sizeof(waitQueueEntry));
	entry->pcapHeader = header;
	entry->frame = (char *)malloc(strlen(frame));
	strncpy(entry->frame,frame,strlen(frame));

	//lock mutex

	pthread_mutex_lock(&waitQueueMutex);
	{
		//add to queue 
		//signal frame processing thread	
		if(waitQueue.empty())
		{
			waitQueue.push(entry);
			pthred_cond_signal(&packetReceivedSignal);
		}
		else
		{
			waitQueue.push(entry);
		}
	}
	
	//unlock
	pthread_mutex_unlock(&waitQueueMutex);	
}




void ProcessReceivedFrame();
{

	//wait for the signal
	//if queue is empty go back to conditional wait
	//else 
	// process the packet
	// First Decreemnt TTL 

	//conditions to be checked for routing;
	//1. if the packet is a broadcast or multicast then drop it
	//2. if packet is destined to a network that router is directly connected then drop it
	//

}


uint8_t *
allocate_ustrmem (int len)
{
  void *tmp;

  tmp = (uint8_t *) malloc (len * sizeof (uint8_t));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (uint8_t));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_ustrmem().\n");
    exit (EXIT_FAILURE);
  }
}








