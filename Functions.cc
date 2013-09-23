#include"Functions.h"



bool init(char* interface1, char* interface2)
{

	forwarding_address * entries[3];
		
	int mask[3]={30,29,23};
	entries[0]= create_forward_structure( ip_to_long_ip("10.10.0.1"),ip_to_long_ip("10.10.0.0"), NULL,interface1);
	entries[1]= create_forward_structure( ip_to_long_ip("10.99.0.1"),ip_to_long_ip("10.1.0.0"), NULL,interface2);
	entries[2]= create_forward_structure( ip_to_long_ip("10.99.0.2"),ip_to_long_ip("10.1.2.0"),NULL,interface2);

	for(int i=0;i<3;i++)
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

	//lock mutex

	//add to queue 

	//unlock

	//signal frame processing thread
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








