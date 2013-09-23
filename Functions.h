#include"GlobalData.h"

// Initialization - update table
bool init(char* interface1, char* interface2);


//start the router functionality
void start(char* interface1, char* interface2);


//pcap callback function 
void callback(u_char *args, const struct pcap_pkthdr *header, const u_char* frame);


//process the Received frame
void ProcessReceivedFrame();

uint8_t*
allocate_ustrmem (int len);

uint8_t* GetMACAddressFromInterface(char* interface);

