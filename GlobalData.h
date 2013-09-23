// Queue 

#pragma once

#include<queue>
#include<map>
#include<mutex.h>
#include<pthread.h>
#include<pcap.h>



typedef struct 
{
	long next_hop_ip_addr;
	long nw_addr;
	char *mac_addr;
	char *interface_name;
}forwarding_address;

map<long,struct forwarding_address*>routing_table;
typedef map<long,struct forwarding_address*>::iterator routing_table_iterator;


typedef struct
{
	struct pcap_pkthdr *pcapHeader;
	u_char *frame;
}waitQueueEntry;

queue<waitQueueEntry> waitQueue;
pthread_mutex_t waitQueueMutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t packetReceivedSignal= PTHREAD_COND_INITIALIZER;

pcap_t *pcap1, *pcap2;
pthread_t interfaceListen1, interfaceListen2, frameProcessThread;
int ipRawSocket, arpRawSocket; /* for sending the processed frames */



