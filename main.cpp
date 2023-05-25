#include "proto_structures.h"
#include "local_address.h"
#include <pcap.h>
#include <string>
#include <iostream>
pcap_t* handle;
std::string forbidden;
void tcp_rst(const unsigned char* packet){
	
}

bool https_check(const unsigned char* data,int len){ // get tcp content
}

bool http_check(const unsigned char* data,int len){ // get tcp content
}

void tcp_check(tcp_ipv4_eth* packet){ // get ip packet
	int iplen=packet->len;
	auto head=packet->get_tcp();
	if(head->tport==80){
	}
	else if(1){
	}
}

int main(int c, char** v){
	if(c!=3){
		std::cout<<"u : tcp-block <interface> <pattern>"<<std::endl;
		return 1;
	}
	forbidden=v[2];
	mac_addr my_mac=get_mac_addr(v[1]);
	char errbuf[PCAP_ERRBUF_SIZE];
	handle=pcap_open_live(v[1],BUFSIZ,1,1,errbuf);
	if(handle==nullptr){
		std::cout<<"pcap error : "<<errbuf<<std::endl;
		exit(1);
	}
	for(;;){
		pcap_pkthdr* hdr;
		const uint8_t* ptr;
		if(!pcap_next_ex(handle,&hdr,&ptr)){
			printf("pcap listing failed\n");
			exit(1);
		}
		if(!memcmp(&((ethernet_packet*)ptr)->src,&my_mac,6))
			continue;
		if(((tcp_ipv4_eth*)ptr)->is_valid())
			tcp_check((tcp_ipv4_eth*)ptr);
	}
}
