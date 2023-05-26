#include "proto_structures.h"
#include "local_address.h"
#include <pcap.h>
#include <string>
#include <iostream>
#include <cstdlib>
#include <algorithm>
pcap_t* handle;
std::string forbidden;
void send_tcp_rst(const tcp_ipv4_eth& packet,uint32_t datalen,int flag){ // flag=1: rst flag=2: fin
	tcp_ipv4_eth forward=packet;
	auto fortcp=forward.get_tcp();
	fortcp->seq=fortcp->seq+datalen;
	fortcp->flags=0x14; // ack rst
	forward.len=(uint8_t*)fortcp-forward+sizeof*fortcp;
	forward.validate();
	
	tcp_ipv4_eth backward=forward;
	auto backtcp=backward.get_tcp();
	std::swap(backward.src,backward.dst);
	std::swap(backward.sip,backward.tip);
	std::swap(backtcp->sport,backtcp->tport);
	std::swap(backtcp->seq,backtcp->ack);
	backward.ttl=64+rand()%64;
	backward.validate();
}

bool https_check(const uint8_t* begin,const uint8_t* end){ // get tcp content
	
}

bool http_check(const uint8_t* begin,const uint8_t* end){ // get tcp content
	
}

void tcp_check(const tcp_ipv4_eth& packet){
	int iplen=packet.len+sizeof(ethernet_packet);
	int flag=0;
	switch(packet.get_tcp()->tport){
	case 80:
		flag=http_check(packet.get_content(),packet+iplen)<<1;
		break;
	case 443:
		flag=https_check(packet.get_content(),packet+iplen);
		break;
	}
	if(flag)
		send_tcp_rst(packet,packet+iplen-packet.get_content(),flag);
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
			tcp_check(*(tcp_ipv4_eth*)ptr);
	}
}
