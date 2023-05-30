#include "proto_structures.h"
#include "local_address.h"
#include <pcap.h>
#include <string>
#include <iostream>
#include <cstdlib>
#include <algorithm>
#include <unistd.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
pcap_t* handle;
std::string forbidden,interf;
char redirection[]="HTTP/1.1 302 Redirect\r\nLocation: http://warning.or.kr\r\n\r\n";
mac_addr my_mac;
void send_raw_eth(const uint8_t* data,int len){
	uint8_t* tmp=(uint8_t*)malloc(len); memcpy(tmp,data,len);
	int sd = socket(AF_PACKET, SOCK_RAW, 0xbbf1);
	if(sd==-1){
		std::cout<<"raw socket fail"<<std::endl;
		perror("");
		exit(1);
	}
	ifreq ifr;
	strcpy(ifr.ifr_name,interf.c_str());
	ioctl(sd, SIOCGIFINDEX, &ifr);
	
	sockaddr_ll addr;
        memset(&addr, 0, sizeof(addr));
        addr.sll_family = AF_PACKET;
        addr.sll_protocol = 0xbbf1;
        addr.sll_ifindex = ifr.ifr_ifindex; 
        bind(sd, (struct sockaddr *)(&addr), sizeof addr);
        
        ((ethernet_packet*)tmp)->src=my_mac;
        
        if(send(sd, tmp, len, 0)==-1){
		std::cout<<"raw socket send fail"<<std::endl;
		perror("");
		exit(1);
	}
        
        free(tmp);
}
void send_tcp_rst(const tcp_ipv4_eth& packet,uint32_t datalen,int flag){ // flag=1: rst flag=2: fin
	std::cout<<"; forbidden host detected"<<std::endl;
	uint8_t _forward[20+sizeof packet]; 
	memcpy(_forward,packet,sizeof packet); 
	memcpy(_forward+sizeof packet,packet.get_tcp(),20);
	tcp_ipv4_eth &forward=*(tcp_ipv4_eth*)_forward;
	forward.len=40;
	forward.v_hs=0x45;
	auto fortcp=forward.get_tcp();
	fortcp->hs_0=0x50;
	fortcp->seq=fortcp->seq+datalen;
	fortcp->flags=0x14; // ack rst
	forward.validate();
	//pcap_sendpacket(handle,forward,sizeof _forward);
	//send_raw_ip(_forward+sizeof(ethernet_packet),40);
	send_raw_eth(_forward,40+sizeof(ethernet_packet));
	
	uint8_t _backward[20+sizeof packet+sizeof redirection];
	memcpy(_backward,_forward,sizeof _forward);
	tcp_ipv4_eth &backward=*(tcp_ipv4_eth*)_backward;
	auto backtcp=backward.get_tcp();
	if(flag==2){
		memcpy(_backward+sizeof _forward,redirection,sizeof redirection);
		backward.len=40+sizeof redirection;
		backtcp->flags=0x11;
	}
	std::swap(backward.src,backward.dst);
	
	std::swap(backward.sip,backward.tip);
	
	std::swap(backtcp->sport,backtcp->tport);
	std::swap(backtcp->seq,backtcp->ack);
	backward.ttl=64+rand()%64;
	
	backward.validate();
	//pcap_sendpacket(handle,backward,sizeof _forward+(flag-1)*sizeof redirection);
	//send_raw_ip(_backward+sizeof(ethernet_packet),40+(flag-1)*sizeof redirection);
	send_raw_eth(_backward,40+sizeof(ethernet_packet)+(flag-1)*sizeof redirection);
	//std::cout<<"ip "<<forward.sip<<' '<<forward.tip<<std::endl;
	//std::cout<<"ip "<<backward.sip<<' '<<backward.tip<<std::endl;
	std::cout<<'!'<<forward.len<<std::endl;
}

bool https_check(const uint8_t* begin,const uint8_t* end){ // get tcp content
	std::cout<<"; https detected"<<std::endl;
	return ~std::string(begin,end).find(forbidden);
}

bool http_check(const uint8_t* begin,const uint8_t* end){ // get tcp content
	std::cout<<"; http detected"<<std::endl;
	//for(const uint8_t* it=begin;it!=end;it++)
	//	std::cout<<(char)*it;
	//std::cout<<"http end---"<<std::endl;
	for(const uint8_t* x=begin;;){
		while(x!=end&&*x++!='\n');
		if(x+6>=end)return false;
		if(*x++=='\r')return false;
		if(*(int*)x++==':tso'){ // x->st: *
			int n=forbidden.size();
			std::cout<<"!\n"<<x+4;
			return memcmp(x+4,forbidden.c_str(),n)==0 && x[n+4]=='\r';
		}
	}
}

void tcp_check(const tcp_ipv4_eth& packet){
	//std::cout<<"; tcp detected "<<packet.get_tcp()->sport<<' '<<packet.get_tcp()->tport<<std::endl;
	//for(int i=0;i<20;i++)
	//	std::cout<<std::hex<<(int)packet.data[i]<<std::endl;
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
	my_mac=get_mac_addr(v[1]);
	interf=v[1];
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
		//if(!memcmp(&((ethernet_packet*)ptr)->src,&my_mac,6))
		//	continue;
		if(((tcp_ipv4_eth*)ptr)->is_valid())
			tcp_check(*(tcp_ipv4_eth*)ptr);
	}
}
