#include "proto_structures.h"
tcp_port::tcp_port(uint16_t x){
	word=htons(x);
}
tcp_port::operator uint16_t() const{
	return htons(word);
}
ipv4_addr::ipv4_addr(uint32_t x){
	word=htonl(x);
}
ipv4_addr::ipv4_addr(const std::string& x){
	std::istringstream ss(x);
	char _;
	for(int i=0;i<siz;i++){
		if(i)ss>>_;
		int tmp;ss>>tmp;
		addr[i]=tmp;
	}
}
ipv4_addr::ipv4_addr(const char *x){
	for(int i=0;i<siz;i++){
		int n;
		sscanf(x,"%hhd%n",addr+i,&n);
		x+=n+1;
	}
}
ipv4_addr::operator std::string() const{
	std::ostringstream ss;
	for(int i=0;i<siz;i++){
		if(i)ss<<'.';
		int tmp=addr[i];
		ss<<tmp;
	}
	return ss.str();
}
ipv4_addr::operator uint32_t() const{
	return htonl(word);
}
mac_addr::mac_addr(const std::string& x){
	std::istringstream ss(x);ss>>std::hex;
	char _;
	for(int i=0;i<siz;i++){
		if(i)ss>>_;
		int tmp;ss>>tmp;
		addr[i]=tmp;
	}
}
mac_addr::mac_addr(const char *x){
	for(int i=0;i<siz;i++){
		int n;
		sscanf(x,"%hhx%n",addr+i,&n);
		x+=n+1;
	}
}
mac_addr::operator std::string() const{
	std::ostringstream ss;ss<<std::hex;
	for(int i=0;i<siz;i++){
		if(i)ss<<'-';
		int tmp=addr[i];
		ss<<tmp/16<<tmp%16;
	}
	return ss.str();
}
bool mac_addr::is_broadcast() const{
	uint8_t res=0xff;
	for(int i=0;i<siz;i++)
		res&=addr[i];
	return !~res;
}

ethernet_packet::ethernet_packet(const mac_addr& src):src(src){
	memset(&dst,-1,sizeof dst);
}
ethernet_packet::operator const uint8_t*() const{
	return (uint8_t*)this;
}
bool ipv4_eth::is_valid() const{
	return ethtype==0x0800;
}
bool tcp_ipv4_eth::is_valid() const{
	return ipv4_eth::is_valid()&&protocall==0x06;
}
tcp_ipv4_eth::tcp* tcp_ipv4_eth::get_tcp() const{
	return (tcp*)(data+((v_hs&0xf)<<2));
}
uint8_t* tcp_ipv4_eth::get_content() const{
	tcp* head=get_tcp();
	return head->data+((head->hs_0>>4)<<2);
}
