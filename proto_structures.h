#pragma once

#include <cstdint>
#include <iostream>
#include <sstream>
#include <cstring>
#include <netinet/in.h>

#define TOKEN_PASTE(x, y) x##y
#define CAT(x,y) TOKEN_PASTE(x,y)
#define ignore_bytes(n) uint8_t CAT(nevermind,__LINE__)[n];

union __attribute__((packed)) tcp_port{
	static constexpr int siz=2;
	uint8_t addr[2];
	uint16_t word;
	tcp_port(){}
	tcp_port(uint16_t x);
};

union __attribute__((packed)) ipv4_addr{
	static constexpr uint16_t ethtype=0x0800;
	static constexpr int siz=4;
	uint8_t addr[4];
	uint32_t word;
	ipv4_addr(){}
	ipv4_addr(uint32_t x);
	ipv4_addr(const std::string& x);
	ipv4_addr(const char *x);
	operator std::string() const;
};

struct __attribute__((packed)) mac_addr{
	static constexpr int siz=6;
	uint8_t addr[6];
	mac_addr(){}
	mac_addr(const std::string& x);
	mac_addr(const char *x);
	operator std::string() const;
	bool is_broadcast() const;
};

struct __attribute__((packed)) ethernet_packet{
	mac_addr dst;
	mac_addr src;
	uint16_t ethtype;
	ethernet_packet(){}
	ethernet_packet(const mac_addr& src);
	ethernet_packet(const mac_addr& src,const mac_addr& dst):src(src),dst(dst){}
	operator const uint8_t*() const;
};

struct __attribute__((packed)) arp_eth_ipv4:public ethernet_packet{
	uint16_t l2type;
	uint16_t l3type;
	uint8_t l2addr_siz;
	uint8_t l3addr_siz;
	uint16_t arptype;
	mac_addr smac;
	ipv4_addr sip;
	mac_addr dmac;
	ipv4_addr tip;
	arp_eth_ipv4();
	arp_eth_ipv4(const mac_addr& src,const ipv4_addr& sip,const ipv4_addr& tip); // request
	arp_eth_ipv4(const mac_addr& src,const mac_addr& dst,const ipv4_addr& sip,const ipv4_addr& tip); // reply
	bool is_valid() const;
};
struct __attribute__((packed)) ipv4_eth:public ethernet_packet{
	ignore_bytes(2);
	uint16_t len;
	ignore_bytes(5);
	uint8_t protocall;
	ignore_bytes(2);
	ipv4_addr sip;
	ipv4_addr tip;
	bool is_valid() const;
};
struct __attribute__((packed)) tcp_ipv4_eth:public ipv4_eth{
	bool is_valid() const;
};
