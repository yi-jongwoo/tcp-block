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
	operator uint16_t() const;
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
	operator uint32_t() const;
};
typedef tcp_port nint16_t;
typedef ipv4_addr nint32_t;

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
	nint16_t ethtype;
	ethernet_packet(){}
	ethernet_packet(const mac_addr& src);
	ethernet_packet(const mac_addr& src,const mac_addr& dst):src(src),dst(dst){}
	operator const uint8_t*() const;
};

struct __attribute__((packed)) ipv4_eth:public ethernet_packet{
	uint8_t v_hs;
	ignore_bytes(1);
	nint16_t len;
	ignore_bytes(4);
	uint8_t ttl;
	uint8_t protocall;
	nint16_t checksum;
	ipv4_addr sip;
	ipv4_addr tip;
	bool is_valid() const;
	void validate();
};
struct __attribute__((packed)) tcp_ipv4_eth:public ipv4_eth{
	uint8_t data[0];
	struct __attribute__((packed)) tcp{
		tcp_port sport;
		tcp_port tport;
		nint32_t seq;
		nint32_t ack;
		uint8_t hs_0;
		uint8_t flags;
		ignore_bytes(2);
		nint16_t checksum;
		ignore_bytes(2);
		uint8_t data[0];
	};
	bool is_valid() const;
	tcp* get_tcp() const;
	uint8_t* get_content() const;
	void validate();
};
