#include "local_address.h"
#include <iostream>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
mac_addr get_mac_addr(const char *dev){
	std::ifstream fs(std::string("/sys/class/net/")+dev+"/address");
	if(!fs.is_open()){
		printf("can\'t access %s\n",dev);
	}
	std::string s;fs>>s;
	mac_addr res(s);
	return res;
}
mac_addr get_gateway_mac(const char *dev){
	std::string x("route -n | grep ");
	x+=std::string(dev);
	x+=std::string(" > tmp.txt");
	system(x.c_str());
	{
		std::ifstream fs("tmp.txt");
		fs>>x;fs>>x;
	}
	system("rm tmp.txt");
	//ipv4_addr res(x);
	x=std::string("arp -a | grep ")+x+std::string(" > tmp.txt");
	system(x.c_str());
	{
		std::ifstream fs("tmp.txt");
		while(x!="at")fs>>x;
		fs>>x;
	}
	system("rm tmp.txt");
	std::cout<<x;
	return mac_addr(x);
}
