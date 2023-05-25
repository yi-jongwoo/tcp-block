#include "local_address.h"
#include <iostream>
mac_addr get_mac_addr(const char *dev){
	std::ifstream fs(std::string("/sys/class/net/")+dev+"/address");
	if(!fs.is_open()){
		printf("can\'t access %s\n",dev);
	}
	std::string s;fs>>s;
	mac_addr res(s);
	return res;
}
