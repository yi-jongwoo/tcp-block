#include <pcap.h>
#include <queue>
#include <iostream>
#include <thread>
#include <mutex>
#include <semaphore> //c++20 required

struct multiqueue:public std::queue<std::string>{
	std::counting_semaphore<1024> sem;
	std::mutex ex;
	multiqueue():std::queue<std::string>(),sem(0),ex(){}
	void push(const std::string& x){
		ex.lock();
		std::queue<std::string>::push(x);
		if(size()>=1024){
			std::cout<<"queue overflow"<<std::endl;
			exit(1);
		}
		ex.unlock();
		sem.release();
	}
	std::string pop(){
		sem.acquire();
		ex.lock();
		std::string res=front();
		std::queue<std::string>::pop();
		ex.unlock();
		return res;
	}
} Q;

void https_check(const unsigned char* data){ // get tcp content
}

void http_check(const unsigned char* data){ // get tcp content
}

void fast_check(const unsigned char* packet){ // get ip packet
}

int main(int c, char** v){
}
