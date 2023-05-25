all : tcp-block

tcp-block : main.o proto_structures.o local_address.o
	g++ main.o proto_structures.o local_address.o -lpcap -o tcp-block

main.o : main.cpp proto_structures.h
	g++ -c main.cpp -o main.o -std=c++20

local_address.o : local_address.cpp local_address.h
	g++ -c local_address.cpp -o local_address.o

proto_structures.o : proto_structures.cpp proto_structures.h
	g++ -c proto_structures.cpp -o proto_structures.o

clean :
	rm -f *.o
	rm -f tcp-block
