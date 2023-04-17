build:	ipk-sniffer.cpp
	c++ --std=c++20 -Wall -g ipk-sniffer.cpp -o ipk-sniffer -lpcap

clean:
	rm ipk-sniffer

