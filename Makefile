build:	ipk-sniffer.cpp
	c++ --std=c++20 ipk-sniffer.cpp -o ipk-sniffer -lpcap
test: ipk-sniffer test.py
	python3 test.py

clean:
	rm ipk-sniffer

