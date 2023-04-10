build:	ipk-sniffer.c
	gcc -std=gnu99 ipk-sniffer.c -o ipk-sniffer
test: ipk-sniffer test.py
	python3 test.py

clean:
	rm ipk-sniffer

