all:	dns_spoof.o arp_attack.o
	gcc -o dns_spoof dns_spoof.o -lpcap	
	gcc -o arp_attack arp_attack.o -lpcap

dns_spoof.o:	dns_spoof.c
	gcc -c dns_spoof.c

arp_attack.o:	arp_attack.c
	gcc -c arp_attack.c

clean:
	rm dns_spoof.o dns_spoof arp_attack.o arp_attack

