LDLIBS=-lpcap

all: send-arp-test

main.o: mac.h ip.h ethhdr.h arphdr.h getMacaddr.h getIPv4addr.h etharppacket.h setEthArpPacket.h flow.h relatedspoof.h resolve_arp.h  main.cpp

arphdr.o: mac.h ip.h arphdr.h arphdr.cpp

ethhdr.o: mac.h ethhdr.h ethhdr.cpp

ip.o: ip.h ip.cpp

mac.o : mac.h mac.cpp

getMacaddr.o : getMacaddr.h getMacaddr.cpp

getIPv4addr.o : getIPv4addr.h getIPv4addr.cpp

relatedspoof.o : mac.h ip.h ethippacket.h flow.h ethhdr.h relatedspoof.h relatedspoof.cpp

resolve_arp.o : etharppacket.h setEthArpPacket.h mac.h ip.h resolve_arp.h resolve_arp.cpp

setEthArpPacket.o : mac.h ip.h etharppacket.h ethhdr.h arphdr.h setEthArpPacket.h setEthArpPacket.cpp

iphdr.o : iphdr.h iphdr.cpp

etharppacket.o : ethhdr.h arphdr.h etharppacket.h



send-arp-test: main.o arphdr.o ethhdr.o ip.o mac.o getMacaddr.o getIPv4addr.o relatedspoof.o resolve_arp.o setEthArpPacket.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f send-arp-test *.o
