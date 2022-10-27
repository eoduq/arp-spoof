#include "setEthArpPacket.h"

void setEthArpPacket(EthArpPacket* packet, Mac dmac, Mac smac, Ip sip, Mac tmac, Ip tip){

    packet->eth_.dmac_ = dmac;//broadcast adress to send the packet to all of hosts
	packet->eth_.smac_ = smac;
	packet->eth_.type_ = htons(EthHdr::Arp);
	packet->arp_.hrd_ = htons(ArpHdr::ETHER);
	packet->arp_.pro_ = htons(EthHdr::Ip4);
	packet->arp_.hln_ = Mac::SIZE;
	packet->arp_.pln_ = Ip::SIZE;
	packet->arp_.op_ = htons(ArpHdr::Request);
	packet->arp_.smac_ = smac;
	packet->arp_.sip_ = htonl(sip);
	packet->arp_.tmac_ = tmac;
	packet->arp_.tip_ = htonl(tip);

}