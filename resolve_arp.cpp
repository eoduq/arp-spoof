#include "resolve_arp.h"

Mac resolve_arp(pcap_t* handle,  Mac dmac, Mac smac, Ip sip, Mac tmac, Ip tip ){
    EthArpPacket reqPacket;//store request packet
    setEthArpPacket(&reqPacket,dmac,smac,sip,tmac,tip);
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&reqPacket), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		//return -1;
        exit(-1);
	}
    while(1){
        struct pcap_pkthdr* header;
	    const u_char* packet;
	    res = pcap_next_ex(handle, &header, &packet);
	    if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
		    printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
		    exit(-1);
	    }
        //is packet from sender?
        EthArpPacket* replypacket=(EthArpPacket*)packet;
        if(replypacket->eth_.type_==replypacket->eth_.Arp){
            if(replypacket->arp_.sip_==tip){
                return replypacket->eth_.smac_;
            }
            else 
                continue;
        }

    }
    
}