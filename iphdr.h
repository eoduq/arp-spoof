#pragma once

#include <arpa/inet.h>
#include "mac.h"
#include "ip.h"

#pragma pack(push, 1)
struct IpHdr final {
	uint8_t ver_IHL_;
    uint8_t tos_;
    uint16_t total_length_;
    uint16_t identiciation_;
    uint16_t flag_fragmentation_;
    uint8_t ttl_;
    uint8_t protocol_;
    uint32_t hdr_checksum;
    Ip dip_;
	Ip sip_;
	

	Ip dip() { return dip_; }
	Ip sip() { return sip_; }
	

	// Type(type_)
	enum: uint8_t {
		ICMP = 0x01,
		TCP = 0x06,
		UDP = 0x11
	};
};
typedef IpHdr *PIpHdr;
#pragma pack(pop)
