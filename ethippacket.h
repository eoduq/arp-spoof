#pragma once

#include "ethhdr.h"
#include "iphdr.h"
#pragma pack(push, 1)
struct EthIpPacket final {
	EthHdr eth_;
	IpHdr iph_;
};
#pragma pack(pop)