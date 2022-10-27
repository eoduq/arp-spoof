#pragma once
#include <pcap.h>
#include "etharppacket.h"
#include "setEthArpPacket.h"
#include "mac.h"
#include "ip.h"

Mac resolve_arp(pcap_t* handle, Mac dmac, Mac smac, Ip sip, Mac tmac, Ip tip );
