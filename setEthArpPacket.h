#include "ethhdr.h"
#include "arphdr.h"
#include "etharppacket.h"
#include "mac.h"
#include "ip.h"
void setEthArpPacket(EthArpPacket* packet, Mac dmac, Mac smac, Ip sip, Mac tmac, Ip tip);
