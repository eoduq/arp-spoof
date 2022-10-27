#pragma once
#include "ip.h"
#include "mac.h"
#include "etharppacket.h"

struct flow{
    Ip attacker_ip;
    Mac attaceker_mac;
    Ip sender_ip;
    Mac sender_mac;
    Ip target_ip;
    Mac target_mac;
    EthArpPacket infectionPacket;
};