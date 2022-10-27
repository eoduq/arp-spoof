#pragma once
#include <iostream>
#include <vector>
#include <pcap.h>
#include <unistd.h>//sleep()
#include "mac.h"
#include "ip.h"
#include "ethippacket.h"
#include "flow.h"
#include "ethhdr.h"

using namespace std;

void Infect(pcap_t* handle,vector<flow> flows);

void Relay(pcap_t *handle, const u_char *spoofed_packet, struct flow f);

void Receive(pcap_t *handle, vector<flow> flows);