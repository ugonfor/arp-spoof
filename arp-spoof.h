// custom header files
#include "header/arphdr.h"
#include "header/ethhdr.h"
#include "header/ip.h"
#include "header/mac.h"

#include <stdio.h>
#include <pcap.h>

// cpp library
#include <iostream>
#include <string>
#include <thread>
#include <stdint.h>
#include <signal.h>
#include <queue>
#include <map>

// for struct ifreq, socket, ioctl
#include <linux/if.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

// packet structure
#pragma pack(push, 1)
// Iphdr
struct IpHdr final{
    uint8_t version:4;
    uint8_t header_length:4;
    uint8_t tos;

    uint16_t total_length;
    uint16_t identification;
    
    uint8_t flags:3;
    uint16_t fragment_offset:13;

    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    
    Ip sip;
    Ip dip;
};


// Eth - ARP
struct EthArpPacket{
    EthHdr eth_;
    ArpHdr arp_;
};

// Eth - IP
struct EthIpPacket{
    EthHdr eth_;
    IpHdr ip_;
};
#pragma pack(pop)

// Packet Related
extern Mac myMac;
extern Ip myIp;
extern pcap_t* handle;

extern std::map<Ip, Mac> ArpTable;
extern std::map<Ip, Ip> Send2Tar;


#define ARP_REP_TYPE 0
#define ARP_REQ_TYPE 1
void MakeEthArpPkt(EthArpPacket* lp_arp_pkt, Mac eth_smac, Mac eth_dmac, Mac arp_smac, Ip arp_sip , Mac arp_tmac , Ip arp_tip, int type);


// MAC/IP Address Related
Mac GetMyMac(char* dev);
Ip GetMyIp(char* dev);
Mac GetMacfromIp(pcap_t* handle, Ip tip);

// ARP table infection
bool SendArpInfectPkt(pcap_t* handle, Ip sender_ip, Mac sender_mac, Ip target_ip, int type);

// Arp Infection
void PeriodicInfection(pcap_t* handle, std::map<Ip, Ip> Send2Tar, std::map<Ip, Mac> ArpTable);

// Ip Relay
bool IpPacketRelay(pcap_t* handle, std::map<Ip, Ip> Send2Tar, std::map<Ip, Mac> ArpTable);

// Sig handler
void SigINTHandler(int sig);