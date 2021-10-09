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



// MAC/IP Address Related
Mac GetMyMac(char* dev);
Ip GetMyIp(char* dev);

Mac GetMacfromIp(pcap_t* handle, Ip tip);