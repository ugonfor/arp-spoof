#include "arp-spoof.h"

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
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);

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
    Ip sender_ip = Ip(argv[2]);
    Mac sender_mac = GetMacfromIp(handle, sender_ip);

    // get target IP/MAC address 
    Ip target_ip = Ip(argv[3]);
    Mac target_mac = GetMacfromIp(handle, target_ip);

    // information logging
    std::cout << "sender    Mac :" << std::string(sender_mac) << "\n";
    std::cout << "sender    IP  :" << std::string(sender_ip) << "\n";
    std::cout << "target    Mac :" << std::string(target_mac) << "\n";
    std::cout << "target    IP  :" << std::string(target_ip) << "\n";

    // ARP infection

    // IP Packet Relay    
    

    return 0;
}
