#include "arp-spoof.h"

Mac GetMyMac(char* dev){
	struct ifreq s;
	int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

	strcpy(s.ifr_ifrn.ifrn_name, dev);

	if(ioctl(fd, SIOCGIFHWADDR, &s) != 0) {
		perror("[!] ERROR on ioctl\n");
		exit(-1);
	}
	
	Mac mac = Mac( (uint8_t *) s.ifr_hwaddr.sa_data);
	return mac;
}

Ip GetMyIp(char* dev){
	struct ifreq ifr; 
	char ipstr[40]; 
	int s; 
	s = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP); 
	strncpy(ifr.ifr_name, dev, IFNAMSIZ); 

	if (ioctl(s, SIOCGIFADDR, &ifr) < 0){
		perror("[!] ERROR on ioctl\n");
		exit(-1);
	}
    
	inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, ipstr,sizeof(struct sockaddr));
	return Ip(ipstr);
	
}

Mac GetMacfromIp(pcap_t* handle, Ip tip){
    static Mac tmac;
    EthArpPacket arp_pkt;

    // logging
    std::cout << "My        Mac :" << std::string(myMac) << "\n";
    std::cout << "My        IP  :" << std::string(myIp) << "\n";
    
    // arp packet for arp request
    // eth_dmac : broadcast
    arp_pkt.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
    arp_pkt.eth_.smac_ = myMac;
    arp_pkt.eth_.type_ = htons(EthHdr::Arp);
    
	arp_pkt.arp_.hrd_ = htons(ArpHdr::ETHER);
	arp_pkt.arp_.pro_ = htons(EthHdr::Ip4);
	arp_pkt.arp_.hln_ = Mac::SIZE;
	arp_pkt.arp_.pln_ = Ip::SIZE;
    // arp request
	arp_pkt.arp_.op_ = htons(ArpHdr::Request);
	arp_pkt.arp_.smac_ = Mac(myMac);
	arp_pkt.arp_.sip_ = Ip(myIp); // why only myIp doesn't work?
    // reply dmac
	arp_pkt.arp_.tmac_ = Mac("00:00:00:00:00:00");
	arp_pkt.arp_.tip_ = Ip(tip);

    std::thread t1([](pcap_t* handle, EthArpPacket* lparp_pkt){
        int cnt = 0;
        while (tmac.isNull())
        {
            // send arp packet
            int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(lparp_pkt), sizeof(EthArpPacket));
            if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
            }
            std::this_thread::sleep_for(std::chrono::seconds(3));
            
            if (++cnt == 5){
                fprintf(stderr, "Cannot get target mac address (at sendpacket)\n");
                break;
            }
        }
    }, handle, &arp_pkt);
    

    std::thread t2([](pcap_t* handle, Ip tip){
        // receive packet
        int cnt = 0;
        while (true){
            pcap_pkthdr* header;
            const u_char* recv_packet;
            
            int res = pcap_next_ex(handle, &header, &recv_packet);
            if (res == 0) continue;
            if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
                printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
                break;
            }
            
            EthArpPacket* _recv_packet =(EthArpPacket*) recv_packet;
            if (_recv_packet->eth_.type() == EthHdr::Arp){
                if (_recv_packet->arp_.op() == ArpHdr::Reply && _recv_packet->arp_.sip() == tip){
                    tmac = _recv_packet->arp_.smac();
                    printf("CATCH");
                    break;
                }
            }
        }

    }, handle, tip);
    
    t1.join();
    t2.join();

    return tmac;
}