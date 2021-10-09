#include "arp-spoof.h"

void MakeEthArpPkt(EthArpPacket* lp_arp_pkt, Mac eth_dmac, Mac eth_smac, Mac arp_tmac , Ip arp_tip, Mac arp_smac, Ip arp_sip ,int type){
    // arp packet for arp request
    // eth_dmac : broadcast
    lp_arp_pkt->eth_.dmac_ = eth_dmac;
    lp_arp_pkt->eth_.smac_ = eth_smac;
    lp_arp_pkt->eth_.type_ = htons(EthHdr::Arp);
    
	lp_arp_pkt->arp_.hrd_ = htons(ArpHdr::ETHER);
	lp_arp_pkt->arp_.pro_ = htons(EthHdr::Ip4);
	lp_arp_pkt->arp_.hln_ = Mac::SIZE;
	lp_arp_pkt->arp_.pln_ = Ip::SIZE;

    // arp request / reply
	if(type==ARP_REP_TYPE) lp_arp_pkt->arp_.op_ = htons(ArpHdr::Reply);
	else if(type==ARP_REQ_TYPE) lp_arp_pkt->arp_.op_ = htons(ArpHdr::Request);
    else {
        fprintf(stderr, "Wrong Arp type on MakeEthArpPkt\n");
        exit(-1);
    }

	lp_arp_pkt->arp_.smac_ = arp_smac;
	lp_arp_pkt->arp_.sip_ = htonl(arp_sip); // why only myIp doesn't work?
    // reply dmac
	lp_arp_pkt->arp_.tmac_ = arp_tmac;
	lp_arp_pkt->arp_.tip_ = htonl(arp_tip); // why only myIp doesn't work?
    return ;
}

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
    static Mac tmac; // why static Mac tmac = Mac::nullMac() doesn't work?
    tmac = Mac::nullMac(); 
    
    EthArpPacket arp_pkt;

    // logging
    // std::cout << "My        Mac :" << std::string(myMac) << "\n";
    // std::cout << "My        IP  :" << std::string(myIp) << "\n";
    
    // arp packet for arp request
    // eth_dmac : broadcast, arp_tmac : unknown
    // arp request
    MakeEthArpPkt(&arp_pkt, Mac("FF:FF:FF:FF:FF:FF"), myMac,
                    Mac("00:00:00:00:00:00"), tip, myMac, myIp, ARP_REQ_TYPE);
    
    std::thread t1([](pcap_t* handle, EthArpPacket* lparp_pkt){
        int cnt = 0;
        while (tmac.isNull())
        {
            // send arp packet
            int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(lparp_pkt), sizeof(EthArpPacket));
            if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
            }
            std::this_thread::sleep_for(std::chrono::seconds(1));
            
            if (++cnt == 5){
                fprintf(stderr, "Cannot get target mac address (at sendpacket)\n");
                exit(-1);
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
                    break;
                }
            }
        }

    }, handle, tip);
    
    t1.join();
    t2.join();
    
    return tmac;
}


bool ArpInfection( Ip sender_ip, Mac sender_mac, Ip target_ip, Mac target_mac, int type){
    return true;
}