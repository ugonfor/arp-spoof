# arp-spoof
Arp spoofing Application

### Caution!
* resolving은 2번으로 해결할 것.
* VM으로 실행할 때, Host ARP Table 처리
* Threading을 통해서 동시에 처리할 것
* `signal(SIGINT, function pointer)`를 통해서 Ctrl+C 를 처리하기
* 무선상에서는 패킷 loss가 생길 수 있으니, sleep이 꼭 필요함
* IP 패킷과 ARP 패킷을 따로 처리를 해주는 것이 과제의 핵심
* Flow를 관리하기 위해서 std::vector, std::map, list 등 사용 하는 데... 이 부분 가장 중요
* TCP, HTTP 잘 이동하는 지 확인

* 동글이 Ubuntu에 집어 넣는 법 `https://askubuntu.com/questions/1162974/wireless-usb-adapter-0bdac811-realtek-semiconductor-corp` 보고 해보니 성공!
