# arp-spoof
Arp spoofing Application

## How to use
```shell
syntax : ./arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]
sample : ./arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2
```
## Description
* `sender ip` is the victim's ip.
* `target ip` is the gateway's ip.
* attacker is you.
* header/* and skeleton codes are from https://gitlab.com/gilgil/send-arp-test.git

### Code
구현한 것
* 여러개의 input들이 들어올 때 모두 처리
* SIGINT가 발생시 arp-spoof를 풀어주는 과정
* 주기적으로 Infection 패킷을 보내는 것
  * 쓰레딩을 통해 해결1
* 패킷 릴레이 해주는 것
* Arp 패킷이 오면 infection 패킷을 보내는 것
  * 쓰레딩을 통해 해결2
 

## Test 
### Request
![image](https://user-images.githubusercontent.com/56115311/137070298-1368d366-fa0b-49b0-bd93-d9c6258287ef.png)
### Reply
![image](https://user-images.githubusercontent.com/56115311/137070343-74593284-050b-4a7a-981e-19e144223d3f.png)

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
