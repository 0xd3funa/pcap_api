# PCAP-API: C 기반 실시간 패킷 분석기

본 프로젝트는 `libpcap` API를 활용하여 네트워크 트래픽을 실시간으로 캡처하고, Ethernet/IP/TCP/HTTP 계층 구조를 동적으로 분석하는 프로그램이다. 고정 오프셋 방식이 아닌, 각 헤더의 `Length` 필드를 기반으로 페이로드를 정확히 추출하도록 설계되었다.

---

## 1. 프로젝트 목표

- 계층적 분석: Ethernet → IP → TCP → HTTP 계층 구조의 실시간 파싱
- 동적 Parsing: 고정 오프셋이 아닌 `IHL` 및 `TH_OFF` 필드를 활용한 정확한 헤더 길이 계산
- 필터링: BPF(Berkeley Packet Filter)를 활용한 TCP 80번 포트 트래픽 선별

---

## 2. 주요 기능

- 헤더 분석: SRC/DST MAC, IP, Port 정보 출력
- HTTP Payload: TCP 페이로드 내 가독성 있는 HTTP 데이터만 필터링하여 출력
- 안정성: 인터페이스를 인자로 전달받아 다양한 환경에서 동작 가능하도록 구현

---

## 3. 실행 환경 및 설치

실행 환경: Ubuntu Linux / GCC Compiler

```bash
# 1. 의존성 설치
sudo apt update
sudo apt install libpcap-dev -y

# 2. 컴파일
gcc packet_analyzer.c -o analyzer -lpcap
```

---

## 4.  실행 및 테스트 방법

프로그램 실행 시 감시할 네트워크 인터페이스를 지정해야 하므로, 다음 명령어로 인터페이스 이름을 확인해야 한다.

```bash
# 1. 네트워크 인터페이스 확인

ip addr  # 예: eth0, enp0s3, wlan0 등 확인

# 2. 프로그램 실행 (반드시 sudo 권한으로 실행해야 한다.)

sudo ./analyzer <인터페이스명>  # 예: sudo ./analyzer eth0

# 3. HTTP 트래픽 발생 (테스트)

분석기는 TCP Port 80(HTTP) 트래픽만 감지. HTTPS(443)는 암호화되어 내용 확인이 어려우므로, 테스트를 위해 새로운 터미널 창에서 다음 명령어를 실행해야 한다. 

# HTTP 사이트에 요청을 보내 트래픽 발생
curl [http://info.cern.ch/](http://info.cern.ch/)
```

## 4. 핵심 설계 원리

IP/TCP Header 길이 계산: * ip_header_len = ip->iph_ihl * 4;

tcp_header_len = TH_OFF(tcp) * 4;

HTTP 페이로드: 전체 길이에서 각 헤더 길이를 감산하여 시작 위치를 동적으로 결정.

BPF 필터링: 커널 레벨에서 TCP 80 포트 패킷만 필터링하여 분석 성능 최적화.