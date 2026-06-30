# PCAP API 기반 패킷 분석기

## 1. 프로젝트 개요

본 프로젝트는 libpcap API를 활용하여 네트워크 패킷을 실시간으로 캡처하고,
Ethernet → IP → TCP → HTTP 계층 구조로 분석하는 프로그램이다.
UDP 패킷은 제외하고 TCP 패킷만 분석 대상으로 한다.
SEED Labs Sniffing 예제를 기반으로 하되,
header length 기반 parsing 구조로 확장 구현하였다.

--- 

## 2. 프로젝트 목표

(1) 네트워크 패킷 구조 이해
(2) Ethernet / IP / TCP / Application Layer 분석
(3) header 기반 동적 parsing 구현
(4) Wireshark와 유사한 패킷 분석 구조 구현

--- 

## 3. 주요 기능

(1) Ethernet Header 분석 (MAC 주소 출력)
(2) IP Header 분석 (Source / Destination IP)
(3) TCP Header 분석 (Source / Destination Port)
(4) HTTP Payload 출력
(5) TCP only 처리 (UDP 제외)
(6) Header length 기반 parsing

---

## 4. 설계 구조

패킷 처리 흐름:

Ethernet → IP → TCP → HTTP

핵심 parsing 방식:

- IP Header Length: ip->iph_ihl * 4
- TCP Header Length: TH_OFF(tcp) * 4
- HTTP 시작 위치: (char *)tcp + tcp_header_len

---

## 5. 실행 환경 

- Ubuntu Linux
- GCC Compiler
- libpcap-dev

---

## 6. 의존성 설치 

sudo apt update
sudo apt install libpcap-dev -y

--- 

## 7. 컴파일 방법

gcc packet_analyzer.c -o analyzer -lpcap

---

## 8. 실행 방법 (중요: sudo 필요)

sudo ./analyzer

---

## 9. 테스트 방법

HTTP 트래픽 생성:

curl http://example.com

또는 추가 트래픽 생성:

curl https://example.com

--- 

## 10. 결론

본 프로젝트는 단순 패킷 출력이 아니라
계층 구조 기반 네트워크 분석 구조를 직접 구현한 것이다.

특히 header length 기반 parsing을 통해
고정 offset 방식보다 일반화된 패킷 분석이 가능하도록 설계하였다.