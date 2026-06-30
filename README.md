# PCAP API 기반 패킷 분석기

---

## 1. 프로젝트 개요

본 프로젝트는 libpcap API를 활용하여 네트워크 패킷을 실시간으로 캡처하고,
Ethernet → IP → TCP → HTTP 계층 구조로 분석하는 프로그램이다.

UDP 패킷은 제외하고 TCP 패킷만 분석 대상으로 한다.

SEED Labs Sniffing 예제를 기반으로 하되,
header length 기반 parsing 구조로 확장 구현하였다.

---

## 2. 프로젝트 목표

- 네트워크 패킷 구조에 대한 이해
- Ethernet / IP / TCP / Application Layer 분석
- header 기반 동적 parsing 구현
- Wireshark와 유사한 패킷 분석 구조 직접 구현

---

## 3. 주요 기능

- Ethernet Header 분석 (MAC 주소 출력)
- IP Header 분석 (Source / Destination IP)
- TCP Header 분석 (Source / Destination Port)
- HTTP Payload 출력
- TCP only 처리 (UDP 제외)
- Header length 기반 parsing

---

## 4. 설계 구조

패킷 처리 흐름:

Ethernet → IP → TCP → HTTP

핵심 parsing 방식:

- IP Header Length: `ip->iph_ihl * 4`
- TCP Header Length: `TH_OFF(tcp) * 4`
- HTTP 시작 위치: `(char*)tcp + tcp_header_len`

---

## 5. 핵심 설계 의의

기존 방식은 고정 offset(packet + 54)을 사용하지만,
이는 네트워크 환경에 따라 정확하지 않을 수 있다.

본 구현은 header field 기반 parsing을 적용하여
환경 독립적인 구조를 갖는다.

---

## 6. 실행 환경

- Ubuntu 20.04 / 22.04 / Codespaces
- gcc
- libpcap-dev

---

## 7. 의존성 설치

```bash id="dep1"
sudo apt update
sudo apt install libpcap-dev -y

## 실행 테스트 방법

트래픽이 없을 경우 아래 명령으로 테스트 가능합니다:

curl http://example.com