#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <ctype.h>
#include "myheader.h"

static int packet_cnt = 0;

void print_mac(u_char *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ethheader *eth = (struct ethheader *)packet;
    if (ntohs(eth->ether_type) != 0x0800) return;

    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
    int ip_header_len = ip->iph_ihl * 4;

    if (ip->iph_protocol != IPPROTO_TCP) return;

    struct tcpheader *tcp = (struct tcpheader *)((u_char *)ip + ip_header_len);

    // [중요] 필터링 로직을 코드 내부로 이동 (WSL 환경 대응)
    if (ntohs(tcp->tcp_sport) != 80 && ntohs(tcp->tcp_dport) != 80) return;

    int tcp_header_len = TH_OFF(tcp) * 4;
    char *http = (char *)tcp + tcp_header_len;
    int ip_total_len = ntohs(ip->iph_len);
    int payload_len = ip_total_len - ip_header_len - ip_header_len;
    // 참고: 실제 구현에 맞춰 payload 계산식 확인 필요 (일반적으로: ip_total - ip_h - tcp_h)

    packet_cnt++;
    printf("\n[Packet #%d] Captured Length: %d bytes\n", packet_cnt, header->caplen);
    printf("[Ethernet] SRC: "); print_mac(eth->ether_shost); printf(" | DST: "); print_mac(eth->ether_dhost);
    printf("\n[IPv4] SRC: %s | DST: %s\n", inet_ntoa(ip->iph_sourceip), inet_ntoa(ip->iph_destip));
    printf("[TCP] SRC Port: %d | DST Port: %d\n", ntohs(tcp->tcp_sport), ntohs(tcp->tcp_dport));

    if (payload_len > 0) {
        printf("[HTTP Data]\n");
        for (int i = 0; i < payload_len; i++) {
            if (isprint(http[i]) || http[i] == '\n' || http[i] == '\r')
                printf("%c", http[i]);
        }
        printf("\n");
    }
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("Usage: sudo %s <interface>\n", argv[0]);
        return 1;
    }

    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    // pcap_open_live 호출 시 필터링 없이 전체 패킷 수신
    handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        return 1;
    }

    printf("Listening on %s for HTTP (port 80) traffic...\n", argv[1]);
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);
    return 0;
}