#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <ctype.h>
#include "myheader.h"

static int packet_cnt = 0;

/* MAC 출력 */
void print_mac(u_char *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ethheader *eth = (struct ethheader *)packet;

    // IPv4(0x0800)가 아니면 종료
    if (ntohs(eth->ether_type) != 0x0800) return;

    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
    int ip_header_len = ip->iph_ihl * 4;

    // TCP가 아니면 종료
    if (ip->iph_protocol != IPPROTO_TCP) return;

    struct tcpheader *tcp = (struct tcpheader *)((u_char *)ip + ip_header_len);
    int tcp_header_len = TH_OFF(tcp) * 4;

    char *http = (char *)tcp + tcp_header_len;
    int ip_total_len = ntohs(ip->iph_len);
    int payload_len = ip_total_len - ip_header_len - tcp_header_len;

    packet_cnt++;

    printf("\n==============================================\n");
    printf("Packet #%d\n", packet_cnt);
    printf("Captured Length : %d bytes\n", header->caplen);
    printf("==============================================\n\n");

    printf("[Ethernet] SRC MAC: "); print_mac(eth->ether_shost);
    printf(" | DST MAC: "); print_mac(eth->ether_dhost);
    printf("\n[IPv4] SRC IP: %s | DST IP: %s\n", inet_ntoa(ip->iph_sourceip), inet_ntoa(ip->iph_destip));
    printf("[TCP] SRC Port: %d | DST Port: %d\n", ntohs(tcp->tcp_sport), ntohs(tcp->tcp_dport));
    printf("[Payload] Length: %d bytes\n\n", payload_len);

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
        printf("Usage: sudo %s <interface>\nExample: sudo %s eth0\n", argv[0], argv[0]);
        return 1;
    }

    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp port 80";

    // 인자로 받은 인터페이스 사용
    handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        return 1;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "pcap_compile failed\n");
        return 1;
    }

    if (pcap_setfilter(handle, &fp) != 0) {
        fprintf(stderr, "pcap_setfilter failed\n");
        return 1;
    }

    printf("Listening on %s for port 80 traffic...\n", argv[1]);
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);
    return 0;
}