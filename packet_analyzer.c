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

    if (ntohs(eth->ether_type) != 0x0800)
        return;

    struct ipheader *ip =
        (struct ipheader *)(packet + sizeof(struct ethheader));

    int ip_header_len = ip->iph_ihl * 4;

    /* TCP Only */
    if (ip->iph_protocol != IPPROTO_TCP)
        return;

    struct tcpheader *tcp =
        (struct tcpheader *)((u_char *)ip + ip_header_len);

    int tcp_header_len = TH_OFF(tcp) * 4;

    char *http = (char *)tcp + tcp_header_len;

    int ip_total_len = ntohs(ip->iph_len);
    int payload_len = ip_total_len - ip_header_len - tcp_header_len;

    packet_cnt++;

    printf("\n==============================================\n");
    printf("Packet #%d\n", packet_cnt);
    printf("Captured Length : %d bytes\n", header->caplen);
    printf("==============================================\n\n");

    /* Ethernet */
    printf("[Ethernet]\n");
    printf("Destination MAC : ");
    print_mac(eth->ether_dhost);
    printf("\nSource MAC      : ");
    print_mac(eth->ether_shost);
    printf("\n\n");

    /* IP */
    printf("[IPv4]\n");
    printf("Source IP       : %s\n", inet_ntoa(ip->iph_sourceip));
    printf("Destination IP  : %s\n", inet_ntoa(ip->iph_destip));
    printf("Header Length   : %d bytes\n", ip_header_len);
    printf("Total Length    : %d bytes\n\n", ip_total_len);

    /* TCP */
    printf("[TCP]\n");
    printf("Source Port     : %d\n", ntohs(tcp->tcp_sport));
    printf("Destination Port: %d\n", ntohs(tcp->tcp_dport));
    printf("Header Length   : %d bytes\n", tcp_header_len);

    printf("\nPayload Length  : %d bytes\n\n", payload_len);

    /* HTTP */
    printf("[HTTP]\n\n");

    if (payload_len > 0) {
        for (int i = 0; i < payload_len; i++) {
            if (isprint(http[i]))
                printf("%c", http[i]);
        }
    }

    printf("\n==============================================\n");
}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;

    /* TCP only filter */
    char filter_exp[] = "tcp port 80";

    bpf_u_int32 net;

    handle = pcap_open_live("any", BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        return 1;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "pcap_compile failed\n");
        return 1;
    }

    if (pcap_setfilter(handle, &fp) != 0) {
        fprintf(stderr, "pcap_setfilter failed\n");
        return 1;
    }

    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);
    return 0;
}