#include <stdio.h>                      // for printf, scanf
#include <netinet/in.h>                 
#include <stdbool.h>
#include <arpa/inet.h>
#include <jansson.h>
#include <net/ethernet.h>               // for ethernet header
#include <netinet/ip.h>                 // for ipV4 header
#include <netinet/ip6.h>                // for ipV6 header
#include <netinet/icmp6.h>                // for ARP
#include <netinet/tcp.h>                // for TCP header
#include <netinet/udp.h>                // for UDP header
#include <netinet/ip_icmp.h>            // for icmp header
#include <netinet/if_ether.h>           // for ARP header
#include <stdlib.h>                     // for fprintf
#include <pcap.h>                       // for libpcap
#include <sys/socket.h>
#include <unistd.h>
#include "include/utils/handle_signal.h"

// Параметры запуска
typedef struct {
    char *interface;    // Сетевой интерфейс (eth0, wlan0)
    char *filter_exp;   // Фильтр BPF (например, "tcp port 80")
    bool save_to_json;  // Сохранять в JSON?
    bool verbose;       // Подробный вывод?
} sniffer_params;

// Функция для разбора аргументов
sniffer_params parse_args(int argc, char **argv) {

    sniffer_params params = { 
    .interface = NULL, 
    .filter_exp = NULL, 
    .save_to_json = false, 
    .verbose = false 
    };
    int opt;

    while ((opt = getopt(argc, argv, "i:f:jv")) != -1) {
        switch (opt) {
            case 'i': params.interface = optarg; break;  // -i eth0
            case 'f': params.filter_exp = optarg; break; // -f "tcp port 443"
            case 'j': params.save_to_json = true; break; // -j (сохранять в JSON)
            case 'v': params.verbose = true; break;      // -v (подробный вывод)
            default: fprintf(stderr, "Usage: %s [-i interface] [-f filter] [-j] [-v]\n", argv[0]);
        }
    }
    return params;
}

void info_eth(const struct ether_header *eth_hdr) {
    printf("=== Ethernet Header -> ");
    printf("Source MAC: %02X:%02X:%02X:%02X:%02X:%02X ; ", 
           eth_hdr->ether_shost[0], eth_hdr->ether_shost[1],
           eth_hdr->ether_shost[2], eth_hdr->ether_shost[3],
           eth_hdr->ether_shost[4], eth_hdr->ether_shost[5]);
    printf("Destination MAC: %02X:%02X:%02X:%02X:%02X:%02X ; ",
           eth_hdr->ether_dhost[0], eth_hdr->ether_dhost[1],
           eth_hdr->ether_dhost[2], eth_hdr->ether_dhost[3],
           eth_hdr->ether_dhost[4], eth_hdr->ether_dhost[5]);
    printf("Type: 0x%04X \n", ntohs(eth_hdr->ether_type));
}

void info_ipv4(struct iphdr *ip_hdr){
    char *src_ip = (char *)malloc(sizeof(char) * INET_ADDRSTRLEN);
            char *dst_ip = (char *)malloc(sizeof(char) * INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ip_hdr->saddr), src_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ip_hdr->daddr), dst_ip, INET_ADDRSTRLEN);
            
            const char *proto_name;
            switch(ip_hdr->protocol) {
                case IPPROTO_TCP: proto_name = "TCP"; break;
                case IPPROTO_UDP: proto_name = "UDP"; break;
                case IPPROTO_ICMP: proto_name = "ICMP"; break;
                default: proto_name = "Unknown";
            }
            
            printf("=== IPv4 Header -> "
                "Source IP: %s ; "
                "Destination IP: %s ; "
                "Protocol: %s (%d) ; "
                "TTL: %d ; "
                "Header Length:  %d bytes \n",
                src_ip, dst_ip, proto_name, ip_hdr->protocol, 
                ip_hdr->ttl, ip_hdr->ihl * 4);
};

void info_ipv6(struct ip6_hdr *ip6_hdr){
    char *src_ip6 = (char *)malloc(sizeof(char) * INET6_ADDRSTRLEN);
    char *dst_ip6 = (char *)malloc(sizeof(char) * INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(ip6_hdr->ip6_src), src_ip6, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(ip6_hdr->ip6_dst), dst_ip6, INET6_ADDRSTRLEN);
    
    printf("=== IPv6 Header -> "
        "Source IP: %s ; "
        "Destination IP: %s ; "
        "Payload Length: %d ; "
        "Next Header: %d\n",
        src_ip6, dst_ip6, 
        ntohs(ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_plen),
        ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt);
};

void info_tcp(const struct tcphdr *tcp_hdr) {
    printf("=== TCP Header -> ");
    printf("Source Port: %d ; ", ntohs(tcp_hdr->source));
    printf("Dest Port: %d ; ", ntohs(tcp_hdr->dest));
    printf("Flags: %s%s%s%s%s%s \n",
           tcp_hdr->syn ? "SYN " : "",
           tcp_hdr->ack ? "ACK " : "",
           tcp_hdr->fin ? "FIN " : "",
           tcp_hdr->rst ? "RST " : "",
           tcp_hdr->psh ? "PSH " : "",
           tcp_hdr->urg ? "URG " : "");
};

void info_udp(const struct udphdr *udp_hdr) {
    printf("=== UDP Header -> ");
    printf("Source Port: %d ; ", ntohs(udp_hdr->source));
    printf("Dest Port: %d \n", ntohs(udp_hdr->dest));
};

void info_icmp() {
    printf("=== ICMP Header -> ");
    printf("ICMP packet detected\n");
};

void packet_handler(__u_char *user_data, const struct pcap_pkthdr *pkthdr, const __u_char *packet){
    struct ether_header *eth_hdr = (struct ether_struct *)packet;
    info_eth(eth_hdr);
    switch(ntohs(eth_hdr->ether_type)){
        case ETHERTYPE_IP:
            struct iphdr *ip_hdr = (struct iphdr *)(packet + sizeof(struct ether_header));
            info_ipv4(ip_hdr);
            
            __u_char *transport = (__u_char *)ip_hdr + sizeof(struct iphdr);
            switch(ip_hdr->protocol) {
                case IPPROTO_TCP:
                    info_tcp((struct tcphdr *)transport);
                    break;
                case IPPROTO_UDP:
                    info_udp((struct udphdr *)transport);
                    break;
                case IPPROTO_ICMP:
                    info_icmp();
                    break;
            }
            break;
        case ETHERTYPE_IPV6:
            struct ip6_hdr *ip6_hdr = (struct ip6_hdr *)(packet + sizeof(struct ether_header));
            info_ipv6(ip6_hdr);
            
            __u_char *transportv6 = (__u_char *)ip6_hdr + sizeof(struct ip6_hdr);
            switch(ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt) {
                case IPPROTO_TCP:
                    info_tcp((struct tcphdr *)transportv6);
                    break;
                case IPPROTO_UDP:
                    info_udp((struct udphdr *)transportv6);
                    break;
                case IPPROTO_ICMPV6:
                    info_icmp();
                    break;
            }
            break;
        case ETHERTYPE_ARP:
            printf("ARP packet detected\n");
            break;
        default:
            printf("\nUnsupported EtherType: 0x%04X\n", ntohs(eth_hdr->ether_type));
    };
    printf("\n");
};

int main (int argc, char **argv){

    char errbuf[PCAP_ERRBUF_SIZE];
    sniffer_params params = parse_args(argc, argv);
    if (params.interface == NULL) {
        fprintf(stderr, "Error: No network interface specified. Use -i <interface>\n");
        fprintf(stderr, "Available interfaces:\n");
        
        pcap_if_t *alldevs;
        if (pcap_findalldevs(&alldevs, errbuf) == -1) {
            fprintf(stderr, "Error finding devices: %s\n", errbuf);
            return EXIT_FAILURE;
        }
        
        for (pcap_if_t *d = alldevs; d != NULL; d = d->next) {
            fprintf(stderr, "- %s", d->name);
            if (d->description)
                fprintf(stderr, " (%s)", d->description);
            fprintf(stderr, "\n");
        }
        pcap_freealldevs(alldevs);
        return EXIT_FAILURE;
    }
    pcap_t *handle = pcap_open_live(params.interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening interface %s: %s\n", params.interface, errbuf);
        
        pcap_if_t *alldevs;
        if (pcap_findalldevs(&alldevs, errbuf) != -1) {
            int found = 0;
            for (pcap_if_t *d = alldevs; d != NULL; d = d->next) {
                if (strcmp(d->name, params.interface) == 0) {
                    found = 1;
                    break;
                }
            }
            if (!found) {
                fprintf(stderr, "Interface %s does not exist on this system\n", params.interface);
            }
            pcap_freealldevs(alldevs);
        }
        return EXIT_FAILURE;
    }
    // Устанавливаем фильтр BPF, если задан
    if (params.filter_exp) {
        struct bpf_program filter;
        pcap_compile(handle, &filter, params.filter_exp, 0, PCAP_NETMASK_UNKNOWN);
        pcap_setfilter(handle, &filter);
    }

    printf("Starting sniffer... Press Ctrl+C to stop.\n");
    pcap_loop(handle, 0, packet_handler, NULL);
    pcap_close(handle);
    return 0;
}