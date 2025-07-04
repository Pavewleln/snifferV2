#include <stdio.h>                      // for printf, scanf
#include <time.h>
#include <string.h>
#include <netinet/in.h>                 
#include <arpa/inet.h>
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

#include "include/utils/handle_signal.h"
#include "include/utils/sniffer_params.h"

void print_mac(const __u_char *mac) {
    printf("%02X:%02X:%02X:%02X:%02X:%02X", 
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void info_eth(struct ether_header *eth_hdr){
    printf("\n=== Ethernet Header ===\n");
    printf("Source MAC: ");
    print_mac(eth_hdr->ether_shost);
    printf("\nDestination MAC: ");
    print_mac(eth_hdr->ether_dhost);
    printf("\nType: 0x%04X\n", ntohs(eth_hdr->ether_type));
};

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
            
            printf("\n=== IPv4 Header ===\n"
                "Source IP:      %s\n"
                "Destination IP: %s\n"
                "Protocol:       %s (%d)\n"
                "TTL:            %d\n"
                "Header Length:  %d bytes\n",
                src_ip, dst_ip, proto_name, ip_hdr->protocol, 
                ip_hdr->ttl, ip_hdr->ihl * 4);
};

void info_ipv6(struct ip6_hdr *ip6_hdr){
    char *src_ip6 = (char *)malloc(sizeof(char) * INET6_ADDRSTRLEN);
    char *dst_ip6 = (char *)malloc(sizeof(char) * INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(ip6_hdr->ip6_src), src_ip6, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(ip6_hdr->ip6_dst), dst_ip6, INET6_ADDRSTRLEN);
    
    printf("\n=== IPv6 Header ===\n"
        "Source IP:      %s\n"
        "Destination IP: %s\n"
        "Payload Length: %d bytes\n"
        "Next Header:    %d\n",
        src_ip6, dst_ip6, 
        ntohs(ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_plen),
        ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt);
};

void info_TCP(){

};
void info_UDP(){

};
void info_ICMP(){

};

void packet_handler(__u_char *user_data, const struct pcap_pkthdr *pkthdr, const __u_char *packet){
    struct ether_header *eth_hdr = (struct ether_struct *)packet;

    info_eth(eth_hdr);
    switch(ntohs(eth_hdr->ether_type)){
        case ETHERTYPE_IP:
            struct iphdr *ip_hdr = (struct iphdr *)(packet + sizeof(struct ether_header));
            info_ipv4(ip_hdr);
            break;
        case ETHERTYPE_IPV6:
            struct ip6_hdr *ip6_hdr = (struct ip6_hdr *)(packet + sizeof(struct ether_header));
            info_ipv6(ip6_hdr);
            break;
        case ETHERTYPE_ARP:
            printf("ARP packet detected\n");
            break;
        default:
            printf("\nUnsupported EtherType: 0x%04X\n", ntohs(eth_hdr->ether_type));
    };

    
    
};

int main (int argc, char **argv){

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    signal(SIGINT, handle_signal);

    handle = pcap_open_live("wlp0s20f3", BUFSIZ, 1, 1000, errbuf);
    if(!handle){
        fprintf(__func__, "Live open failed: %s\n", errbuf);
        return 1;
    }

    printf("Starting sniffer... Press Ctrl+C to stop.\n");
    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_close(handle);
    return 0;
}