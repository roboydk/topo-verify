/*
 * Copyright (c) 2015 by Cisco Systems, Inc.
 * All rights reserved.
 * 
 * Description: utility to send packets over raw L2 socket 
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <unistd.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include "send_raw_l2.h"


#define GETOPT_STR "i:l:d:s:m:R6h"
#define PKT_BUF_SZ 1514

#define IS_IPV6_ADDR_MATCH(addr1, addr2) \
    (((addr1).s6_addr32[0] == (addr2).s6_addr32[0]) && \
    ((addr1).s6_addr32[1] == (addr2).s6_addr32[1]) && \
    ((addr1).s6_addr32[1] == (addr2).s6_addr32[2]) && \
    ((addr1).s6_addr32[3] == (addr2).s6_addr32[3])) \

unsigned char pktbuf[PKT_BUF_SZ]; 

static void 
print_help_msg(void)
{
    const int strlen1 = 16;
    const int strlen2 = 60;
    char str1[strlen1];
    char str2[strlen2];
    
    printf("\nDescription:\n");
    printf("This program constructs L2 frames and sends them over an L2 level "
        "raw socket. The L2 payload consists of IPv4 or IPv6 ICMP echo "
        "request.\n");
    printf("[*] indicates a mandatory argument to the command\n\n");
    
    snprintf(str1, strlen1, "-6");
    snprintf(str2, strlen2, "IPv6 address family, default is IPv4");
    printf(" %-16s%-60s\n", str1, str2);

    snprintf(str1, strlen1, "-i <name>");
    snprintf(str2, strlen2, "Interface to send packet on [*]");
    printf(" %-16s%-60s\n", str1, str2);

    snprintf(str1, strlen1, "-m <dst mac>");
    snprintf(str2, strlen2, "Destination MAC address [* if no -R]");
    printf(" %-16s%-60s\n", str1, str2);

    snprintf(str1, strlen1, "-R");
    snprintf(str2, strlen2, "perform Rx Inject");
    printf(" %-16s%-60s\n", str1, str2);

    snprintf(str1, strlen1, "-s <IP addr>");
    snprintf(str2, strlen2, "Source IPv4/ IPv6 address [*]");
    printf(" %-16s%-60s\n", str1, str2);
    
    snprintf(str1, strlen1, "-d <IP addr>");
    snprintf(str2, strlen2, "Destination IPv4/ IPv6 address [*]");
    printf(" %-16s%-60s\n", str1, str2);

    snprintf(str1, strlen1, "-l <payload sz>");
    snprintf(str2, strlen2, "Size in bytes of the payload (after ICMP hdr)");
    printf(" %-16s%-60s\n", str1, str2);

    printf("\n");
    return;
}
    
/* Function to calculate the checksum */
static uint16_t 
csum (unsigned short *buf, int nwords)
{
        unsigned long sum;
           for (sum = 0; nwords > 0; nwords--)
                      sum += *buf++;
              sum = (sum >> 16) + (sum & 0xffff);
                 sum += (sum >> 16);
                    return ~sum;

}


uint16_t
icmpv6_calc_cksum (struct ipv6hdr *ip6h, struct icmp6hdr *icmp6h, 
        uint32_t icmpv6_len)
{
    uint8_t *cksum_buf = NULL;
    uint16_t cksum = 0;
    typedef struct {
        struct  in6_addr    saddr;
        struct  in6_addr    daddr;
        uint32_t icmpv6_len;
        uint8_t zero1;
        uint8_t zero2;
        uint8_t zero3;
        uint8_t nexthdr;
    } icmpv6_ph_t;    /* ICMPv6 pseudo header */
    icmpv6_ph_t *icmpv6_ph;
    uint16_t cksum_buf_sz; 
    /*uint16_t i;*/  /* for dbg */

    cksum_buf_sz = sizeof(icmpv6_ph_t) + icmpv6_len;
    cksum_buf = (uint8_t *)calloc(1, cksum_buf_sz);
    if(!cksum_buf) {
        printf("icmpv6_calc_cksum: malloc failed!\n");
        goto quit; 
    }
    icmpv6_ph = (icmpv6_ph_t *)cksum_buf; 
    memcpy((void *)&icmpv6_ph->saddr, (void *)&ip6h->saddr, 
                                    sizeof(struct in6_addr));
    memcpy((void *)&icmpv6_ph->daddr, (void *)&ip6h->daddr, 
                                    sizeof(struct in6_addr));
    icmpv6_ph->icmpv6_len = htonl(icmpv6_len);
    icmpv6_ph->nexthdr = ip6h->nexthdr;

    /* copy ICMPv6 hdr + payload into the cksum buffer */
    memcpy((void *)(cksum_buf + sizeof(icmpv6_ph_t)), (void *)icmp6h, 
            icmpv6_len);
#if 0
    /* Debug: print the checksum buffer */
    printf("cksum buffer (%u bytes): \n", cksum_buf_sz);
    for (i = 0; i < cksum_buf_sz; ++i) {
        printf("%02x ", cksum_buf[i]);
    }
    printf("\n");
#endif
    cksum = csum((unsigned short *) cksum_buf, (cksum_buf_sz/2));
    
quit:
    if(cksum_buf) {
        free(cksum_buf);
    }    
    printf("icmpv6 cksum = 0x%x\n", cksum);
    return cksum; 
}


static int 
fill_ipv6_icmp_hdr(uint8_t *ip, uint32_t ip_tot_len, 
        struct in6_addr *src, struct in6_addr *dst)
{
    struct ipv6hdr *ip6h;
    struct icmp6hdr *icmp6h;
    uint8_t pattern[] = {0xab, 0xcd, 0xef, 0x0};
    uint32_t offset = 0;
    int rc = 0;

    if IS_IPV6_ADDR_MATCH(*src, in6addr_any) {
        printf("error: Source IP unknown\n");
        rc = -1;
        goto quit; 
    }
    if IS_IPV6_ADDR_MATCH(*dst, in6addr_any) {
        printf("error: Dest IP unknown\n");
        rc = -1;
        goto quit; 
    }

    /* fill ipv6 hdr */
    ip6h = (struct ipv6hdr *)ip;
    ip6h->version = 6;
    ip6h->payload_len = htons(ip_tot_len - sizeof(struct ipv6hdr));
    ip6h->nexthdr = IPPROTO_ICMPV6;
    ip6h->hop_limit = 32;
    memcpy((void *)&ip6h->saddr, src, sizeof(struct in6_addr));
    memcpy((void *)&ip6h->daddr, dst, sizeof(struct in6_addr));
    offset += sizeof(struct ipv6hdr); 

    /* fill icmpv6 hdr */
    icmp6h = (struct icmp6hdr *)(ip + offset);
    icmp6h->icmp6_type = ICMPV6_ECHO_REQUEST;
    icmp6h->icmp6_identifier = htons(0x9999);
    icmp6h->icmp6_sequence = 0;
    icmp6h->icmp6_cksum = 0;
    offset += sizeof(struct icmp6hdr); 

    /* fill pattern in the payload */
    while ((offset + sizeof(pattern)) <= ip_tot_len) {
        memcpy((void *)(ip + offset), (void *)pattern, sizeof(pattern));
        offset += sizeof(pattern);
    }

    /* calculate checksum */
    icmp6h->icmp6_cksum = icmpv6_calc_cksum(ip6h, icmp6h, 
                            (ip_tot_len - sizeof(struct ipv6hdr)));    
quit:
    return rc;
}


static int 
fill_ipv4_icmp_hdr(uint8_t *ip, uint32_t ip_tot_len, 
        struct in_addr *src, struct in_addr *dst)
{
    struct iphdr *iph;
    struct icmphdr *icmph;
    uint8_t pattern[] = {0xab, 0xcd, 0xef, 0x0};
    uint32_t pay_len, offset = 0;
    int rc = 0;

    if (src->s_addr == INADDR_ANY) {
        printf("error: Source IP unknown\n");
        rc = -1;
        goto quit; 
    }
    if (dst->s_addr == INADDR_ANY) {
        printf("error: Dst IP unknown\n");
        rc = -1;
        goto quit; 
    }

    /* fill IP header */
    iph = (struct iphdr *)ip;
    iph->version = 4;
    iph->ihl = 5;
    iph->tos = 0;
    iph->id = htons(0x1234);
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_ICMP;
    iph->saddr = src->s_addr;
    iph->daddr = dst->s_addr; 
    iph->tot_len = htons(ip_tot_len);
    iph->check = 0;
    iph->check = csum((unsigned short *) iph, (iph->ihl << 1));
    offset += sizeof(struct iphdr);

    /* fill ICMP hdr */
    icmph = (struct icmphdr *)(ip + offset);
    icmph->type = ICMP_ECHO;
    icmph->code = 0;
    icmph->un.echo.id = htons(0x9999);
    icmph->un.echo.sequence = htons(0);
    icmph->checksum = 0;
    offset += sizeof(struct icmphdr);

    while ((offset + sizeof(pattern)) <= ip_tot_len) {
        memcpy((void *)(ip + offset), (void *)pattern, sizeof(pattern));
        offset += sizeof(pattern);
    }

    /* set ICMP checksum */
    pay_len = ip_tot_len - sizeof(struct iphdr *) - sizeof(struct icmphdr); 
    icmph->checksum = csum((unsigned short *)icmph, 
                    (sizeof(struct icmphdr) + pay_len)>>1);

quit:
    return rc;
}

int 
main (int argc, char *argv[])
{
    const int name_sz = 64;
    int optval;
    char    ifname[name_sz]; 
    uint32_t pktlen = 0, msglen = 0, offset = 0;
    struct ether_header *ehdr = NULL;
    /* use the same structure for holding IPv4 or IPv6 address */
    struct in6_addr ip_sa = IN6ADDR_ANY_INIT, 
                    ip_da = IN6ADDR_ANY_INIT;
    char ip_str[INET6_ADDRSTRLEN];
    int sfd = -1;
    int ifindex;
    struct ifreq ifr;
    const int mac_str_len = 20;
    char mac_str[mac_str_len];
    struct sockaddr mac_addr;
    struct sockaddr_ll ll_addr; 
    uint8_t dmac[] = {0x2, 0x3, 0x4, 0x5, 0x6, 0x7};
    int intmac[6];
    int i, rc;
    uint8_t rx_inj = 0;
    uint8_t addr_family = AF_INET;

    ifname[0] = '\0';
   
    while ( (optval = getopt(argc, argv, GETOPT_STR)) != -1) {
        switch (optval) {
        case 'h':
            print_help_msg();
            return 0; 
            
        case '6':
            addr_family = AF_INET6;
            printf("Addr family IPv6 (%u)\n", addr_family); 
            break;
        case 'i':
            strncpy(ifname, optarg, name_sz);
            printf("Tx interface: %s\n", ifname);
            break;
        case 'l':
            msglen = atoi(optarg);
            if (msglen % 2) {
                ++msglen;   /* make it even */
            }
            printf("payload len = %u bytes\n", msglen);
            break;
        case 'd': 
            if ((rc = inet_pton(addr_family, optarg, (void *)&ip_da)) 
                <= 0) {
                printf("Invalid %s destination address! (rc %d)\n", 
                    (addr_family == AF_INET6) ? "IPv6": "IPv4", rc);
                return 0;
            }
            if (inet_ntop(addr_family, &ip_da, ip_str, INET6_ADDRSTRLEN)
                    == NULL) {
                perror("inet_pton");
                return 0;
            }
            printf("Dest IP: %s\n", ip_str);            
            break;

        case 's':
            if ((rc = inet_pton(addr_family, optarg, (void *)&ip_sa)) 
                <= 0) {
                printf("Invalid %s source address! (rc %d)\n", 
                    (addr_family == AF_INET6) ? "IPv6": "IPv4", rc);
                return 0;    
            }
            if (inet_ntop(addr_family, (void *)&ip_sa, ip_str, INET6_ADDRSTRLEN)
                    == NULL) {
                perror("inet_pton");
                return 0;
            }
            printf("Source IP: %s\n", ip_str);            
            break;

        case 'm':
            if(6 != sscanf(optarg, "%2x:%2x:%2x:%2x:%2x:%2x", 
                &intmac[0], &intmac[1], &intmac[2], &intmac[3], &intmac[4], 
                &intmac[5])) {
                printf("invalid mac address!\n");
            }
            for (i= 0; i < 6; ++i) {
                dmac[i] = (uint8_t)intmac[i];
            }
            break;

        case 'R':
            /* request for Rx or Ingress inject */
            rx_inj = 1;
            break;
        }
    }

    if (!strlen(ifname)) {
        printf("Error! Interface not specified\n");
        goto quit;
    }
    
    if (addr_family == AF_INET6) {
        pktlen = msglen + sizeof(struct ether_header) + 
                    sizeof(struct ipv6hdr) + sizeof(struct icmphdr);
    } else {
        pktlen = msglen + sizeof(struct ether_header) + 
                    sizeof(struct iphdr) + sizeof(struct icmphdr);
    }
    if (pktlen > PKT_BUF_SZ) {
        printf("Packet length exceeds maximum program limit of %u bytes\n",
            PKT_BUF_SZ);
        goto quit; 
    }
    printf("pkt len = %u bytes\n", pktlen);

    if((sfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
        perror("socket");
        goto quit; 
    }

    /* Get the index of the interface to send on */
    memset(&ifr, 0, sizeof(struct ifreq));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
    if (ioctl(sfd, SIOCGIFINDEX, &ifr) < 0) {
        perror("SIOCGIFINDEX");
        goto quit;
    } else {
        ifindex = ifr.ifr_ifindex;
        printf("Got ifindex %d\n", ifindex);
    }

    /* Get the MAC address of the interface to send on */
    memset(&ifr, 0, sizeof(struct ifreq));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
    if (ioctl(sfd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("SIOCGIFHWADDR");
        goto quit;
    } else {
        mac_addr = ifr.ifr_hwaddr; 
        snprintf(mac_str, mac_str_len, "%02x:%02x:%02x:%02x:%02x:%02x",
                    (uint8_t)mac_addr.sa_data[0],
                    (uint8_t)mac_addr.sa_data[1],
                    (uint8_t)mac_addr.sa_data[2],
                    (uint8_t)mac_addr.sa_data[3],
                    (uint8_t)mac_addr.sa_data[4],
                    (uint8_t)mac_addr.sa_data[5]);
        printf("Src mac: %s\n", mac_str);
    }

    if (rx_inj) {
        /* set dmac to the intf's own mac */
        memcpy((void *)dmac, (void *)mac_addr.sa_data, 6);
    }
    printf("Dest mac: %0x:%0x:%0x:%0x:%0x:%0x\n", 
        dmac[0], dmac[1], dmac[2], dmac[3], dmac[4], dmac[5]);
    
    /* construct ether hdr */
    ehdr = (struct ether_header *)pktbuf; 
    memcpy((void *)ehdr->ether_shost, (void *)mac_addr.sa_data, 6);
    memcpy((void *)ehdr->ether_dhost, (void *)dmac, 6);
    offset += sizeof(struct ether_header);

    /* construct IPv4 and ICMP header */
    if (addr_family == AF_INET6) {
        ehdr->ether_type = htons(ETH_P_IPV6);        
        rc = fill_ipv6_icmp_hdr(&pktbuf[offset], (pktlen - offset), 
                                &ip_sa, &ip_da);
    } else {
        ehdr->ether_type = htons(ETH_P_IP);    
        rc = fill_ipv4_icmp_hdr(&pktbuf[offset], (pktlen - offset), 
                (struct in_addr *)&ip_sa, (struct in_addr *)&ip_da);
    }
    if (rc) {
        goto quit;
    }
    
    /* set dst info in sockaddr struct */
    ll_addr.sll_family = AF_PACKET;
    ll_addr.sll_ifindex = ifindex;
    ll_addr.sll_halen = ETH_ALEN;
    ll_addr.sll_protocol = htons(ETH_P_IP);
    memcpy(ll_addr.sll_addr, dmac, ETH_ALEN);

    /* debug - dump pkt contents */
    printf("tx packet: \n");
    for (i = 0; i < pktlen; ++i) {
        printf("%02x ", pktbuf[i]);
    }
    printf("\ntotal bytes = %d\n", i);
    
    if (sendto(sfd, pktbuf, pktlen, 0, (struct sockaddr*)&ll_addr, 
                                sizeof(struct sockaddr_ll)) < 0) 
    {
        perror("sendto");
    }

quit:
    if (sfd != -1) {
        close(sfd);
    }
    return 0;

}

