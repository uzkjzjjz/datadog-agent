#ifndef __SKB_H
#define __SKB_H

#include <linux/skbuff.h>
#include <uapi/linux/in.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/if_ether.h>

#include "types.h"

// returns the data length of the skb or a negative value in case of an error
static __always_inline int sk_buff_to_tuple(struct sk_buff *skb, tuple_t *tup) {
    // TODO get L4 protocol from skb->sk->sk_protocol bitfield so we can filter out non-TCP/UDP early
    // TODO requires tricks to read bitfield
    u16 l3_proto = 0;
    bpf_probe_read_kernel(&l3_proto, sizeof(l3_proto), &skb->protocol);
    if (
        l3_proto != bpf_htons(ETH_P_IP)
#ifdef FEATURE_IPV6_ENABLED
        && l3_proto != bpf_htons(ETH_P_IPV6)
#endif
    ) {
        return -EIGNOREPROTO;
    }

    unsigned char *head;
    int ret = bpf_probe_read_kernel(&head, sizeof(head), &skb->head);
    if (ret) {
        log_debug("ERR reading head\n");
        return ret;
    }
    if (!head) {
        log_debug("ERR reading head\n");
        return -1;
    }
    u16 net_head;
    ret = bpf_probe_read_kernel(&net_head, sizeof(net_head), &skb->network_header);
    if (ret) {
        log_debug("ERR reading network_header\n");
        return ret;
    }

    struct iphdr iph = {};
    ret = bpf_probe_read_kernel(&iph, sizeof(iph), (struct iphdr *)(head + net_head));
    if (ret) {
        log_debug("ERR reading iphdr\n");
        return ret;
    }

    int trans_len = 0;
    if (iph.version == 4) {
        if (iph.protocol != IPPROTO_UDP && iph.protocol != IPPROTO_TCP) {
            return -EIGNOREPROTO;
        }
        trans_len = bpf_ntohs(iph.tot_len) - (iph.ihl * 4);
        tup->protocol = iph.protocol;
        tup->family = AF_INET;
        bpf_probe_read_kernel(&tup->saddr, sizeof(__be32), &iph.saddr);
        bpf_probe_read_kernel(&tup->daddr, sizeof(__be32), &iph.daddr);
    }
#ifdef FEATURE_IPV6_ENABLED
    else if (iph.version == 6) {
        struct ipv6hdr ip6h = {};
        ret = bpf_probe_read_kernel(&ip6h, sizeof(ip6h), (struct ipv6hdr *)(head + net_head));
        if (ret) {
            return ret;
        }
        if (ip6h.nexthdr != IPPROTO_UDP && ip6h.nexthdr != IPPROTO_TCP) {
            return -EIGNOREPROTO;
        }
        trans_len = bpf_ntohs(ip6h.payload_len) - sizeof(struct ipv6hdr);
        tup->protocol = ip6h.nexthdr;
        tup->family = AF_INET6;
        bpf_probe_read_kernel(&tup->saddr, sizeof(__be32[4]), (__u8*)&ip6h.saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&tup->daddr, sizeof(__be32[4]), (__u8*)&ip6h.daddr.in6_u.u6_addr32);
    }
#endif
    else {
        return -EIGNOREPROTO;
    }

    u16 trans_head;
    ret = bpf_probe_read_kernel(&trans_head, sizeof(trans_head), &skb->transport_header);
    if (ret) {
        log_debug("ERR reading trans_head\n");
        return ret;
    }

#ifdef FEATURE_UDP_ENABLED
    if (tup->protocol == IPPROTO_UDP) {
        struct udphdr udph = {};
        ret = bpf_probe_read_kernel(&udph, sizeof(udph), (struct udphdr *)(head + trans_head));
        if (ret) {
            log_debug("ERR reading udphdr\n");
            return ret;
        }
        tup->sport = bpf_ntohs(udph.source);
        tup->dport = bpf_ntohs(udph.dest);

        //log_debug("udp recv: udphdr.len=%d\n", bpf_ntohs(udph.len));
        return (int)(bpf_ntohs(udph.len) - sizeof(struct udphdr));
    }
#endif
#ifdef FEATURE_TCP_ENABLED
    if (tup->protocol == IPPROTO_TCP) {
        struct tcphdr tcph = {};
        ret = bpf_probe_read_kernel(&tcph, sizeof(tcph), (struct tcphdr *)(head + trans_head));
        if (ret) {
            log_debug("ERR reading tcphdr\n");
            return ret;
        }
        tup->sport = bpf_ntohs(tcph.source);
        tup->dport = bpf_ntohs(tcph.dest);

        //log_debug("tcp recv: trans_len=%u tcphdr.doff=%u\n", trans_len, tcph.doff*4);
        return trans_len - (tcph.doff * 4);
    }
#endif

    return -EIGNOREPROTO;
}

#endif