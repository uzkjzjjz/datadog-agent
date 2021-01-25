#ifndef __IP_H
#define __IP_H

#include "bpf_helpers.h"
#include "bpf_endian.h"
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>

static __always_inline void read_ipv6_skb(struct __sk_buff* skb, __u64 off, __be32* addr) {
    addr[0] = bpf_htonl(load_word(skb, off));
    addr[1] = bpf_htonl(load_word(skb, off + 4));
    addr[2] = bpf_htonl(load_word(skb, off + 8));
    addr[3] = bpf_htonl(load_word(skb, off + 12));
}

static __always_inline void read_ipv4_skb(struct __sk_buff* skb, __u64 off, __be32* addr) {
    *addr = bpf_htonl(load_word(skb, off));
}

static __always_inline __u64 read_conn_tuple_skb(struct __sk_buff* skb, skb_info_t* info) {
    __builtin_memset(info, 0, sizeof(skb_info_t));
    info->data_off = ETH_HLEN;

    __u16 l3_proto = load_half(skb, offsetof(struct ethhdr, h_proto));
    __u8 l4_proto = 0;
    switch (l3_proto) {
    case ETH_P_IP:
        l4_proto = load_byte(skb, info->data_off + offsetof(struct iphdr, protocol));
        info->tup.metadata |= CONN_V4;
        read_ipv4_skb(skb, info->data_off + offsetof(struct iphdr, saddr), &info->tup.saddr4);
        read_ipv4_skb(skb, info->data_off + offsetof(struct iphdr, daddr), &info->tup.daddr4);
        info->data_off += sizeof(struct iphdr); // TODO: this assumes there are no IP options
        break;
    case ETH_P_IPV6:
        l4_proto = load_byte(skb, info->data_off + offsetof(struct ipv6hdr, nexthdr));
        info->tup.metadata |= CONN_V6;
        read_ipv6_skb(skb, info->data_off + offsetof(struct ipv6hdr, saddr), info->tup.saddr6);
        read_ipv6_skb(skb, info->data_off + offsetof(struct ipv6hdr, daddr), info->tup.daddr6);
        info->data_off += sizeof(struct ipv6hdr);
        break;
    default:
        return 0;
    }

    switch (l4_proto) {
    case IPPROTO_UDP:
        info->tup.metadata |= CONN_TYPE_UDP;
        info->tup.sport = load_half(skb, info->data_off + offsetof(struct udphdr, source));
        info->tup.dport = load_half(skb, info->data_off + offsetof(struct udphdr, dest));
        info->data_off += sizeof(struct udphdr);
        break;
    case IPPROTO_TCP:
        info->tup.metadata |= CONN_TYPE_TCP;
        info->tup.sport = load_half(skb, info->data_off + offsetof(struct tcphdr, source));
        info->tup.dport = load_half(skb, info->data_off + offsetof(struct tcphdr, dest));

        info->tcp_flags = load_byte(skb, info->data_off + TCP_FLAGS_OFFSET);
        // TODO: Improve readability and explain the bit twiddling below
        info->data_off += ((load_byte(skb, info->data_off + offsetof(struct tcphdr, ack_seq) + 4)& 0xF0) >> 4)*4;
        break;
    default:
        return 0;
    }

    return 1;
}

static __always_inline void flip_tuple(conn_tuple_t* t) {
    // TODO: we can probably replace this by swap operations
    __u16 tmp_port = t->sport;
    t->sport = t->dport;
    t->dport = tmp_port;

    __be32 tmp_ip_part[4] = {};
    __builtin_memcpy(tmp_ip_part, t->saddr, sizeof(tmp_ip_part));
    __builtin_memcpy(t->saddr, t->daddr, sizeof(t->saddr));
    __builtin_memcpy(t->daddr, tmp_ip_part, sizeof(t->daddr));
}

#endif
