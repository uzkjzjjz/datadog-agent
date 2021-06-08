#ifndef __IP_H
#define __IP_H

#include "bpf_helpers.h"
#include "bpf_endian.h"
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>

static __always_inline void read_ipv6_skb(struct __sk_buff *skb, __u64 off, __u64 *addr_l, __u64 *addr_h) {
    *addr_h |= (__u64)load_word(skb, off) << 32;
    *addr_h |= (__u64)load_word(skb, off + 4);
    *addr_h = bpf_ntohll(*addr_h);

    *addr_l |= (__u64)load_word(skb, off + 8) << 32;
    *addr_l |= (__u64)load_word(skb, off + 12);
    *addr_l = bpf_ntohll(*addr_l);
}

static __always_inline void read_ipv4_skb(struct __sk_buff *skb, __u64 off, __u64 *addr) {
    *addr = load_word(skb, off);
    *addr = bpf_ntohll(*addr) >> 32;
}

static __always_inline __u64 read_conn_tuple_skb(struct __sk_buff *skb, skb_info_t *info) {
    __builtin_memset(info, 0, sizeof(skb_info_t));
    info->data_off = ETH_HLEN;

    __u8 l4_proto = 0;
    switch (skb->protocol) {
    case bpf_htons(ETH_P_IP):
        l4_proto = load_byte(skb, info->data_off + offsetof(struct iphdr, protocol));
        info->tup.metadata |= CONN_V4;
        read_ipv4_skb(skb, info->data_off + offsetof(struct iphdr, saddr), &info->tup.saddr_l);
        read_ipv4_skb(skb, info->data_off + offsetof(struct iphdr, daddr), &info->tup.daddr_l);
        // ihl field is header length in words, convert to bytes. Field is second 4 bits of first byte.
        u8 iphdrLen = (load_byte(skb, info->data_off) & IPHDR_LEN) * 4;
        info->data_off += iphdrLen;
        break;
    case bpf_htons(ETH_P_IPV6):
        l4_proto = load_byte(skb, info->data_off + offsetof(struct ipv6hdr, nexthdr));
        info->tup.metadata |= CONN_V6;
        read_ipv6_skb(skb, info->data_off + offsetof(struct ipv6hdr, saddr), &info->tup.saddr_l, &info->tup.saddr_h);
        read_ipv6_skb(skb, info->data_off + offsetof(struct ipv6hdr, daddr), &info->tup.daddr_l, &info->tup.daddr_h);
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
        // data offset is next field after acknowledgment number (ack_seq)
        u32 doffOffset = offsetof(struct tcphdr, ack_seq) + sizeof_field(struct tcphdr, ack_seq);
        u8 doffByte = load_byte(skb, info->data_off + doffOffset);
        // data offset field is count of 32bit words and only the first 4 bits of the byte
        u8 doffWords = (doffByte & TCPHDR_DATA_OFFSET) >> 4;
        // convert word count to bytes
        info->data_off += doffWords * 4;
        break;
    default:
        return 0;
    }

    return 1;
}

static __always_inline void flip_tuple(conn_tuple_t *t) {
    // TODO: we can probably replace this by swap operations
    __u16 tmp_port = t->sport;
    t->sport = t->dport;
    t->dport = tmp_port;

    __u64 tmp_ip_part = t->saddr_l;
    t->saddr_l = t->daddr_l;
    t->daddr_l = tmp_ip_part;

    tmp_ip_part = t->saddr_h;
    t->saddr_h = t->daddr_h;
    t->daddr_h = tmp_ip_part;
}

static __always_inline void print_ip(u64 ip_h, u64 ip_l, u16 port, u32 metadata) {
    if (metadata & CONN_V6) {
        log_debug("v6 %llx%llx:%u\n", bpf_ntohll(ip_h), bpf_ntohll(ip_l), port);
    } else {
        log_debug("v4 %x:%u\n", bpf_ntohl((u32)ip_l), port);
    }
}

#endif
