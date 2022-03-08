#ifndef __TUPLE_H
#define __TUPLE_H

#include <linux/types.h>
#include <net/ipv6.h>
#include <net/sock.h>

#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "types.h"

static __always_inline void flip_tuple(tuple_t *tup) {
    struct in6_addr tmpaddr = tup->saddr;
    tup->saddr = tup->daddr;
    tup->daddr = tmpaddr;

    u16 tmpport = tup->sport;
    tup->sport = tup->dport;
    tup->dport = tmpport;
}

static __always_inline bool valid_tuple(tuple_t *tup) {
    if (!tup->sport ||
        !tup->dport ||
        !tup->protocol ||
        !tup->family ||
        ipv6_addr_any(&tup->saddr) ||
        ipv6_addr_any(&tup->daddr)) {
        return false;
        }
    return true;
}

static __always_inline void tuple_from_sock(struct sock *sk, u8 protocol, tuple_t *tup) {
    tup->protocol = protocol;
    bpf_probe_read_kernel(&tup->family, sizeof(tup->family), &sk->sk_family);
    bpf_probe_read_kernel(&tup->sport, sizeof(tup->sport), &sk->sk_num);
    bpf_probe_read_kernel(&tup->dport, sizeof(tup->dport), &sk->sk_dport);
    tup->dport = bpf_ntohs(tup->dport);

    if (tup->family == AF_INET) {
        bpf_probe_read_kernel(&tup->saddr, sizeof(__be32), (__u8*)&sk->sk_rcv_saddr);
        bpf_probe_read_kernel(&tup->daddr, sizeof(__be32), (__u8*)&sk->sk_daddr);
    } else if (tup->family == AF_INET6) {
        bpf_probe_read_kernel(&tup->saddr, sizeof(__be32[4]), (__u8*)&sk->sk_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&tup->daddr, sizeof(__be32[4]), (__u8*)&sk->sk_v6_daddr.in6_u.u6_addr32);
    }
}

#endif