#ifndef __SOCK_H
#define __SOCK_H

#include <linux/types.h>
#include <net/sock.h>
#include <net/ipv6.h>

#include "bpf_helpers.h"
#include "types.h"
#include "netns.h"

struct bpf_map_def SEC("maps/open_socks") open_socks = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct sock *),
    .value_size = sizeof(socket_info_t),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

static __always_inline void add_open_sock(struct sock *sk, u8 protocol, enum conn_direction dir) {
    socket_info_t skinfo = {};
    skinfo.protocol = protocol;
    // TODO this isn't the real socket creation time if not called from udp_init_sock
    skinfo.created_ns = bpf_ktime_get_ns();
    // TODO this may not be available depending on where it is called from
    skinfo.tgid = bpf_get_current_pid_tgid() >> 32;
    skinfo.netns = get_netns(&sk->sk_net);
    skinfo.direction = dir;
    bpf_probe_read_kernel(&skinfo.family, sizeof(skinfo.family), &sk->sk_family);
    bpf_map_update_elem(&open_socks, &sk, &skinfo, BPF_NOEXIST);
}

static __always_inline socket_info_t *get_or_create_open_sock(struct sock *sk, u8 protocol) {
    socket_info_t *skinfo = bpf_map_lookup_elem(&open_socks, &sk);
    if (!skinfo) {
        add_open_sock(sk, protocol, CONN_DIRECTION_UNKNOWN);
        skinfo = bpf_map_lookup_elem(&open_socks, &sk);
    }
    return skinfo;
}

#endif
