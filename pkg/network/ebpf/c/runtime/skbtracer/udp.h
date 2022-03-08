#ifndef __UDP_H
#define __UDP_H

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>

#include "sock.h"
#include "types.h"

#ifdef FEATURE_UDP_ENABLED

struct bpf_map_def SEC("maps/udp_stats") udp_stats = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(udp_flow_t),
    .value_size = sizeof(flow_stats_t),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/udp_close_event") udp_close_event = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 0, // This will get overridden at runtime
    .pinning = 0,
    .namespace = "",
};

SEC("kprobe/udp_init_sock")
int kprobe__udp_init_sock(struct pt_regs *ctx) {
    struct sock* sk = (struct sock *)PT_REGS_PARM1(ctx);
    log_debug("kprobe/udp_init_sock: sk=%llx\n", sk);
    socket_info_t *skinfo = bpf_map_lookup_elem(&open_socks, &sk);
    if (skinfo) {
        return 0;
    }

    add_open_sock(sk, IPPROTO_UDP, CONN_DIRECTION_UNKNOWN);
    return 0;
}

static __always_inline flow_stats_t *get_or_create_udp_stats(udp_flow_t *flow) {
    flow_stats_t *stats = bpf_map_lookup_elem(&udp_stats, flow);
    if (!stats) {
        flow_stats_t tmpstats = {};
        bpf_map_update_elem(&udp_stats, flow, &tmpstats, BPF_NOEXIST);
        stats = bpf_map_lookup_elem(&udp_stats, flow);
    }
    return stats;
}

#endif

#endif
