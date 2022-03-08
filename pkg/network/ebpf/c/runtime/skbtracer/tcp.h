#ifndef __TCP_H
#define __TCP_H

#include <net/tcp.h>

#include "tuple.h"

#ifdef FEATURE_TCP_ENABLED

struct bpf_map_def SEC("maps/tcp_stats") tcp_stats = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(tcp_flow_t),
    .value_size = sizeof(tcp_flow_stats_t),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/tcp_close_event") tcp_close_event = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 0, // This will get overridden at runtime
    .pinning = 0,
    .namespace = "",
};

static __always_inline tcp_flow_stats_t *get_tcp_stats(tcp_flow_t *flow) {
    return bpf_map_lookup_elem(&tcp_stats, flow);
}

static __always_inline tcp_flow_stats_t *create_tcp_stats(tcp_flow_t *flow, tuple_t *tup) {
    tcp_flow_stats_t stats = {};
    stats.tup = *tup;
    bpf_map_update_elem(&tcp_stats, flow, &stats, BPF_NOEXIST);
    return bpf_map_lookup_elem(&tcp_stats, flow);
}

static __always_inline tcp_flow_stats_t *get_or_create_tcp_stats(tcp_flow_t *flow, tuple_t *tup) {
    tcp_flow_stats_t *stats = get_tcp_stats(flow);
    if (!stats) {
        stats = create_tcp_stats(flow, tup);
    }
    return stats;
}

static __always_inline void update_rtt(struct sock *sk, tcp_stats_t *stats) {
    u32 rtt = 0;
    bpf_probe_read_kernel(&rtt, sizeof(rtt), &tcp_sk(sk)->srtt_us);
    if (rtt > 0) {
        u32 rtt_var = 0;
        bpf_probe_read_kernel(&rtt_var, sizeof(rtt_var), &tcp_sk(sk)->mdev_us);
        // For more information on the bit shift operations see:
        // https://elixir.bootlin.com/linux/v4.6/source/net/ipv4/tcp.c#L2686
        stats->rtt = rtt >> 3;
        stats->rtt_var = rtt_var >> 2;
        log_debug("update_rtt: sk=%llx rtt=%d rtt_var=%d\n", sk, stats->rtt, stats->rtt_var);
    }
}

static __always_inline struct tcp_skb_cb *get_tcp_skb_cb(struct sk_buff *skb) {
    struct tcp_skb_cb *cb;
    bpf_probe_read_kernel(&cb, sizeof(cb), &skb->cb);
    return cb;
}

static __always_inline int tcp_skb_cb_pcount(struct tcp_skb_cb *cb) {
    int pcount = 0;
    bpf_probe_read_kernel(&pcount, sizeof(pcount), &cb->tcp_gso_segs);
    return (pcount || 1);
}

static __always_inline int tcp_skb_packetcount(struct sk_buff *skb) {
    struct tcp_skb_cb *cb = get_tcp_skb_cb(skb);
    if (!cb) {
        return 1;
    }
    return tcp_skb_cb_pcount(cb);
}

SEC("kprobe/tcp_init_sock")
int kprobe__tcp_init_sock(struct pt_regs *ctx) {
    struct sock* sk = (struct sock *)PT_REGS_PARM1(ctx);
    log_debug("kprobe/tcp_init_sock: sk=%llx\n", sk);
    socket_info_t *skinfo = bpf_map_lookup_elem(&open_socks, &sk);
    if (skinfo) {
        return 0;
    }

    add_open_sock(sk, IPPROTO_TCP, CONN_DIRECTION_UNKNOWN);
    return 0;
}

SEC("kprobe/tcp_connect")
int kprobe__tcp_connect(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    log_debug("kprobe/tcp_connect: sk=%llx\n", sk);
    socket_info_t *skinfo = bpf_map_lookup_elem(&open_socks, &sk);
    if (!skinfo) {
        return 0;
    }
    skinfo->direction = CONN_DIRECTION_OUTGOING;
    return 0;
}

SEC("kretprobe/inet_csk_accept")
int kretprobe__inet_csk_accept(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_RC(ctx);
    if (!sk) {
        return 0;
    }
    log_debug("kretprobe/inet_csk_accept: sk=%llx\n", sk);

    u16 family = 0;
    bpf_probe_read_kernel(&family, sizeof(family), &sk->sk_family);
    if (family != AF_INET && family != AF_INET6) {
        return 0;
    }

    socket_info_t *skinfo = bpf_map_lookup_elem(&open_socks, &sk);
    if (!skinfo) {
        return 0;
    }
    skinfo->direction = CONN_DIRECTION_INCOMING;
    return 0;
}

SEC("kprobe/tcp_retransmit_skb")
int kprobe__tcp_retransmit_skb(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 7, 0)
    int segs = 1;
#else
    int segs = (int)PT_REGS_PARM3(ctx);
#endif
    log_debug("kprobe/tcp_retransmit_skb: sk=%llx\n", sk);

    tcp_flow_t flow = { .sk = (u64)sk };
    tcp_flow_stats_t *stats = get_tcp_stats(&flow);
    if (!stats) {
        return 0;
    }
    __sync_fetch_and_add(&stats->tcp_stats.retransmits, segs);
    return 0;
}

SEC("kprobe/tcp_set_state")
int kprobe__tcp_set_state(struct pt_regs *ctx) {
    int state = (int)PT_REGS_PARM2(ctx);
    if (state != TCP_ESTABLISHED && state != TCP_CLOSE) {
        return 0;
    }

    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    log_debug("kprobe/tcp_set_state: sk=%llx state=%d\n", sk, state);

    u16 family = 0;
    bpf_probe_read_kernel(&family, sizeof(family), &sk->sk_family);
    if (family != AF_INET && family != AF_INET6) {
        return 0;
    }

    get_or_create_open_sock(sk, IPPROTO_TCP);
    tcp_flow_t flow = { .sk = (u64)sk };
    tcp_flow_stats_t *stats = get_tcp_stats(&flow);
    if (!stats) {
        tuple_t tup = {};
        tuple_from_sock(sk, IPPROTO_TCP, &tup);
        if (!valid_tuple(&tup)) {
            return 0;
        }
        stats = create_tcp_stats(&flow, &tup);
    }

    if (stats) {
        stats->tcp_stats.state_transitions |= (1 << state);
    }
    return 0;
}

#endif

#endif