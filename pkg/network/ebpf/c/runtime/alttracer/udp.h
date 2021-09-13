#ifndef __UDP_H
#define __UDP_H

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>

#include "bpf_helpers.h"
#include "types.h"
#include "netns.h"
#include "inet.h"

struct bpf_map_def SEC("maps/udp_open_socks") udp_open_socks = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct sock *),
    .value_size = sizeof(socket_info_t),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/udp_stats") udp_stats = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(tuple_t),
    .value_size = sizeof(flow_stats_t),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/udp_tuples_to_socks") udp_tuples_to_socks = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(tuple_t),
    .value_size = sizeof(struct sock *),
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

struct bpf_map_def SEC("maps/udp_lib_get_port_args") udp_lib_get_port_args = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(struct sock *),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

static __always_inline void add_udp_open_sock(struct sock *skp, enum conn_direction dir) {
    socket_info_t udp_sk_info = {};
    udp_sk_info.created_ns = bpf_ktime_get_ns();
    udp_sk_info.tgid = bpf_get_current_pid_tgid() >> 32;
    udp_sk_info.netns = get_netns(&skp->sk_net);
    udp_sk_info.direction = dir;
    bpf_map_update_elem(&udp_open_socks, &skp, &udp_sk_info, BPF_NOEXIST);
}

SEC("kprobe/udp_lib_get_port")
int kprobe__udp_lib_get_port(struct pt_regs* ctx) {
    struct sock *skp = (struct sock*)PT_REGS_PARM1(ctx);
    unsigned short snum = (unsigned short)PT_REGS_PARM2(ctx);
    log_debug("kprobe/udp_v4_get_port: sk=%llx snum=%u\n", skp, snum);

    if (snum > 0) {
        u64 pid_tgid = bpf_get_current_pid_tgid();
        bpf_map_update_elem(&udp_lib_get_port_args, &pid_tgid, &skp, BPF_ANY);
    }
    return 0;
}

SEC("kretprobe/udp_lib_get_port")
int kretprobe__udp_lib_get_port(struct pt_regs* ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sock **skpp = bpf_map_lookup_elem(&udp_lib_get_port_args, &pid_tgid);
    if (!skpp) {
        return 0;
    }
    struct sock *skp = *skpp;
    bpf_map_delete_elem(&udp_lib_get_port_args, &pid_tgid);
    log_debug("kretprobe/udp_lib_get_port: sk=%llx\n", skp);

    int err = (int)PT_REGS_RC(ctx);
    if (err) {
        return 0;
    }

    socket_info_t *skinfop = bpf_map_lookup_elem(&udp_open_socks, &skp);
    if (!skinfop) {
        return 0;
    }

    skinfop->direction = CONN_DIRECTION_INCOMING;
    return 0;
}

SEC("kprobe/udp_init_sock")
int kprobe__udp_init_sock(struct pt_regs* ctx) {
    struct sock* skp = (struct sock*)PT_REGS_PARM1(ctx);
    log_debug("kprobe/udp_init_sock: sk=%llx\n", skp);
    socket_info_t *udp_sk_infop = bpf_map_lookup_elem(&udp_open_socks, &skp);
    if (udp_sk_infop) {
        return 0;
    }

    add_udp_open_sock(skp, CONN_DIRECTION_OUTGOING);
    return 0;
}

// returns UDP payload length
static __always_inline u64 udp_sk_buff_to_tuple(struct sk_buff *skb, u8 (*laddr)[16], u16 *lport, u8 (*raddr)[16], u16* rport, u8* family) {
    unsigned char *head;
    bpf_probe_read(&head, sizeof(head), &skb->head);
    if (!head) {
        return 0;
    }
    u16 net_head;
    int ret = bpf_probe_read(&net_head, sizeof(net_head), &skb->network_header);
    if (ret) {
        return 0;
    }

    struct iphdr iph = {};
    ret = bpf_probe_read(&iph, sizeof(iph), (struct iphdr *)(head + net_head));
    if (ret) {
        return 0;
    }

    if (iph.version == 4) {
        if (iph.protocol != IPPROTO_UDP) {
            return 0;
        }

        *family = AF_INET;
        bpf_probe_read(laddr, sizeof(__be32), &iph.saddr);
        bpf_probe_read(raddr, sizeof(__be32), &iph.daddr);
    } else if (iph.version == 6) {
        struct ipv6hdr ip6h = {};
        ret = bpf_probe_read(&ip6h, sizeof(ip6h), (struct ipv6hdr *)(head + net_head));
        if (ret || ip6h.nexthdr != IPPROTO_UDP) {
            return 0;
        }

        *family = AF_INET6;
        bpf_probe_read(laddr, sizeof(__be32[4]), (__u8*)&ip6h.saddr.in6_u.u6_addr32);
        bpf_probe_read(raddr, sizeof(__be32[4]), (__u8*)&ip6h.daddr.in6_u.u6_addr32);
    } else {
        return 0;
    }

    u16 trans_head;
    ret = bpf_probe_read(&trans_head, sizeof(trans_head), &skb->transport_header);
    if (ret) {
        return 0;
    }

    struct udphdr udph = {};
    ret = bpf_probe_read(&udph, sizeof(udph), (struct udphdr *)(head + trans_head));
    if (ret) {
        return 0;
    }

    *lport = bpf_ntohs(udph.source);
    *rport = bpf_ntohs(udph.dest);

    return (u64)(bpf_ntohs(udph.len) - sizeof(struct udphdr));
}

static __always_inline flow_stats_t *ensure_udp_stats_exist(tuple_t *tup, struct sock *skp) {
    flow_stats_t stats = {};
    bpf_map_update_elem(&udp_stats, tup, &stats, BPF_NOEXIST);
    // TODO do we need to care if entry already exists for a tuple?
    bpf_map_update_elem(&udp_tuples_to_socks, tup, &skp, BPF_ANY);
    return bpf_map_lookup_elem(&udp_stats, tup);
}

static __always_inline int ip46_send_skb(struct sk_buff *skb) {
    struct sock *skp;
    bpf_probe_read(&skp, sizeof(skp), &skb->sk);
    if (!skp) {
        return 0;
    }

    tuple_t tup = { .protocol = IPPROTO_UDP };
    u64 len = udp_sk_buff_to_tuple(skb, &tup.saddr, &tup.sport, &tup.daddr, &tup.dport, &tup.family);
    if (!len) {
        return 0;
    }
    log_debug("kprobe/ip46_send_skb: sk=%llx len=%u\n", skp, len);

    flow_stats_t *statsp = ensure_udp_stats_exist(&tup, skp);
    if (!statsp) {
        return 0;
    }

    statsp->last_update = bpf_ktime_get_ns();
    __sync_fetch_and_add(&statsp->sent_bytes, len);
    return 0;
}

// ip_send_skb is IPv4 only
SEC("kprobe/ip_send_skb")
int kprobe__ip_send_skb(struct pt_regs* ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
    return ip46_send_skb(skb);
}

SEC("kprobe/ip6_send_skb")
int kprobe__ip6_send_skb(struct pt_regs* ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    return ip46_send_skb(skb);
}

SEC("kprobe/skb_consume_udp")
int kprobe__skb_consume_udp(struct pt_regs* ctx) {
    struct sock *skp = (struct sock *)PT_REGS_PARM1(ctx);
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
    int len = (int)PT_REGS_PARM3(ctx);
    if (len <= 0) {
        return 0;
    }

    tuple_t tup = { .protocol = IPPROTO_UDP };
    // raddr needs to be datagram source address
    u64 readlen = udp_sk_buff_to_tuple(skb, &tup.daddr, &tup.dport, &tup.saddr, &tup.sport, &tup.family);
    if (!readlen) {
        return 0;
    }
    log_debug("kprobe/skb_consume_udp: sk=%llx len=%u\n", skp, len);

    flow_stats_t *statsp = ensure_udp_stats_exist(&tup, skp);
    if (!statsp) {
        return 0;
    }

    statsp->last_update = bpf_ktime_get_ns();
    __sync_fetch_and_add(&statsp->recv_bytes, readlen);
    return 0;
}

SEC("kprobe/udp4_seq_show")
int kprobe__udp4_seq_show(struct pt_regs* ctx) {
    void *v = PT_REGS_PARM2(ctx);
    struct sock *skp = (struct sock *)v;
    if (v == SEQ_START_TOKEN) {
        return 0;
    }
    log_debug("kprobe/udp4_seq_show: sk=%llx\n", skp);
}

SEC("kprobe/udp6_seq_show")
int kprobe__udp6_seq_show(struct pt_regs* ctx) {
    void *v = PT_REGS_PARM2(ctx);
    struct sock *skp = (struct sock *)v;
    if (v == SEQ_START_TOKEN) {
        return 0;
    }
    log_debug("kprobe/udp6_seq_show: sk=%llx\n", skp);
}

#endif