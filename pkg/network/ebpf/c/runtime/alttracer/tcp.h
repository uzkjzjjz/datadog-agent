#ifndef __TCP_H
#define __TCP_H

#include "bpf_helpers.h"
#include "types.h"
#include "netns.h"
#include "inet.h"

struct bpf_map_def SEC("maps/tcp_open_socks") tcp_open_socks = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct sock *),
    .value_size = sizeof(socket_info_t),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/tcp_flows") tcp_flows = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct sock *),
    .value_size = sizeof(tcp_flow_t),
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

struct bpf_map_def SEC("maps/inet_csk_listen_start_args") inet_csk_listen_start_args = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(struct sock *),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/inet_csk_accept_args") inet_csk_accept_args = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(struct sock *),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/tcp_sendmsg_args") tcp_sendmsg_args = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(struct sock *),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

static __always_inline void create_tcp_flow(struct sock *skp, u16 family) {
    tuple_t tup = {
        .family   = family,
        .protocol = IPPROTO_TCP,
    };
    bpf_probe_read(&tup.sport, sizeof(tup.sport), &skp->sk_num);
    bpf_probe_read(&tup.dport, sizeof(tup.dport), &skp->sk_dport);
    tup.dport = bpf_ntohs(tup.dport);

    if (tup.family == AF_INET) {
        bpf_probe_read(tup.saddr, sizeof(__be32), (__u8*)&skp->sk_rcv_saddr);
        bpf_probe_read(tup.daddr, sizeof(__be32), (__u8*)&skp->sk_daddr);
    } else if (tup.family == AF_INET6) {
        bpf_probe_read(tup.saddr, sizeof(tup.saddr), (__u8*)&skp->sk_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read(tup.daddr, sizeof(tup.daddr), (__u8*)&skp->sk_v6_daddr.in6_u.u6_addr32);
    }

    tcp_flow_t flow = {};
    flow.tup = tup;
    bpf_map_update_elem(&tcp_flows, &skp, &flow, BPF_ANY);
}

// socket OPEN

static __always_inline void add_tcp_open_sock(struct sock *skp, enum conn_direction dir) {
    socket_info_t tcp_sk_info = {};
    tcp_sk_info.created_ns = bpf_ktime_get_ns();
    tcp_sk_info.tgid = bpf_get_current_pid_tgid() >> 32;
    tcp_sk_info.netns = get_netns(&skp->sk_net);
    tcp_sk_info.direction = dir;
    bpf_map_update_elem(&tcp_open_socks, &skp, &tcp_sk_info, BPF_NOEXIST);
}

SEC("kprobe/tcp_init_sock")
int kprobe__tcp_init_sock(struct pt_regs* ctx) {
    struct sock* skp = (struct sock*)PT_REGS_PARM1(ctx);
    log_debug("kprobe/tcp_init_sock: sk=%llx\n", skp);
    socket_info_t *tcp_sk_infop = bpf_map_lookup_elem(&tcp_open_socks, &skp);
    if (tcp_sk_infop) {
        return 0;
    }

    add_tcp_open_sock(skp, CONN_DIRECTION_UNKNOWN);
    return 0;
}

// socket CONNECT

SEC("kprobe/tcp_connect")
int kprobe__tcp_connect(struct pt_regs* ctx) {
    struct sock *skp = (struct sock*)PT_REGS_PARM1(ctx);
    log_debug("kprobe/tcp_connect: sk=%llx\n", skp);
    socket_info_t *tcp_sk_infop = bpf_map_lookup_elem(&tcp_open_socks, &skp);
    if (!tcp_sk_infop) {
        return 0;
    }
    tcp_sk_infop->direction = CONN_DIRECTION_OUTGOING;

    u16 family = 0;
    bpf_probe_read(&family, sizeof(family), &skp->sk_family);
    create_tcp_flow(skp, family);
    return 0;
}

// socket LISTEN

SEC("kprobe/inet_csk_listen_start")
int kprobe__inet_csk_listen_start(struct pt_regs* ctx) {
    struct sock *skp = (struct sock*)PT_REGS_PARM1(ctx);
    log_debug("kprobe/inet_csk_listen_start: sk=%llx\n", skp);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&inet_csk_listen_start_args, &pid_tgid, &skp, BPF_ANY);
    return 0;
}

SEC("kretprobe/inet_csk_listen_start")
int kretprobe__inet_csk_listen_start(struct pt_regs* ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sock **skpp = bpf_map_lookup_elem(&inet_csk_listen_start_args, &pid_tgid);
    if (!skpp) {
        return 0;
    }
    log_debug("kretprobe/inet_csk_listen_start: sk=%llx\n", *skpp);
    bpf_map_delete_elem(&inet_csk_listen_start_args, &pid_tgid);

    socket_info_t *tcp_sk_infop = bpf_map_lookup_elem(&tcp_open_socks, skpp);
    if (!tcp_sk_infop) {
        return 0;
    }

    tcp_sk_infop->direction = CONN_DIRECTION_INCOMING;
    return 0;
}

// socket ACCEPT

SEC("kprobe/inet_csk_accept")
int kprobe__inet_csk_accept(struct pt_regs* ctx) {
    struct sock *skp = (struct sock*)PT_REGS_PARM1(ctx);
    log_debug("kprobe/inet_csk_accept: sk=%llx\n", skp);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&inet_csk_accept_args, &pid_tgid, &skp, BPF_ANY);
    return 0;
}

SEC("kretprobe/inet_csk_accept")
int kretprobe__inet_csk_accept(struct pt_regs* ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sock **skpp = bpf_map_lookup_elem(&inet_csk_accept_args, &pid_tgid);
    if (!skpp) {
        return 0;
    }
    bpf_map_delete_elem(&inet_csk_accept_args, &pid_tgid);

    struct sock *newskp = (struct sock*)PT_REGS_RC(ctx);
    if (!newskp) {
        return 0;
    }
    log_debug("kretprobe/inet_csk_accept: sk=%llx newsk=%llx\n", *skpp, newskp);

    u16 family = 0;
    bpf_probe_read(&family, sizeof(family), &newskp->sk_family);
    if (family != AF_INET && family != AF_INET6) {
        return 0;
    }

    add_tcp_open_sock(newskp, CONN_DIRECTION_INCOMING);
    create_tcp_flow(newskp, family);
    return 0;
}

// socket SEND

SEC("kprobe/tcp_sendmsg")
int kprobe__tcp_sendmsg(struct pt_regs* ctx) {
    struct sock *skp = (struct sock*)PT_REGS_PARM1(ctx);
    log_debug("kprobe/tcp_sendmsg: sk=%llx\n", skp);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&tcp_sendmsg_args, &pid_tgid, &skp, BPF_ANY);
    return 0;
}

SEC("kretprobe/tcp_sendmsg")
int kretprobe__tcp_sendmsg(struct pt_regs* ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sock **skpp = bpf_map_lookup_elem(&tcp_sendmsg_args, &pid_tgid);
    if (!skpp) {
        return 0;
    }
    struct sock *skp = *skpp;
    log_debug("kretprobe/tcp_sendmsg: sk=%llx\n", skp);
    bpf_map_delete_elem(&tcp_sendmsg_args, &pid_tgid);

    int copied = (int)PT_REGS_RC(ctx);
    if (copied <= 0) {
        return 0;
    }

    tcp_flow_t *flow = bpf_map_lookup_elem(&tcp_flows, &skp);
    if (!flow) {
        return 0;
    }

    flow->stats.last_update = bpf_ktime_get_ns();
    __sync_fetch_and_add(&flow->stats.sent_bytes, copied);
    return 0;
}

// socket RECV

SEC("kprobe/tcp_cleanup_rbuf")
int kprobe__tcp_cleanup_rbuf(struct pt_regs* ctx) {
    int copied = (int)PT_REGS_PARM2(ctx);
    if (copied <= 0) {
        return 0;
    }

    struct sock *skp = (struct sock*)PT_REGS_PARM1(ctx);
    log_debug("kprobe/tcp_cleanup_rbuf: sk=%llx copied=%u\n", skp, copied);
    tcp_flow_t *flow = bpf_map_lookup_elem(&tcp_flows, &skp);
    if (!flow) {
        return 0;
    }

    flow->stats.last_update = bpf_ktime_get_ns();
    __sync_fetch_and_add(&flow->stats.recv_bytes, copied);
    return 0;
}

#endif
