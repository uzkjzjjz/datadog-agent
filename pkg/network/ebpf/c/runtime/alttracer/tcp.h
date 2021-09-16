#ifndef __TCP_H
#define __TCP_H

#include <linux/tcp.h>

#include "bpf_helpers.h"
#include "bpf_read.h"
#include "types.h"
#include "netns.h"
#include "sock.h"

struct bpf_map_def SEC("maps/tcp_sock_stats") tcp_sock_stats = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct sock *),
    .value_size = sizeof(tcp_sock_stats_t),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/tcp_flows") tcp_flows = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(tcp_flow_key_t),
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

struct bpf_map_def SEC("maps/tcp_sendpage_args") tcp_sendpage_args = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(struct sock *),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

static __always_inline void update_rtt(struct sock *skp, tcp_sock_stats_t *statsp) {
    u32 rtt = 0;
    bpf_probe_read(&rtt, sizeof(rtt), &tcp_sk(skp)->srtt_us);
    if (rtt > 0) {
        u32 rtt_var = 0;
        bpf_probe_read(&rtt_var, sizeof(rtt_var), &tcp_sk(skp)->mdev_us);
        // For more information on the bit shift operations see:
        // https://elixir.bootlin.com/linux/v4.6/source/net/ipv4/tcp.c#L2686
        statsp->rtt = rtt >> 3;
        statsp->rtt_var = rtt_var >> 2;
        log_debug("update_rtt: sk=%llx rtt=%d rtt_var=%d\n", skp, statsp->rtt, statsp->rtt_var);
    }
}

static __always_inline void create_tcp_flow(struct sock *skp, tcp_sock_stats_t **statspp) {
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    tuple_t tup = {};
    tuple_from_sock(skp, IPPROTO_TCP, tgid, &tup);

    tcp_sock_stats_t stats = {};
    update_rtt(skp, &stats);
    bpf_map_update_elem(&tcp_sock_stats, &skp, &stats, BPF_NOEXIST);
    if (statspp) {
        *statspp = bpf_map_lookup_elem(&tcp_sock_stats, &skp);
    }

    tcp_flow_t flow = {};
    flow.tup = tup;

    tcp_flow_key_t key = {};
    key.skp = (__u64)skp;
    key.tgid = tgid;
    bpf_map_update_elem(&tcp_flows, &key, &flow, BPF_NOEXIST);
}

// socket OPEN

SEC("kprobe/tcp_init_sock")
int kprobe__tcp_init_sock(struct pt_regs* ctx) {
    struct sock* skp = (struct sock*)PT_REGS_PARM1(ctx);
    log_debug("kprobe/tcp_init_sock: sk=%llx\n", skp);
    socket_info_t *skinfop = bpf_map_lookup_elem(&open_socks, &skp);
    if (skinfop) {
        return 0;
    }

    add_open_sock(skp, IPPROTO_TCP, CONN_DIRECTION_UNKNOWN);
    return 0;
}

// socket CONNECT

SEC("kprobe/tcp_connect")
int kprobe__tcp_connect(struct pt_regs* ctx) {
    struct sock *skp = (struct sock*)PT_REGS_PARM1(ctx);
    log_debug("kprobe/tcp_connect: sk=%llx\n", skp);
    socket_info_t *skinfop = bpf_map_lookup_elem(&open_socks, &skp);
    if (!skinfop) {
        return 0;
    }
    skinfop->direction = CONN_DIRECTION_OUTGOING;
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

    socket_info_t *skinfop = bpf_map_lookup_elem(&open_socks, skpp);
    if (!skinfop) {
        return 0;
    }

    skinfop->direction = CONN_DIRECTION_INCOMING;
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

    socket_info_t *skinfop = bpf_map_lookup_elem(&open_socks, &newskp);
    if (!skinfop) {
        return 0;
    }
    skinfop->direction = CONN_DIRECTION_INCOMING;
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
    bpf_map_delete_elem(&tcp_sendmsg_args, &pid_tgid);

    int copied = (int)PT_REGS_RC(ctx);
    if (copied <= 0) {
        return 0;
    }

    struct sock *skp = *skpp;
    log_debug("kretprobe/tcp_sendmsg: sk=%llx sent=%u\n", skp, copied);
    tcp_flow_key_t key = {};
    key.skp = (__u64)skp;
    key.tgid = pid_tgid >> 32;
    // TODO handle if this is a new key
    tcp_flow_t *flow = bpf_map_lookup_elem(&tcp_flows, &key);
    if (!flow) {
        return 0;
    }

    flow->stats.last_update = bpf_ktime_get_ns();
    __sync_fetch_and_add(&flow->stats.sent_bytes, copied);

    tcp_sock_stats_t *statsp = bpf_map_lookup_elem(&tcp_sock_stats, &skp);
    if (statsp) {
        update_rtt(skp, statsp);
    }
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
    log_debug("kprobe/tcp_cleanup_rbuf: sk=%llx recv=%u\n", skp, copied);
    tcp_flow_key_t key = {};
    key.skp = (__u64)skp;
    key.tgid = bpf_get_current_pid_tgid() >> 32;
    // TODO handle if this is a new key
    tcp_flow_t *flow = bpf_map_lookup_elem(&tcp_flows, &key);
    if (!flow) {
        return 0;
    }

    flow->stats.last_update = bpf_ktime_get_ns();
    __sync_fetch_and_add(&flow->stats.recv_bytes, copied);
    return 0;
}

SEC("kprobe/tcp_retransmit_skb")
int kprobe__tcp_retransmit_skb(struct pt_regs* ctx) {
    struct sock* skp = (struct sock*)PT_REGS_PARM1(ctx);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 7, 0)
    int segs = 1;
#else
    int segs = (int)PT_REGS_PARM3(ctx);
#endif
    log_debug("kprobe/tcp_retransmit sk=%llx\n", skp);

    socket_info_t *skinfop = bpf_map_lookup_elem(&open_socks, &skp);
    if (!skinfop) {
        return 0;
    }

    tcp_sock_stats_t *statsp = bpf_map_lookup_elem(&tcp_sock_stats, &skp);
    if (!statsp) {
        return 0;
    }
    __sync_fetch_and_add(&statsp->retransmits, segs);
    return 0;
}

SEC("kprobe/tcp_set_state")
int kprobe__tcp_set_state(struct pt_regs* ctx) {
    int state = (int)PT_REGS_PARM2(ctx);
    if (state != TCP_ESTABLISHED) {
        return 0;
    }

    struct sock *skp = (struct sock *)PT_REGS_PARM1(ctx);
    log_debug("kprobe/tcp_set_state: sk=%llx state=%d\n", skp, state);

    u16 family = 0;
    bpf_probe_read(&family, sizeof(family), &skp->sk_family);
    if (family != AF_INET && family != AF_INET6) {
        return 0;
    }

    add_open_sock(skp, IPPROTO_TCP, CONN_DIRECTION_UNKNOWN);
    tcp_sock_stats_t *statsp;
    create_tcp_flow(skp, &statsp);
    if (statsp) {
        statsp->state_transitions |= (1 << TCP_ESTABLISHED);
    }
    return 0;
}

SEC("kprobe/tcp4_seq_show")
int kprobe__tcp4_seq_show(struct pt_regs* ctx) {
    void *v = (void *)PT_REGS_PARM2(ctx);
    if (v == SEQ_START_TOKEN) {
        return 0;
    }
    struct sock *skp = (struct sock *)v;
    int family = read_fs_socket(skp, IPPROTO_TCP, TCP_LISTEN);
    if (family) {
        create_tcp_flow(skp, NULL);
    }
    return 0;
}

SEC("kprobe/tcp6_seq_show")
int kprobe__tcp6_seq_show(struct pt_regs* ctx) {
    void *v = (void *)PT_REGS_PARM2(ctx);
    if (v == SEQ_START_TOKEN) {
        return 0;
    }
    struct sock *skp = (struct sock *)v;
    // TODO use tail calls
    int family = read_fs_socket(skp, IPPROTO_TCP, TCP_LISTEN);
    if (family) {
        create_tcp_flow(skp, NULL);
    }
    return 0;
}

SEC("kprobe/tcp_sendpage")
int kprobe__tcp_sendpage(struct pt_regs* ctx) {
    struct sock *skp = (struct sock *)PT_REGS_PARM1(ctx);
    log_debug("kprobe/tcp_sendpage: sk=%llx\n", skp);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&tcp_sendpage_args, &pid_tgid, &skp, BPF_ANY);
    return 0;
}

SEC("kretprobe/tcp_sendpage")
int kretprobe__tcp_sendpage(struct pt_regs* ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sock **skpp = bpf_map_lookup_elem(&tcp_sendpage_args, &pid_tgid);
    if (!skpp) {
        return 0;
    }
    bpf_map_delete_elem(&tcp_sendmsg_args, &pid_tgid);

    int sent = (int)PT_REGS_RC(ctx);
    if (sent <= 0) {
        return 0;
    }

    struct sock *skp = *skpp;
    log_debug("kretprobe/tcp_sendpage: sk=%llx sent=%u\n", skp, sent);
    tcp_flow_key_t key = {};
    key.skp = (__u64)skp;
    key.tgid = pid_tgid >> 32;
    // TODO handle if this is a new key
    tcp_flow_t *flow = bpf_map_lookup_elem(&tcp_flows, &key);
    if (!flow) {
        return 0;
    }

    flow->stats.last_update = bpf_ktime_get_ns();
    __sync_fetch_and_add(&flow->stats.sent_bytes, sent);

    tcp_sock_stats_t *statsp = bpf_map_lookup_elem(&tcp_sock_stats, &skp);
    if (statsp) {
        update_rtt(skp, statsp);
    }
    return 0;
}

#endif
