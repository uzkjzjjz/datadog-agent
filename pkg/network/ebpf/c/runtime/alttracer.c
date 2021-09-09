#include <linux/kconfig.h>
#include <linux/version.h>
#include <linux/types.h>

#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "alttracer-types.h"
#include "alttracer-maps.h"
#include "netns.h"

#ifndef LINUX_VERSION_CODE
#error "kernel version not included?"
#endif

// socket OPEN

static __always_inline void add_tcp_open_sock(struct sock *skp, enum conn_direction dir) {
    tcp_socket_info_t tcp_sk_info = {};
    tcp_sk_info.created_ns = bpf_ktime_get_ns();
    tcp_sk_info.tgid = bpf_get_current_pid_tgid() >> 32;
    tcp_sk_info.netns = get_netns(&skp->sk_net);
    tcp_sk_info.direction = dir;
    bpf_map_update_elem(&tcp_open_socks, &skp, &tcp_sk_info, BPF_NOEXIST);
}

static __always_inline void set_tuple(struct sock *skp, u16 family, u8 protocol) {
    tuple_t tup = {
        .family   = family,
        .protocol = protocol,
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

    bpf_map_update_elem(&tuples, &skp, &tup, BPF_ANY);
}

SEC("kprobe/tcp_init_sock")
int kprobe__tcp_init_sock(struct pt_regs* ctx) {
    struct sock* skp = (struct sock*)PT_REGS_PARM1(ctx);
    log_debug("kprobe/tcp_init_sock: sk=%llx\n", skp);
    tcp_socket_info_t *tcp_sk_infop = bpf_map_lookup_elem(&tcp_open_socks, &skp);
    if (tcp_sk_infop) {
        return 0;
    }

    add_tcp_open_sock(skp, CONN_DIRECTION_UNKNOWN);
    return 0;
}

// socket CLOSE

//SEC("kprobe/inet_release")
//int kprobe__inet_release(struct pt_regs* ctx) {
//    struct socket* socketp = (struct socket*)PT_REGS_PARM1(ctx);
//    struct sock* skp;
//    bpf_probe_read(&skp, sizeof(skp), &socketp->sk);
//    if (!skp) {
//        return 0;
//    }
//    log_debug("kprobe/inet_release: sk=%x\n", skp);
//
//    u64 pid_tgid = bpf_get_current_pid_tgid();
//    bpf_map_update_elem(&inet_release_args, &pid_tgid, &skp, BPF_ANY);
//
//    return 0;
//}
//
//SEC("kretprobe/inet_release")
//int kretprobe__inet_release(struct pt_regs* ctx) {
//    u64 pid_tgid = bpf_get_current_pid_tgid();
//    struct sock **skpp = bpf_map_lookup_elem(&inet_release_args, &pid_tgid);
//    if (!skpp) {
//        return 0;
//    }
//    log_debug("kretprobe/inet_release: sk=%x\n", *skpp);
//    bpf_map_delete_elem(&inet_release_args, &pid_tgid);
//
//
//
//    bpf_map_delete_elem(&tcp_open_socks, skpp);
//    bpf_map_delete_elem(&tuples, skpp);
//    return 0;
//}

SEC("kprobe/security_sk_free")
int kprobe__security_sk_free(struct pt_regs* ctx) {
    struct sock* skp = (struct sock*)PT_REGS_PARM1(ctx);
    log_debug("kprobe/security_sk_free: sk=%llx\n", skp);

    tcp_socket_info_t *skinfop = bpf_map_lookup_elem(&tcp_open_socks, &skp);
    if (skinfop) {
        tuple_t *tupp = bpf_map_lookup_elem(&tuples, &skp);
        if (tupp) {
            log_debug("closed perf send: sk=%llx\n", skp);
            conn_event_t evt = {
                .skp = (__u64)skp,
                .skinfo = *skinfop,
                .tup = *tupp,
            };
            int ret = bpf_perf_event_output(ctx, &conn_close_event, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
            if (ret) {
                log_debug("send error: ret=%u sk=%llx\n", ret, skp);
            }
        }
    }

    bpf_map_delete_elem(&tcp_open_socks, &skp);
    bpf_map_delete_elem(&tuples, &skp);
    return 0;
}

// socket CONNECT

SEC("kprobe/tcp_connect")
int kprobe__tcp_connect(struct pt_regs* ctx) {
    struct sock *skp = (struct sock*)PT_REGS_PARM1(ctx);
    log_debug("kprobe/tcp_connect: sk=%llx\n", skp);
    tcp_socket_info_t *tcp_sk_infop = bpf_map_lookup_elem(&tcp_open_socks, &skp);
    if (!tcp_sk_infop) {
        return 0;
    }
    tcp_sk_infop->direction = CONN_DIRECTION_OUTGOING;

    u16 family = 0;
    bpf_probe_read(&family, sizeof(family), &skp->sk_family);
    set_tuple(skp, family, IPPROTO_TCP);
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

    tcp_socket_info_t *tcp_sk_infop = bpf_map_lookup_elem(&tcp_open_socks, skpp);
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
    set_tuple(newskp, family, IPPROTO_TCP);
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
    log_debug("kretprobe/tcp_sendmsg: sk=%llx\n", *skpp);
    bpf_map_delete_elem(&tcp_sendmsg_args, &pid_tgid);

    int copied = (int)PT_REGS_RC(ctx);
    if (copied <= 0) {
        return 0;
    }

    tuple_t *tup = bpf_map_lookup_elem(&tuples, skpp);
    if (!tup) {
        return 0;
    }

    __sync_fetch_and_add(&tup->sent_bytes, copied);
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
    tuple_t *tup = bpf_map_lookup_elem(&tuples, &skp);
    if (!tup) {
        return 0;
    }

    __sync_fetch_and_add(&tup->recv_bytes, copied);
    return 0;
}

__u32 _version SEC("version") = 0xFFFFFFFE;
char _license[] SEC("license") = "GPL";
