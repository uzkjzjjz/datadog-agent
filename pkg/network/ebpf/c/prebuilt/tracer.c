#include "tracer.h"

#include "tracer-events.h"
#include "tracer-maps.h"
#include "tracer-stats.h"
#include "tracer-telemetry.h"

#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "syscalls.h"
#include "ip.h"
#include "ipv6.h"

#include <linux/kconfig.h>
#include <net/inet_sock.h>
#include <net/net_namespace.h>
#include <net/tcp_states.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/ptrace.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>

/* The LOAD_CONSTANT macro is used to define a named constant that will be replaced
 * at runtime by the Go code. This replaces usage of a bpf_map for storing values, which
 * eliminates a bpf_map_lookup_elem per kprobe hit. The constants are best accessed with a
 * dedicated inlined function. See example functions offset_* below.
 */
#define LOAD_CONSTANT(param, var) asm("%0 = " param " ll" \
                                      : "=r"(var))

static const __u64 ENABLED = 1;

static __always_inline bool dns_stats_enabled() {
    __u64 val = 0;
    LOAD_CONSTANT("dns_stats_enabled", val);
    return val == ENABLED;
}

static __always_inline __u64 offset_family() {
    __u64 val = 0;
    LOAD_CONSTANT("offset_family", val);
    return val;
}

static __always_inline __u64 offset_saddr() {
    __u64 val = 0;
    LOAD_CONSTANT("offset_saddr", val);
    return val;
}

static __always_inline __u64 offset_daddr() {
    __u64 val = 0;
    LOAD_CONSTANT("offset_daddr", val);
    return val;
}

static __always_inline __u64 offset_daddr_ipv6() {
    __u64 val = 0;
    LOAD_CONSTANT("offset_daddr_ipv6", val);
    return val;
}

static __always_inline __u64 offset_sport() {
    __u64 val = 0;
    LOAD_CONSTANT("offset_sport", val);
    return val;
}

static __always_inline __u64 offset_dport() {
    __u64 val = 0;
    LOAD_CONSTANT("offset_dport", val);
    return val;
}

static __always_inline __u64 offset_netns() {
    __u64 val = 0;
    LOAD_CONSTANT("offset_netns", val);
    return val;
}

static __always_inline __u64 offset_ino() {
    __u64 val = 0;
    LOAD_CONSTANT("offset_ino", val);
    return val;
}

static __always_inline __u64 offset_rtt() {
    __u64 val = 0;
    LOAD_CONSTANT("offset_rtt", val);
    return val;
}

static __always_inline __u64 offset_rtt_var() {
    __u64 val = 0;
    LOAD_CONSTANT("offset_rtt_var", val);
    return val;
}

static __always_inline bool is_ipv6_enabled() {
    __u64 val = 0;
    LOAD_CONSTANT("ipv6_enabled", val);
    return val == ENABLED;
}

static __always_inline bool are_fl4_offsets_known() {
    __u64 val = 0;
    LOAD_CONSTANT("fl4_offsets", val);
    return val == ENABLED;
}

static __always_inline __u64 offset_saddr_fl4() {
    __u64 val = 0;
    LOAD_CONSTANT("offset_saddr_fl4", val);
    return val;
}

static __always_inline __u64 offset_daddr_fl4() {
     __u64 val = 0;
     LOAD_CONSTANT("offset_daddr_fl4", val);
     return val;
}

static __always_inline __u64 offset_sport_fl4() {
    __u64 val = 0;
    LOAD_CONSTANT("offset_sport_fl4", val);
    return val;
}

static __always_inline __u64 offset_dport_fl4() {
     __u64 val = 0;
     LOAD_CONSTANT("offset_dport_fl4", val);
     return val;
}

static __always_inline bool are_fl6_offsets_known() {
    __u64 val = 0;
    LOAD_CONSTANT("fl6_offsets", val);
    return val == ENABLED;
}

static __always_inline __u64 offset_saddr_fl6() {
    __u64 val = 0;
    LOAD_CONSTANT("offset_saddr_fl6", val);
    return val;
}

static __always_inline __u64 offset_daddr_fl6() {
     __u64 val = 0;
     LOAD_CONSTANT("offset_daddr_fl6", val);
     return val;
}

static __always_inline __u64 offset_sport_fl6() {
    __u64 val = 0;
    LOAD_CONSTANT("offset_sport_fl6", val);
    return val;
}

static __always_inline __u64 offset_dport_fl6() {
     __u64 val = 0;
     LOAD_CONSTANT("offset_dport_fl6", val);
     return val;
}

static __always_inline __u32 get_netns_from_sock(struct sock* sk) {
    possible_net_t* skc_net = NULL;
    __u32 net_ns_inum = 0;
    bpf_probe_read(&skc_net, sizeof(possible_net_t*), ((char*)sk) + offset_netns());
    bpf_probe_read(&net_ns_inum, sizeof(net_ns_inum), ((char*)skc_net) + offset_ino());
    return net_ns_inum;
}

static __always_inline __u16 read_sport(struct sock* sk) {
    __u16 sport = 0;
    // try skc_num, then inet_sport
    bpf_probe_read(&sport, sizeof(sport), ((char*)sk) + offset_dport() + sizeof(sport));
    if (sport == 0) {
        bpf_probe_read(&sport, sizeof(sport), ((char*)sk) + offset_sport());
        sport = bpf_ntohs(sport);
    }
    return sport;
}

static __always_inline bool check_family(struct sock* sk, u16 expected_family) {
    u16 family = 0;
    bpf_probe_read(&family, sizeof(u16), ((char*)sk) + offset_family());
    return family == expected_family;
}

/**
 * Reads values into a `conn_tuple_t` from a `sock`. Any values that are already set in conn_tuple_t
 * are not overwritten. Returns 1 success, 0 otherwise.
 */
static __always_inline int read_conn_tuple_partial(conn_tuple_t * t, struct sock* skp, metadata_mask_t type) {
    t->metadata = type;

    // Retrieve network namespace id first since addresses and ports may not be available for unconnected UDP
    // sends
    //t->netns = get_netns_from_sock(skp);

    // Retrieve addresses
    if (check_family(skp, AF_INET)) {
        t->metadata |= CONN_V4;
        if (t->saddr_l == 0) {
            bpf_probe_read(&t->saddr_l, sizeof(u32), ((char*)skp) + offset_saddr());
        }
        if (t->daddr_l == 0) {
            bpf_probe_read(&t->daddr_l, sizeof(u32), ((char*)skp) + offset_daddr());
        }

        if (!t->saddr_l || !t->daddr_l) {
            log_debug("ERR(read_conn_tuple.v4): src or dst addr not set src=%d, dst=%d\n", t->saddr_l, t->daddr_l);
            return 0;
        }
    } else if (check_family(skp, AF_INET6)) {
        if (!is_ipv6_enabled()) {
            return 0;
        }

        if (t->saddr_h == 0) {
            bpf_probe_read(&t->saddr_h, sizeof(t->saddr_h), ((char*)skp) + offset_daddr_ipv6() + 2 * sizeof(u64));
        }
        if (t->saddr_l == 0) {
            bpf_probe_read(&t->saddr_l, sizeof(t->saddr_l), ((char*)skp) + offset_daddr_ipv6() + 3 * sizeof(u64));
        }
        if (t->daddr_h == 0) {
            bpf_probe_read(&t->daddr_h, sizeof(t->daddr_h), ((char*)skp) + offset_daddr_ipv6());
        }
        if (t->daddr_l == 0) {
            bpf_probe_read(&t->daddr_l, sizeof(t->daddr_l), ((char*)skp) + offset_daddr_ipv6() + sizeof(u64));
        }

        // We can only pass 4 args to bpf_trace_printk
        // so split those 2 statements to be able to log everything
        if (!(t->saddr_h || t->saddr_l)) {
            log_debug("ERR(read_conn_tuple.v6): src addr not set: type=%d, saddr_l=%d, saddr_h=%d\n",
                      type, t->saddr_l, t->saddr_h);
            return 0;
        }

        if (!(t->daddr_h || t->daddr_l)) {
            log_debug("ERR(read_conn_tuple.v6): dst addr not set: type=%d, daddr_l=%d, daddr_h=%d\n",
                      type, t->daddr_l, t->daddr_h);
            return 0;
        }

        // Check if we can map IPv6 to IPv4
        if (is_ipv4_mapped_ipv6(t->saddr_h, t->saddr_l, t->daddr_h, t->daddr_l)) {
            t->metadata |= CONN_V4;
            t->saddr_h = 0;
            t->daddr_h = 0;
            t->saddr_l = (__u32)(t->saddr_l >> 32);
            t->daddr_l = (__u32)(t->daddr_l >> 32);
        } else {
            t->metadata |= CONN_V6;
        }
    }

    // Retrieve ports
    if (t->sport == 0) {
        t->sport = read_sport(skp);
    }
    if (t->dport == 0) {
        bpf_probe_read(&t->dport, sizeof(t->dport), ((char*)skp) + offset_dport());
        t->dport = bpf_ntohs(t->dport);
    }

    if (t->sport == 0 || t->dport == 0) {
        log_debug("ERR(read_conn_tuple.v4): src/dst port not set: src:%d, dst:%d\n", t->sport, t->dport);
        return 0;
    }

    return 1;
}

/**
 * Reads values into a `conn_tuple_t` from a `sock`. Initializes all values in conn_tuple_t to `0`. Returns 1 success, 0 otherwise.
 */
static __always_inline int read_conn_tuple(conn_tuple_t* t, struct sock* skp, metadata_mask_t type) {
    __builtin_memset(t, 0, sizeof(conn_tuple_t));
    return read_conn_tuple_partial(t, skp, type);
}

static __always_inline void update_rtt_from_sock(tcp_stats_t *ts, struct sock* sk) {
    u32 rtt = 0;
    u32 rtt_var = 0;
    bpf_probe_read(&rtt, sizeof(rtt), ((char*)sk) + offset_rtt());
    bpf_probe_read(&rtt_var, sizeof(rtt_var), ((char*)sk) + offset_rtt_var());
    update_rtt(ts, rtt, rtt_var);
}

int handle_tcp_sendmsg(struct sock* sk, size_t size) {
    log_debug("kprobe/tcp_sendmsg: size: %d\n", size);
    conn_tuple_t t = {};
    if (!read_conn_tuple(&t, sk, CONN_TYPE_TCP)) {
        return 0;
    }

    tcp_stats_t *ts = get_tcp_stats(&t);
    if (ts == NULL) {
        return 0;
    }
    update_rtt_from_sock(ts, sk);

    conn_stats_ts_t *cs = get_conn_stats(&t);
    if (cs == NULL) {
        return 0;
    }
    set_pid(cs, bpf_get_current_pid_tgid() >> 32);
    set_netns_from_sock(cs, sk);

//    add_sent_bytes(&t, cs, size);
//    infer_direction(&t, cs);
//    update_timestamp(cs);
    return 0;
}

SEC("kprobe/tcp_sendmsg")
int kprobe__tcp_sendmsg(struct pt_regs* ctx) {
    struct sock* sk = (struct sock*)PT_REGS_PARM1(ctx);
    size_t size = (size_t)PT_REGS_PARM3(ctx);
    return handle_tcp_sendmsg(sk, size);
}

SEC("kprobe/tcp_sendmsg/pre_4_1_0")
int kprobe__tcp_sendmsg__pre_4_1_0(struct pt_regs* ctx) {
    struct sock* sk = (struct sock*)PT_REGS_PARM2(ctx);
    size_t size = (size_t)PT_REGS_PARM4(ctx);
    return handle_tcp_sendmsg(sk, size);
}

SEC("kprobe/tcp_cleanup_rbuf")
int kprobe__tcp_cleanup_rbuf(struct pt_regs* ctx) {
    struct sock* sk = (struct sock*)PT_REGS_PARM1(ctx);
    int copied = (int)PT_REGS_PARM2(ctx);
    if (copied < 0) {
        return 0;
    }
    log_debug("kprobe/tcp_cleanup_rbuf: copied: %d\n", copied);

    conn_tuple_t t = {};
    if (!read_conn_tuple(&t, sk, CONN_TYPE_TCP)) {
        return 0;
    }

    conn_stats_ts_t *cs = upsert_conn_stats(&t);
    if (cs == NULL) {
        return 0;
    }
    set_pid(cs, bpf_get_current_pid_tgid() >> 32);
    set_netns_from_sock(cs, sk);
    return 0;
}

// this is called for both IPv4 and IPv6
SEC("kprobe/tcp_v4_destroy_sock")
int kprobe__tcp_v4_destroy_sock(struct pt_regs* ctx) {
    struct sock* sk = (struct sock*)PT_REGS_PARM1(ctx);
    conn_tuple_t t = {};
    if (!read_conn_tuple(&t, sk, CONN_TYPE_TCP)) {
        return 0;
    }
    log_debug("kprobe/tcp_v4_destroy_sock: sport: %u, dport: %u\n", t.sport, t.dport);
    cleanup_conn(&t);
    return 0;
}

SEC("kretprobe/tcp_close")
int kretprobe__tcp_close(struct pt_regs* ctx) {
    flush_conn_close_if_full(ctx);
    return 0;
}

static __always_inline int handle_ip6_skb(struct sock* sk, size_t size, struct flowi6* fl6) {
    size = size - sizeof(struct udphdr);

    conn_tuple_t t = {};
    if (!read_conn_tuple(&t, sk, CONN_TYPE_UDP)) {
        if (!are_fl6_offsets_known()) {
            log_debug("ERR: src/dst addr not set, fl6 offsets are not known\n");
            increment_telemetry_count(udp_send_missed);
            return 0;
        }
        read_in6_addr(&t.saddr_h, &t.saddr_l, (struct in6_addr*)(((char*)fl6) + offset_saddr_fl6()));
        read_in6_addr(&t.daddr_h, &t.daddr_l, (struct in6_addr*)(((char*)fl6) + offset_daddr_fl6()));

        if (!(t.saddr_h || t.saddr_l)) {
            log_debug("ERR(fl6): src addr not set src_l:%d,src_h:%d\n", t.saddr_l, t.saddr_h);
            increment_telemetry_count(udp_send_missed);
            return 0;
        }
        if (!(t.daddr_h || t.daddr_l)) {
            log_debug("ERR(fl6): dst addr not set dst_l:%d,dst_h:%d\n", t.daddr_l, t.daddr_h);
            increment_telemetry_count(udp_send_missed);
            return 0;
        }

        // Check if we can map IPv6 to IPv4
        if (is_ipv4_mapped_ipv6(t.saddr_h, t.saddr_l, t.daddr_h, t.daddr_l)) {
            t.metadata |= CONN_V4;
            t.saddr_h = 0;
            t.daddr_h = 0;
            t.saddr_l = (u32)(t.saddr_l >> 32);
            t.daddr_l = (u32)(t.daddr_l >> 32);
        } else {
            t.metadata |= CONN_V6;
        }

        bpf_probe_read(&t.sport, sizeof(t.sport), ((char*)fl6) + offset_sport_fl6());
        bpf_probe_read(&t.dport, sizeof(t.dport), ((char*)fl6) + offset_dport_fl6());

        if (t.sport == 0 || t.dport == 0) {
            log_debug("ERR(fl6): src/dst port not set: src:%d, dst:%d\n", t.sport, t.dport);
            increment_telemetry_count(udp_send_missed);
            return 0;
        }

        t.sport = ntohs(t.sport);
        t.dport = ntohs(t.dport);
    }

    log_debug("kprobe/ip6_make_skb: size: %d\n", size);
    conn_stats_ts_t *cs = upsert_conn_stats(&t);
    if (cs == NULL) {
        return 0;
    }
    add_sent_bytes(&t, cs, size);
    infer_direction(&t, cs);
    update_timestamp(cs);
    increment_telemetry_count(udp_send_processed);

    return 0;
}

// commit: https://github.com/torvalds/linux/commit/26879da58711aa604a1b866cbeedd7e0f78f90ad
// changed the arguments to ip6_make_skb and introduced the struct ipcm6_cookie
SEC("kprobe/ip6_make_skb/pre_4_7_0")
int kprobe__ip6_make_skb__pre_4_7_0(struct pt_regs* ctx) {
    struct sock* sk = (struct sock*)PT_REGS_PARM1(ctx);
    size_t size = (size_t)PT_REGS_PARM4(ctx);
    struct flowi6* fl6 = (struct flowi6*)PT_REGS_PARM9(ctx);

    return handle_ip6_skb(sk, size, fl6);
}

SEC("kprobe/ip6_make_skb")
int kprobe__ip6_make_skb(struct pt_regs* ctx) {
    struct sock* sk = (struct sock*)PT_REGS_PARM1(ctx);
    size_t size = (size_t)PT_REGS_PARM4(ctx);
    struct flowi6* fl6 = (struct flowi6*)PT_REGS_PARM7(ctx);

    return handle_ip6_skb(sk, size, fl6);
}

// Note: This is used only in the UDP send path.
SEC("kprobe/ip_make_skb")
int kprobe__ip_make_skb(struct pt_regs* ctx) {
    struct sock* sk = (struct sock*)PT_REGS_PARM1(ctx);
    size_t size = (size_t)PT_REGS_PARM5(ctx);
    size = size - sizeof(struct udphdr);

    conn_tuple_t t = {};
    if (!read_conn_tuple(&t, sk, CONN_TYPE_UDP)) {
        if (!are_fl4_offsets_known()) {
            log_debug("ERR: src/dst addr not set src:%d,dst:%d. fl4 offsets are not known\n", t.saddr_l, t.daddr_l);
            increment_telemetry_count(udp_send_missed);
            return 0;
        }

        struct flowi4* fl4 = (struct flowi4*)PT_REGS_PARM2(ctx);
        bpf_probe_read(&t.saddr_l, sizeof(__u32), ((char*)fl4) + offset_saddr_fl4());
        bpf_probe_read(&t.daddr_l, sizeof(__u32), ((char*)fl4) + offset_daddr_fl4());

        if (!t.saddr_l || !t.daddr_l) {
            log_debug("ERR(fl4): src/dst addr not set src:%d,dst:%d\n", t.saddr_l, t.daddr_l);
            increment_telemetry_count(udp_send_missed);
            return 0;
        }

        bpf_probe_read(&t.sport, sizeof(t.sport), ((char*)fl4) + offset_sport_fl4());
        bpf_probe_read(&t.dport, sizeof(t.dport), ((char*)fl4) + offset_dport_fl4());

        if (t.sport == 0 || t.dport == 0) {
            log_debug("ERR(fl4): src/dst port not set: src:%d, dst:%d\n", t.sport, t.dport);
            increment_telemetry_count(udp_send_missed);
            return 0;
        }

        t.sport = ntohs(t.sport);
        t.dport = ntohs(t.dport);
    }

    log_debug("kprobe/ip_send_skb: size: %d\n", size);

    conn_stats_ts_t *cs = upsert_conn_stats(&t);
    if (cs == NULL) {
        return 0;
    }
    add_sent_bytes(&t, cs, size);
    infer_direction(&t, cs);
    update_timestamp(cs);
    increment_telemetry_count(udp_send_processed);
    return 0;
}

// We can only get the accurate number of copied bytes from the return value, so we pass our
// sock* pointer from the kprobe to the kretprobe via a map (udp_recv_sock) to get all required info
//
// The same issue exists for TCP, but we can conveniently use the downstream function tcp_cleanup_rbuf
//
// On UDP side, no similar function exists in all kernel versions, though we may be able to use something like
// skb_consume_udp (v4.10+, https://elixir.bootlin.com/linux/v4.10/source/net/ipv4/udp.c#L1500)
SEC("kprobe/udp_recvmsg")
int kprobe__udp_recvmsg(struct pt_regs* ctx) {
    struct sock* sk = (struct sock*)PT_REGS_PARM1(ctx);
    struct msghdr* msg = (struct msghdr*)PT_REGS_PARM2(ctx);
    int flags = (int)PT_REGS_PARM5(ctx);
    log_debug("kprobe/udp_recvmsg: flags: %x\n", flags);
    if (flags & MSG_PEEK) {
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    udp_recv_sock_t t = { .sk = NULL, .msg = NULL };
    if (sk) {
        bpf_probe_read(&t.sk, sizeof(t.sk), &sk);
    }
    if (msg) {
        bpf_probe_read(&t.msg, sizeof(t.msg), &msg);
    }

    bpf_map_update_elem(&udp_recv_sock, &pid_tgid, &t, BPF_ANY);
    return 0;
}

SEC("kprobe/udp_recvmsg/pre_4_1_0")
int kprobe__udp_recvmsg_pre_4_1_0(struct pt_regs* ctx) {
    struct sock* sk = (struct sock*)PT_REGS_PARM2(ctx);
    struct msghdr* msg = (struct msghdr*)PT_REGS_PARM3(ctx);
    int flags = (int)PT_REGS_PARM6(ctx);
    log_debug("kprobe/udp_recvmsg: flags: %x\n", flags);
    if (flags & MSG_PEEK) {
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    udp_recv_sock_t t = { .sk = NULL, .msg = NULL };
    if (sk) {
        bpf_probe_read(&t.sk, sizeof(t.sk), &sk);
    }
    if (msg) {
        bpf_probe_read(&t.msg, sizeof(t.msg), &msg);
    }

    bpf_map_update_elem(&udp_recv_sock, &pid_tgid, &t, BPF_ANY);
    return 0;
}

SEC("kretprobe/udp_recvmsg")
int kretprobe__udp_recvmsg(struct pt_regs* ctx) {
    // Retrieve socket pointer from kprobe via pid/tgid
    u64 pid_tgid = bpf_get_current_pid_tgid();
    udp_recv_sock_t* st = bpf_map_lookup_elem(&udp_recv_sock, &pid_tgid);
    if (!st) {
        return 0;
    }
    // Make sure we clean up the key
    bpf_map_delete_elem(&udp_recv_sock, &pid_tgid);

    int copied = (int)PT_REGS_RC(ctx);
    if (copied < 0) { // Non-zero values are errors (or a peek) (e.g -EINVAL)
        log_debug("kretprobe/udp_recvmsg: ret=%d < 0\n", copied);
        return 0;
    }

    log_debug("kretprobe/udp_recvmsg: ret=%d\n", copied);

    struct sockaddr * sa = NULL;
    if (st->msg) {
        bpf_probe_read(&sa, sizeof(sa), &(st->msg->msg_name));
    }

    conn_tuple_t t = {};
    __builtin_memset(&t, 0, sizeof(conn_tuple_t));
    sockaddr_to_addr(sa, &t.daddr_h, &t.daddr_l, &t.dport);

    if (!read_conn_tuple_partial(&t, st->sk, CONN_TYPE_UDP)) {
        log_debug("ERR(kretprobe/udp_recvmsg): error reading conn tuple\n");
        return 0;
    }

    log_debug("kretprobe/udp_recvmsg: return: %d\n", copied);

    conn_stats_ts_t *cs = upsert_conn_stats(&t);
    if (cs == NULL) {
        return 0;
    }
    add_recv_bytes(&t, cs, copied);
    infer_direction(&t, cs);
    update_timestamp(cs);
    return 0;
}

SEC("kprobe/tcp_retransmit_skb")
int kprobe__tcp_retransmit_skb(struct pt_regs* ctx) {
    struct sock* sk = (struct sock*)PT_REGS_PARM1(ctx);
    int segs = (int)PT_REGS_PARM3(ctx);
    log_debug("kprobe/tcp_retransmit\n");

    return handle_retransmit(sk, segs);
}

SEC("kprobe/tcp_retransmit_skb/pre_4_7_0")
int kprobe__tcp_retransmit_skb_pre_4_7_0(struct pt_regs* ctx) {
    struct sock* sk = (struct sock*)PT_REGS_PARM1(ctx);
    log_debug("kprobe/tcp_retransmit/pre_4_7_0\n");

    return handle_retransmit(sk, 1);
}

SEC("kprobe/tcp_connect")
int kprobe__tcp_connect(struct pt_regs* ctx) {
    log_debug("kprobe/tcp_connect\n");
    struct sock* sk = (struct sock*)PT_REGS_PARM1(ctx);
    conn_tuple_t t = {};
    if (!read_conn_tuple(&t, sk, CONN_TYPE_TCP)) {
        return 0;
    }

    conn_stats_ts_t *cs = upsert_conn_stats(&t);
    if (cs == NULL) {
        return 0;
    }
    set_pid(cs, bpf_get_current_pid_tgid() >> 32);
    set_netns_from_sock(cs, sk);
    return 0;
}

SEC("kprobe/tcp_set_state")
int kprobe__tcp_set_state(struct pt_regs* ctx) {
    u8 state = (u8)PT_REGS_PARM2(ctx);
    // For now we're tracking only TCP_ESTABLISHED
    if (state != TCP_ESTABLISHED) {
        return 0;
    }

    struct sock* sk = (struct sock*)PT_REGS_PARM1(ctx);
    conn_tuple_t t = {};
    if (!read_conn_tuple(&t, sk, CONN_TYPE_TCP)) {
        return 0;
    }

    tcp_stats_t *stats = get_tcp_stats(&t);
    if (stats == NULL) {
        return 0;
    }
    update_state_transitions(stats, (1 << state));
    return 0;
}

SEC("kretprobe/inet_csk_accept")
int kretprobe__inet_csk_accept(struct pt_regs* ctx) {
    struct sock* sk = (struct sock*)PT_REGS_RC(ctx);
    if (sk == NULL) {
        return 0;
    }
    log_debug("kretprobe/inet_csk_accept\n");

    conn_tuple_t t = {};
    if (!read_conn_tuple(&t, sk, CONN_TYPE_TCP)) {
        return 0;
    }

    tcp_stats_t *ts = get_tcp_stats(&t);
    if (ts == NULL) {
        return 0;
    }
    update_rtt_from_sock(ts, sk);

    conn_stats_ts_t *cs = upsert_conn_stats(&t);
    if (cs == NULL) {
        return 0;
    }
    set_direction(cs, CONN_DIRECTION_INCOMING);
    set_netns_from_sock(cs, sk);
    add_tcp_port_binding(t.sport, cs->netns);
    update_timestamp(cs);

    log_debug("kretprobe/inet_csk_accept: sport: %u, dport: %u\n", t.sport, t.dport);
    return 0;
}

SEC("kprobe/inet_csk_listen_stop")
int kprobe__inet_csk_listen_stop(struct pt_regs* ctx) {
    struct sock* sk = (struct sock*)PT_REGS_PARM1(ctx);
    __u16 lport = read_sport(sk);
    if (lport == 0) {
        log_debug("ERR(inet_csk_listen_stop): lport is 0 \n");
        return 0;
    }

    u32 netns = get_netns_from_sock(sk);
    delete_tcp_port_binding(lport, netns);
    log_debug("kprobe/inet_csk_listen_stop: net ns: %u, lport: %u\n", netns, lport);
    return 0;
}

SEC("kprobe/udp_destroy_sock")
int kprobe__udp_destroy_sock(struct pt_regs* ctx) {
    struct sock* sk = (struct sock*)PT_REGS_PARM1(ctx);
    conn_tuple_t tup = {};
    int valid_tuple = read_conn_tuple(&tup, sk, CONN_TYPE_UDP);

    __u16 lport = 0;
    if (valid_tuple) {
        cleanup_conn(&tup);
        lport = tup.sport;
    } else {
        // get the port for the current sock
        lport = read_sport(sk);
    }

    if (lport == 0) {
        log_debug("ERR(udp_destroy_sock): lport is 0\n");
        return 0;
    }

    // although we have net ns info, we don't use it in the key
    // since we don't have it everywhere for udp port bindings
    // (see sys_enter_bind/sys_exit_bind below)
    delete_udp_port_binding(lport);
    log_debug("kprobe/udp_destroy_sock: port %d marked as closed\n", lport);

    return 0;
}

SEC("kretprobe/udp_destroy_sock")
int kretprobe__udp_destroy_sock(struct pt_regs * ctx) {
    flush_conn_close_if_full(ctx);
    return 0;
}

//region sys_enter_bind

static __always_inline int sys_enter_bind(struct socket* sock, struct sockaddr* addr) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    __u16 type = 0;
    bpf_probe_read(&type, sizeof(__u16), &sock->type);
    if ((type & SOCK_DGRAM) == 0) {
        return 0;
    }

    if (addr == NULL) {
        log_debug("sys_enter_bind: could not read sockaddr, sock=%llx, pid_tgid=%u\n", sock, pid_tgid);
        return 0;
    }

    u16 sin_port = 0;
    sa_family_t family = 0;
    bpf_probe_read(&family, sizeof(sa_family_t), &addr->sa_family);
    if (family == AF_INET) {
        bpf_probe_read(&sin_port, sizeof(u16), &(((struct sockaddr_in*)addr)->sin_port));
    } else if (family == AF_INET6) {
        bpf_probe_read(&sin_port, sizeof(u16), &(((struct sockaddr_in6*)addr)->sin6_port));
    }

    sin_port = ntohs(sin_port);
    if (sin_port == 0) {
        log_debug("ERR(sys_enter_bind): sin_port is 0\n");
        return 0;
    }

    // write to pending_binds so the retprobe knows we can mark this as binding.
    bind_syscall_args_t args = {};
    args.port = sin_port;

    bpf_map_update_elem(&pending_bind, &pid_tgid, &args, BPF_ANY);
    log_debug("sys_enter_bind: started a bind on UDP port=%d sock=%llx pid_tgid=%u\n", sin_port, sock, pid_tgid);

    return 0;
}

SEC("kprobe/inet_bind")
int kprobe__inet_bind(struct pt_regs* ctx) {
    struct socket *sock = (struct socket*)PT_REGS_PARM1(ctx);
    struct sockaddr* addr = (struct sockaddr*)PT_REGS_PARM2(ctx);
    log_debug("kprobe/inet_bind: sock=%llx, umyaddr=%x\n", sock, addr);
    return sys_enter_bind(sock, addr);
}

SEC("kprobe/inet6_bind")
int kprobe__inet6_bind(struct pt_regs* ctx) {
    struct socket *sock = (struct socket*)PT_REGS_PARM1(ctx);
    struct sockaddr* addr = (struct sockaddr*)PT_REGS_PARM2(ctx);
    log_debug("kprobe/inet6_bind: sock=%llx, umyaddr=%x\n", sock, addr);
    return sys_enter_bind(sock, addr);
}

//endregion

//region sys_exit_bind

static __always_inline int sys_exit_bind(__s64 ret) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    log_debug("sys_exit_bind: pid_tgid=%u, ret=%d\n", pid_tgid, ret);

    // bail if this bind() is not the one we're instrumenting
    bind_syscall_args_t* args = bpf_map_lookup_elem(&pending_bind, &pid_tgid);
    if (args == NULL) {
        log_debug("sys_exit_bind: was not a UDP bind, will not process\n");
        return 0;
    }

    bpf_map_delete_elem(&pending_bind, &pid_tgid);
    if (ret != 0) {
        return 0;
    }

    add_udp_port_binding(args->port);
    log_debug("sys_exit_bind: bound UDP port %u\n", args->port);
    return 0;
}

SEC("kretprobe/inet_bind")
int kretprobe__inet_bind(struct pt_regs* ctx) {
    __s64 ret = PT_REGS_RC(ctx);
    log_debug("kretprobe/inet_bind: ret=%d\n", ret);
    return sys_exit_bind(ret);
}

SEC("kretprobe/inet6_bind")
int kretprobe__inet6_bind(struct pt_regs* ctx) {
    __s64 ret = PT_REGS_RC(ctx);
    log_debug("kretprobe/inet6_bind: ret=%d\n", ret);
    return sys_exit_bind(ret);
}

//endregion

    print_ip(skb_info.tup.daddr_h, skb_info.tup.daddr_l, skb_info.tup.dport, skb_info.tup.metadata);
    log_debug("dir=%d\n", dir);

    return 0;
}

// This function is meant to be used as a BPF_PROG_TYPE_SOCKET_FILTER.
// When attached to a RAW_SOCKET, this code filters out everything but DNS traffic.
// All structs referenced here are kernel independent as they simply map protocol headers (Ethernet, IP and UDP).
SEC("socket/dns_filter")
int socket__dns_filter(struct __sk_buff* skb) {
    skb_info_t skb_info;

    if (!read_conn_tuple_skb(skb, &skb_info)) {
        return 0;
    }

    if (skb_info.tup.sport != 53 && (!dns_stats_enabled() || skb_info.tup.dport != 53)) {
        return 0;
    }

    return -1;
}

// This number will be interpreted by elf-loader to set the current running kernel version
__u32 _version SEC("version") = 0xFFFFFFFE; // NOLINT(bugprone-reserved-identifier)

char _license[] SEC("license") = "GPL"; // NOLINT(bugprone-reserved-identifier)
