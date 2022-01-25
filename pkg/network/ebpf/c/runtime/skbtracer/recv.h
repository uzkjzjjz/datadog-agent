#ifndef __RECV_H
#define __RECV_H

#include <linux/skbuff.h>
#include <uapi/linux/in.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/tcp.h>

#include "bpf_helpers.h"
#include "bpf_endian.h"

#include "tracepoint.h"
#include "skb.h"
#include "ip.h"
#include "types.h"
#include "udp.h"

SEC("kprobe/security_sock_rcv_skb")
int kprobe__security_sock_rcv_skb(struct pt_regs* ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);

    tuple_t tup = {};
    int recv_count = sk_buff_to_tuple(skb, &tup);
    if (recv_count <= 0) {
        if (recv_count < 0) {
            log_debug("ERR(kprobe/security_sock_rcv_skb): error reading tuple: sk=%llx skb=%llx ret=%d\n", sk, skb, recv_count);
        }
        return 0;
    }

    // TODO REMOVE - testing only
    if (tup.sport == 22 || tup.dport == 22) {
        return 0;
    }

    // swap src and dst because we are receiving and
    // we want the src to represent the local addr (the dst in this case)
    flip_tuple(&tup);

    log_debug("kprobe/security_sock_rcv_skb: sk=%llx skb=%llx bytes=%d\n", sk, skb, recv_count);
    print_ip(tup.saddr, tup.sport, tup.family, tup.protocol);
    print_ip(tup.daddr, tup.dport, tup.family, tup.protocol);

    if (tup.protocol == IPPROTO_UDP) {
        udp_flow_t flow = { .tup = tup, .sk = (u64)sk };
        flow_stats_t *stats = get_or_create_udp_stats(&flow);
        if (!stats) {
            // TODO data loss
            return 0;
        }
        __sync_fetch_and_add(&stats->recv_bytes, (u64)recv_count);
        stats->last_update = bpf_ktime_get_ns();
    }

    return 0;
}

SEC("tracepoint/net/net_dev_queue")
int tracepoint__net_dev_queue(struct tracepoint_net_net_dev_queue_t *args) {
    tuple_t tup = {};
    struct sk_buff *skb = (struct sk_buff *)args->skbaddr;
    struct sock *sk = NULL;
    bpf_probe_read_kernel(&sk, sizeof(sk), &skb->sk);
    if (!sk) {
        return 0;
    }

    int sent_count = sk_buff_to_tuple(skb, &tup);
    if (sent_count <= 0) {
        if (sent_count < 0) {
            log_debug("ERR(tracepoint/net/net_dev_queue): error reading tuple: sk=%llx skb=%llx ret=%d\n", sk, skb, sent_count);
        }
        return 0;
    }

    // TODO REMOVE - testing only
    if (tup.sport == 22 || tup.dport == 22) {
        return 0;
    }

    log_debug("tracepoint/net/net_dev_queue: sk=%llx name=%s bytes=%d\n", sk, __get_str(args, name), sent_count);
    print_ip(tup.saddr, tup.sport, tup.family, tup.protocol);
    print_ip(tup.daddr, tup.dport, tup.family, tup.protocol);

    if (tup.protocol == IPPROTO_UDP) {
        udp_flow_t flow = { .tup = tup, .sk = (u64)sk };
        flow_stats_t *stats = get_or_create_udp_stats(&flow);
        if (!stats) {
            // TODO data loss
            return 0;
        }
        __sync_fetch_and_add(&stats->sent_bytes, (u64)sent_count);
        stats->last_update = bpf_ktime_get_ns();
    }

    return 0;
}

#endif