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
#include "tcp.h"
#include "tuple.h"

SEC("kprobe/security_sock_rcv_skb")
int kprobe__security_sock_rcv_skb(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);

    tuple_t tup = {};
    int recv_count = sk_buff_to_tuple(skb, &tup);
    if (recv_count < 0) {
        if (recv_count != -EIGNOREPROTO) {
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

#ifdef FEATURE_UDP_ENABLED
    if (tup.protocol == IPPROTO_UDP) {
        udp_flow_t flow = { .tup = tup, .sk = (u64)sk };
        flow_stats_t *stats = get_or_create_udp_stats(&flow);
        if (!stats) {
            // TODO data loss
            return 0;
        }
        if (stats->recv_bytes + stats->sent_bytes == 0) {
            socket_info_t *skinfo = get_or_create_open_sock(sk, tup.protocol);
            if (!skinfo) {
                return 0;
            }
            if (skinfo->direction == CONN_DIRECTION_UNKNOWN) {
                // TODO this is likely to be wrong if we don't see the socket be created
                skinfo->direction = CONN_DIRECTION_INCOMING;
            }
        }

        __sync_fetch_and_add(&stats->recv_bytes, (u64)recv_count);
        // TODO is there a 1:1 relationship between sk_buff and datagram?
        __sync_fetch_and_add(&stats->recv_packets, 1);
        stats->last_update = bpf_ktime_get_ns();
    }
#endif

#ifdef FEATURE_TCP_ENABLED
    if (tup.protocol == IPPROTO_TCP) {
        tcp_flow_t flow = { .sk = (u64)sk };
        tcp_flow_stats_t *tcp_flow_stats = get_or_create_tcp_stats(&flow, &tup);
        if (!tcp_flow_stats) {
            // TODO data loss
            return 0;
        }
        flow_stats_t *stats = &(tcp_flow_stats->flow_stats);
        if (stats->recv_bytes + stats->sent_bytes == 0) {
            socket_info_t *skinfo = get_or_create_open_sock(sk, tup.protocol);
            if (!skinfo) {
                return 0;
            }
            if (skinfo->direction == CONN_DIRECTION_UNKNOWN) {
                // TODO this is likely to be wrong if we don't see the socket be created
                // TODO we could check TCP flags for handshake packets here
                skinfo->direction = CONN_DIRECTION_INCOMING;
            }
        }

        __sync_fetch_and_add(&stats->recv_bytes, (u64)recv_count);
        __sync_fetch_and_add(&stats->recv_packets, 1);
        stats->last_update = bpf_ktime_get_ns();
        log_debug("kprobe/security_sock_rcv_skb: sk=%llx packets=%d\n", sk, pcount);
        // TODO find a better spot to update RTT since this doesn't match with where we were collecting before
        // TODO ideally somewhere in the receive pipeline after ACKs are processed
        update_rtt(sk, &tcp_flow_stats->tcp_stats);
    }
#endif

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
    if (sent_count < 0) {
        if (sent_count != -EIGNOREPROTO) {
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

#ifdef FEATURE_UDP_ENABLED
    if (tup.protocol == IPPROTO_UDP) {
        udp_flow_t flow = { .tup = tup, .sk = (u64)sk };
        flow_stats_t *stats = get_or_create_udp_stats(&flow);
        if (!stats) {
            // TODO data loss
            return 0;
        }
        if (stats->recv_bytes + stats->sent_bytes == 0) {
            socket_info_t *skinfo = get_or_create_open_sock(sk, tup.protocol);
            if (!skinfo) {
                return 0;
            }
            // TODO this is likely to be wrong if we don't see the socket be created
            skinfo->direction = CONN_DIRECTION_OUTGOING;
        }
        __sync_fetch_and_add(&stats->sent_bytes, (u64)sent_count);
        // TODO is there a 1:1 relationship between sk_buff and datagram?
        __sync_fetch_and_add(&stats->sent_packets, 1);
        stats->last_update = bpf_ktime_get_ns();
    }
#endif

#ifdef FEATURE_TCP_ENABLED
    if (tup.protocol == IPPROTO_TCP) {
        tcp_flow_t flow = { .sk = (u64)sk };
        tcp_flow_stats_t *tcp_flow_stats = get_or_create_tcp_stats(&flow, &tup);
        if (!tcp_flow_stats) {
            log_debug("ERR(tracepoint/net/net_dev_queue): no TCP flow stats\n");
            // TODO data loss
            return 0;
        }
        flow_stats_t *stats = &(tcp_flow_stats->flow_stats);
        if (stats->recv_bytes + stats->sent_bytes == 0) {
            socket_info_t *skinfo = get_or_create_open_sock(sk, tup.protocol);
            if (!skinfo) {
                log_debug("ERR(tracepoint/net/net_dev_queue): no TCP socket info\n");
                return 0;
            }
            // TODO this is likely to be wrong if we don't see the socket be created
            // TODO we could check TCP flags for handshake packets here
            skinfo->direction = CONN_DIRECTION_OUTGOING;
        }

        __sync_fetch_and_add(&stats->sent_bytes, (u64)sent_count);
        // TODO get real packet number somehow
        __sync_fetch_and_add(&stats->sent_packets, 1);
        stats->last_update = bpf_ktime_get_ns();
    }
#endif

    return 0;
}

#endif