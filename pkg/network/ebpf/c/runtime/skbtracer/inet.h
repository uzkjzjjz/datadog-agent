#ifndef __INET_H
#define __INET_H

#include "sock.h"
#include "types.h"
#include "tcp.h"

SEC("kprobe/security_sk_free")
int kprobe__security_sk_free(struct pt_regs* ctx) {
    struct sock* sk = (struct sock*)PT_REGS_PARM1(ctx);
    log_debug("kprobe/security_sk_free: sk=%llx\n", sk);
    socket_info_t *skinfo = bpf_map_lookup_elem(&open_socks, &sk);
    if (!skinfo) {
        return 0;
    }

#ifdef FEATURE_UDP_ENABLED
    if (skinfo->protocol == IPPROTO_UDP) {
         udp_close_event_t evt = {
            .sk = (__u64)sk,
            .skinfo = *skinfo,
        };
        if (bpf_perf_event_output(ctx, &udp_close_event, BPF_F_CURRENT_CPU, &evt, sizeof(evt))) {
            log_debug("udp close send error: sk=%llx\n", sk);
        }
    }
#endif

#ifdef FEATURE_TCP_ENABLED
    if (skinfo->protocol == IPPROTO_TCP) {
        tcp_flow_t flow = { .sk = (u64)sk };
        tcp_flow_stats_t *stats = get_tcp_stats(&flow);
        if (stats) {
            stats->tcp_stats.state_transitions |= (1 << TCP_CLOSE);
        }

        tcp_close_event_t evt = {
            .sk = (__u64)sk,
            .skinfo = *skinfo,
        };
        if (bpf_perf_event_output(ctx, &tcp_close_event, BPF_F_CURRENT_CPU, &evt, sizeof(evt))) {
            log_debug("tcp close send error: sk=%llx\n", sk);
        }
    }
#endif

    bpf_map_delete_elem(&open_socks, &sk);
    return 0;
}

#endif
