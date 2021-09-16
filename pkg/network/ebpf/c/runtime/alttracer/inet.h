#ifndef __INET_H
#define __INET_H

#include <linux/types.h>

#include "bpf_helpers.h"
#include "types.h"
#include "tcp.h"
#include "udp.h"

// socket CLOSE

SEC("kprobe/security_sk_free")
int kprobe__security_sk_free(struct pt_regs* ctx) {
    struct sock* skp = (struct sock*)PT_REGS_PARM1(ctx);
    log_debug("kprobe/security_sk_free: sk=%llx\n", skp);
    socket_info_t *skinfop = bpf_map_lookup_elem(&open_socks, &skp);
    if (!skinfop) {
        return 0;
    }

    if (skinfop->protocol == IPPROTO_TCP) {
        // TODO check conditions which cause tcp_sock_stats_t to exist
        tcp_sock_stats_t *tcpstatsp = bpf_map_lookup_elem(&tcp_sock_stats, &skp);
        if (tcpstatsp) {
            tcpstatsp->state_transitions |= (1 << TCP_CLOSE);
            tcp_close_event_t evt = {
                .skp = (__u64)skp,
                .skinfo = *skinfop,
                .stats = *tcpstatsp,
                //.flow = *flowp,
            };
            if (bpf_perf_event_output(ctx, &tcp_close_event, BPF_F_CURRENT_CPU, &evt, sizeof(evt))) {
                log_debug("tcp close send error: sk=%llx\n", skp);
            }
        }
        // TODO how to get TCP flow if PID might be different from skinfop->tgid?

//        tcp_flow_key_t key = {};
//        key.skp = skp;
//        key.tgid = skinfop->tgid;
//        tcp_flow_t *flowp = bpf_map_lookup_elem(&tcp_flows, &key);
//        if (flowp) {
//            log_debug("closed perf send: sk=%llx\n", skp);
//            bpf_map_delete_elem(&tcp_flows, &key);
//        }
    } else if (skinfop->protocol == IPPROTO_UDP) {
        udp_close_event_t evt = {
            .skp = (__u64)skp,
            .skinfo = *skinfop,
        };
        if (bpf_perf_event_output(ctx, &udp_close_event, BPF_F_CURRENT_CPU, &evt, sizeof(evt))) {
            log_debug("udp close send error: sk=%llx\n", skp);
        }
    }

    bpf_map_delete_elem(&open_socks, &skp);
    return 0;
}

#endif
