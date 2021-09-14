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

    {
        socket_info_t *skinfop = bpf_map_lookup_elem(&tcp_open_socks, &skp);
        if (skinfop) {
            tcp_flow_t *flowp = bpf_map_lookup_elem(&tcp_flows, &skp);
            if (flowp) {
                flowp->tcpstats.state_transitions |= (1 << TCP_CLOSE);
                log_debug("closed perf send: sk=%llx\n", skp);
                tcp_close_event_t evt = {
                    .skp = (__u64)skp,
                    .skinfo = *skinfop,
                    .flow = *flowp,
                };
                int ret = bpf_perf_event_output(ctx, &tcp_close_event, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
                if (ret) {
                    log_debug("tcp close send error: ret=%d sk=%llx\n", ret, skp);
                }
                bpf_map_delete_elem(&tcp_flows, &skp);
            }
            bpf_map_delete_elem(&tcp_open_socks, &skp);
            return 0;
        }
    }
    {
        socket_info_t *skinfop = bpf_map_lookup_elem(&udp_open_socks, &skp);
        if (skinfop) {
            udp_close_event_t evt = {
                .skp = (__u64)skp,
                .skinfo = *skinfop,
            };
            int ret = bpf_perf_event_output(ctx, &udp_close_event, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
            if (ret) {
                log_debug("udp close send error: ret=%d sk=%llx\n", ret, skp);
            }
            bpf_map_delete_elem(&udp_open_socks, &skp);
            return 0;
        }
    }

    return 0;
}

#endif
