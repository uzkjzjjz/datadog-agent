#ifndef __SOCK_H
#define __SOCK_H

#include <linux/types.h>
#include <net/sock.h>

#include "bpf_helpers.h"
#include "types.h"
#include "inet.h"
#include "tcp.h"
#include "udp.h"

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

    {
        socket_info_t *skinfop = bpf_map_lookup_elem(&tcp_open_socks, &skp);
        if (skinfop) {
            tcp_flow_t *flowp = bpf_map_lookup_elem(&tcp_flows, &skp);
            if (flowp) {
                log_debug("closed perf send: sk=%llx\n", skp);
                tcp_close_event_t evt = {
                    .skp = (__u64)skp,
                    .skinfo = *skinfop,
                    .flow = *flowp,
                };
                int ret = bpf_perf_event_output(ctx, &tcp_close_event, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
                if (ret) {
                    log_debug("tcp close send error: ret=%u sk=%llx\n", ret, skp);
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
                log_debug("udp close send error: ret=%u sk=%llx\n", ret, skp);
            }
            bpf_map_delete_elem(&udp_open_socks, &skp);
            return 0;
        }
    }

    return 0;
}

#endif