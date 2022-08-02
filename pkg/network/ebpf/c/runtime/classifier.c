#include "bpf_helpers.h"

/* some header soup here
 * tracer.h must be included before ip.h
 * and ip.h must be included before tls.h
 * This order satisfies these dependencies */
#include "classifier.h"
#include "ip.h"
#include "tls.h"
/* */
#include "map-defs.h"
#include "classifier-telemetry.h"
#include "conn-tuple.h"

#define PROTO_PROG_TLS 1
#define PROG_INDX(indx) ((indx)-1)

BPF_PROG_ARRAY(proto_progs, 1)

// max entries of this array will be #cpus
BPF_ARRAY_MAP(filter_args, conn_tuple_t, 0)

static __always_inline int fingerprint_proto(skb_info_t* skb_info, struct __sk_buff* skb) {
    if (is_tls(skb, skb_info->data_off))
        return PROTO_PROG_TLS;

    return 0;
}

static __always_inline void do_tail_call(void* ctx, int protocol) {
        bpf_tail_call_compat(ctx, &proto_progs, PROG_INDX(protocol));
}

/* This function runs the socket filter on both egress and ingress.
 * ingress: https://elixir.bootlin.com/linux/v4.14/source/net/core/filter.c#L73
 * egress: https://elixir.bootlin.com/linux/v4.14/source/net/ipv4/ip_output.c#L297
 * We use this hook to associate a struct sock* with a 
 * (saddr, daddr, sport, dport) tuple. */
SEC("kprobe/__cgroup_bpf_run_filter_skb")
int kprobe____cgroup_bpf_run_filter_skb(struct pt_regs *ctx) {
    conn_tuple_t tup;
    struct sock* sk = (struct sock *)PT_REGS_PARM1(ctx);
    u32 cpu = bpf_get_smp_processor_id();
    if (sk == 0)
        return 0;

    if (!read_conn_tuple(&tup, sk, 0, 0)) {
        return 0;
    }
    tup.netns = get_netns(&sk->sk_net);
    bpf_map_update_elem(&filter_args, &cpu, &tup, BPF_ANY);

    return 0;
}

SEC("socket/classifier_filter")
int socket__classifier_filter(struct __sk_buff* skb) {
    conn_tuple_t *intup;
    proto_args_t args;
    session_t new_session;
    skb_info_t* skb_info = &args.skb_info;
    conn_tuple_t* tup = &args.tup;
    u32 cpu = bpf_get_smp_processor_id();

    __builtin_memset(&args, 0, sizeof(proto_args_t));
    __builtin_memset(&new_session, 0, sizeof(new_session));

    if (!read_conn_tuple_skb(skb, skb_info, tup))
        return 0;

    intup = bpf_map_lookup_elem(&filter_args, &cpu);
    if (intup == 0)
        return 0;

    if ((!intup->saddr_h || !intup->saddr_l) && (!intup->daddr_h || !intup->daddr_l) && !intup->sport && !intup->dport)
        return 0;

    if (!(tup->metadata&CONN_TYPE_TCP))
        return 0;

    intup->metadata |= CONN_TYPE_TCP;
    __builtin_memcpy(tup, intup, sizeof(conn_tuple_t));
    
    // 'delete' the tuple being passed in
    __builtin_memset(intup, 0, sizeof(conn_tuple_t));

    normalize_tuple(tup);
    if (skb_info->tcp_flags & TCPHDR_FIN) {
	    bpf_map_delete_elem(&proto_in_flight, tup);
	    return 0;
    }

    cnx_info_t *info = bpf_map_lookup_elem(&proto_in_flight, tup);
    if (info != NULL) {
        if (info->done)
            return 0;
    }

    int protocol = fingerprint_proto(skb_info, skb);
    if (protocol) {
        int err = bpf_map_update_elem(&proto_args, &cpu, &args, BPF_ANY);
        if (err < 0)
            return 0;

        bpf_map_update_elem(&proto_in_flight, tup, &new_session, BPF_NOEXIST);
        do_tail_call(skb, protocol);
        increment_classifier_telemetry_count(tail_call_failed);
    }

    return 0;
}

// This number will be interpreted by elf-loader to set the current running kernel version
__u32 _version SEC("version") = 0xFFFFFFFE; // NOLINT(bugprone-reserved-identifier)

char _license[] SEC("license") = "GPL"; // NOLINT(bugprone-reserved-identifier)
