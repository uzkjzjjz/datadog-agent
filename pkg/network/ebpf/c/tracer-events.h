#ifndef __TRACER_EVENTS_H
#define __TRACER_EVENTS_H

#include "tracer.h"

#include "tracer-maps.h"
#include "tracer-telemetry.h"
#include "tcp_states.h"
#include "tcp.h"

#include "bpf_helpers.h"

static __always_inline int get_proto(conn_tuple_t * t) {
    return (t->metadata & CONN_TYPE_TCP) ? CONN_TYPE_TCP : CONN_TYPE_UDP;
}

static __always_inline void cleanup_conn(struct pt_regs * ctx, conn_tuple_t* tup) {
    // Will hold the full connection data to send through the perf buffer
    conn_t conn = { .tup = *tup };
    tcp_stats_t* tst = NULL;
    conn_stats_ts_t* cst = NULL;

    // TCP stats don't have the PID
    if (get_proto(&conn.tup) == CONN_TYPE_TCP) {
        conn.tup.pid = 0;
        tst = bpf_map_lookup_elem(&tcp_stats, &(conn.tup));
        if (tst) {
            conn.tcp_stats = *tst;
        }
        bpf_map_delete_elem(&tcp_stats, &(conn.tup));
        conn.tup.pid = tup->pid;
        conn.tcp_stats.state_transitions |= (1 << TCP_CLOSE);
    }

    cst = bpf_map_lookup_elem(&conn_stats, &(conn.tup));
    if (cst) {
        conn.conn_stats = *cst;
    }
    bpf_map_delete_elem(&conn_stats, &(conn.tup));
    conn.conn_stats.timestamp = bpf_ktime_get_ns();

    add_conn_t_to_batch(ctx, &conn);
}

#endif // __TRACER_EVENTS_H
