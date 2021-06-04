#ifndef __TRACER_STATS_H
#define __TRACER_STATS_H

#include "tracer.h"

static int read_conn_tuple(conn_tuple_t *t, struct sock *skp, u64 pid_tgid, metadata_mask_t type);

static __always_inline void _update_udp_conn_state(conn_stats_ts_t *cs, size_t sent_bytes, size_t recv_bytes) {
    if (cs->flags & CONN_ASSURED) {
        return;
    }

    if (cs->recv_bytes == 0 && sent_bytes > 0) {
        cs->flags |= CONN_L_INIT;
        return;
    }

    if (cs->sent_bytes == 0 && recv_bytes > 0) {
        cs->flags |= CONN_R_INIT;
        return;
    }

    // If a three-way "handshake" was established, we mark the connection as assured
    if ((cs->flags & CONN_L_INIT && cs->recv_bytes > 0 && sent_bytes > 0) || (cs->flags & CONN_R_INIT && cs->sent_bytes > 0 && recv_bytes > 0)) {
        cs->flags |= CONN_ASSURED;
    }
}

static __always_inline conn_stats_ts_t *get_conn_stats(conn_tuple_t *t) {
    conn_stats_ts_t empty = {};
    __builtin_memset(&empty, 0, sizeof(conn_stats_ts_t));
    if (bpf_map_update_elem(&conn_stats, t, &empty, BPF_NOEXIST) == -E2BIG) {
        increment_telemetry_count(conn_stats_max_entries_hit);
    }
    return bpf_map_lookup_elem(&conn_stats, t);
}

static __always_inline void add_sent_bytes(conn_tuple_t *t, conn_stats_ts_t *cs, size_t sent_bytes) {
    if (sent_bytes <= 0) {
        return;
    }
    __sync_fetch_and_add(&cs->sent_bytes, sent_bytes);
    if ((t->metadata & CONN_TYPE_MASK) != CONN_TYPE_UDP) {
        return;
    }
    _update_udp_conn_state(cs, sent_bytes, 0);
}

static __always_inline void add_recv_bytes(conn_tuple_t *t, conn_stats_ts_t *cs, size_t recv_bytes) {
    if (recv_bytes <= 0) {
        return;
    }
    __sync_fetch_and_add(&cs->recv_bytes, recv_bytes);
    if ((t->metadata & CONN_TYPE_MASK) != CONN_TYPE_UDP) {
        return;
    }
    _update_udp_conn_state(cs, 0, recv_bytes);
}

static __always_inline void add_sent_packets(conn_stats_ts_t *cs, u32 sent_packets) {
    if (sent_packets <= 0) {
        return;
    }
    __sync_fetch_and_add(&cs->sent_packets, sent_packets);
}

static __always_inline void set_sent_packets(conn_stats_ts_t *cs, u32 sent_packets) {
    if (sent_packets <= 0) {
        return;
    }
    cs->sent_packets = sent_packets;
}

static __always_inline void add_recv_packets(conn_stats_ts_t *cs, u32 recv_packets) {
    if (recv_packets <= 0) {
        return;
    }
    __sync_fetch_and_add(&cs->recv_packets, recv_packets);
}

static __always_inline void set_recv_packets(conn_stats_ts_t *cs, u32 recv_packets) {
    if (recv_packets <= 0) {
        return;
    }
    cs->recv_packets = recv_packets;
}

static __always_inline void update_timestamp(conn_stats_ts_t *cs) {
    cs->timestamp = bpf_ktime_get_ns();
}

static __always_inline void set_direction(conn_stats_ts_t *cs, conn_direction_t dir) {
    if (dir == CONN_DIRECTION_UNKNOWN) {
        return;
    }
    cs->direction = dir;
}

static __always_inline void infer_direction(conn_tuple_t *t, conn_stats_ts_t *cs) {
    if (cs->direction != CONN_DIRECTION_UNKNOWN) {
        return;
    }
    u8 *state = NULL;
    port_binding_t pb = {};
    pb.port = t->sport;
    if (t->metadata & CONN_TYPE_TCP) {
        //pb.netns = t->netns;
        state = bpf_map_lookup_elem(&port_bindings, &pb);
    } else {
        state = bpf_map_lookup_elem(&udp_port_bindings, &pb);
    }
    cs->direction = (state != NULL) ? CONN_DIRECTION_INCOMING : CONN_DIRECTION_OUTGOING;
}

static __always_inline tcp_stats_t *get_tcp_stats(conn_tuple_t *t) {
    // initialize-if-no-exist the connection state, and load it
    tcp_stats_t empty = {};
    bpf_map_update_elem(&tcp_stats, t, &empty, BPF_NOEXIST);
    return bpf_map_lookup_elem(&tcp_stats, t);
}

static __always_inline void update_retransmits(tcp_stats_t *t, u32 retransmits) {
    if (retransmits <= 0) {
        return;
    }
    __sync_fetch_and_add(&t->retransmits, retransmits);
}

static __always_inline void update_rtt(tcp_stats_t *t, u32 rtt, u32 rtt_var) {
    if (rtt <= 0) {
        return;
    }
    // For more information on the bit shift operations see:
    // https://elixir.bootlin.com/linux/v4.6/source/net/ipv4/tcp.c#L2686
    t->rtt = rtt >> 3;
    t->rtt_var = rtt_var >> 2;
}

static __always_inline void update_state_transitions(tcp_stats_t *t, u16 transitions) {
    if (transitions <= 0) {
        return;
    }
    t->state_transitions |= transitions;
}

static __always_inline int handle_retransmit(struct sock *sk, int segs) {
    conn_tuple_t t = {};
    u64 zero = 0;
    if (!read_conn_tuple(&t, sk, zero, CONN_TYPE_TCP)) {
        return 0;
    }
    tcp_stats_t *stats = get_tcp_stats(&t);
    if (stats == NULL) {
        return 0;
    }
    update_retransmits(stats, segs);
    return 0;
}

#endif // __TRACER_STATS_H
