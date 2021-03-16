#ifndef __TRACER_TELEMETRY_H
#define __TRACER_TELEMETRY_H

#include "tracer-maps.h"

#include "bpf_endian.h"

#include <linux/kconfig.h>
#include <net/sock.h>

enum telemetry_counter {
    tcp_sent_miscounts,
    missed_tcp_close,
    missed_udp_close,
    udp_send_processed,
    udp_send_missed,
    tcp_established,
    tcp_closed,
    tuple_read_err,
    tcp_sent_bytes,
    tcp_recv_bytes,
//    perf_ring_error,
    conn_stats_created,
};

static __always_inline void increment_telemetry_amount(enum telemetry_counter counter_name, size_t amount) {
    if (amount < 1) {
        return;
    }

    __u64 key = 0;
    telemetry_t* val = NULL;
    val = bpf_map_lookup_elem(&telemetry, &key);
    if (val == NULL) {
        return;
    }

    switch (counter_name) {
    case tcp_sent_miscounts:
        __sync_fetch_and_add(&val->tcp_sent_miscounts, amount);
        break;
    case missed_tcp_close:
        __sync_fetch_and_add(&val->missed_tcp_close, amount);
        break;
    case missed_udp_close:
        __sync_fetch_and_add(&val->missed_udp_close, amount);
        break;
    case udp_send_processed:
        __sync_fetch_and_add(&val->udp_sends_processed, amount);
        break;
    case udp_send_missed:
        __sync_fetch_and_add(&val->udp_sends_missed, amount);
        break;
    case tcp_established:
        __sync_fetch_and_add(&val->tcp_established, amount);
        break;
    case tcp_closed:
        __sync_fetch_and_add(&val->tcp_closed, amount);
        break;
    case tuple_read_err:
        __sync_fetch_and_add(&val->tuple_read_err, amount);
        break;
    case tcp_sent_bytes:
        __sync_fetch_and_add(&val->tcp_sent_bytes, amount);
        break;
    case tcp_recv_bytes:
        __sync_fetch_and_add(&val->tcp_recv_bytes, amount);
        break;
//    case perf_ring_error:
//        __sync_fetch_and_add(&val->perf_ring_error, amount);
//        break;
    case conn_stats_created:
        __sync_fetch_and_add(&val->conn_stats_created, amount);
        break;
    }
}

static __always_inline void increment_telemetry_count(enum telemetry_counter counter_name) {
    increment_telemetry_amount(counter_name, 1);
}

static __always_inline void sockaddr_to_addr(struct sockaddr * sa, u64 * addr_h, u64 * addr_l, u16 * port) {
    if (!sa) return;

    u16 family = 0;
    bpf_probe_read(&family, sizeof(family), &sa->sa_family);

    struct sockaddr_in * sin;
    struct sockaddr_in6 * sin6;
    switch (family) {
    case AF_INET:
        sin = (struct sockaddr_in *) sa;
        if (addr_l) {
            bpf_probe_read(addr_l, sizeof(__be32), &(sin->sin_addr.s_addr));
        }
        if (port) {
            bpf_probe_read(port, sizeof(__be16), &sin->sin_port);
            *port = bpf_ntohs(*port);
        }
        break;
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) sa;
        if (addr_l && addr_h) {
            bpf_probe_read(addr_h, sizeof(u64), sin6->sin6_addr.s6_addr);
            bpf_probe_read(addr_l, sizeof(u64), &(sin6->sin6_addr.s6_addr[8]));
        }
        if (port) {
            bpf_probe_read(port, sizeof(u16), &sin6->sin6_port);
            *port = bpf_ntohs(*port);
        }
        break;
    }
}

#endif // __TRACER_TELEMETRY_H
