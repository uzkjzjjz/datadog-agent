#ifndef __TYPES_H
#define __TYPES_H

#include <linux/types.h>
#include <linux/in6.h>

#define EIGNOREPROTO 255

enum conn_direction {
    CONN_DIRECTION_UNKNOWN = 0,
    CONN_DIRECTION_INCOMING,
    CONN_DIRECTION_OUTGOING,
};

typedef struct {
    __u16 sport;
    __u16 dport;
    __u8  family;
    __u8  protocol;
    struct in6_addr saddr;
    struct in6_addr daddr;
} tuple_t;

typedef struct {
    __u64 created_ns;
    __u32 tgid;
    __u32 netns;
    __u8  direction;
    __u8  family;
    __u8  protocol;
} socket_info_t;

typedef struct {
    __u64   last_update;
    __u64   sent_bytes;
    __u64   recv_bytes;
    __u64   sent_packets;
    __u64   recv_packets;
} flow_stats_t;

typedef struct {
    tuple_t tup;
    __u64 sk;
} udp_flow_t;

typedef struct {
    __u64 sk;
} tcp_flow_t;

typedef struct {
    __u32   retransmits;
    __u32   rtt;
    __u32   rtt_var;

    // Bit mask containing all TCP state transitions tracked by our tracer
    __u16   state_transitions;
} tcp_stats_t;

typedef struct {
    tuple_t tup;
    flow_stats_t flow_stats;
    tcp_stats_t tcp_stats;
} tcp_flow_stats_t;

typedef struct {
    __u64           sk;
    socket_info_t   skinfo;
} udp_close_event_t;

typedef struct {
    __u64           sk;
    socket_info_t   skinfo;
} tcp_close_event_t;

#endif