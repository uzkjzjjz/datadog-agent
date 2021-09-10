#ifndef __ALTTRACER_TYPES_H
#define __ALTTRACER_TYPES_H

#include <linux/types.h>

enum conn_direction {
    CONN_DIRECTION_UNKNOWN = 0,
    CONN_DIRECTION_INCOMING,
    CONN_DIRECTION_OUTGOING,
};

typedef struct {
    __u64 created_ns;
    __u32 tgid;
    __u32 netns;
    __u8  direction;
} socket_info_t;

typedef struct {
    __u8  family;
    __u8  protocol;
    __u16 sport;
    __u16 dport;
    __u8  saddr[16];
    __u8  daddr[16];
} tuple_t;

typedef struct {
    __u64   last_update;
    __u64   sent_bytes;
    __u64   recv_bytes;
} flow_stats_t;

typedef struct {
    tuple_t       tup;
    flow_stats_t  stats;
} tcp_flow_t;

typedef struct {
    __u64               skp;
    tcp_flow_t          flow;
    socket_info_t   skinfo;
} tcp_close_event_t;

typedef struct {
    __u64               skp;
    socket_info_t   skinfo;
} udp_close_event_t;

#endif
