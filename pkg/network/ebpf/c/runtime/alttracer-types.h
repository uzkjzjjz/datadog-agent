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
} tcp_socket_info_t;

typedef struct {
    __u8  family;
    __u8  protocol;
    __u16 sport;
    __u16 dport;
    __u8  saddr[16];
    __u8  daddr[16];

    __u64 sent_bytes;
    __u64 recv_bytes;
} tuple_t;

typedef struct {
    __u64               skp;
    tcp_socket_info_t   skinfo;
    tuple_t             tup;
} conn_event_t;

#endif
