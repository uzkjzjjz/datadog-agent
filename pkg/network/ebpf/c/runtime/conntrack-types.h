#ifndef __CONNTRACK_TYPES_H
#define __CONNTRACK_TYPES_H

#include <linux/types.h>
#include "../tracer.h"

typedef struct {
    conn_tuple_t tup;
    __u32 netns;
} conntrack_key_t;

typedef struct {
    __u64 registers;
    __u64 registers_dropped;
} conntrack_telemetry_t;

enum conntrack_telemetry_counter {
    registers,
    registers_dropped,
};

#endif
