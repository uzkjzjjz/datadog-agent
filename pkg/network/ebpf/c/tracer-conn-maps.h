#ifndef __TRACER_CONN_MAPS_H
#define __TRACER_CONN_MAPS_H

#include "tracer.h"
#include "bpf_helpers.h"
#include "map-defs.h"

/* This is a key/value store with the keys being a conn_tuple_t for send & recv calls
 * and the values being conn_stats_ts_t *.
 */
BPF_HASH_MAP(conn_stats, conn_tuple_t, conn_stats_ts_t, 0)
    
#endif
