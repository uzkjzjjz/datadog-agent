#ifndef __TLS_MAPS_H
#define __TLS_MAPS_H

#include "tracer.h"
#include "bpf_helpers.h"
#include "tls-types.h"
#include "map-defs.h"

/* This map is used to keep track of in-flight TLS transactions for each TCP connection */
BPF_HASH_MAP(proto_in_flight, conn_tuple_t, session_t, 1)
    
#endif
