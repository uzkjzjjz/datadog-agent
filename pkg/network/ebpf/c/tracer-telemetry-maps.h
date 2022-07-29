#ifndef __TRACER_TELEMETRY_MAPS_H
#define __TRACER_TELEMETRY_MAPS_H

#include "tracer.h"
#include "bpf_helpers.h"
#include "map-defs.h"

/* This map is used for telemetry in kernelspace
 * only key 0 is used
 * value is a telemetry object
 */
BPF_ARRAY_MAP(telemetry, telemetry_t, 1)
    
#endif
