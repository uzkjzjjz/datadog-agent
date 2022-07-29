#ifndef __CLASSIFIER_MAPS_H
#define __CLASSIFIER_MAPS_H

#include "tracer.h"
#include "bpf_helpers.h"
#include "map-defs.h"

/* This map is used for telemetry in kernelspace
 * only key 0 is used
 * value is a telemetry object
 */
BPF_ARRAY_MAP(classifier_telemetry, classifier_telemetry_t, 1)
#endif
