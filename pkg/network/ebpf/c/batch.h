#ifndef __BATCH_H
#define __BATCH_H

#include "tracer.h"
#include "bpf_helpers.h"

typedef struct {
    u64 offset;
    u8 len;
} batch_cpu_t;

typedef struct {
    u64 offset;
    u8 len;
} batch_notification_t;

#define BATCH_OBJS(obj, batch_size, num_batches_per_cpu) \
\
struct bpf_map_def SEC("maps/" #obj "_batch_event") obj ## _batch_event = {  \
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,  \
    .key_size = sizeof(__u32),  \
    .value_size = sizeof(__u32),    \
    .max_entries = 0,   \
    .pinning = 0,   \
    .namespace = "",    \
};  \
\
struct bpf_map_def SEC("maps/" #obj "_batch_offsets") obj ## _batch_offsets = {  \
    .type = BPF_MAP_TYPE_ARRAY, \
    .key_size = sizeof(__u32),  \
    .value_size = sizeof(batch_cpu_t),  \
    .max_entries = 0,    \
    .pinning = 0,   \
    .namespace = "",    \
};  \
\
struct bpf_map_def SEC("maps/" #obj "_batched") obj ## _batched = {    \
    .type = BPF_MAP_TYPE_HASH,  \
    .key_size = sizeof(__u64),  \
    .value_size = sizeof(obj),  \
    .max_entries = 0, \
    .pinning = 0,   \
    .namespace = "",    \
};  \
\
static __always_inline void add_## obj ##_to_batch(struct pt_regs * ctx, obj *val) {   \
    __add_to_batch(ctx, &(obj ##_batch_offsets), &(obj ##_batched), &(obj ##_batch_event), batch_size, num_batches_per_cpu, val);   \
}
// end BATCH_OBJS macro

static __always_inline void __add_to_batch(struct pt_regs * ctx, struct bpf_map_def *offset_map, struct bpf_map_def *obj_map, struct bpf_map_def *perf_map, u8 batch_size, u16 num_batches_per_cpu, void *obj) {
    u32 cpu = bpf_get_smp_processor_id();
    batch_cpu_t *cpu_batch = bpf_map_lookup_elem(offset_map, &cpu);
    if (!cpu_batch) {
        return;
    }

    u64 index = cpu_batch->offset + cpu_batch->len;
    bpf_map_update_elem(obj_map, &index, obj, BPF_ANY);
    cpu_batch->len++;

    if (cpu_batch->len == batch_size) {
        batch_notification_t note;
        __builtin_memset(&note, 0, sizeof(batch_notification_t));
        note.offset = cpu_batch->offset;
        note.len = batch_size;
        bpf_perf_event_output(ctx, perf_map, cpu, &note, sizeof(batch_notification_t));

        // ranges from cpu*batch_size*num_batches_per_cpu to (cpu+1)*batch_size*num_batches_per_cpu
        u16 per_cpu = batch_size*num_batches_per_cpu;
        cpu_batch->offset = (cpu*per_cpu) + ((cpu_batch->offset + batch_size) % per_cpu);
        cpu_batch->len = 0;
    }
}

#endif
