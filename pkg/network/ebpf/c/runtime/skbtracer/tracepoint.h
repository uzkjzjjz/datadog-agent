#ifndef __TRACEPOINT_H
#define __TRACEPOINT_H

struct tracepoint_net_net_dev_queue_t {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    void *skbaddr;
    unsigned int len;
    u32 __data_loc_name;
};

#define __get_dynamic_array(__entry, field)	\
		((void *)__entry + (__entry->__data_loc_##field & 0xffff))
#define __get_str(__entry, field) ((char *)__get_dynamic_array(__entry, field))

#endif
