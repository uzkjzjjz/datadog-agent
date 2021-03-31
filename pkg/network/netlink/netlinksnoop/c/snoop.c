#include <linux/kconfig.h>
#include <linux/version.h>
#include <linux/types.h>

#include <linux/socket.h>
#include <uapi/linux/netlink.h>

#include "bpf_helpers.h"

#ifndef LINUX_VERSION_CODE
# error "kernel version not included?"
#endif

#define MAX_MSG_SIZE 32768

typedef struct {
    void *base;
    char data[MAX_MSG_SIZE];
} nl_msg_t;

struct bpf_map_def SEC("maps/buffers") buffers = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32), // cpu num
    .value_size = sizeof(nl_msg_t),
    .max_entries = 16,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/nlmsgs") nlmsgs = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 0, // This will get overridden at runtime
    .pinning = 0,
    .namespace = "",
};

SEC("kprobe/netlink_recvmsg")
int kprobe__netlink_recvmsg(struct pt_regs* ctx) {
    __u64 pidtgid = bpf_get_current_pid_tgid();
    __u32 pid = pidtgid >> 32;
    if (pid != FILTER_PID) {
        return 0;
    }
    u32 cpu = bpf_get_smp_processor_id();

    nl_msg_t *msg = (nl_msg_t *)bpf_map_lookup_elem(&buffers, &cpu);
    if (!msg) {
        return 0;
    }
    msg->base = NULL;

    struct msghdr *mhdr = (struct msghdr *)PT_REGS_PARM2(ctx);
    if (!mhdr) {
        return 0;
    }
    struct iov_iter iter = {};
    bpf_probe_read(&iter, sizeof(iter), &mhdr->msg_iter);

    struct iovec iov = {};
    bpf_probe_read(&iov, sizeof(iov), (struct iovec *)iter.iov);

    msg->base = iov.iov_base;

    log_debug("kprobe/netlink_recvmsg: base:%x\n", msg->base);
}

SEC("kretprobe/netlink_recvmsg")
int kretprobe__netlink_recvmsg(struct pt_regs* ctx) {
    __u64 pidtgid = bpf_get_current_pid_tgid();
    __u32 pid = pidtgid >> 32;
    if (pid != FILTER_PID) {
        return 0;
    }
    int copied = PT_REGS_RC(ctx);
    if (copied < 0) {
        return 0;
    }

    u32 cpu = bpf_get_smp_processor_id();
    nl_msg_t *msg = (nl_msg_t *)bpf_map_lookup_elem(&buffers, &cpu);
    if (!msg || !msg->base) {
        log_debug("ERR(kretprobe/netlink_recvmsg): invalid msg\n");
        return 0;
    }

    u32 size = copied > sizeof(msg->data) ? sizeof(msg->data) : copied;
    if (bpf_probe_read(&msg->data, size, msg->base) == 0) {
        log_debug("kretprobe/netlink_recvmsg: sending msg size:%u\n", size);
        bpf_perf_event_output(ctx, &nlmsgs, cpu, &msg->data, size);
    }
    msg->base = NULL;
}

// This number will be interpreted by elf-loader to set the current running kernel version
__u32 _version SEC("version") = 0xFFFFFFFE; // NOLINT(bugprone-reserved-identifier)

char _license[] SEC("license") = "GPL"; // NOLINT(bugprone-reserved-identifier)
