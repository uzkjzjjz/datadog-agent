#include <linux/kconfig.h>
#include "pid_mapper.h"
#include <linux/net.h>
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/sched.h>
#include <net/sock.h>
#include <linux/socket.h>

#define SOCKET_OPS_ID 1
#define TCP_OPS_ID 2
#define INET_OPS_ID 3

struct bpf_map_def SEC("maps/tgidpid_to_fd") tgidpid_to_fd = {
   .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u64),
    .value_size = sizeof(int),
    .max_entries = 1,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/symbol_table") symbol_table = {
   .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u64),
    .value_size = sizeof(__u32),
    .max_entries = 3,
    .pinning = 0,
    .namespace = "",
};


#define KERNEL_READ_FAIL(dest, sz, src)\
    do {                                            \
    if (bpf_probe_read_kernel(dest, sz, src) < 0)   \
        return 0;                                   \
    } while(0);

/* The following hooks are used to form a mapping for the struct sock*
 * objects created before system probe was started. Userspace triggers
 * the ebpf program by interacting with procfs.
 * do_sys_open hooks helps us filter out */

// prefix: /proc/
#define PREFIX_END 6
#define MAX_UINT_LEN 10
#define FDPATH_SZ 32
static int __always_inline parse_fd(char* buffer) {
    // /proc/<MAX_UINT_LEN>/fd/<MAX_UINT_LEN>
    char *fdptr = buffer+PREFIX_END;


#pragma unroll
    for (int i = 0; i < MAX_UINT_LEN; ++i) {
        if (*fdptr == '/')
            break;

        if ((*fdptr < '0') || (*fdptr > '9'))
            return -1;

        fdptr++;
    }

    if (!((fdptr[1] == 'f') && (fdptr[2] == 'd') && (fdptr[3] == '/')))
        return -1;

    fdptr += 4;

    int fd = 0;
#pragma unroll
    for (int i = 0; i < MAX_UINT_LEN; i++) {
        if (fdptr[i] == 0)
            return fd;

        if ((fdptr[i] < '0') || (fdptr[i] > '9'))
            return -1;

        fd = (fdptr[i] - '0') + (fd* 10);
    }

    return fd;
}

SEC("kprobe/user_path_at_empty")
int kprobe__do_sys_open(struct pt_regs* ctx) {
    char* path = (char *)PT_REGS_PARM2(ctx);
    char buffer[FDPATH_SZ];
    __builtin_memset(buffer, 0, FDPATH_SZ);

    if (path == 0)
        return 0;

    if (bpf_probe_read_user(&buffer, FDPATH_SZ, path) < 0)
        return 0;

    if (!((buffer[0] == '/') && (buffer[1] == 'p') && (buffer[2] == 'r') && (buffer[3] == 'o') && (buffer[4] == 'c') && (buffer[5] == '/')))
        return 0;

    int fd = parse_fd(buffer);
    if (fd < 0)
        return 0;

    u64 tgidpid = bpf_get_current_pid_tgid();

    bpf_map_update_elem(&tgidpid_to_fd, &tgidpid, &fd, BPF_NOEXIST);

    return 0;
}

//static __always_inline void map_sock_to_pid(struct file* f, u32 pid) {
//    struct socket* sock;
//    struct sock* sk;
//
//    bpf_probe_read_kernel(&sock, sizeof(struct socket *), &f->private_data);
//    if (sock == NULL)
//        return;
//
//    bpf_probe_read_kernel(&sk, sizeof(struct sock *), &sock->sk);
//    if (sk == NULL)
//        return;
//
//    bpf_map_update_elem(&sock_to_pid, &sk, &pid, BPF_NOEXIST);
//}
//
//static __always_inline int fingerprint_tcp_inet_ops(struct file* f) {
//    struct socket* sock;
//    struct proto_ops *pops;
//
//    KERNEL_READ_FAIL(&sock, sizeof(struct socket *), &f->private_data);
//    if (sock == NULL)
//        return 0;
//
//    KERNEL_READ_FAIL(&pops, sizeof(struct proto_ops *), &sock->ops);
//
//    u32 *addr_id = bpf_map_lookup_elem(&symbol_table, &pops);
//    if (!addr_id)
//        return 0;
//
//    if ((*addr_id == TCP_OPS_ID) || (*addr_id == INET_OPS_ID)) {
//        return 1;
//    }
//
//    return 0;
//}

static __always_inline int is_inode_socket(struct inode* i) {
    struct inode_operations *i_op;
    KERNEL_READ_FAIL(&i_op, sizeof(struct inode_operations *), &i->i_op); 

    log_info("i_op %lx\n", i_op);
    u32 *addr_id = bpf_map_lookup_elem(&symbol_table, &i_op);
    if (!addr_id)
        return 0;

    return *addr_id == SOCKET_OPS_ID;
}

SEC("kprobe/security_inode_readlink")
int kprobe__security_inode_readlink(struct pt_regs* ctx) {
    u64 tgidpid = bpf_get_current_pid_tgid();
    void* x = bpf_map_lookup_elem(&tgidpid_to_fd, &tgidpid);
    if (!x)
        return 0;

    bpf_map_delete_elem(&tgidpid_to_fd, &tgidpid);

    struct dentry* d = (struct dentry *)PT_REGS_PARM1(ctx);
    struct inode* i;

    KERNEL_READ_FAIL(&i, sizeof(struct inode *), &d->d_inode);
    if (!i)
        return 0;

    is_inode_socket(i);

    return 0;
}

/* The following hooks are used to track the lifecycle of the process */
struct audit_context {
    int dummy;
    int in_syscall;
};

static __always_inline int is_syscall_ctx(struct task_struct *tsk) {
    int in_syscall;
    struct audit_context* actx;

    KERNEL_READ_FAIL(&actx, sizeof(struct audit_context *), &tsk->audit_context);
    if (!actx)
        return 0;

    KERNEL_READ_FAIL(&in_syscall, sizeof(int), &actx->in_syscall);
    return in_syscall;
}


SEC("kprobe/security_sk_alloc")
int kprobe__security_sk_alloc(struct pt_regs *ctx) {
    struct sock* sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk)
        return 0;

    struct task_struct *tsk = (struct task_struct *)bpf_get_current_task();
    if (tsk == NULL)
        return 0;

    int family = PT_REGS_PARM2(ctx);
    if (!((family == AF_INET) || (family == AF_INET6)))
        return 0;

    if (!is_syscall_ctx(tsk))
        return 0;

    u64 tgid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_update_elem(&sock_to_pid, &sk, &tgid, BPF_NOEXIST);

    return 0;
}

SEC("kprobe/security_sk_clone")
int kprobe__security_sk_clone(struct pt_regs *ctx) {
    struct sock* sk = (struct sock *)PT_REGS_PARM2(ctx);
    if (sk == NULL)
        return 0;

    struct task_struct *tsk = (struct task_struct *)bpf_get_current_task();
    if (tsk == NULL)
        return 0;

    if (!is_syscall_ctx(tsk))
        return 0;

    u64 tgid = bpf_get_current_pid_tgid() >> 32;

    bpf_map_update_elem(&sock_to_pid, &sk, &tgid, BPF_NOEXIST);

    return 0;
}

SEC("kprobe/security_sk_free")
int kprobe__security_sk_free(struct pt_regs* ctx) {
    struct sock* sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (sk == NULL)
        return 0;

    bpf_map_delete_elem(&sock_to_pid, &sk);

    return 0;
}

// This number will be interpreted by elf-loader to set the current running kernel version
__u32 _version SEC("version") = 0xFFFFFFFE; // NOLINT(bugprone-reserved-identifier)
char _license[] SEC("license") = "GPL"; // NOLINT(bugprone-reserved-identifier)
