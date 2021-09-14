#ifndef __SOCK_H
#define __SOCK_H

#include <linux/types.h>
#include <net/sock.h>

#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "bpf_read.h"
#include "types.h"
#include "netns.h"

typedef struct {
    u8  family;
    u8  protocol;
    u16 port;
    u32 netns;
} port_binding_t;

struct bpf_map_def SEC("maps/seq_listen_ports") seq_listen_ports = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(port_binding_t),
    .value_size = sizeof(__u8),
    .max_entries = 32768,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/ino_to_pid") ino_to_pid = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u64),
    .value_size = sizeof(__u32),
    .max_entries = 65536,
    .pinning = 0,
    .namespace = "",
};

// expects tuple_t.family to already be set
static __always_inline void tuple_from_sock(struct sock *skp, tuple_t *tup) {
    bpf_probe_read(&tup->sport, sizeof(tup->sport), &skp->sk_num);
    bpf_probe_read(&tup->dport, sizeof(tup->dport), &skp->sk_dport);
    tup->dport = bpf_ntohs(tup->dport);

    if (tup->family == AF_INET) {
        bpf_probe_read(tup->saddr, sizeof(__be32), (__u8*)&skp->sk_rcv_saddr);
        bpf_probe_read(tup->daddr, sizeof(__be32), (__u8*)&skp->sk_daddr);
    } else if (tup->family == AF_INET6) {
        bpf_probe_read(tup->saddr, sizeof(tup->saddr), (__u8*)&skp->sk_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read(tup->daddr, sizeof(tup->daddr), (__u8*)&skp->sk_v6_daddr.in6_u.u6_addr32);
    }
}

static __always_inline int read_fs_socket(struct sock *skp, u8 protocol, u8 listen_state, struct bpf_map_def *open_socket_map) {
    u16 family = 0;
    bpf_probe_read(&family, sizeof(family), &skp->sk_family);
    if (family != AF_INET && family != AF_INET6) {
        return 0;
    }

    struct inode *inodep;
    BPF_PROBE_READ_INTO(&inodep, skp, sk_socket, file, f_inode);
    if (!inodep) {
        return 0;
    }

    u64 ino;
    int ret = bpf_probe_read(&ino, sizeof(ino), &inodep->i_ino);
    if (ret) {
        return 0;
    }

    // read PID from ino-to-pid map
    u32 *pidp = bpf_map_lookup_elem(&ino_to_pid, &ino);
    if (!pidp) {
        return 0;
    }
    bpf_map_delete_elem(&ino_to_pid, &ino);

    // read created time from: sk->sk_socket->file->f_inode->i_ctime
    struct timespec64 ctime;
    ret = bpf_probe_read(&ctime, sizeof(ctime), &inodep->i_ctime);
    if (ret) {
        return 0;
    }
    socket_info_t sk_info = {};
    sk_info.tgid = *pidp;
    sk_info.netns = get_netns(&skp->sk_net);
    sk_info.created_ns = (u64)timespec64_to_ns(&ctime);
    sk_info.direction = CONN_DIRECTION_UNKNOWN;

    port_binding_t pb = {};
    pb.protocol = protocol;
    pb.family = family;
    pb.netns = sk_info.netns;
    ret = bpf_probe_read(&pb.port, sizeof(pb.port), &skp->sk_num);
    if (ret) {
        return 0;
    }

    u8 state = 0;
    bpf_probe_read(&state, sizeof(state), (void *)&skp->sk_state);
    if (state == listen_state) {
        u8 one = 1;
        // store port as listening/bound port
        bpf_map_update_elem(&seq_listen_ports, &pb, &one, BPF_ANY);
        log_debug("kprobe/seq_show: add port binding: protocol=%u family=%u port=%u\n", pb.protocol, pb.family, pb.port);
        // create open sock
        bpf_map_update_elem(open_socket_map, &skp, &sk_info, BPF_NOEXIST);
    } else if (state == TCP_ESTABLISHED || (state >= TCP_FIN_WAIT1 && state != TCP_CLOSE)) {
        // check if bound port, set to incoming if so
        u8 *bound = bpf_map_lookup_elem(&seq_listen_ports, &pb);
        sk_info.direction = (bound) ? CONN_DIRECTION_INCOMING : CONN_DIRECTION_OUTGOING;

        // create open sock and flow
        bpf_map_update_elem(open_socket_map, &skp, &sk_info, BPF_NOEXIST);
        return family;
    }
    return 0;
}

#endif