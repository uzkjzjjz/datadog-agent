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

struct bpf_map_def SEC("maps/open_socks") open_socks = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct sock *),
    .value_size = sizeof(socket_info_t),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

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

static __always_inline void add_open_sock(struct sock *skp, u8 protocol, enum conn_direction dir) {
    socket_info_t skinfo = {};
    skinfo.protocol = protocol;
    skinfo.created_ns = bpf_ktime_get_ns();
    skinfo.tgid = bpf_get_current_pid_tgid() >> 32;
    skinfo.netns = get_netns(&skp->sk_net);
    skinfo.direction = dir;
    bpf_probe_read(&skinfo.family, sizeof(skinfo.family), &skp->sk_family);
    bpf_map_update_elem(&open_socks, &skp, &skinfo, BPF_NOEXIST);
}

static __always_inline void tuple_from_sock(struct sock *skp, u8 protocol, u32 tgid, tuple_t *tup) {
    tup->tgid = tgid;
    tup->protocol = protocol;
    bpf_probe_read(&tup->family, sizeof(tup->family), &skp->sk_family);
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

static __always_inline int socket_info_from_procfs_sock(struct sock *skp, u8 protocol, socket_info_t *skinfop) {
    u16 family = 0;
    int ret = bpf_probe_read(&family, sizeof(family), &skp->sk_family);
    if (ret || (family != AF_INET && family != AF_INET6)) {
        return 1;
    }
    skinfop->family = family;

    struct inode *inodep;
    BPF_PROBE_READ_INTO(&inodep, skp, sk_socket, file, f_inode);
    if (!inodep) {
        return 1;
    }

    u64 ino;
    if (bpf_probe_read(&ino, sizeof(ino), &inodep->i_ino)) {
        return 1;
    }

    // read PID from ino-to-pid map
    u32 *pidp = bpf_map_lookup_elem(&ino_to_pid, &ino);
    if (!pidp) {
        return 1;
    }
    bpf_map_delete_elem(&ino_to_pid, &ino);

    // read created time from: sk->sk_socket->file->f_inode->i_ctime
    struct timespec64 ctime;
    if (bpf_probe_read(&ctime, sizeof(ctime), &inodep->i_ctime)) {
        return 1;
    }

    skinfop->protocol = protocol;
    skinfop->tgid = *pidp;
    skinfop->netns = get_netns(&skp->sk_net);
    skinfop->created_ns = (u64)timespec64_to_ns(&ctime);
    skinfop->direction = CONN_DIRECTION_UNKNOWN;
    return 0;
}

static __always_inline int read_fs_socket(struct sock *skp, u8 protocol, u8 listen_state) {
    socket_info_t skinfo = {};
    if (socket_info_from_procfs_sock(skp, protocol, &skinfo)) {
        return 0;
    }

    port_binding_t pb = {};
    pb.protocol = skinfo.protocol;
    pb.family = skinfo.family;
    pb.netns = skinfo.netns;
    if (bpf_probe_read(&pb.port, sizeof(pb.port), &skp->sk_num)) {
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
        bpf_map_update_elem(&open_socks, &skp, &skinfo, BPF_NOEXIST);
    } else if (state == TCP_ESTABLISHED || (state >= TCP_FIN_WAIT1 && state != TCP_CLOSE)) {
        // check if bound port, set to incoming if so
        u8 *bound = bpf_map_lookup_elem(&seq_listen_ports, &pb);
        skinfo.direction = (bound) ? CONN_DIRECTION_INCOMING : CONN_DIRECTION_OUTGOING;

        // create open sock and flow
        bpf_map_update_elem(&open_socks, &skp, &skinfo, BPF_NOEXIST);
        return skinfo.family;
    }
    return 0;
}

#endif