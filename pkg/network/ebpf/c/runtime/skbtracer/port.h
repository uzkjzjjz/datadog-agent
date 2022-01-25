#ifndef __PORT_H
#define __PORT_H

#include <net/sock.h>

#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "types.h"

SEC("kprobe/security_socket_bind")
int kprobe__security_socket_bind(struct pt_regs* ctx) {
    struct socket *sock = (struct socket *)PT_REGS_PARM1(ctx);
    struct sockaddr *address = (struct sockaddr *)PT_REGS_PARM2(ctx);
    int addr_len = (int)PT_REGS_PARM3(ctx);

    if (addr_len < sizeof(struct sockaddr)) {
        return 0;
    }

    struct sock *sk;
    bpf_probe_read_kernel(&sk, sizeof(sk), &sock->sk);
    if (!sk) {
        return 0;
    }

    unsigned short family;
    bpf_probe_read_kernel(&family, sizeof(family), &sk->sk_family);
    if (family != AF_INET && family != AF_INET6) {
        return 0;
    }

    struct sockaddr_in *sin = (struct sockaddr_in *)address;
    unsigned short snum;
    bpf_probe_read_kernel(&snum, sizeof(snum), &sin->sin_port);
    if (!snum) {
        return 0;
    }

    socket_info_t *skinfo = bpf_map_lookup_elem(&open_socks, &sk);
    if (!skinfo) {
        return 0;
    }

    log_debug("kprobe/security_socket_bind: sk=%llx port=%u\n", sk, bpf_ntohs(snum));
    skinfo->direction = CONN_DIRECTION_INCOMING;
    return 0;
}

#endif