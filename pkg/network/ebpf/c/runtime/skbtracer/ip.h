#ifndef __IP_H
#define __IP_H

#include <uapi/linux/ip.h>

#include "bpf_helpers.h"
#include "bpf_endian.h"

static __always_inline void print_ip(struct in6_addr addr, u16 port, u8 family, u8 protocol) {
    if (family == AF_INET6) {
        if (protocol == IPPROTO_TCP) {
            log_debug("TCPv6 %llx%llx:%u\n", bpf_ntohll(*((u64*)&addr.s6_addr32[0])), bpf_ntohll(*((u64*)&addr.s6_addr32[2])), port);
        } else {
            log_debug("UDPv6 %llx%llx:%u\n", bpf_ntohll(*((u64*)&addr.s6_addr32[0])), bpf_ntohll(*((u64*)&addr.s6_addr32[2])), port);
        }
    } else {
        if (protocol == IPPROTO_TCP) {
            log_debug("TCPv4 %x:%u\n", bpf_ntohl(addr.s6_addr32[0]), port);
        } else {
            log_debug("UDPv4 %x:%u\n", bpf_ntohl(addr.s6_addr32[0]), port);
        }
    }
}

#endif

