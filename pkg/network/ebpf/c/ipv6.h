#ifndef __IPV6_H
#define __IPV6_H

/* check if IPs are IPv4 mapped to IPv6 ::ffff:xxxx:xxxx
 * https://tools.ietf.org/html/rfc4291#section-2.5.5
 * the addresses are stored in network byte order so IPv4 adddress is stored
 * in the most significant 32 bits of addr.
 * Meanwhile the end of the mask is stored in the least significant 32 bits.
 */
static __always_inline bool is_ipv4_mapped_ipv6(__be32 addr[4]) {
    return ((u64)(addr[0] | addr[1]) | (u64)(addr[2] ^ bpf_cpu_to_be32(0x0000ffff))) == 0L;
}

static __always_inline bool is_ipv6_addr_set(__be32 addr[4]) {
    return (addr[0] | addr[1] | addr[2] | addr[3]) != 0;
}

static __always_inline __be64 be32_pair_to_be64(__be32 x, __be32 y) {
    return ((__be64)x << 32) | (__be64)y;
}

#endif
