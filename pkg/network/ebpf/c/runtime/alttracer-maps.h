#ifndef __ALTTRACER_MAPS_H
#define __ALTTRACER_MAPS_H

#include <net/sock.h>

#include "bpf_helpers.h"
#include "alttracer-types.h"

struct bpf_map_def SEC("maps/tcp_open_socks") tcp_open_socks = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct sock *),
    .value_size = sizeof(tcp_socket_info_t),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/tuples") tuples = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct sock *),
    .value_size = sizeof(tuple_t),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/conn_close_event") conn_close_event = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 0, // This will get overridden at runtime
    .pinning = 0,
    .namespace = "",
};

// ARGS

//struct bpf_map_def SEC("maps/inet_release_args") inet_release_args = {
//    .type = BPF_MAP_TYPE_HASH,
//    .key_size = sizeof(u64),
//    .value_size = sizeof(struct sock *),
//    .max_entries = 1024,
//    .pinning = 0,
//    .namespace = "",
//};

struct bpf_map_def SEC("maps/inet_csk_listen_start_args") inet_csk_listen_start_args = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(struct sock *),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/inet_csk_accept_args") inet_csk_accept_args = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(struct sock *),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/tcp_sendmsg_args") tcp_sendmsg_args = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(struct sock *),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

#endif
