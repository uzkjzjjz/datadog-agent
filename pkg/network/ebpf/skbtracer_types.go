//  Unless explicitly stated otherwise all files in this repository are licensed
//  under the Apache License Version 2.0.
//  This product includes software developed at Datadog (https://www.datadoghq.com/).
//  Copyright 2016-present Datadog, Inc.

//+build ignore

package ebpf

/*
#include "./c/runtime/skbtracer/types.h"
*/
import "C"

type In6Addr C.struct_in6_addr
type Tuple C.tuple_t
type SocketInfo C.socket_info_t
type FlowStats C.flow_stats_t
type UDPFlow C.udp_flow_t
type UDPCloseEvent C.udp_close_event_t
type TCPFlow C.tcp_flow_t
type TCPConnStats C.tcp_stats_t
type TCPFlowStats C.tcp_flow_stats_t
type TCPCloseEvent C.tcp_close_event_t
