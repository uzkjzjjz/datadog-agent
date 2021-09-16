//+build ignore

package ebpf

/*
#include "./c/runtime/alttracer/types.h"
*/
import "C"

type Tuple C.tuple_t
type FlowStats C.flow_stats_t
type SocketInfo C.socket_info_t

type TCPSockStats C.tcp_sock_stats_t
type TCPFlow C.tcp_flow_t
type TCPFlowKey C.tcp_flow_key_t

type TCPCloseEvent C.tcp_close_event_t
type UDPCloseEvent C.udp_close_event_t
