//+build ignore

package ebpf

/*
#include "./c/runtime/alttracer-types.h"
*/
import "C"

type Tuple C.tuple_t
type TCPSocketInfo C.tcp_socket_info_t
type ConnEvent C.conn_event_t
