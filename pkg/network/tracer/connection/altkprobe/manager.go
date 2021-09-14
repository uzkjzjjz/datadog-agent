//+build linux_bpf

package altkprobe

import (
	"os"

	"github.com/DataDog/datadog-agent/pkg/ebpf"

	"github.com/DataDog/ebpf/manager"
)

const (
	// maxActive configures the maximum number of instances of the kretprobe-probed functions handled simultaneously.
	// This value should be enough for typical workloads (e.g. some amount of processes blocked on the `accept` syscall).
	maxActive = 128
)

func newManager(tcpClosedHandler *ebpf.PerfHandler, udpClosedHandler *ebpf.PerfHandler) *manager.Manager {
	mgr := &manager.Manager{
		Maps: []*manager.Map{
			{Name: tcpOpenSocksName},
			{Name: tcpFlowsMapName},
			{Name: "inet_csk_listen_start_args"},
			{Name: "inet_csk_accept_args"},
			{Name: "tcp_sendmsg_args"},
			{Name: boundPortsMap},
			{Name: inoToPIDMap},

			{Name: udpOpenSocksName},
			{Name: udpStatsName},
			{Name: udpTuplesToSocksName},
		},
		PerfMaps: []*manager.PerfMap{
			{
				Map: manager.Map{Name: "tcp_close_event"},
				PerfMapOptions: manager.PerfMapOptions{
					PerfRingBufferSize: 8 * os.Getpagesize(),
					Watermark:          1,
					DataHandler:        tcpClosedHandler.DataHandler,
					LostHandler:        tcpClosedHandler.LostHandler,
				},
			},
			{
				Map: manager.Map{Name: "udp_close_event"},
				PerfMapOptions: manager.PerfMapOptions{
					PerfRingBufferSize: 8 * os.Getpagesize(),
					Watermark:          1,
					DataHandler:        udpClosedHandler.DataHandler,
					LostHandler:        udpClosedHandler.LostHandler,
				},
			},
		},
		Probes: []*manager.Probe{
			{Section: "kprobe/tcp_init_sock"},
			{Section: "kprobe/security_sk_free"},
			{Section: "kprobe/tcp_connect"},
			{Section: "kprobe/inet_csk_listen_start"},
			{Section: "kretprobe/inet_csk_listen_start", KProbeMaxActive: maxActive},
			{Section: "kprobe/inet_csk_accept"},
			{Section: "kretprobe/inet_csk_accept", KProbeMaxActive: maxActive},
			{Section: "kprobe/tcp_sendmsg"},
			{Section: "kretprobe/tcp_sendmsg", KProbeMaxActive: maxActive},
			{Section: "kprobe/tcp_cleanup_rbuf"},
			{Section: "kprobe/tcp_retransmit_skb"},
			{Section: "kprobe/tcp_set_state"},
			{Section: tcp4SeqShowProbe},
			{Section: tcp6SeqShowProbe},
			{Section: udp4SeqShowProbe},
			{Section: udp6SeqShowProbe},

			{Section: "kprobe/udp_lib_get_port"},
			{Section: "kretprobe/udp_lib_get_port", KProbeMaxActive: maxActive},
			{Section: "kprobe/udp_init_sock"},
			{Section: "kprobe/ip_send_skb"},
			{Section: "kprobe/ip6_send_skb"},
			{Section: "kprobe/skb_consume_udp"},
		},
	}
	return mgr
}
