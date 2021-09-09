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

func newManager(closedHandler *ebpf.PerfHandler) *manager.Manager {
	mgr := &manager.Manager{
		Maps: []*manager.Map{
			{Name: "tcp_open_socks"},
			{Name: "tuples"},
			//{Name: "inet_release_args"},
			{Name: "inet_csk_listen_start_args"},
			{Name: "inet_csk_accept_args"},
			{Name: "tcp_sendmsg_args"},
		},
		PerfMaps: []*manager.PerfMap{
			{
				Map: manager.Map{Name: "conn_close_event"},
				PerfMapOptions: manager.PerfMapOptions{
					PerfRingBufferSize: 8 * os.Getpagesize(),
					Watermark:          1,
					DataHandler:        closedHandler.DataHandler,
					LostHandler:        closedHandler.LostHandler,
				},
			},
		},
		Probes: []*manager.Probe{
			{Section: "kprobe/tcp_init_sock"},
			//{Section: "kprobe/inet_release"},
			//{Section: "kretprobe/inet_release", KProbeMaxActive: maxActive},
			{Section: "kprobe/security_sk_free"},
			{Section: "kprobe/tcp_connect"},
			{Section: "kprobe/inet_csk_listen_start"},
			{Section: "kretprobe/inet_csk_listen_start", KProbeMaxActive: maxActive},
			{Section: "kprobe/inet_csk_accept"},
			{Section: "kretprobe/inet_csk_accept", KProbeMaxActive: maxActive},
			{Section: "kprobe/tcp_sendmsg"},
			{Section: "kretprobe/tcp_sendmsg", KProbeMaxActive: maxActive},
			{Section: "kprobe/tcp_cleanup_rbuf"},
		},
	}
	return mgr
}
