//+build linux_bpf

package altkprobe

import (
	"os"

	"github.com/DataDog/datadog-agent/pkg/ebpf"
	"github.com/DataDog/ebpf-manager"
)

const (
	// maxActive configures the maximum number of instances of the kretprobe-probed functions handled simultaneously.
	// This value should be enough for typical workloads (e.g. some amount of processes blocked on the `accept` syscall).
	maxActive = 128
)

var mainProbes = map[string]string{
	"kprobe/tcp_init_sock":            "kprobe__tcp_init_sock",
	"kprobe/security_sk_free":         "kprobe__security_sk_free",
	"kprobe/tcp_connect":              "kprobe__tcp_connect",
	"kprobe/inet_csk_listen_start":    "kprobe__inet_csk_listen_start",
	"kretprobe/inet_csk_listen_start": "kretprobe__inet_csk_listen_start",
	"kprobe/inet_csk_accept":          "kprobe__inet_csk_accept",
	"kretprobe_inet_csk_accept":       "kretprobe__inet_csk_accept",
	"kprobe/tcp_sendmsg":              "kprobe__tcp_sendmsg",
	"kretprobe/tcp_sendmsg":           "kretprobe_tcp_sendmsg",
	"kprobe/tcp_sendpage":             "kprobe__tcp_sendpage",
	"kretprobe/tcp_sendpage":          "kretprobe__tcp_sendpage",
	"kprobe/tcp_cleanup_rbuf":         "kprobe__tcp_cleanup_rbuf",
	"kprobe/tcp_retransmit_skb":       "kprobe__tcp_retransmit_skb",
	"kprobe/tcp_set_state":            "kprobe__tcp_set_state",
	tcp4SeqShowProbe:                  "kprobe__tcp4_seq_show",
	tcp6SeqShowProbe:                  "kprobe__tcp6_seq_show",
	udp4SeqShowProbe:                  "kprobe__udp4_seq_show",
	udp6SeqShowProbe:                  "kprobe__udp6_seq_show",
	"kprobe/udp_lib_get_port":         "kprobe__udp_lib_get_port",
	"kretprobe/udp_lib_get_port":      "kretprobe__udp_lib_get_port",
}

func newManager(tcpClosedHandler *ebpf.PerfHandler, udpClosedHandler *ebpf.PerfHandler) *manager.Manager {
	mgr := &manager.Manager{
		Maps: []*manager.Map{
			{Name: openSocksName},
			{Name: boundPortsMap},
			{Name: inoToPIDMap},

			{Name: tcpFlowsMapName},
			{Name: tcpSockStatsMapName},
			{Name: "inet_csk_listen_start_args"},
			{Name: "inet_csk_accept_args"},
			{Name: "tcp_sendmsg_args"},
			{Name: "tcp_sendpage_args"},

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
			{ProbeIdentificationPair: pip("kprobe/tcp_init_sock")},
			{ProbeIdentificationPair: pip("kprobe/security_sk_free")},
			{ProbeIdentificationPair: pip("kprobe/tcp_connect")},
			{ProbeIdentificationPair: pip("kprobe/inet_csk_listen_start")},
			{ProbeIdentificationPair: pip("kretprobe/inet_csk_listen_start"), KProbeMaxActive: maxActive},
			{ProbeIdentificationPair: pip("kprobe/inet_csk_accept")},
			{ProbeIdentificationPair: pip("kretprobe/inet_csk_accept"), KProbeMaxActive: maxActive},
			{ProbeIdentificationPair: pip("kprobe/tcp_sendmsg")},
			{ProbeIdentificationPair: pip("kretprobe/tcp_sendmsg"), KProbeMaxActive: maxActive},
			{ProbeIdentificationPair: pip("kprobe/tcp_sendpage")},
			{ProbeIdentificationPair: pip("kretprobe/tcp_sendpage"), KProbeMaxActive: maxActive},
			{ProbeIdentificationPair: pip("kprobe/tcp_cleanup_rbuf")},
			{ProbeIdentificationPair: pip("kprobe/tcp_retransmit_skb")},
			{ProbeIdentificationPair: pip("kprobe/tcp_set_state")},
			{ProbeIdentificationPair: pip(tcp4SeqShowProbe)},
			{ProbeIdentificationPair: pip(tcp6SeqShowProbe)},
			{ProbeIdentificationPair: pip(udp4SeqShowProbe)},
			{ProbeIdentificationPair: pip(udp6SeqShowProbe)},
			{ProbeIdentificationPair: pip("kprobe/udp_lib_get_port")},
			{ProbeIdentificationPair: pip("kretprobe/udp_lib_get_port"), KProbeMaxActive: maxActive},
			{ProbeIdentificationPair: pip("kprobe/udp_init_sock")},
			{ProbeIdentificationPair: pip("kprobe/ip_send_skb")},
			{ProbeIdentificationPair: pip("kprobe/ip6_send_skb")},
			{ProbeIdentificationPair: pip("kprobe/skb_consume_udp")},
		},
	}
	return mgr
}

func pip(section string) manager.ProbeIdentificationPair {
	return manager.ProbeIdentificationPair{
		EBPFSection:  section,
		EBPFFuncName: mainProbes[section],
	}
}
