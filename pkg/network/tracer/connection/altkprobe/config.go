//+build linux_bpf

package altkprobe

import (
	"github.com/DataDog/datadog-agent/pkg/network/config"
)

func enableProbe(enabled map[string]string, name string) {
	if fn, ok := mainProbes[name]; ok {
		enabled[name] = fn
		return
	}
}

func enabledProbes(c *config.Config) (map[string]string, error) {
	enabled := make(map[string]string, 0)

	if c.CollectTCPConns {
		enableProbe(enabled, "kprobe/tcp_init_sock")
		enableProbe(enabled, "kprobe/security_sk_free")
		enableProbe(enabled, "kprobe/tcp_connect")
		enableProbe(enabled, "kprobe/inet_csk_listen_start")
		enableProbe(enabled, "kretprobe/inet_csk_listen_start")
		enableProbe(enabled, "kprobe/inet_csk_accept")
		enableProbe(enabled, "kretprobe/inet_csk_accept")
		enableProbe(enabled, "kprobe/tcp_sendmsg")
		enableProbe(enabled, "kretprobe/tcp_sendmsg")
		enableProbe(enabled, "kprobe/tcp_sendpage")
		enableProbe(enabled, "kretprobe/tcp_sendpage")
		enableProbe(enabled, "kprobe/tcp_cleanup_rbuf")
		enableProbe(enabled, "kprobe/tcp_retransmit_skb")
		enableProbe(enabled, "kprobe/tcp_set_state")
		enableProbe(enabled, tcp4SeqShowProbe)

		if c.CollectIPv6Conns {
			enableProbe(enabled, tcp6SeqShowProbe)
		}
	}

	if c.CollectUDPConns {
		enableProbe(enabled, "kprobe/udp_init_sock")
		enableProbe(enabled, "kprobe/ip_send_skb")
		enableProbe(enabled, "kprobe/skb_consume_udp")
		enableProbe(enabled, "kprobe/udp_lib_get_port")
		enableProbe(enabled, "kretprobe/udp_lib_get_port")
		enableProbe(enabled, "kprobe/security_sk_free")
		enableProbe(enabled, udp4SeqShowProbe)

		if c.CollectIPv6Conns {
			enableProbe(enabled, "kprobe/ip6_send_skb")
			enableProbe(enabled, udp6SeqShowProbe)
		}
	}

	return enabled, nil
}
