//+build linux_bpf

package altkprobe

import (
	"github.com/DataDog/datadog-agent/pkg/network/config"
)

func enabledProbes(c *config.Config) (map[string]struct{}, error) {
	enabled := make(map[string]struct{}, 0)

	if c.CollectTCPConns {
		enabled["kprobe/tcp_init_sock"] = struct{}{}
		enabled["kprobe/security_sk_free"] = struct{}{}
		enabled["kprobe/tcp_connect"] = struct{}{}
		enabled["kprobe/inet_csk_listen_start"] = struct{}{}
		enabled["kretprobe/inet_csk_listen_start"] = struct{}{}
		enabled["kprobe/inet_csk_accept"] = struct{}{}
		enabled["kretprobe/inet_csk_accept"] = struct{}{}
		enabled["kprobe/tcp_sendmsg"] = struct{}{}
		enabled["kretprobe/tcp_sendmsg"] = struct{}{}
		enabled["kprobe/tcp_sendpage"] = struct{}{}
		enabled["kretprobe/tcp_sendpage"] = struct{}{}
		enabled["kprobe/tcp_cleanup_rbuf"] = struct{}{}
		enabled["kprobe/tcp_retransmit_skb"] = struct{}{}
		enabled["kprobe/tcp_set_state"] = struct{}{}
		enabled[tcp4SeqShowProbe] = struct{}{}

		if c.CollectIPv6Conns {
			enabled[tcp6SeqShowProbe] = struct{}{}
		}
	}

	if c.CollectUDPConns {
		enabled["kprobe/udp_init_sock"] = struct{}{}
		enabled["kprobe/ip_send_skb"] = struct{}{}
		enabled["kprobe/skb_consume_udp"] = struct{}{}
		enabled["kprobe/udp_lib_get_port"] = struct{}{}
		enabled["kretprobe/udp_lib_get_port"] = struct{}{}
		enabled["kprobe/security_sk_free"] = struct{}{}
		enabled[udp4SeqShowProbe] = struct{}{}

		if c.CollectIPv6Conns {
			enabled["kprobe/ip6_send_skb"] = struct{}{}
			enabled[udp6SeqShowProbe] = struct{}{}
		}
	}

	return enabled, nil
}
