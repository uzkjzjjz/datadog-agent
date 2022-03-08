//  Unless explicitly stated otherwise all files in this repository are licensed
//  under the Apache License Version 2.0.
//  This product includes software developed at Datadog (https://www.datadoghq.com/).
//  Copyright 2016-present Datadog, Inc.

package skb

import "github.com/DataDog/datadog-agent/pkg/network/config"

func enableProbe(enabled map[string]string, name string) {
	if fn, ok := mainProbes[name]; ok {
		enabled[name] = fn
		return
	}
	if fn, ok := returnProbes[name]; ok {
		enabled[name] = fn
		return
	}
}

func enabledProbes(c *config.Config) (map[string]string, error) {
	enabled := make(map[string]string, 0)
	enableProbe(enabled, "kprobe/security_sock_rcv_skb")
	enableProbe(enabled, "tracepoint/net/net_dev_queue")
	enableProbe(enabled, "tracepoint/net/net_dev_xmit")
	enableProbe(enabled, "kprobe/security_sk_free")

	if c.CollectUDPConns {
		enableProbe(enabled, "kprobe/udp_init_sock")
	}
	if c.CollectTCPConns {
		enableProbe(enabled, "kprobe/tcp_init_sock")
		enableProbe(enabled, "kprobe/tcp_connect")
		enableProbe(enabled, "kretprobe/inet_csk_accept")
		enableProbe(enabled, "kprobe/tcp_retransmit_skb")
		enableProbe(enabled, "kprobe/tcp_set_state")
	}

	return enabled, nil
}
