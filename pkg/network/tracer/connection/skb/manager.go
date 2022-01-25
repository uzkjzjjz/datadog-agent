//  Unless explicitly stated otherwise all files in this repository are licensed
//  under the Apache License Version 2.0.
//  This product includes software developed at Datadog (https://www.datadoghq.com/).
//  Copyright 2016-present Datadog, Inc.

package skb

import (
	"os"

	"github.com/DataDog/datadog-agent/pkg/ebpf"
	manager "github.com/DataDog/ebpf-manager"
)

var mainProbes = map[string]string{
	// TCP/UDP recv
	"kprobe/security_sock_rcv_skb": "kprobe__security_sock_rcv_skb",
	// TCP/UDP send
	"tracepoint/net/net_dev_queue": "tracepoint__net_dev_queue",
	// UDP socket create
	"kprobe/udp_init_sock": "kprobe__udp_init_sock",
	// TCP/UDP socket destroy
	"kprobe/security_sk_free": "kprobe__security_sk_free",
	// TCP/UDP socket bind
	"kprobe/security_socket_bind": "kprobe__security_socket_bind",
}

func newManager(udpClosedFunc ebpf.PerfFunc) *manager.Manager {
	mgr := &manager.Manager{
		Maps: []*manager.Map{
			{Name: "open_socks"},
			{Name: "udp_stats"},
		},
		PerfMaps: []*manager.PerfMap{
			{
				Map: manager.Map{Name: "udp_close_event"},
				PerfMapOptions: manager.PerfMapOptions{
					PerfRingBufferSize: 8 * os.Getpagesize(),
					Watermark:          1,
					DataHandler:        udpClosedFunc,
					LostHandler:        nil,
				},
			},
		},
		Probes: []*manager.Probe{},
	}
	for k := range mainProbes {
		mgr.Probes = append(mgr.Probes, &manager.Probe{
			ProbeIdentificationPair: pip(k),
		})
	}

	return mgr
}

func pip(section string) manager.ProbeIdentificationPair {
	return manager.ProbeIdentificationPair{
		EBPFSection:  section,
		EBPFFuncName: mainProbes[section],
	}
}
