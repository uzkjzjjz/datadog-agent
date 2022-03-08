//  Unless explicitly stated otherwise all files in this repository are licensed
//  under the Apache License Version 2.0.
//  This product includes software developed at Datadog (https://www.datadoghq.com/).
//  Copyright 2016-present Datadog, Inc.

package skb

import (
	"fmt"
	"io"
	"math"
	"os"

	"github.com/DataDog/datadog-agent/pkg/ebpf"
	"github.com/DataDog/datadog-agent/pkg/network/config"
	manager "github.com/DataDog/ebpf-manager"
	"golang.org/x/sys/unix"
)

const (
	// maxActive configures the maximum number of instances of the kretprobe-probed functions handled simultaneously.
	// This value should be enough for typical workloads (e.g. some amount of processes blocked on the `accept` syscall).
	maxActive = 128
)

var mainProbes = map[string]string{
	// TCP/UDP recv
	"kprobe/security_sock_rcv_skb": "kprobe__security_sock_rcv_skb",
	// TCP/UDP send
	"tracepoint/net/net_dev_queue": "tracepoint__net_dev_queue",
	// TCP/UDP socket destroy
	"kprobe/security_sk_free": "kprobe__security_sk_free",
	// UDP socket create
	"kprobe/udp_init_sock": "kprobe__udp_init_sock",
	// TCP socket create
	"kprobe/tcp_init_sock": "kprobe__tcp_init_sock",
	// TCP outgoing socket labeling
	"kprobe/tcp_connect": "kprobe__tcp_connect",
	// TCP retransmit notification
	"kprobe/tcp_retransmit_skb": "kprobe__tcp_retransmit_skb",
	// TCP state change
	"kprobe/tcp_set_state": "kprobe__tcp_set_state",
}

var returnProbes = map[string]string{
	// TCP incoming socket labeling
	"kretprobe/inet_csk_accept": "kretprobe__inet_csk_accept",
}

func newManager(cfg *config.Config, buf io.ReaderAt, udpClosedFunc, tcpClosedFunc ebpf.PerfFunc) (*manager.Manager, error) {
	mgr := &manager.Manager{
		Maps: []*manager.Map{
			{Name: "open_socks"},
		},
		PerfMaps: []*manager.PerfMap{},
		Probes:   []*manager.Probe{},
	}

	if cfg.CollectUDPConns {
		mgr.Maps = append(mgr.Maps, &manager.Map{Name: "udp_stats"})
		mgr.PerfMaps = append(mgr.PerfMaps, &manager.PerfMap{
			Map: manager.Map{Name: "udp_close_event"},
			PerfMapOptions: manager.PerfMapOptions{
				PerfRingBufferSize: 8 * os.Getpagesize(),
				Watermark:          1,
				DataHandler:        udpClosedFunc,
				LostHandler:        nil,
			},
		})
	}
	if cfg.CollectTCPConns {
		mgr.Maps = append(mgr.Maps, &manager.Map{Name: "tcp_stats"})
		mgr.PerfMaps = append(mgr.PerfMaps, &manager.PerfMap{
			Map: manager.Map{Name: "tcp_close_event"},
			PerfMapOptions: manager.PerfMapOptions{
				PerfRingBufferSize: 8 * os.Getpagesize(),
				Watermark:          1,
				DataHandler:        tcpClosedFunc,
				LostHandler:        nil,
			},
		})
	}

	mgrOptions := manager.Options{
		RLimit: &unix.Rlimit{
			Cur: math.MaxUint64,
			Max: math.MaxUint64,
		},
		MapSpecEditors: map[string]manager.MapSpecEditor{},
	}
	err := configProbes(cfg, mgr, &mgrOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to configure probes: %w", err)
	}

	err = mgr.InitWithOptions(buf, mgrOptions)
	if err != nil {
		return nil, err
	}
	return mgr, nil
}

func kprobePip(section string) (manager.ProbeIdentificationPair, bool) {
	if fn, ok := mainProbes[section]; ok {
		return manager.ProbeIdentificationPair{
			EBPFSection:  section,
			EBPFFuncName: fn,
		}, true
	}
	return manager.ProbeIdentificationPair{}, false
}

func kretprobePip(section string) (manager.ProbeIdentificationPair, bool) {
	if fn, ok := returnProbes[section]; ok {
		return manager.ProbeIdentificationPair{
			EBPFSection:  section,
			EBPFFuncName: fn,
		}, true
	}
	return manager.ProbeIdentificationPair{}, false
}

func configProbes(cfg *config.Config, m *manager.Manager, mgrOptions *manager.Options) error {
	for k := range mainProbes {
		if pi, ok := kprobePip(k); ok {
			m.Probes = append(m.Probes, &manager.Probe{
				ProbeIdentificationPair: pi,
			})
		} else {
			return fmt.Errorf("no kprobe function name available for section %s", k)
		}
	}
	for k := range returnProbes {
		if pi, ok := kretprobePip(k); ok {
			m.Probes = append(m.Probes, &manager.Probe{
				ProbeIdentificationPair: pi,
				KProbeMaxActive:         maxActive,
			})
		} else {
			return fmt.Errorf("no kretprobe function name available for section %s", k)
		}
	}

	enabledProbes, err := enabledProbes(cfg)
	if err != nil {
		return fmt.Errorf("invalid probe configuration: %v", err)
	}
	// exclude all non-enabled probes to ensure we don't run into problems with unsupported probe types
	for _, p := range m.Probes {
		if _, enabled := enabledProbes[p.EBPFSection]; !enabled {
			mgrOptions.ExcludedFunctions = append(mgrOptions.ExcludedFunctions, p.EBPFFuncName)
		}
	}
	for probeName, funcName := range enabledProbes {
		mgrOptions.ActivatedProbes = append(
			mgrOptions.ActivatedProbes,
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFSection:  probeName,
					EBPFFuncName: funcName,
				},
			})
	}
	return nil
}
