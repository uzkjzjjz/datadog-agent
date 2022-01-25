//  Unless explicitly stated otherwise all files in this repository are licensed
//  under the Apache License Version 2.0.
//  This product includes software developed at Datadog (https://www.datadoghq.com/).
//  Copyright 2016-present Datadog, Inc.

package skb

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"github.com/DataDog/datadog-agent/pkg/util/log"

	"github.com/DataDog/datadog-agent/pkg/network"
	"github.com/DataDog/datadog-agent/pkg/network/config"
	netebpf "github.com/DataDog/datadog-agent/pkg/network/ebpf"
	"github.com/DataDog/datadog-agent/pkg/network/tracer/connection"
	"github.com/DataDog/datadog-agent/pkg/process/util"
	manager "github.com/DataDog/ebpf-manager"
	"github.com/cilium/ebpf"
)

var _ connection.Tracer = &tracer{}

type tracer struct {
	m        *manager.Manager
	callback func([]network.ConnectionStats)

	udpStatsMap  *ebpf.Map
	openSocksMap *ebpf.Map

	cfg *config.Config
}

func New(cfg *config.Config) (connection.Tracer, error) {
	buf, err := getRuntimeCompiledSKBTracer(cfg)
	if err != nil {
		return nil, err
	}

	tr := &tracer{
		cfg: cfg,
	}
	tr.m, err = newManager(cfg, buf, tr.udpClosed)
	if err != nil {
		return nil, fmt.Errorf("failed to init ebpf manager: %w", err)
	}

	if cfg.CollectUDPConns {
		tr.udpStatsMap, _, err = tr.m.GetMap("udp_stats")
		if err != nil {
			_ = tr.m.Stop(manager.CleanAll)
			return nil, fmt.Errorf("unable to find udp_stats map: %w", err)
		}
	}

	tr.openSocksMap, _, err = tr.m.GetMap("open_socks")
	if err != nil {
		_ = tr.m.Stop(manager.CleanAll)
		return nil, fmt.Errorf("unable to find open_socks map: %w", err)
	}

	return tr, nil
}

func (t *tracer) Start(callback func([]network.ConnectionStats)) error {
	t.callback = callback
	if err := t.m.Start(); err != nil {
		return fmt.Errorf("could not start ebpf manager: %s", err)
	}
	return nil
}

func (t *tracer) Stop() {
	_ = t.m.Stop(manager.CleanAll)
}

func (t *tracer) GetConnections(buffer *network.ConnectionBuffer, filter func(*network.ConnectionStats) bool) error {
	flow, stats, skinfo := &netebpf.UDPFlow{}, &netebpf.FlowStats{}, &netebpf.SocketInfo{}
	if t.udpStatsMap != nil {
		entries := t.udpStatsMap.Iterate()
		for entries.Next(unsafe.Pointer(flow), unsafe.Pointer(stats)) {
			if err := t.openSocksMap.Lookup(unsafe.Pointer(&flow.Sk), unsafe.Pointer(skinfo)); err != nil {
				log.Warnf("error looking up open sock %x: %s", flow.Sk, err)
				continue
			}

			c := toConn(flow.Sk, &flow.Tup, skinfo, stats)
			if filter != nil && filter(&c) {
				*buffer.Next() = c
			}
		}
		if err := entries.Err(); err != nil {
			return err
		}
	}

	return nil
}

func (t *tracer) FlushPending() {
}

func (t *tracer) Remove(conn *network.ConnectionStats) error {
	if conn.Type == network.UDP {
		flow := netebpf.UDPFlow{
			Sk: conn.ID,
			Tup: netebpf.Tuple{
				Sport:    conn.SPort,
				Dport:    conn.DPort,
				Family:   conn.Family.SyscallType(),
				Protocol: syscall.IPPROTO_UDP,
			},
		}
		copy(flow.Tup.Saddr.U[:], conn.Source.Bytes())
		copy(flow.Tup.Daddr.U[:], conn.Dest.Bytes())

		return t.udpStatsMap.Delete(unsafe.Pointer(&flow))
	}

	return nil
}

func (t *tracer) GetTelemetry() map[string]int64 {
	return nil
}

func (t *tracer) GetMap(_ string) *ebpf.Map {
	return nil
}

func (t *tracer) DumpMaps(_ ...string) (string, error) {
	return "", nil
}

func (t *tracer) udpClosed(_ int, data []byte, _ *manager.PerfMap, _ *manager.Manager) {
	evt := (*netebpf.UDPCloseEvent)(unsafe.Pointer(&data[0]))
	log.Debugf("UDP closed event: sk=%x", evt.Sk)

	flow, stats := &netebpf.UDPFlow{}, &netebpf.FlowStats{}
	conns := make([]network.ConnectionStats, 0, 1)
	flows := make([]netebpf.UDPFlow, 0, 1)
	entries := t.udpStatsMap.Iterate()
	for entries.Next(unsafe.Pointer(flow), unsafe.Pointer(stats)) {
		// TODO improve this so we don't have to iterate to find matching flows for the socket
		if flow.Sk == evt.Sk {
			c := toConn(flow.Sk, &flow.Tup, &evt.Skinfo, stats)
			log.Debugf("UDP closed conn: %s", c)
			conns = append(conns, c)
			// do not delete here, since we don't want to delete while iterating
			flows = append(flows, *flow)
		}
	}
	if entries.Err() != nil {
		log.Warnf("error iterating over UDP flows: %w", entries.Err())
		return
	}
	if len(conns) > 0 {
		for _, f := range flows {
			if err := t.udpStatsMap.Delete(unsafe.Pointer(&f)); err != nil {
				log.Warnf("error deleting UDP flow from eBPF map: %w", err)
			}
		}
		t.callback(conns)
	}
}

func toConn(sk uint64, tuple *netebpf.Tuple, skinfo *netebpf.SocketInfo, stats *netebpf.FlowStats) network.ConnectionStats {
	conn := network.ConnectionStats{
		ID:                      sk,
		Pid:                     skinfo.Tgid,
		NetNS:                   skinfo.Netns,
		LastUpdateEpoch:         stats.Last_update,
		Direction:               network.ConnectionDirection(skinfo.Direction),
		MonotonicSentBytes:      stats.Sent_bytes,
		MonotonicRecvBytes:      stats.Recv_bytes,
		MonotonicSentPackets:    0,
		MonotonicRecvPackets:    0,
		MonotonicRetransmits:    0,
		RTT:                     0,
		RTTVar:                  0,
		MonotonicTCPEstablished: 0,
		MonotonicTCPClosed:      0,
		SPort:                   tuple.Sport,
		DPort:                   tuple.Dport,
		Type:                    connType(tuple.Protocol),
		Family:                  connFamily(tuple.Family),
		IsAssured:               false,
	}

	//if tcpStats != nil {
	//	conn.MonotonicRetransmits = tcpStats.Retransmits
	//	conn.RTT = tcpStats.Rtt
	//	conn.RTTVar = tcpStats.Rtt_var
	//	conn.MonotonicTCPEstablished = uint32(tcpStats.State_transitions >> netebpf.Established & 1)
	//	conn.MonotonicTCPClosed = uint32(tcpStats.State_transitions >> netebpf.Close & 1)
	//}

	if conn.Family == network.AFINET {
		conn.Source = util.V4AddressFromBytes(tuple.Saddr.U[:net.IPv4len])
		conn.Dest = util.V4AddressFromBytes(tuple.Daddr.U[:net.IPv4len])
	} else {
		conn.Source = util.V6AddressFromBytes(tuple.Saddr.U[:])
		conn.Dest = util.V6AddressFromBytes(tuple.Daddr.U[:])
	}

	return conn
}

func connType(proto uint8) network.ConnectionType {
	switch proto {
	case syscall.IPPROTO_TCP:
		return network.TCP
	case syscall.IPPROTO_UDP:
		return network.UDP
	default:
		return network.TCP
	}
}

func connFamily(family uint8) network.ConnectionFamily {
	switch family {
	case syscall.AF_INET:
		return network.AFINET
	case syscall.AF_INET6:
		return network.AFINET6
	default:
		return network.AFINET
	}
}
