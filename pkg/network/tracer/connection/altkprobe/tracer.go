//+build linux_bpf

package altkprobe

import (
	"fmt"
	"math"
	"net"
	"syscall"
	"unsafe"

	ddebpf "github.com/DataDog/datadog-agent/pkg/ebpf"
	"github.com/DataDog/datadog-agent/pkg/util/log"

	"github.com/DataDog/datadog-agent/pkg/network"
	"github.com/DataDog/datadog-agent/pkg/network/config"
	netebpf "github.com/DataDog/datadog-agent/pkg/network/ebpf"
	"github.com/DataDog/datadog-agent/pkg/network/tracer/connection"
	"github.com/DataDog/datadog-agent/pkg/process/util"
	"github.com/DataDog/ebpf"
	"github.com/DataDog/ebpf/manager"
	"golang.org/x/sys/unix"
)

const (
	defaultClosedChannelSize = 500
)

var _ connection.Tracer = &tracer{}

type tracer struct {
	m           *manager.Manager
	perfHandler *ddebpf.PerfHandler
	closedCh    chan network.ConnectionStats
	conns       *ebpf.Map
	socks       *ebpf.Map
}

func New(config *config.Config) (connection.Tracer, error) {
	mgrOptions := manager.Options{
		RLimit: &unix.Rlimit{
			Cur: math.MaxUint64,
			Max: math.MaxUint64,
		},
		MapSpecEditors: map[string]manager.MapSpecEditor{
			"tcp_open_socks": {Type: ebpf.Hash, MaxEntries: uint32(config.MaxTrackedConnections), EditorFlag: manager.EditMaxEntries},
			"tuples":         {Type: ebpf.Hash, MaxEntries: uint32(config.MaxTrackedConnections), EditorFlag: manager.EditMaxEntries},
		},
	}

	buf, err := getRuntimeCompiledAlttracer(config)
	if err != nil {
		return nil, err
	}

	closedChannelSize := defaultClosedChannelSize
	if config.ClosedChannelSize > 0 {
		closedChannelSize = config.ClosedChannelSize
	}
	perfHandlerTCP := ddebpf.NewPerfHandler(closedChannelSize)
	m := newManager(perfHandlerTCP)
	err = m.InitWithOptions(buf, mgrOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to init ebpf manager: %v", err)
	}

	tr := &tracer{
		m:           m,
		perfHandler: perfHandlerTCP,
	}

	tr.conns, _, err = m.GetMap("tuples")
	if err != nil {
		tr.Stop()
		return nil, fmt.Errorf("error retrieving the bpf %s map: %s", "tuples", err)
	}

	tr.socks, _, err = m.GetMap("tcp_open_socks")
	if err != nil {
		tr.Stop()
		return nil, fmt.Errorf("error retrieving the bpf %s map: %s", "tcp_open_socks", err)
	}

	if err = tr.initPerfPolling(); err != nil {
		tr.Stop()
		return nil, fmt.Errorf("error starting perf event polling: %s", err)
	}

	return tr, nil
}

func (t *tracer) Start() (<-chan network.ConnectionStats, error) {
	t.closedCh = make(chan network.ConnectionStats)
	if err := t.m.Start(); err != nil {
		return nil, fmt.Errorf("could not start ebpf manager: %s", err)
	}
	return t.closedCh, nil
}

func (t *tracer) Stop() {
	_ = t.m.Stop(manager.CleanAll)
	t.perfHandler.Stop()
	if t.closedCh != nil {
		close(t.closedCh)
	}
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

func (t *tracer) GetConnections(buffer []network.ConnectionStats, filter func(*network.ConnectionStats) bool) ([]network.ConnectionStats, error) {
	// Iterate through all key-value pairs in map
	key, stats, skinfo := uint64(0), &netebpf.Tuple{}, &netebpf.TCPSocketInfo{}
	entries := t.conns.IterateFrom(unsafe.Pointer(&key))
	for entries.Next(unsafe.Pointer(&key), unsafe.Pointer(stats)) {
		err := t.socks.Lookup(unsafe.Pointer(&key), unsafe.Pointer(skinfo))
		if err != nil {
			continue
		}

		conn := toConn(key, stats, skinfo)
		if filter != nil && filter(&conn) {
			buffer = append(buffer, conn)
		}
	}

	if err := entries.Err(); err != nil {
		return nil, fmt.Errorf("unable to iterate connection map: %s", err)
	}

	return buffer, nil
}

func (t *tracer) FlushPending() []network.ConnectionStats {
	// TODO implement
	return nil
}

func (t *tracer) Remove(conn *network.ConnectionStats) error {
	err := t.socks.Delete(unsafe.Pointer(&conn.ID))
	if err != nil {
		return err
	}
	return t.conns.Delete(unsafe.Pointer(&conn.ID))
}

func (t *tracer) GetTelemetry() map[string]int64 {
	return map[string]int64{}
}

func (t *tracer) GetMap(s string) *ebpf.Map {
	return nil
}

func toEvent(b []byte) *netebpf.ConnEvent {
	return (*netebpf.ConnEvent)(unsafe.Pointer(&b[0]))
}

func toConn(key uint64, stats *netebpf.Tuple, skinfo *netebpf.TCPSocketInfo) network.ConnectionStats {
	conn := network.ConnectionStats{
		ID:                      key,
		Pid:                     skinfo.Tgid,
		NetNS:                   skinfo.Netns,
		LastUpdateEpoch:         skinfo.Ns,
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
		SPort:                   stats.Sport,
		DPort:                   stats.Dport,
		Type:                    connType(stats.Protocol),
		Family:                  connFamily(stats.Family),
		IsAssured:               false,
	}

	if conn.Family == network.AFINET {
		conn.Source = util.V4AddressFromBytes(stats.Saddr[:net.IPv4len])
		conn.Dest = util.V4AddressFromBytes(stats.Daddr[:net.IPv4len])
	} else {
		conn.Source = util.V6AddressFromBytes(stats.Saddr[:])
		conn.Dest = util.V6AddressFromBytes(stats.Daddr[:])
	}

	return conn
}

func (t *tracer) initPerfPolling() error {
	go func() {
		for {
			select {
			case batchData, ok := <-t.perfHandler.DataChannel:
				if !ok {
					return
				}
				//atomic.AddInt64(&t.perfReceived, 1)
				evt := toEvent(batchData.Data)
				c := toConn(evt.Skp, &evt.Tup, &evt.Skinfo)
				log.Debugf("closed conn: %x %s", evt.Skp, c)
				t.closedCh <- c
			case _, ok := <-t.perfHandler.LostChannel:
				if !ok {
					return
				}
				//atomic.AddInt64(&t.perfLost, int64(lostCount))
			}
		}
	}()

	return nil
}
