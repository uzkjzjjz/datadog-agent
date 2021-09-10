//+build linux_bpf

package altkprobe

import (
	"errors"
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

	tcpFlowsMapName      = "tcp_flows"
	tcpOpenSocksName     = "tcp_open_socks"
	udpOpenSocksName     = "udp_open_socks"
	udpStatsName         = "udp_stats"
	udpTuplesToSocksName = "udp_tuples_to_socks"
)

var _ connection.Tracer = &tracer{}

type tracer struct {
	m                *manager.Manager
	perfHandlerTCP   *ddebpf.PerfHandler
	perfHandlerUDP   *ddebpf.PerfHandler
	closedCh         chan network.ConnectionStats
	tcpFlows         *ebpf.Map
	tcpSocks         *ebpf.Map
	udpSocks         *ebpf.Map
	udpTuplesToSocks *ebpf.Map
	udpStats         *ebpf.Map
}

func New(config *config.Config) (connection.Tracer, error) {
	mgrOptions := manager.Options{
		RLimit: &unix.Rlimit{
			Cur: math.MaxUint64,
			Max: math.MaxUint64,
		},
		MapSpecEditors: map[string]manager.MapSpecEditor{
			tcpOpenSocksName:     {Type: ebpf.Hash, MaxEntries: uint32(config.MaxTrackedConnections), EditorFlag: manager.EditMaxEntries},
			tcpFlowsMapName:      {Type: ebpf.Hash, MaxEntries: uint32(config.MaxTrackedConnections), EditorFlag: manager.EditMaxEntries},
			udpOpenSocksName:     {Type: ebpf.Hash, MaxEntries: uint32(config.MaxTrackedConnections), EditorFlag: manager.EditMaxEntries},
			udpStatsName:         {Type: ebpf.Hash, MaxEntries: uint32(config.MaxTrackedConnections), EditorFlag: manager.EditMaxEntries},
			udpTuplesToSocksName: {Type: ebpf.Hash, MaxEntries: uint32(config.MaxTrackedConnections), EditorFlag: manager.EditMaxEntries},
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
	perfHandlerUDP := ddebpf.NewPerfHandler(closedChannelSize)
	m := newManager(perfHandlerTCP, perfHandlerUDP)

	enabledProbes, err := enabledProbes(config)
	if err != nil {
		return nil, fmt.Errorf("invalid probe configuration: %v", err)
	}
	// exclude all non-enabled probes to ensure we don't run into problems with unsupported probe types
	for _, p := range m.Probes {
		if _, enabled := enabledProbes[p.Section]; !enabled {
			mgrOptions.ExcludedSections = append(mgrOptions.ExcludedSections, p.Section)
		}
	}
	for probeName := range enabledProbes {
		mgrOptions.ActivatedProbes = append(
			mgrOptions.ActivatedProbes,
			&manager.ProbeSelector{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					Section: probeName,
				},
			})
	}

	err = m.InitWithOptions(buf, mgrOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to init ebpf manager: %v", err)
	}

	tr := &tracer{
		m:              m,
		perfHandlerTCP: perfHandlerTCP,
		perfHandlerUDP: perfHandlerUDP,
	}

	tr.tcpFlows, _, err = m.GetMap(tcpFlowsMapName)
	if err != nil {
		tr.Stop()
		return nil, fmt.Errorf("error retrieving the bpf %s map: %s", tcpFlowsMapName, err)
	}

	tr.tcpSocks, _, err = m.GetMap(tcpOpenSocksName)
	if err != nil {
		tr.Stop()
		return nil, fmt.Errorf("error retrieving the bpf %s map: %s", tcpOpenSocksName, err)
	}

	tr.udpSocks, _, err = m.GetMap(udpOpenSocksName)
	if err != nil {
		tr.Stop()
		return nil, fmt.Errorf("error retrieving the bpf %s map: %s", udpOpenSocksName, err)
	}

	tr.udpTuplesToSocks, _, err = m.GetMap(udpTuplesToSocksName)
	if err != nil {
		tr.Stop()
		return nil, fmt.Errorf("error retrieving the bpf %s map: %s", udpTuplesToSocksName, err)
	}

	tr.udpStats, _, err = m.GetMap(udpStatsName)
	if err != nil {
		tr.Stop()
		return nil, fmt.Errorf("error retrieving the bpf %s map: %s", udpStatsName, err)
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
	t.perfHandlerTCP.Stop()
	t.perfHandlerUDP.Stop()
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
	key, flow, skinfo := uint64(0), &netebpf.TCPFlow{}, &netebpf.SocketInfo{}
	entries := t.tcpFlows.IterateFrom(unsafe.Pointer(&key))
	for entries.Next(unsafe.Pointer(&key), unsafe.Pointer(flow)) {
		err := t.tcpSocks.Lookup(unsafe.Pointer(&key), unsafe.Pointer(skinfo))
		if err != nil {
			continue
		}

		conn := toConn(key, &flow.Tup, &flow.Stats, skinfo)
		if filter != nil && filter(&conn) {
			buffer = append(buffer, conn)
		}
	}
	if err := entries.Err(); err != nil {
		return nil, fmt.Errorf("unable to iterate tcp connection map: %s", err)
	}

	sk, tup, stats := uint64(0), netebpf.Tuple{}, netebpf.FlowStats{}
	entries = t.udpStats.IterateFrom(unsafe.Pointer(&tup))
	for entries.Next(unsafe.Pointer(&tup), unsafe.Pointer(&stats)) {
		err := t.udpTuplesToSocks.Lookup(unsafe.Pointer(&tup), unsafe.Pointer(&sk))
		if err != nil {
			continue
		}
		// TODO this seems unnecessary, simplify
		err = t.udpSocks.Lookup(unsafe.Pointer(&sk), unsafe.Pointer(skinfo))
		if err != nil {
			continue
		}

		conn := toConn(sk, &tup, &stats, skinfo)
		if filter != nil && filter(&conn) {
			buffer = append(buffer, conn)
		}
	}
	if err := entries.Err(); err != nil {
		return nil, fmt.Errorf("unable to iterate udp connection map: %s", err)
	}

	return buffer, nil
}

func (t *tracer) FlushPending() []network.ConnectionStats {
	// TODO implement
	return nil
}

func (t *tracer) Remove(conn *network.ConnectionStats) error {
	if conn.Type == network.TCP {
		if err := t.tcpSocks.Delete(unsafe.Pointer(&conn.ID)); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
		if err := t.tcpFlows.Delete(unsafe.Pointer(&conn.ID)); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
	} else if conn.Type == network.UDP {
		if err := t.udpSocks.Delete(unsafe.Pointer(&conn.ID)); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
		tup := netebpf.Tuple{
			Sport:    conn.SPort,
			Dport:    conn.DPort,
			Protocol: syscall.IPPROTO_UDP,
		}
		copy(tup.Saddr[:], conn.Source.Bytes())
		copy(tup.Daddr[:], conn.Dest.Bytes())
		if conn.Family == network.AFINET {
			tup.Family = syscall.AF_INET
		} else if conn.Family == network.AFINET6 {
			tup.Family = syscall.AF_INET6
		}

		if err := t.udpStats.Delete(unsafe.Pointer(&tup)); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
		if err := t.udpTuplesToSocks.Delete(unsafe.Pointer(&tup)); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
	}
	return nil
}

func (t *tracer) GetTelemetry() map[string]int64 {
	return map[string]int64{}
}

func (t *tracer) GetMap(_ string) *ebpf.Map {
	return nil
}

func toTCPEvent(b []byte) *netebpf.TCPCloseEvent {
	return (*netebpf.TCPCloseEvent)(unsafe.Pointer(&b[0]))
}

func toUDPEvent(b []byte) *netebpf.UDPCloseEvent {
	return (*netebpf.UDPCloseEvent)(unsafe.Pointer(&b[0]))
}

func toConn(key uint64, tuple *netebpf.Tuple, stats *netebpf.FlowStats, skinfo *netebpf.SocketInfo) network.ConnectionStats {
	conn := network.ConnectionStats{
		ID:                      key,
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

	if conn.Family == network.AFINET {
		conn.Source = util.V4AddressFromBytes(tuple.Saddr[:net.IPv4len])
		conn.Dest = util.V4AddressFromBytes(tuple.Daddr[:net.IPv4len])
	} else {
		conn.Source = util.V6AddressFromBytes(tuple.Saddr[:])
		conn.Dest = util.V6AddressFromBytes(tuple.Daddr[:])
	}

	return conn
}

func (t *tracer) initPerfPolling() error {
	go func() {
		for {
			select {
			case eventData, ok := <-t.perfHandlerTCP.DataChannel:
				if !ok {
					return
				}
				//atomic.AddInt64(&t.perfReceived, 1)
				evt := toTCPEvent(eventData.Data)
				c := toConn(evt.Skp, &evt.Flow.Tup, &evt.Flow.Stats, &evt.Skinfo)
				log.Debugf("closed tcp conn: %x %s", evt.Skp, c)
				t.closedCh <- c
			case _, ok := <-t.perfHandlerTCP.LostChannel:
				if !ok {
					return
				}
				//atomic.AddInt64(&t.perfLost, int64(lostCount))

			case eventData, ok := <-t.perfHandlerUDP.DataChannel:
				if !ok {
					return
				}
				//atomic.AddInt64(&t.perfReceived, 1)
				evt := toUDPEvent(eventData.Data)
				tups, err := t.findUDPTuplesFromSock(evt.Skp)
				if err != nil {
					log.Warnf("error finding udp tuples from sk: %s", err)
					return
				}
				for _, tp := range tups {
					st := netebpf.FlowStats{}
					if err := t.udpStats.Lookup(unsafe.Pointer(&tp), unsafe.Pointer(&st)); err != nil {
						continue
					}
					c := toConn(evt.Skp, &tp, &st, &evt.Skinfo)
					log.Debugf("closed udp conn: %x %s", evt.Skp, c)
					t.closedCh <- c
				}

			case _, ok := <-t.perfHandlerUDP.LostChannel:
				if !ok {
					return
				}
				//atomic.AddInt64(&t.perfLost, int64(lostCount))
			}
		}
	}()

	return nil
}

func (t *tracer) findUDPTuplesFromSock(sk uint64) ([]netebpf.Tuple, error) {
	tp, entrySk := netebpf.Tuple{}, uint64(0)
	entries := t.udpStats.IterateFrom(unsafe.Pointer(&tp))

	var tuples []netebpf.Tuple
	for entries.Next(unsafe.Pointer(&tp), unsafe.Pointer(&entrySk)) {
		if sk == entrySk {
			tuples = append(tuples, tp)
		}
	}
	if err := entries.Err(); err != nil {
		return nil, err
	}
	return tuples, nil
}
