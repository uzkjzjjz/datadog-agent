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
	"github.com/DataDog/datadog-agent/pkg/ebpf/bytecode/runtime"
	"github.com/DataDog/datadog-agent/pkg/network"
	"github.com/DataDog/datadog-agent/pkg/network/config"
	netebpf "github.com/DataDog/datadog-agent/pkg/network/ebpf"
	"github.com/DataDog/datadog-agent/pkg/network/tracer/connection"
	"github.com/DataDog/datadog-agent/pkg/process/util"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/DataDog/ebpf"
	"github.com/DataDog/ebpf/manager"
	"golang.org/x/sys/unix"
)

const (
	defaultClosedChannelSize = 500

	tcpFlowsMapName      = "tcp_flows"
	tcpSockStatsMapName  = "tcp_sock_stats"
	openSocksName        = "open_socks"
	udpStatsName         = "udp_stats"
	udpTuplesToSocksName = "udp_tuples_to_socks"

	boundPortsMap = "seq_listen_ports"
	inoToPIDMap   = "ino_to_pid"

	tcp4SeqShowProbe = "kprobe/tcp4_seq_show"
	tcp6SeqShowProbe = "kprobe/tcp6_seq_show"
	udp4SeqShowProbe = "kprobe/udp4_seq_show"
	udp6SeqShowProbe = "kprobe/udp6_seq_show"
)

var _ connection.Tracer = &tracer{}

type tracer struct {
	m              *manager.Manager
	perfHandlerTCP *ddebpf.PerfHandler
	perfHandlerUDP *ddebpf.PerfHandler
	closedCh       chan network.ConnectionStats
	tcpFlowsMap    *ebpf.Map
	socks          *ebpf.Map
	sockStats      *ebpf.Map
	udpStats       *ebpf.Map
	inoToPID       *ebpf.Map

	// TODO max size on these maps?
	// map from struct sock * to tgid(s), so we can craft a flow key
	tcpFlows map[uint64][]uint32
	// map from struct sock * to tuples
	udpTuples map[uint64][]netebpf.Tuple

	cfg *config.Config
}

func New(cfg *config.Config) (connection.Tracer, error) {
	runtime.RuntimeCompilationEnabled = true
	mgrOptions := manager.Options{
		RLimit: &unix.Rlimit{
			Cur: math.MaxUint64,
			Max: math.MaxUint64,
		},
		MapSpecEditors: map[string]manager.MapSpecEditor{
			openSocksName:        {Type: ebpf.Hash, MaxEntries: uint32(cfg.MaxTrackedConnections), EditorFlag: manager.EditMaxEntries},
			tcpSockStatsMapName:  {Type: ebpf.Hash, MaxEntries: uint32(cfg.MaxTrackedConnections), EditorFlag: manager.EditMaxEntries},
			tcpFlowsMapName:      {Type: ebpf.Hash, MaxEntries: uint32(cfg.MaxTrackedConnections), EditorFlag: manager.EditMaxEntries},
			udpStatsName:         {Type: ebpf.Hash, MaxEntries: uint32(cfg.MaxTrackedConnections), EditorFlag: manager.EditMaxEntries},
			udpTuplesToSocksName: {Type: ebpf.Hash, MaxEntries: uint32(cfg.MaxTrackedConnections), EditorFlag: manager.EditMaxEntries},
		},
	}

	buf, err := getRuntimeCompiledAlttracer(cfg)
	if err != nil {
		return nil, err
	}

	closedChannelSize := defaultClosedChannelSize
	if cfg.ClosedChannelSize > 0 {
		closedChannelSize = cfg.ClosedChannelSize
	}
	perfHandlerTCP := ddebpf.NewPerfHandler(closedChannelSize)
	perfHandlerUDP := ddebpf.NewPerfHandler(closedChannelSize)
	m := newManager(perfHandlerTCP, perfHandlerUDP)

	enabledProbes, err := enabledProbes(cfg)
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
		cfg:            cfg,
		tcpFlows:       map[uint64][]uint32{},
		udpTuples:      map[uint64][]netebpf.Tuple{},
	}

	tr.tcpFlowsMap, _, err = m.GetMap(tcpFlowsMapName)
	if err != nil {
		tr.Stop()
		return nil, fmt.Errorf("error retrieving the bpf %s map: %s", tcpFlowsMapName, err)
	}

	tr.socks, _, err = m.GetMap(openSocksName)
	if err != nil {
		tr.Stop()
		return nil, fmt.Errorf("error retrieving the bpf %s map: %s", openSocksName, err)
	}

	tr.socks, _, err = m.GetMap(tcpSockStatsMapName)
	if err != nil {
		tr.Stop()
		return nil, fmt.Errorf("error retrieving the bpf %s map: %s", tcpSockStatsMapName, err)
	}

	tr.udpStats, _, err = m.GetMap(udpStatsName)
	if err != nil {
		tr.Stop()
		return nil, fmt.Errorf("error retrieving the bpf %s map: %s", udpStatsName, err)
	}

	tr.inoToPID, _, err = m.GetMap(inoToPIDMap)
	if err != nil {
		tr.Stop()
		return nil, fmt.Errorf("error retrieving the bpf %s map: %s", inoToPIDMap, err)
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
	go t.getExistingSockets()
	return t.closedCh, nil
}

func (t *tracer) Stop() {
	_ = t.m.Stop(manager.CleanAll)
	t.perfHandlerTCP.Stop()
	t.perfHandlerUDP.Stop()
	if t.closedCh != nil {
		close(t.closedCh)
	}
	t.tcpFlows = map[uint64][]uint32{}
	t.udpTuples = map[uint64][]netebpf.Tuple{}
}

func (t *tracer) getExistingSockets() {
	err := t.walkProcFds()
	if err != nil {
		log.Warnf("error walking existing process fds to create ino-to-pid mapping: %s", err)
		return
	}

	err = walkProcNets(t.cfg)
	if err != nil {
		log.Warnf("error walking existing processes to read existing sockets: %s", err)
		return
	}

	probes := []string{tcp4SeqShowProbe, tcp6SeqShowProbe, udp4SeqShowProbe, udp6SeqShowProbe}
	for _, probeName := range probes {
		if sp, ok := t.m.GetProbe(manager.ProbeIdentificationPair{Section: probeName}); ok {
			_ = sp.Stop()
		}
	}

	maps := []string{boundPortsMap, inoToPIDMap}
	for _, mapName := range maps {
		m, _, _ := t.m.GetMap(mapName)
		if m != nil {
			_ = m.Close()
		}
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
	{
		key, flow, skinfo, tcpStats := &netebpf.TCPFlowKey{}, &netebpf.TCPFlow{}, &netebpf.SocketInfo{}, &netebpf.TCPSockStats{}
		entries := t.tcpFlowsMap.IterateFrom(unsafe.Pointer(&key))
		for entries.Next(unsafe.Pointer(&key), unsafe.Pointer(flow)) {
			err := t.socks.Lookup(unsafe.Pointer(&key), unsafe.Pointer(skinfo))
			if err != nil {
				continue
			}
			err = t.sockStats.Lookup(unsafe.Pointer(&key.Skp), unsafe.Pointer(tcpStats))
			if err != nil {
				continue
			}

			conn := toConn(key.Skp, &flow.Tup, &flow.Stats, skinfo, tcpStats)
			if filter != nil && filter(&conn) {
				buffer = append(buffer, conn)
			}
		}
		if err := entries.Err(); err != nil {
			return nil, fmt.Errorf("unable to iterate tcp connection map: %s", err)
		}
	}

	{
		sk, tup, skinfo, stats := uint64(0), netebpf.Tuple{}, &netebpf.SocketInfo{}, netebpf.FlowStats{}
		entries := t.udpStats.IterateFrom(unsafe.Pointer(&tup))
		for entries.Next(unsafe.Pointer(&tup), unsafe.Pointer(&stats)) {
			// TODO pivot from tuple to socket info?
			// TODO this seems unnecessary, simplify
			err := t.socks.Lookup(unsafe.Pointer(&sk), unsafe.Pointer(skinfo))
			if err != nil {
				continue
			}

			conn := toConn(sk, &tup, &stats, skinfo, nil)
			if filter != nil && filter(&conn) {
				buffer = append(buffer, conn)
			}
		}
		if err := entries.Err(); err != nil {
			return nil, fmt.Errorf("unable to iterate udp connection map: %s", err)
		}
	}

	return buffer, nil
}

func (t *tracer) FlushPending() []network.ConnectionStats {
	// TODO implement
	return nil
}

func (t *tracer) Remove(conn *network.ConnectionStats) error {
	if err := t.socks.Delete(unsafe.Pointer(&conn.ID)); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}

	if conn.Type == network.TCP {
		var key netebpf.TCPFlowKey
		if tgids, ok := t.tcpFlows[conn.ID]; ok {
			for _, tgid := range tgids {
				key.Skp, key.Tgid = conn.ID, tgid
				if err := t.tcpFlowsMap.Delete(unsafe.Pointer(&key)); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
					return err
				}
			}
			delete(t.tcpFlows, conn.ID)
		}

		if err := t.sockStats.Delete(unsafe.Pointer(&conn.ID)); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
	} else if conn.Type == network.UDP {
		tup := netebpf.Tuple{
			Sport:    conn.SPort,
			Dport:    conn.DPort,
			Protocol: syscall.IPPROTO_UDP,
			Tgid:     conn.Pid,
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

func toConn(skp uint64, tuple *netebpf.Tuple, stats *netebpf.FlowStats, skinfo *netebpf.SocketInfo, tcpStats *netebpf.TCPSockStats) network.ConnectionStats {
	conn := network.ConnectionStats{
		ID:                      skp,
		Pid:                     tuple.Tgid,
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

	if tcpStats != nil {
		conn.MonotonicRetransmits = tcpStats.Retransmits
		conn.RTT = tcpStats.Rtt
		conn.RTTVar = tcpStats.Rtt_var
		conn.MonotonicTCPEstablished = uint32(tcpStats.State_transitions >> netebpf.Established & 1)
		conn.MonotonicTCPClosed = uint32(tcpStats.State_transitions >> netebpf.Close & 1)
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
				if tgids, ok := t.tcpFlows[evt.Skp]; ok {
					key, flow := netebpf.TCPFlowKey{}, netebpf.TCPFlow{}
					for _, tgid := range tgids {
						if tgid == evt.Flow.Tup.Tgid {
							c := toConn(evt.Skp, &evt.Flow.Tup, &evt.Flow.Stats, &evt.Skinfo, &evt.Tcpstats)
							//log.Debugf("closed tcp conn: %x state=%x %s", evt.Skp, evt.Flow.Tcpstats.State_transitions, c)
							t.closedCh <- c
						} else {
							key.Skp, key.Tgid = evt.Skp, tgid
							if err := t.tcpFlowsMap.Lookup(unsafe.Pointer(&key), unsafe.Pointer(&flow)); err == nil {
								addStats := evt.Tcpstats
								addStats.Retransmits = 0
								c := toConn(evt.Skp, &flow.Tup, &flow.Stats, &evt.Skinfo, &addStats)
								//log.Debugf("add closed tcp conn: %x state=%x %s", evt.Skp, evt.Flow.Tcpstats.State_transitions, c)
								t.closedCh <- c
							}
						}
					}
					delete(t.tcpFlows, evt.Skp)
				} else {
					// pass through data as given
					c := toConn(evt.Skp, &evt.Flow.Tup, &evt.Flow.Stats, &evt.Skinfo, &evt.Tcpstats)
					//log.Debugf("closed tcp conn: %x state=%x %s", evt.Skp, evt.Flow.Tcpstats.State_transitions, c)
					t.closedCh <- c
				}
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
				tups, ok := t.udpTuples[evt.Skp]
				if !ok {
					continue
				}
				for _, tp := range tups {
					st := netebpf.FlowStats{}
					if err := t.udpStats.Lookup(unsafe.Pointer(&tp), unsafe.Pointer(&st)); err != nil {
						continue
					}
					c := toConn(evt.Skp, &tp, &st, &evt.Skinfo, nil)
					//log.Debugf("closed udp conn: %x %s", evt.Skp, c)
					t.closedCh <- c
				}
				delete(t.udpTuples, evt.Skp)

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
