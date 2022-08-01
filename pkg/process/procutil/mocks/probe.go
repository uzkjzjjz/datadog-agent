// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package mocks

import (
	"time"

	"github.com/stretchr/testify/mock"

	"github.com/DataDog/datadog-agent/pkg/process/procutil"
)

// mockProbe is a mock Probe implementation
type mockProbe struct {
	mock.Mock

	// statsByPid is a map of pid -> Stats object
	statsByPid map[int32]*procutil.Stats

	// processesByPid is a map of pid -> Process object
	processesByPid map[int32]*procutil.Process

	// statsWithPermByPid is a map of pid -> StatsWithPerm object
	statsWithPermByPid map[int32]*procutil.StatsWithPerm
}

// NewMockProbe creates a new mockProbe object
func NewMockProbe() *mockProbe {
	return &mockProbe{}
}

// Close cleans up everything related to Probe object
func (p *mockProbe) Close() {
	// no-op
}

// StatsForPIDs returns a map of stats info indexed by pid using the given pids.
// Note that the time parameter is ignored in this implementation because the stats are supplied by
// mockProbe.SetStatsForPID().
func (p *mockProbe) StatsForPIDs(pids []int32, _ time.Time) (map[int32]*procutil.Stats, error) {
	stats := make(map[int32]*procutil.Stats, len(pids))
	for _, pid := range pids {
		if s, ok := p.statsByPid[pid]; ok {
			stats[pid] = s
		}
	}
	return stats, nil
}

// SetStatsForPID sets the Stats object for the given pid. This object will be returned by
// mockProbe.StatsForPIDs() when the pid is requested.
func (p *mockProbe) SetStatsForPID(pid int32, stats *procutil.Stats) {
	p.statsByPid[pid] = stats
}

// ProcessesByPID returns a map of process info indexed by pid.
// Note that the time and boolean parameters are ignored in this implementation because the
// processes are supplied by mockProbe.SetProcessByPID().
func (p *mockProbe) ProcessesByPID(_ time.Time, _ bool) (map[int32]*procutil.Process, error) {
	return p.processesByPid, nil
}

// SetProcessByPID sets the Process object for the given pid. This object will be returned by
// mockProbe.ProcessesByPID().
func (p *mockProbe) SetProcessByPID(pid int32, process *procutil.Process) {
	p.processesByPid[pid] = process
}

// StatsWithPermByPID returns the stats that require elevated permission to collect for each process
func (p *mockProbe) StatsWithPermByPID(pids []int32) (map[int32]*procutil.StatsWithPerm, error) {
	stats := make(map[int32]*procutil.StatsWithPerm, len(pids))
	for _, pid := range pids {
		if s, ok := p.statsWithPermByPid[pid]; ok {
			stats[pid] = s
		}
	}
	return stats, nil
}

// SetStatsWithPermByPID sets the StatsWithPerm object for the given pid. This object will be
// returned by mockProbe.StatsWithPermByPID() when the pid is requested.
func (p *mockProbe) SetStatsWithPermByPID(pid int32, stats *procutil.StatsWithPerm) {
	p.statsWithPermByPid[pid] = stats
}
