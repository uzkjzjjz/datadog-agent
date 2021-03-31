// +build linux_bpf

package main

import (
	"fmt"
	"io"
	"math"
	"os"

	"github.com/DataDog/datadog-agent/pkg/ebpf"
	"github.com/DataDog/datadog-agent/pkg/ebpf/bytecode/runtime"
	"github.com/DataDog/ebpf/manager"
	"golang.org/x/sys/unix"
)

//go:generate go run ../../../ebpf/include_headers.go ./c/snoop.c ./runtime/netlink_snoop.c ../../../ebpf/c
//go:generate go run ../../../ebpf/bytecode/runtime/integrity.go ./runtime/netlink_snoop.c ./netlink_snoop.go main

func getRuntimeCompiledNetlinkSnoop(pid int) (runtime.CompiledOutput, error) {
	cfg := &ebpf.Config{
		BPFDir:                   ".",
		RuntimeCompilerOutputDir: "./build",
	}
	return Netlinksnoop.Compile(cfg, []string{
		fmt.Sprintf("-DFILTER_PID=%d", pid),
		"-DDEBUG=1",
	})
}

func getManager(buf io.ReaderAt, handler *ebpf.PerfHandler) (*manager.Manager, error) {
	mgr := &manager.Manager{
		Maps: []*manager.Map{
			{Name: "buffers"},
		},
		PerfMaps: []*manager.PerfMap{
			{
				Map: manager.Map{Name: "nlmsgs"},
				PerfMapOptions: manager.PerfMapOptions{
					PerfRingBufferSize: 8 * os.Getpagesize(),
					Watermark:          1,
					DataHandler:        handler.DataHandler,
					LostHandler:        handler.LostHandler,
				},
			},
		},
		Probes: []*manager.Probe{
			{Section: "kprobe/netlink_recvmsg"},
			{Section: "kretprobe/netlink_recvmsg", KProbeMaxActive: 128},
		},
	}

	opts := manager.Options{
		// Extend RLIMIT_MEMLOCK (8) size
		// On some systems, the default for RLIMIT_MEMLOCK may be as low as 64 bytes.
		// This will result in an EPERM (Operation not permitted) error, when trying to create an eBPF map
		// using bpf(2) with BPF_MAP_CREATE.
		//
		// We are setting the limit to infinity until we have a better handle on the true requirements.
		RLimit: &unix.Rlimit{
			Cur: math.MaxUint64,
			Max: math.MaxUint64,
		},
	}

	err := mgr.InitWithOptions(buf, opts)
	if err != nil {
		return nil, err
	}
	return mgr, nil
}
