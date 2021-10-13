// +build linux_bpf

package ebpf

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/DataDog/datadog-agent/pkg/process/util"
	"github.com/DataDog/ebpf/manager"
	"golang.org/x/sys/unix"
)

func bpf(cmd int, attr unsafe.Pointer, size uintptr) (uintptr, error) {
	var err error

	r1, _, errno := unix.Syscall(unix.SYS_BPF, uintptr(cmd), uintptr(attr), size)
	runtime.KeepAlive(attr)
	if errno != 0 {
		err = errno
	}
	return r1, err
}

type bpfObjGetInfoByFdAttr struct {
	bpf_fd   uint32
	info_len uint32
	info     unsafe.Pointer
}

type bpfProgInfo struct {
	progType                 uint32
	id                       uint32
	tag                      [unix.BPF_TAG_SIZE]byte
	jited_prog_len           uint32
	xlated_prog_len          uint32
	jited_prog_insns         unsafe.Pointer
	xlated_prog_insns        unsafe.Pointer
	load_time                uint64
	created_by_uid           uint32
	nr_map_ids               uint32
	map_ids                  unsafe.Pointer
	name                     [unix.BPF_OBJ_NAME_LEN]byte
	ifindex                  uint32
	gpl_compatible           uint32
	netns_dev                uint64
	netns_ino                uint64
	nr_jited_ksyms           uint32
	nr_jited_func_lens       uint32
	jited_ksyms              unsafe.Pointer
	jited_func_lens          unsafe.Pointer
	btf_id                   uint32
	func_info_rec_size       uint32
	func_info                unsafe.Pointer
	nr_func_info             uint32
	nr_line_info             uint32
	line_info                unsafe.Pointer
	jited_line_info          unsafe.Pointer
	nr_jited_line_info       uint32
	line_info_rec_size       uint32
	jited_line_info_rec_size uint32
	nr_prog_tags             uint32
	prog_tags                unsafe.Pointer
	run_time_ns              uint64
	run_cnt                  uint64
}

func bpfGetProgInfoByFD(fd int) (*bpfProgInfo, error) {
	pi := bpfProgInfo{}
	attr := bpfObjGetInfoByFdAttr{
		bpf_fd:   uint32(fd),
		info_len: uint32(unsafe.Sizeof(pi)),
		info:     unsafe.Pointer(&pi),
	}

	_, err := bpf(unix.BPF_OBJ_GET_INFO_BY_FD, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	if err != nil {
		return nil, fmt.Errorf("cannot get obj info by fd: %w", err)
	}
	return &pi, nil
}

type bpfEnableStatsAttr struct {
	enable_stats struct {
		statsType uint32
	}
}

func bpfEnableStats() (*wrappedFD, error) {
	attr := bpfEnableStatsAttr{}
	attr.enable_stats.statsType = unix.BPF_STATS_RUN_TIME

	fd, err := bpf(unix.BPF_ENABLE_STATS, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	if err != nil {
		return nil, fmt.Errorf("cannot enable bpf stats: %w", err)
	}
	return newWrappedFD(int(fd)), nil
}

func supportsBpfEnableStats() func() bool {
	var once sync.Once
	result := false

	return func() bool {
		once.Do(func() {
			fd, err := bpfEnableStats()
			if err != nil {
				return
			}
			result = true
			_ = fd.Close()
		})
		return result
	}
}

var supportsStatsSyscall = supportsBpfEnableStats()

// EnableBPFStats enables the kernel-level collection ebpf program stats
func EnableBPFStats() (func() error, error) {
	var fd *wrappedFD
	var err error

	if supportsStatsSyscall() {
		fd, err = bpfEnableStats()
		if err != nil && !errors.Is(err, unix.EINVAL) {
			return nil, err
		}
	}

	err = writeSysctl(util.HostProc(bpfSysctlProcfile), []byte("1"))
	if err != nil {
		return nil, err
	}
	return disableBPFStats(fd), nil
}

func disableBPFStats(fd *wrappedFD) func() error {
	return func() error {
		if fd != nil {
			return fd.Close()
		}
		return writeSysctl(util.HostProc(bpfSysctlProcfile), []byte("0"))
	}
}

// bpfProgramStats is the statistics collected by the kernel for eBPF programs
type bpfProgramStats struct {
	Name     string
	RunCount uint
	RunTime  time.Duration
}

// getProgramStats gets the BPF statistics for the provided program FD
func getProgramStats(fd int) (*bpfProgramStats, error) {
	pi, err := bpfGetProgInfoByFD(fd)
	if err != nil {
		return nil, err
	}
	name := unix.ByteSliceToString(pi.name[:])
	return &bpfProgramStats{
		Name:     name,
		RunCount: uint(pi.run_cnt),
		RunTime:  time.Duration(pi.run_time_ns),
	}, nil
}

var bpfSysctlProcfile = "/sys/kernel/bpf_stats_enabled"

func fileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func validSysctlPath(path string) error {
	prefix := util.HostProc("/sys/kernel/")
	if !strings.HasPrefix(path, prefix) {
		return fmt.Errorf("invalid sysctl path %s, it must begin with %s", path, prefix)
	}
	exists, err := fileExists(path)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("invalid sysctl path %s, it does not exist", path)
	}
	return nil
}

func writeSysctl(path string, val []byte) error {
	if err := validSysctlPath(path); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	n, err := f.Write(val)
	if err != nil {
		return err
	}
	if n != len(val) {
		return fmt.Errorf("write to sysctl %s too short, expected %d got %d", path, len(val), n)
	}
	return nil
}

// getProfileName returns the name a probe will use in the debugfs kprobe_profile file
func getProfileName(p *manager.Probe) string {
	pid := os.Getpid()
	if strings.HasPrefix(p.Section, "kprobe/") {
		return fmt.Sprintf("p_%s_%s_%d", strings.TrimPrefix(p.Section, "kprobe/"), p.UID, pid)
	} else if strings.HasPrefix(p.Section, "kretprobe/") {
		return fmt.Sprintf("r_%s_%s_%d", strings.TrimPrefix(p.Section, "kretprobe/"), p.UID, pid)
	}
	return ""
}

type probeStats struct {
	runCount uint
	runTime  time.Duration
	hits     int64
	misses   int64
}

var lastStats = map[string]probeStats{}

func GetProbeTimings(m *manager.Manager, useProgInfo bool) map[string]map[string]int64 {
	kstats := map[string]map[string]int64{}
	profileStats, _ := readKprobeProfile(kprobeProfile)
	for _, p := range m.Probes {
		if !p.Enabled {
			continue
		}
		key := strings.Replace(p.Section, "/", "_", -1)
		base, ok := lastStats[key]
		if !ok {
			base = probeStats{}
		}
		kstats[key] = make(map[string]int64)
		cur := probeStats{}

		profileName := getProfileName(p)
		if ps, ok := profileStats[profileName]; ok {
			cur.hits = ps.Hits
			cur.misses = ps.Misses
			kstats[key]["hits"] = cur.hits - base.hits
			kstats[key]["misses"] = cur.misses - base.misses
		}

		if useProgInfo {
			stats, err := getProgramStats(p.Program().FD())
			if err == nil {
				cur.runTime = stats.RunTime
				cur.runCount = stats.RunCount
				rc := int64(cur.runCount - base.runCount)
				if rc > 0 {
					kstats[key]["avg_ns"] = (cur.runTime.Nanoseconds() - base.runTime.Nanoseconds()) / rc
					kstats[key]["run_count"] = rc
				} else {
					kstats[key]["avg_ns"] = 0
					kstats[key]["run_count"] = 0
				}
			}
		}
		lastStats[key] = cur
	}
	return kstats
}
