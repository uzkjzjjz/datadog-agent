package altkprobe

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unsafe"

	"github.com/DataDog/datadog-agent/pkg/network/config"
	"github.com/DataDog/datadog-agent/pkg/process/util"
)

func (t *tracer) walkProcFds() error {
	procRoot := util.HostProc()
	d, err := os.Open(procRoot)
	if err != nil {
		return err
	}
	defer d.Close()

	fnames, err := d.Readdirnames(-1)
	if err != nil {
		return err
	}
	for _, fname := range fnames {
		pid, err := strconv.ParseInt(fname, 10, 32)
		if err != nil {
			// if not numeric name, just skip
			continue
		}

		fdpath := filepath.Join(d.Name(), fname, "fd")
		err = t.getProcFdInodes(int32(pid), fdpath)
		if err != nil {
			continue
		}
	}
	return nil
}

func (t *tracer) getProcFdInodes(pid int32, path string) error {
	fddir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer fddir.Close()

	fdnames, err := fddir.Readdirnames(-1)
	if err != nil {
		return err
	}

	for _, fdname := range fdnames {
		inodePath := filepath.Join(path, fdname)
		inode, err := os.Readlink(inodePath)
		if err != nil {
			continue
		}
		if !strings.HasPrefix(inode, "socket:[") {
			continue
		}
		inodeNum, err := strconv.ParseInt(inode[len("socket:["):len(inode)-1], 10, 64)
		if err != nil {
			continue
		}
		_ = t.inoToPID.Put(unsafe.Pointer(&inodeNum), unsafe.Pointer(&pid))
	}
	return nil
}

func walkProcNets(cfg *config.Config) error {
	var suffixes []string
	if cfg.CollectTCPConns {
		suffixes = append(suffixes, "net/tcp")
		if cfg.CollectIPv6Conns {
			suffixes = append(suffixes, "net/tcp6")
		}
	}
	if cfg.CollectUDPConns {
		suffixes = append(suffixes, "net/udp")
		if cfg.CollectIPv6Conns {
			suffixes = append(suffixes, "net/udp6")
		}
	}
	if len(suffixes) == 0 {
		return nil
	}

	procRoot := util.HostProc()
	d, err := os.Open(procRoot)
	if err != nil {
		return err
	}
	defer d.Close()

	seenNamespaces := map[uint32]struct{}{}
	fnames, err := d.Readdirnames(-1)
	if err != nil {
		return err
	}
	for _, fname := range fnames {
		pid, err := strconv.ParseInt(fname, 10, 32)
		if err != nil {
			// if not numeric name, just skip
			continue
		}
		// don't check the same namespace twice
		ns, err := util.GetNetNsInoFromPid(procRoot, int(pid))
		if err != nil {
			continue
		}
		if _, seen := seenNamespaces[ns]; seen {
			continue
		}
		seenNamespaces[ns] = struct{}{}

		root := filepath.Join(d.Name(), fname)
		for _, s := range suffixes {
			readProcNet(filepath.Join(root, s))
		}
	}

	return nil
}

func readProcNet(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	bio := bufio.NewReader(f)
	// read 2 lines to do full trigger
	_, _, _ = bio.ReadLine()
	_, _, _ = bio.ReadLine()
}
