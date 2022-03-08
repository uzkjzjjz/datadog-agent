// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// +build linux

package flare

import (
	"path/filepath"

	"github.com/DataDog/datadog-agent/pkg/metadata/host"
	"github.com/DataDog/datadog-agent/pkg/process/util"
)

func zipLinuxKernelSymbols(tempDir, hostname string) error {
	return zipFile("/proc/kallsyms", filepath.Join(tempDir, hostname, "kallsyms"))
}

func zipLinuxKrobeEvents(tempDir, hostname string) error {
	return zipFile("/sys/kernel/debug/tracing/kprobe_events", filepath.Join(tempDir, hostname, "kprobe_events"))
}

func zipLinuxKprobeProfile(tempDir, hostname string) error {
	return zipFile("/sys/kernel/debug/tracing/kprobe_profile", filepath.Join(tempDir, hostname, "kprobe_profile"))
}

func zipLinuxPid1MountInfo(tempDir, hostname string) error {
	return zipFile("/proc/1/mountinfo", filepath.Join(tempDir, hostname, "mountinfo"))
}

func zipLinuxTracingAvailableEvents(tempDir, hostname string) error {
	return zipFile("/sys/kernel/debug/tracing/available_events", filepath.Join(tempDir, hostname, "available_events"))
}

func zipLinuxTracingAvailableFilterFunctions(tempDir, hostname string) error {
	return zipFile("/sys/kernel/debug/tracing/available_filter_functions", filepath.Join(tempDir, hostname, "available_filter_functions"))
}

func zipLinuxKernelConfig(tempDir, hostname string) error {
	// path -> content is gzipped
	paths := map[string]bool{
		util.HostProc("/config.gz"): true,
		"/boot/config":              false,
	}

	hi := host.GetStatusInformation()
	if hi.KernelVersion != "" {
		paths["/boot/config-"+hi.KernelVersion] = false
	}

	var err error
	for p, gzipped := range paths {
		out := filepath.Join(tempDir, hostname, "kernel_config")
		if gzipped {
			err = zipGzippedFile(p, out)
		} else {
			err = zipFile(p, out)
		}
		// return on first success
		if err == nil {
			return nil
		}
	}
	return err
}
