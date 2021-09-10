//+build linux_bpf

package altkprobe

import (
	"github.com/DataDog/datadog-agent/pkg/ebpf/bytecode/runtime"
	"github.com/DataDog/datadog-agent/pkg/network/config"
)

//go:generate go run $PWD/pkg/ebpf/include_headers.go $PWD/pkg/network/ebpf/c/runtime/alttracer/alttracer.c $PWD/pkg/ebpf/bytecode/build/runtime/alttracer.c $PWD/pkg/network/ebpf/c/runtime/alttracer $PWD/pkg/ebpf/c $PWD/pkg/network/ebpf/c/runtime $PWD/pkg/network/ebpf/c
//go:generate go run $PWD/pkg/ebpf/bytecode/runtime/integrity.go $PWD/pkg/ebpf/bytecode/build/runtime/alttracer.c $PWD/pkg/ebpf/bytecode/runtime/alttracer.go runtime

func getRuntimeCompiledAlttracer(cfg *config.Config) (runtime.CompiledOutput, error) {
	return runtime.Alttracer.Compile(&cfg.Config, getCFlags(cfg))
}

func getCFlags(cfg *config.Config) []string {
	var cflags []string
	if cfg.BPFDebug {
		cflags = append(cflags, "-DDEBUG=1")
	}
	return cflags
}
