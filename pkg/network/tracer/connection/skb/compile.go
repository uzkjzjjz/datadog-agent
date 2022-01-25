//  Unless explicitly stated otherwise all files in this repository are licensed
//  under the Apache License Version 2.0.
//  This product includes software developed at Datadog (https://www.datadoghq.com/).
//  Copyright 2016-present Datadog, Inc.

package skb

import (
	"github.com/DataDog/datadog-agent/pkg/ebpf/bytecode/runtime"
	"github.com/DataDog/datadog-agent/pkg/network/config"
)

//go:generate go run $PWD/pkg/ebpf/include_headers.go $PWD/pkg/network/ebpf/c/runtime/skbtracer/skbtracer.c $PWD/pkg/ebpf/bytecode/build/runtime/skbtracer.c $PWD/pkg/network/ebpf/c/runtime/skbtracer $PWD/pkg/ebpf/c $PWD/pkg/network/ebpf/c/runtime $PWD/pkg/network/ebpf/c
//go:generate go run $PWD/pkg/ebpf/bytecode/runtime/integrity.go $PWD/pkg/ebpf/bytecode/build/runtime/skbtracer.c $PWD/pkg/ebpf/bytecode/runtime/skbtracer.go runtime

func getRuntimeCompiledSKBTracer(cfg *config.Config) (runtime.CompiledOutput, error) {
	return runtime.Skbtracer.Compile(&cfg.Config, getCFlags(cfg))
}

func getCFlags(cfg *config.Config) []string {
	var cflags []string
	if cfg.CollectUDPConns {
		cflags = append(cflags, "-DFEATURE_UDP_ENABLED")
	}
	if cfg.CollectTCPConns {
		cflags = append(cflags, "-DFEATURE_TCP_ENABLED")
	}
	if cfg.CollectIPv6Conns {
		cflags = append(cflags, "-DFEATURE_IPV6_ENABLED")
	}
	if cfg.BPFDebug {
		cflags = append(cflags, "-DDEBUG=1")
	}
	return cflags
}
