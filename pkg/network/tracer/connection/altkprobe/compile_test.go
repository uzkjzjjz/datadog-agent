//+build linux_bpf

package altkprobe

import (
	"testing"

	"github.com/DataDog/datadog-agent/pkg/ebpf/bytecode/runtime"
	"github.com/DataDog/datadog-agent/pkg/network/config"
	"github.com/stretchr/testify/require"
)

func TestAltTracerCompile(t *testing.T) {
	cfg := config.New()
	_, err := runtime.Alttracer.Compile(&cfg.Config, getCFlags(cfg))
	require.NoError(t, err)
}

func TestAltTracerDebugCompile(t *testing.T) {
	cfg := config.New()
	cfg.BPFDebug = true
	_, err := runtime.Alttracer.Compile(&cfg.Config, getCFlags(cfg))
	require.NoError(t, err)
}
