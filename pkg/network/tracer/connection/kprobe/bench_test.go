package kprobe

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"github.com/DataDog/datadog-agent/pkg/network"
	"github.com/DataDog/datadog-agent/pkg/network/testutil"
	"github.com/DataDog/ebpfbench"
	"github.com/stretchr/testify/require"
)

func benchTracer(b *testing.B, fn func(b *testing.B)) {
	eb := ebpfbench.NewEBPFBenchmark(b)
	defer eb.Close()

	cfg := testConfig()
	cfg.EnableRuntimeCompiler = true
	t, err := New(cfg, nil)
	require.NoError(b, err)
	defer t.Stop()

	err = t.Start(func(_ *network.ConnectionStats) bool { return false })
	require.NoError(b, err)

	tr := t.(*kprobeTracer)
	for _, p := range tr.m.Probes {
		if !p.Enabled {
			continue
		}
		eb.ProfileProgram(p.Program().FD(), p.Section)
	}

	eb.Run(fn)
}

func BenchmarkTCPLatency(b *testing.B) {
	benchTracer(b, benchLatencyEchoTCP(64))
}

func BenchmarkUDPLatency(b *testing.B) {
	benchTracer(b, benchLatencyEchoUDP(64))
}

func benchLatencyEchoTCP(size int) func(b *testing.B) {
	payload := testutil.AlphaPayload(size)
	echoOnMessage := func(c net.Conn) {
		r := bufio.NewReader(c)
		for {
			buf, err := r.ReadBytes(byte('\n'))
			if err == io.EOF {
				c.Close()
				return
			}
			c.Write(buf)
		}
	}

	return func(b *testing.B) {
		addr, closer, err := testutil.NewTCPServer(echoOnMessage)
		require.NoError(b, err)
		defer closer.Close()

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			c, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
			if err != nil {
				b.Fatal(err)
			}
			r := bufio.NewReader(c)

			c.Write(payload)
			buf, err := r.ReadBytes(byte('\n'))

			c.Close()
			if err != nil || len(buf) != len(payload) || !bytes.Equal(payload, buf) {
				b.Fatalf("Sizes: %d, %d. Equal: %v. Error: %s", len(buf), len(payload), bytes.Equal(payload, buf), err)
			}
		}
		b.StopTimer()
	}
}

func benchLatencyEchoUDP(size int) func(b *testing.B) {
	payload := testutil.AlphaPayload(size)
	echoOnMessage := func(b []byte, n int) []byte {
		resp := make([]byte, len(b))
		copy(resp, b)
		return resp
	}

	return func(b *testing.B) {
		addr, closer, err := testutil.NewUDPServer(size, echoOnMessage)
		require.NoError(b, err)
		defer closer.Close()

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			c, err := net.DialTimeout("udp", addr, 50*time.Millisecond)
			if err != nil {
				b.Fatal(err)
			}
			r := bufio.NewReader(c)

			c.Write(payload)
			buf := make([]byte, size)
			n, err := r.Read(buf)

			c.Close()
			if err != nil || n != len(payload) || !bytes.Equal(payload, buf) {
				b.Fatalf("Sizes: %d, %d. Equal: %v. Error: %s", len(buf), len(payload), bytes.Equal(payload, buf), err)
			}
		}
		b.StopTimer()
	}
}
