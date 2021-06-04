// +build linux_bpf

package netlink

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	nettestutil "github.com/DataDog/datadog-agent/pkg/network/testutil"
	"github.com/stretchr/testify/require"
)

func TestConsumerKeepsRunningAfterCircuitBreakerTrip(t *testing.T) {
	defer nettestutil.RunCommands(t, []string{"iptables -D INPUT -m conntrack --ctstate NEW,RELATED,ESTABLISHED -j ACCEPT"}, true)
	nettestutil.RunCommands(t, []string{"iptables -I INPUT 1 -m conntrack --ctstate NEW,RELATED,ESTABLISHED -j ACCEPT"}, false)

	c := NewConsumer("/proc", 1, false)
	require.NotNil(t, c)
	exited := make(chan struct{})
	defer func() {
		c.Stop()
		<-exited
	}()

	ev, err := c.Events()
	require.NoError(t, err)
	require.NotNil(t, ev)

	go func() {
		for range ev {
		}

		close(exited)
	}()

	isRecvLoopRunning := func() bool {
		return atomic.LoadInt32(&c.recvLoopRunning) == 1
	}

	require.Eventually(t, func() bool {
		return isRecvLoopRunning()
	}, 3*time.Second, 100*time.Millisecond)

	srv := nettestutil.StartServerTCP(t, net.ParseIP("127.0.0.1"), 0)
	defer srv.Close()

	l := srv.(net.Listener)

	// this should trip the circuit breaker
	// we have to run this loop for more than
	// `tickInterval` seconds (3s currently) for
	// the circuit breaker to detect the over-limit
	// rate of updates
	delay := 250 * time.Millisecond
	for i := int64(0); i <= int64(tickInterval/delay); i++ {
		conn, err := net.Dial("tcp", l.Addr().String())
		require.NoError(t, err)
		defer conn.Close()

		time.Sleep(delay)
	}

	// on pre 3.15 kernels, the receive loop
	// will simply bail since bpf random sampling
	// is not available
	if pre315Kernel {
		require.Eventually(t, func() bool {
			return !isRecvLoopRunning() && c.breaker.IsOpen()
		}, 3*time.Second, 100*time.Millisecond)
	} else {
		require.Eventually(t, func() bool {
			return c.samplingRate < 1.0
		}, 3*time.Second, 100*time.Millisecond)

		require.True(t, isRecvLoopRunning())
	}

}
