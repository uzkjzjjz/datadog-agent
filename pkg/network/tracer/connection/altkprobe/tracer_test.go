package altkprobe

import (
	"testing"

	"github.com/DataDog/datadog-agent/pkg/network/config"
	"github.com/stretchr/testify/require"
)

func TestLoad(t *testing.T) {
	m, err := New(config.New())
	require.NoError(t, err)
	defer m.Stop()

	_, err = m.Start()
	require.NoError(t, err)
}
