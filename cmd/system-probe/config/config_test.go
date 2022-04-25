package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/DataDog/datadog-agent/pkg/config"
)

func newConfig() {
	config.Datadog = config.NewConfig("datadog", "DD", strings.NewReplacer(".", "_"))
	config.InitConfig(config.Datadog)
}

func TestRuntimeSecurityLoad(t *testing.T) {
	newConfig()

	for i, tc := range []struct {
		cws, fim, process bool
		enabled           bool
	}{
		{cws: false, fim: false, process: false, enabled: false},
		{cws: false, fim: false, process: true, enabled: true},
		{cws: false, fim: true, process: false, enabled: true},
		{cws: false, fim: true, process: true, enabled: true},
		{cws: true, fim: false, process: false, enabled: true},
		{cws: true, fim: false, process: true, enabled: true},
		{cws: true, fim: true, process: false, enabled: true},
		{cws: true, fim: true, process: true, enabled: true},
	} {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			os.Setenv("DD_RUNTIME_SECURITY_CONFIG_ENABLED", strconv.FormatBool(tc.cws))
			os.Setenv("DD_RUNTIME_SECURITY_CONFIG_FIM_ENABLED", strconv.FormatBool(tc.fim))
			os.Setenv("DD_RUNTIME_SECURITY_CONFIG_PROCESS_EVENTS_ENABLED", strconv.FormatBool(tc.process))

			defer os.Unsetenv("DD_RUNTIME_SECURITY_CONFIG_ENABLED")
			defer os.Unsetenv("DD_RUNTIME_SECURITY_CONFIG_FIM_ENABLED")
			defer os.Unsetenv("DD_RUNTIME_SECURITY_CONFIG_PROCESS_EVENTS_ENABLED")

			cfg, err := New("")
			require.NoError(t, err)
			assert.Equal(t, tc.enabled, cfg.ModuleIsEnabled(SecurityRuntimeModule))
		})
	}
}
