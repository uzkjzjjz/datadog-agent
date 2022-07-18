package common

import (
	"testing"

	"github.com/DataDog/datadog-agent/pkg/config"
	"github.com/stretchr/testify/assert"
)

func TestUniqueProviders(t *testing.T) {
	extraConfigProviders := []config.ConfigurationProviders{
		{Name: "foo"},
		{Name: "bar"},
	}

	extraEnvProviders := []config.ConfigurationProviders{
		{Name: "bar"},
	}
	var explicitConfigProviders []config.ConfigurationProviders
	var explicitExtraConfigProviders []string

	uniqueConfigProviders := resolveProviders(extraConfigProviders, extraEnvProviders, explicitConfigProviders, explicitExtraConfigProviders)

	assert.Len(t, uniqueConfigProviders, 2)
}

func TestReplacingDockerProvider(t *testing.T) {
	extraConfigProviders := []config.ConfigurationProviders{
		{Name: "bar"},
	}

	extraEnvProviders := []config.ConfigurationProviders{
		{Name: "bar"},
	}

	explicitConfigProviders := []config.ConfigurationProviders{
		{Name: "docker"},
	}

	var explicitExtraConfigProviders []string

	uniqueConfigProviders := resolveProviders(extraConfigProviders, extraEnvProviders, explicitConfigProviders, explicitExtraConfigProviders)

	hasProvider := func(p string) bool {
		_, found := uniqueConfigProviders[p]
		return found
	}

	assert.False(t, hasProvider("docker"), "Docker found in map %v", uniqueConfigProviders)
	assert.True(t, hasProvider("bar"))
	assert.Len(t, uniqueConfigProviders, 2)
}

func TestConflictingContainerKubeletProviders(t *testing.T) {
	extraConfigProviders := []config.ConfigurationProviders{
		{Name: "kubelet"},
	}

	extraEnvProviders := []config.ConfigurationProviders{
		{Name: "container"},
	}

	explicitConfigProviders := []config.ConfigurationProviders{
		{Name: "foo"},
	}

	var explicitExtraConfigProviders []string

	uniqueConfigProviders := resolveProviders(extraConfigProviders, extraEnvProviders, explicitConfigProviders, explicitExtraConfigProviders)

	hasProvider := func(p string) bool {
		_, found := uniqueConfigProviders[p]
		return found
	}

	assert.False(t, hasProvider("container"), "Container incorrectly found in map %v", uniqueConfigProviders)
	assert.True(t, hasProvider("foo"))
	assert.True(t, hasProvider("kubelet"))
	assert.Len(t, uniqueConfigProviders, 2)
}
