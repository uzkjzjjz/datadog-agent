package utils

import "github.com/DataDog/datadog-agent/pkg/autodiscovery/integration"

// AddContainerCollectAllConfigs adds a low-priority config template containing
// an empty LogsConfig when `logs_config.container_collect_all` is set.  This
// config will be scheduled if no higher-priority configs match the container.

func AddContainerCollectAllConfigs(configs []integration.Config) []integration.Config {
}
