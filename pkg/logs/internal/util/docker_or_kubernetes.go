// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package util

import "github.com/DataDog/datadog-agent/pkg/config"

// DockerOrKubernetes determines how the logs-agent should handle containers:
// either monitoring individual docker containers, or monitoring pods and
// logging the containers within them.
//
// This returns config.Docker, config.Kubernetes, or -- if neither is available -- an empty string.
func DockerOrKubernetes() config.Feature {
	d := config.IsFeaturePresent(config.Docker)
	k := config.IsFeaturePresent(config.Kubernetes)

	switch {
	case d && !k:
		return config.Docker
	case k && !d:
		return config.Kubernetes
	case k && d:
		// prefer kubernetes if k8s_container_use_file is set
		if config.Datadog.GetBool("logs_config.k8s_container_use_file") {
			return config.Kubernetes
		}
		return config.Docker
	}

	return config.Feature("")
}
