// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build kubeapiserver && orchestrator
// +build kubeapiserver,orchestrator

package orchestrator

import (
	"context"

	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/cluster/orchestrator/collectors"
	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/cluster/orchestrator/collectors/inventory"
	"github.com/DataDog/datadog-agent/pkg/orchestrator"
	"github.com/DataDog/datadog-agent/pkg/util/kubernetes/apiserver"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

var (
	discoveryProviders = []DiscoveryProvider{
		new(KubernetesDiscoveryProvider),
	}
)

// DiscoveryProvider represents the entity responsible for discovering
// collectors that should be turned on for a certain environment.
type DiscoveryProvider interface {
	// Name returns the provider's name.
	Name() string

	// Discover returns a list of collectors to enable, based on what is
	// discovered from the environment.
	Discover(inventory *inventory.CollectorInventory) ([]collectors.Collector, error)
}

// KubernetesDiscoveryProvider is the discovery provider for Kubernetes
// collectors.
type KubernetesDiscoveryProvider struct{}

// Discover returns a list of collectors to enable, based on the API list
// exposed by Kubernetes API server.
func (kp *KubernetesDiscoveryProvider) Discover(inventory *inventory.CollectorInventory) ([]collectors.Collector, error) {
	var discoveredCollectors []collectors.Collector

	// TODO: don't block indefinitely.
	client, err := apiserver.WaitForAPIClient(context.Background())
	if err != nil {
		return nil, err
	}

	_, resourceLists, err := client.DiscoveryCl.ServerGroupsAndResources()
	if err != nil {
		return nil, err
	}

	// FIXME: The assumption is that we won't have two API versions for the same
	// resource in the same cluster but that may be wrong. In that case we'd
	// need a more complex logic.
	for _, list := range resourceLists {
		for _, resource := range list.APIResources {
			version := list.GroupVersion

			collector, err := inventory.CollectorForVersion(resource.Name, version)
			if err != nil {
				continue
			}

			// The cluster collector is to be activated when nodes are discovered.
			if collector.Metadata().NodeType == orchestrator.K8sNode {
				clusterCollector, _ := inventory.CollectorForDefaultVersion("clusters")
				discoveredCollectors = append(discoveredCollectors, clusterCollector)
			}

			discoveredCollectors = append(discoveredCollectors, collector)
			log.Infof("Autodiscovered collector %s with version: %s", collector.Metadata().Name, collector.Metadata().Version)

		}
	}

	return discoveredCollectors, nil
}

// Name returns the provider's name.
func (kp *KubernetesDiscoveryProvider) Name() string {
	return "Kubernetes"
}
