// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build kubeapiserver && orchestrator
// +build kubeapiserver,orchestrator

package collectors

import (
	model "github.com/DataDog/agent-payload/v5/process"
	"github.com/DataDog/datadog-agent/pkg/orchestrator"
	"github.com/DataDog/datadog-agent/pkg/orchestrator/config"
	"github.com/DataDog/datadog-agent/pkg/util/kubernetes/apiserver"

	"k8s.io/client-go/tools/cache"
)

// Collector is an interface that represents the collection process for a
// resource type.
type Collector interface {
	// Informer returns the shared informer for that resource.
	Informer() cache.SharedInformer

	// Init is where the collector initialization happens. It is used to create
	// informers and listers.
	Init(*CollectorRunConfig)

	// Metadata is used to access information describing the collector.
	Metadata() *CollectorMetadata

	// Run triggers the collection process given a configuration and returns the
	// collection result. Returns an error if the collection failed.
	Run(*CollectorRunConfig) (*CollectorRunResult, error)
}

type CollectorVersions struct {
	Collectors []Collector
}

func NewCollectorVersions(versions ...Collector) CollectorVersions {
	var collectorVersions CollectorVersions
	for _, collector := range append(versions) {
		collectorVersions.Collectors = append(collectorVersions.Collectors, collector)
	}
	return collectorVersions
}

func (cv *CollectorVersions) CollectorForVersion(version string) (Collector, bool) {
	for _, collector := range cv.Collectors {
		if collector.Metadata().Version == version {
			return collector, true
		}
	}
	return nil, false
}

// CollectorMetadata contains information about a collector.
type CollectorMetadata struct {
	IsDefaultVersion bool
	IsStable         bool
	Name             string
	NodeType         orchestrator.NodeType
	Version          string
}

// CollectorRunConfig is the configuration used to initialize or run the
// collector.
type CollectorRunConfig struct {
	APIClient   *apiserver.APIClient
	ClusterID   string
	Config      *config.OrchestratorConfig
	MsgGroupRef *int32
}

// CollectorRunResult contains information about what the collector has done.
type CollectorRunResult struct {
	Messages           []model.MessageBody
	ResourcesListed    int
	ResourcesProcessed int
}
