// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build kubeapiserver && orchestrator
// +build kubeapiserver,orchestrator

package k8s

import (
	v1crd "k8s.io/apiextensions-apiserver/pkg/client/informers/externalversions/apiextensions/v1"
	v1 "k8s.io/apiextensions-apiserver/pkg/client/listers/apiextensions/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"

	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/cluster/orchestrator/collectors"
	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/cluster/orchestrator/processors"
	"github.com/DataDog/datadog-agent/pkg/orchestrator"
)

// CRDCollector is a collector for Kubernetes clusters.
type CRDCollector struct {
	informer  v1crd.CustomResourceDefinitionInformer
	lister    v1.CustomResourceDefinitionLister
	metadata  *collectors.CollectorMetadata
	processor *processors.Processor
}

// NewCRDCollector creates a new collector for the Kubernetes Cluster
// resource.
func NewCRDCollector() *CRDCollector {
	return &CRDCollector{
		metadata: &collectors.CollectorMetadata{
			IsStable: true,
			Name:     "crds",
			NodeType: orchestrator.K8sCRD,
		},
	}
}

// Informers returns the shared informers.
func (c *CRDCollector) Informers() map[string]cache.SharedInformer {
	return map[string]cache.SharedInformer{c.metadata.Name: c.informer.Informer()}
}

// Init is used to initialize the collector.
func (c *CRDCollector) Init(rcfg *collectors.CollectorRunConfig) {
	c.informer = rcfg.APIClient.CustomResourceDefinitionInformer.Apiextensions().V1().CustomResourceDefinitions()
	c.lister = c.informer.Lister()
}

// IsAvailable returns whether the collector is available.
func (c *CRDCollector) IsAvailable() bool { return true }

// Metadata is used to access information about the collector.
func (c *CRDCollector) Metadata() *collectors.CollectorMetadata {
	return c.metadata
}

// Run triggers the collection process.
func (c *CRDCollector) Run(rcfg *collectors.CollectorRunConfig) (*collectors.CollectorRunResult, error) {
	list, err := c.lister.List(labels.Everything())
	if err != nil {
		return nil, collectors.NewListingError(err)
	}

	ctx := &processors.ProcessorContext{
		APIClient:  rcfg.APIClient,
		Cfg:        rcfg.Config,
		ClusterID:  rcfg.ClusterID,
		MsgGroupID: rcfg.MsgGroupRef.Inc(),
		NodeType:   c.metadata.NodeType,
	}

	messages, processed := c.processor.Process(ctx, list)

	if processed == -1 {
		return nil, collectors.ErrProcessingPanic
	}

	result := &collectors.CollectorRunResult{
		Messages:           messages,
		ResourcesListed:    len(list),
		ResourcesProcessed: processed,
	}

	return result, nil
}
