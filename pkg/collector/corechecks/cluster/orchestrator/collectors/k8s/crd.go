// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build kubeapiserver && orchestrator
// +build kubeapiserver,orchestrator

package k8s

import (
	"sync/atomic"

	model "github.com/DataDog/agent-payload/v5/process"
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
	var messages []model.MessageBody
	var processed int
	for _, lister := range c.listers { // TODO: or let each of the collection run in a go routine and join below
		list, err := lister.List(labels.Everything())
		if err != nil {
			return nil, collectors.NewListingError(err)
		}

		ctx := &processors.ProcessorContext{
			APIClient:  rcfg.APIClient,
			Cfg:        rcfg.Config,
			ClusterID:  rcfg.ClusterID,
			MsgGroupID: atomic.AddInt32(rcfg.MsgGroupRef, 1),
			NodeType:   c.metadata.NodeType,
		}

		m, p := c.processor.Process(ctx, list)

		// This would happen when recovering from a processor panic. In the nominal
		// case we would have a positive integer set at the very end of processing.
		// If this is not the case then it means code execution stopped sooner.
		// Panic recovery will log more information about the error so we can figure
		// out the root cause.
		if p == -1 {
			return nil, collectors.ErrProcessingPanic
		}

		messages = append(messages, m...)
		processed += p

		// The cluster processor can return errors since it has to grab extra
		// information from the API server during processing.
		if err != nil {
			return nil, collectors.NewProcessingError(err)
		}

	}

	result := &collectors.CollectorRunResult{
		Messages:           messages,
		ResourcesListed:    len(c.listers),
		ResourcesProcessed: processed,
	}

	return result, nil
}
