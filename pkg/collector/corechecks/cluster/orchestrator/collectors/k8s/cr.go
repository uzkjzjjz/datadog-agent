// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build kubeapiserver && orchestrator
// +build kubeapiserver,orchestrator

package k8s

import (
	"context"
	"github.com/DataDog/datadog-agent/pkg/orchestrator/config"
	v1 "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/dynamic/dynamiclister"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"
	"sync/atomic"

	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/cluster/orchestrator/collectors"
	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/cluster/orchestrator/processors"
	k8sProcessors "github.com/DataDog/datadog-agent/pkg/collector/corechecks/cluster/orchestrator/processors/k8s"
	"github.com/DataDog/datadog-agent/pkg/orchestrator"

	"k8s.io/client-go/dynamic/dynamicinformer"
)

// CRCollector is a collector for Kubernetes clusters.
type CRCollector struct {
	informers       map[string]informers.GenericInformer
	informerFactory dynamicinformer.DynamicSharedInformerFactory
	lister          dynamiclister.Lister
	metadata        *collectors.CollectorMetadata
	processor       *processors.Processor
}

// NewCRCollector creates a new collector for the Kubernetes Cluster
// resource.
func NewCRCollector() *CRCollector {
	return &CRCollector{
		metadata: &collectors.CollectorMetadata{
			IsStable: true,
			Name:     "crs",
			NodeType: orchestrator.K8sCR,
		},
		processor: processors.NewProcessor(new(k8sProcessors.CRHandlers)),
	}
}

// Informers returns the shared informers.
func (c *CRCollector) Informers() map[string]cache.SharedInformer {
	infs := make(map[string]cache.SharedInformer, len(c.informers))
	for gvr, informer := range c.informers {
		infs[gvr] = informer.Informer()
	}
	return infs
}

// Init is used to initialize the collector.
func (c *CRCollector) Init(rcfg *collectors.CollectorRunConfig) {
	// make GroupVersionResource configurable
	crs := config.GetCRsToCollect()
	println(crs)
	apiextensionsV1Client := v1.New(rcfg.APIClient.DiscoveryCl.RESTClient())
	customResourceDefinitions := apiextensionsV1Client.CustomResourceDefinitions()
	crds, err := customResourceDefinitions.List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return
	}
	// iterate through the crds and generate an informer per crd (given by the customer)
	for _, _ = range crds.Items {
		return
	}
	c.informerFactory = dynamicinformer.NewDynamicSharedInformerFactory(rcfg.APIClient.DynamicCl, 300)

	//c.informers[r.String()] = c.informerFactory.ForResource(r)
	//indexer := c.informers.Informer().GetIndexer()
	//c.lister = dynamiclister.New(indexer, r)
}

// IsAvailable returns whether the collector is available.
func (c *CRCollector) IsAvailable() bool { return true }

// Metadata is used to access information about the collector.
func (c *CRCollector) Metadata() *collectors.CollectorMetadata {
	return c.metadata
}

// Run triggers the collection process.
func (c *CRCollector) Run(rcfg *collectors.CollectorRunConfig) (*collectors.CollectorRunResult, error) {
	list, err := c.lister.List(labels.Everything())
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

	messages, processed := c.processor.Process(ctx, list)

	// This would happen when recovering from a processor panic. In the nominal
	// case we would have a positive integer set at the very end of processing.
	// If this is not the case then it means code execution stopped sooner.
	// Panic recovery will log more information about the error so we can figure
	// out the root cause.
	if processed == -1 {
		return nil, collectors.ErrProcessingPanic
	}

	// The cluster processor can return errors since it has to grab extra
	// information from the API server during processing.
	if err != nil {
		return nil, collectors.NewProcessingError(err)
	}

	result := &collectors.CollectorRunResult{
		Messages:           messages,
		ResourcesListed:    1,
		ResourcesProcessed: processed,
	}

	return result, nil
}
