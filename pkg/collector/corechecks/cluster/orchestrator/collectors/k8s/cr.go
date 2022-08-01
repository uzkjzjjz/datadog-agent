// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build kubeapiserver && orchestrator
// +build kubeapiserver,orchestrator

package k8s

import (
	model "github.com/DataDog/agent-payload/v5/process"
	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/cluster/orchestrator/collectors"
	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/cluster/orchestrator/processors"
	k8sProcessors "github.com/DataDog/datadog-agent/pkg/collector/corechecks/cluster/orchestrator/processors/k8s"
	"github.com/DataDog/datadog-agent/pkg/orchestrator"
	"github.com/DataDog/datadog-agent/pkg/orchestrator/config"
	"github.com/spf13/cast"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/dynamiclister"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"

	"k8s.io/client-go/dynamic/dynamicinformer"
)

// CRCollector is a collector for Kubernetes clusters.
type CRCollector struct {
	informers       map[string]informers.GenericInformer
	informerFactory dynamicinformer.DynamicSharedInformerFactory
	listers         map[string]dynamiclister.Lister
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
		informers: map[string]informers.GenericInformer{},
		listers:   map[string]dynamiclister.Lister{},
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
	// TODO: add message if activated but non collected
	crs := config.GetCRsToCollect()
	grvs := convertToGRV(crs)
	// iterate through the crds and generate an informer per crd (given by the customer)
	c.informerFactory = dynamicinformer.NewDynamicSharedInformerFactory(rcfg.APIClient.DynamicCl, 300)

	for _, grv := range grvs {
		informer := c.informerFactory.ForResource(grv)
		c.informers[grv.String()] = informer
		indexer := informer.Informer().GetIndexer()
		c.listers[grv.String()] = dynamiclister.New(indexer, grv)
	}

}

func convertToGRV(i interface{}) []schema.GroupVersionResource {
	var grvs []schema.GroupVersionResource
	slice := cast.ToSlice(i)
	for _, v := range slice {
		e, err := cast.ToStringMapStringE(v)
		if err != nil {
			return nil
		}
		grvs = append(grvs, schema.GroupVersionResource{
			Group:    e["group"],
			Version:  e["version"],
			Resource: e["resource"],
		})
	}

	return grvs
}

// IsAvailable returns whether the collector is available.
func (c *CRCollector) IsAvailable() bool { return true }

// Metadata is used to access information about the collector.
func (c *CRCollector) Metadata() *collectors.CollectorMetadata {
	return c.metadata
}

// Run triggers the collection process.
func (c *CRCollector) Run(rcfg *collectors.CollectorRunConfig) (*collectors.CollectorRunResult, error) {
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
			MsgGroupID: rcfg.MsgGroupRef.Inc(),
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
