// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build kubeapiserver && orchestrator
// +build kubeapiserver,orchestrator

package k8s

import (
	"context"
	"sync/atomic"

	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/cluster/orchestrator/collectors"
	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/cluster/orchestrator/processors"
	k8sProcessors "github.com/DataDog/datadog-agent/pkg/collector/corechecks/cluster/orchestrator/processors/k8s"
	"github.com/DataDog/datadog-agent/pkg/orchestrator"

	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	netv1Informers "k8s.io/client-go/informers/networking/v1"
	netv1Listers "k8s.io/client-go/listers/networking/v1"
	"k8s.io/client-go/tools/cache"
)

// IngressV1Collector is a collector for Kubernetes Ingresss.
type IngressV1Collector struct {
	informer    netv1Informers.IngressInformer
	lister      netv1Listers.IngressLister
	metadata    *collectors.CollectorMetadata
	processor   *processors.Processor
	retryLister func(ctx context.Context, opts metav1.ListOptions) (*netv1.IngressList, error)
}

// NewIngressV1Collector creates a new collector for the Kubernetes Ingress
// resource.
func NewIngressV1Collector() *IngressV1Collector {
	return &IngressV1Collector{
		metadata: &collectors.CollectorMetadata{
			IsDefaultVersion: true,
			IsStable:         false,
			Name:             "ingresses",
			NodeType:         orchestrator.K8sIngress,
			Version:          "networking.k8s.io/v1",
		},
		processor: processors.NewProcessor(new(k8sProcessors.IngressHandlers)),
	}
}

// Informer returns the shared informer.
func (c *IngressV1Collector) Informer() cache.SharedInformer {
	return c.informer.Informer()
}

// Init is used to initialize the collector.
func (c *IngressV1Collector) Init(rcfg *collectors.CollectorRunConfig) {
	c.informer = rcfg.APIClient.InformerFactory.Networking().V1().Ingresses()
	c.lister = c.informer.Lister()
}

// Metadata is used to access information about the collector.
func (c *IngressV1Collector) Metadata() *collectors.CollectorMetadata {
	return c.metadata
}

// Run triggers the collection process.
func (c *IngressV1Collector) Run(rcfg *collectors.CollectorRunConfig) (*collectors.CollectorRunResult, error) {
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
