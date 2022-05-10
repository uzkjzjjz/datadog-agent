// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build kubeapiserver && orchestrator
// +build kubeapiserver,orchestrator

package k8s

import (
	"context"
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

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/dynamicinformer"
)

// CRDCollector is a collector for Kubernetes clusters.
type CRDCollector struct {
	informer        informers.GenericInformer
	informerFactory dynamicinformer.DynamicSharedInformerFactory
	lister          dynamiclister.Lister
	metadata        *collectors.CollectorMetadata
	processor       *processors.Processor
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
		processor: processors.NewProcessor(new(k8sProcessors.CRDHandlers)),
	}
}

// Informer returns the shared informer.
func (c *CRDCollector) Informer() cache.SharedInformer {
	return c.informer.Informer()
}

/**
apiVersion: datadoghq.com/v1alpha1
kind: DatadogMetric
metadata:
  annotations:
    kubectl.kubernetes.io/last-applied-configuration: |
      {"apiVersion":"datadoghq.com/v1alpha1","kind":"DatadogMetric","metadata":{"annotations":{},"name":"orchestrator-intake-external-metric","namespace":"orchestrator"},"spec":{"query":"100*(ewma_10(max:kubernetes.cpu.usage.total{service:orchestrator-intake,datacenter:eu1.prod.dog,kube_cluster_name:spirou}))/(1000000000*avg:kubernetes.cpu.limits{service:orchestrator-intake,datacenter:eu1.prod.dog,kube_cluster_name:spirou})"}}
    meta.helm.sh/release-name: orchestrator-intake
    meta.helm.sh/release-namespace: orchestrator
  creationTimestamp: "2021-02-09T14:36:09Z"
  generation: 3
  labels:
    admission.datadoghq.com/mutate-pods: "true"
    admission.datadoghq.com/validate-pods: "true"
    admission.datadoghq.com/validate-services: "true"
    app.kubernetes.io/managed-by: Helm
  name: orchestrator-intake-external-metric
  namespace: orchestrator
  resourceVersion: "8162835308"
  uid: 1c171bfe-7d44-4096-8a07-14a2e0a06588
spec:
*/

// Init is used to initialize the collector.
func (c *CRDCollector) Init(rcfg *collectors.CollectorRunConfig) {
	// make GroupVersionResource configurable
	groupVersion := schema.GroupVersion{Group: "datadoghq.com", Version: "v1alpha1"}
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
	r := groupVersion.WithResource("datadogagents")

	c.informer = c.informerFactory.ForResource(r)
	indexer := c.informer.Informer().GetIndexer()
	c.lister = dynamiclister.New(indexer, r)
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
