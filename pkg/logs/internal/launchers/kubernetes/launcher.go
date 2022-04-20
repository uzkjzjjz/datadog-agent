// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build kubelet
// +build kubelet

package kubernetes

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/DataDog/datadog-agent/pkg/logs/auditor"
	"github.com/DataDog/datadog-agent/pkg/logs/config"
	"github.com/DataDog/datadog-agent/pkg/logs/internal/launchers"
	"github.com/DataDog/datadog-agent/pkg/logs/internal/util"
	"github.com/DataDog/datadog-agent/pkg/logs/internal/util/containersorpods"
	"github.com/DataDog/datadog-agent/pkg/logs/pipeline"
	"github.com/DataDog/datadog-agent/pkg/logs/service"
	"github.com/DataDog/datadog-agent/pkg/util/kubernetes/kubelet"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/DataDog/datadog-agent/pkg/workloadmeta"
	"github.com/cenkalti/backoff"
)

const (
	basePath      = "/var/log/pods"
	anyLogFile    = "*.log"
	anyV19LogFile = "%s_*.log"
)

var errCollectAllDisabled = fmt.Errorf("%s disabled", config.ContainerCollectAll)

type retryOps struct {
	service          *service.Service
	backoff          backoff.BackOff
	removalScheduled bool
}

// Launcher looks for new and deleted pods to create or delete one logs-source per container.
type Launcher struct {
	sources            *config.LogSources
	services           *service.Services
	cop                containersorpods.Chooser
	sourcesByContainer map[string]*config.LogSource
	stopped            chan struct{}
	retryOperations    chan *retryOps
	collectAll         bool
	pendingRetries     map[string]*retryOps
	serviceNameFunc    func(string, string) string // serviceNameFunc gets the service name from the tagger, it is in a separate field for testing purpose

	// ctx is the context for the running goroutine, set in Start
	ctx context.Context

	// cancel cancels the running goroutine
	cancel context.CancelFunc
}

// NewLauncher returns a new launcher.
func NewLauncher(sources *config.LogSources, services *service.Services, cop containersorpods.Chooser, collectAll bool) *Launcher {
	launcher := &Launcher{
		sources:            sources,
		services:           services,
		cop:                cop,
		sourcesByContainer: make(map[string]*config.LogSource),
		stopped:            make(chan struct{}),
		collectAll:         collectAll,
		pendingRetries:     make(map[string]*retryOps),
		retryOperations:    make(chan *retryOps),
		serviceNameFunc:    util.ServiceNameFromTags,
	}
	return launcher
}

// Start starts the launcher
func (l *Launcher) Start(sourceProvider launchers.SourceProvider, pipelineProvider pipeline.Provider, registry auditor.Registry) {
	// only start this launcher once it's determined that we should be logging containers, and not pods.
	l.ctx, l.cancel = context.WithCancel(context.Background())
	go l.run(sourceProvider, pipelineProvider, registry)
}

// Stop stops the launcher
func (l *Launcher) Stop() {
	if l.cancel != nil {
		l.cancel()
	}

	// only stop this launcher once it's determined that we should be logging
	// pods, and not containers, but do not block trying to find out.
	if l.cop.Get() == containersorpods.LogPods {
		l.stopped <- struct{}{}
	}
}

// run handles new and deleted pods,
// the kubernetes launcher consumes new and deleted services pushed by the autodiscovery
func (l *Launcher) run(sourceProvider launchers.SourceProvider, pipelineProvider pipeline.Provider, registry auditor.Registry) {
	// if we're not logging pods, then there's nothing to do
	if l.cop.Wait(l.ctx) != containersorpods.LogPods {
		return
	}

	log.Info("Starting Kubernetes launcher")
	addedServices := l.services.GetAllAddedServices()
	removedServices := l.services.GetAllRemovedServices()

	for {
		select {
		case service := <-addedServices:
			l.addSource(service)
		case service := <-removedServices:
			l.removeSource(service)
		case ops := <-l.retryOperations:
			l.addSource(ops.service)
		case <-l.stopped:
			log.Info("Kubernetes launcher stopped")
			return
		}
	}
}

func (l *Launcher) scheduleServiceForRetry(svc *service.Service) {
	containerID := svc.GetEntityID()
	ops, exists := l.pendingRetries[containerID]
	if !exists {
		b := &backoff.ExponentialBackOff{
			InitialInterval:     500 * time.Millisecond,
			RandomizationFactor: 0,
			Multiplier:          2,
			MaxInterval:         5 * time.Second,
			MaxElapsedTime:      30 * time.Second,
			Clock:               backoff.SystemClock,
		}
		b.Reset()
		ops = &retryOps{
			service:          svc,
			backoff:          b,
			removalScheduled: false,
		}
		l.pendingRetries[containerID] = ops
	}
	l.delayRetry(ops)
}

func (l *Launcher) delayRetry(ops *retryOps) {
	delay := ops.backoff.NextBackOff()
	if delay == backoff.Stop {
		log.Warnf("Unable to add source for container %v", ops.service.GetEntityID())
		delete(l.pendingRetries, ops.service.GetEntityID())
		return
	}
	go func() {
		<-time.After(delay)
		l.retryOperations <- ops
	}()
}

// addSource creates a new log-source from a service by resolving the
// pod linked to the entityID of the service
func (l *Launcher) addSource(svc *service.Service) {
	// If the container is already tailed, we don't do anything
	// That shoudn't happen
	if _, exists := l.sourcesByContainer[svc.GetEntityID()]; exists {
		log.Warnf("A source already exist for container %v", svc.GetEntityID())
		return
	}

	source, err := l.getSource(svc)
	if err != nil {
		if err != errCollectAllDisabled {
			log.Warnf("Invalid configuration for service %q: %v", svc.GetEntityID(), err)
		}
		return
	}

	switch svc.Type {
	case config.DockerType:
		source.SetSourceType(config.DockerSourceType)
	default:
		source.SetSourceType(config.KubernetesSourceType)
	}

	l.sourcesByContainer[svc.GetEntityID()] = source
	l.sources.AddSource(source)

	// Clean-up retry logic
	if ops, exists := l.pendingRetries[svc.GetEntityID()]; exists {
		if ops.removalScheduled {
			// A removal was emitted while addSource was being retried
			l.removeSource(ops.service)
		}
		delete(l.pendingRetries, svc.GetEntityID())
	}
}

// removeSource removes a new log-source from a service
func (l *Launcher) removeSource(service *service.Service) {
	containerID := service.GetEntityID()
	if ops, exists := l.pendingRetries[containerID]; exists {
		// Service was added unsuccessfully and is being retried
		ops.removalScheduled = true
		return
	}
	if source, exists := l.sourcesByContainer[containerID]; exists {
		delete(l.sourcesByContainer, containerID)
		l.sources.RemoveSource(source)
	}
}

// kubernetesIntegration represents the name of the integration.
const kubernetesIntegration = "kubernetes"

func (l *Launcher) getSource(svc *service.Service) (*config.LogSource, error) {
	containerID := svc.Identifier
	container, err := workloadmeta.GetGlobalStore().GetContainer(containerID)
	if err != nil {
		return nil, err
	}

	pod, err := workloadmeta.GetGlobalStore().GetKubernetesPodForContainer(containerID)
	if err != nil {
	}

	// TODO(juliogreff): we need an OrchestratorContainer, not a Container

	var cfg *config.LogsConfig

	if annotation := l.getAnnotation(container.Name, pod.Annotations); annotation != "" {
		configs, err := config.ParseJSON([]byte(annotation))
		if err != nil || len(configs) == 0 {
			return nil, fmt.Errorf("could not parse kubernetes annotation %v", annotation)
		}

		// We may have more than one log configuration in the annotation, ignore those
		// unrelated to containers
		containerType := string(container.Runtime)
		for _, c := range configs {
			if c.Type == "" || c.Type == containerType {
				cfg = c
				break
			}
		}

		if cfg == nil {
			log.Debugf("annotation found: %v, for pod %v, container %v, but no config was usable for container log collection", annotation, pod.Name, container.Name)
		}
	}

	standardService := l.serviceNameFunc(container.Name, getTaggerEntityID(containerID))

	if cfg == nil {
		if !l.collectAll {
			return nil, errCollectAllDisabled
		}
		// The logs source is the short image name
		logsSource := ""
		shortImageName := container.Image.ShortName
		if shortImageName == "" {
			log.Debugf("Couldn't get short image for container %q: empty ShortName", container.Name)
			// Fallback and use `kubernetes` as source name
			logsSource = kubernetesIntegration
		} else {
			logsSource = shortImageName
		}

		if standardService != "" {
			cfg = &config.LogsConfig{
				Source:  logsSource,
				Service: standardService,
			}
		} else {
			cfg = &config.LogsConfig{
				Source:  logsSource,
				Service: logsSource,
			}
		}
	}

	if cfg.Service == "" && standardService != "" {
		cfg.Service = standardService
	}

	cfg.Type = config.FileType
	cfg.Path = l.getPath(basePath, pod, container.Name)
	cfg.Identifier = container.ID
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid kubernetes annotation: %v", err)
	}

	sourceName := fmt.Sprintf("%s/%s/%s", pod.Namespace, pod.Name, container.Name)

	return config.NewLogSource(sourceName, cfg), nil
}

// getTaggerEntityID builds an entity ID from a kubernetes container ID
// Transforms the <runtime>:// prefix into container_id://
// Returns the original container ID if an error occurred
func getTaggerEntityID(ctrID string) string {
	taggerEntityID, err := kubelet.KubeContainerIDToTaggerEntityID(ctrID)
	if err != nil {
		log.Warnf("Could not get tagger entity ID: %v", err)
		return ctrID
	}
	return taggerEntityID
}

// configPath refers to the configuration that can be passed over a pod annotation,
// this feature is commonly named 'ad' or 'autodiscovery'.
// The pod annotation must respect the format: ad.datadoghq.com/<container_name>.logs: '[{...}]'.
const (
	configPathPrefix = "ad.datadoghq.com"
	configPathSuffix = "logs"
)

// getConfigPath returns the path of the logs-config annotation for container.
func (l *Launcher) getConfigPath(containerName string) string {
	return fmt.Sprintf("%s/%s.%s", configPathPrefix, containerName, configPathSuffix)
}

// getAnnotation returns the logs-config annotation for container if present.
// FIXME: Reuse the annotation logic from AD
func (l *Launcher) getAnnotation(containerName string, annotations map[string]string) string {
	configPath := l.getConfigPath(containerName)
	if annotation, exists := annotations[configPath]; exists {
		return annotation
	}
	return ""
}

// getPath returns a wildcard matching with any logs file of container in pod.
func (l *Launcher) getPath(basePath string, pod *workloadmeta.KubernetesPod, containerName string) string {
	// the pattern for container logs is different depending on the version of Kubernetes
	// so we need to try three possbile formats
	// until v1.9 it was `/var/log/pods/{pod_uid}/{container_name_n}.log`,
	// v.1.10 to v1.13 it was `/var/log/pods/{pod_uid}/{container_name}/{n}.log`,
	// since v1.14 it is `/var/log/pods/{pod_namespace}_{pod_name}_{pod_uid}/{container_name}/{n}.log`.
	// see: https://github.com/kubernetes/kubernetes/pull/74441 for more information.
	oldDirectory := filepath.Join(basePath, l.getPodDirectoryUntil1_13(pod))
	if _, err := os.Stat(oldDirectory); err == nil {
		v110Dir := filepath.Join(oldDirectory, containerName)
		_, err := os.Stat(v110Dir)
		if err == nil {
			log.Debugf("Logs path found for container %s, v1.13 >= kubernetes version >= v1.10", containerName)
			return filepath.Join(v110Dir, anyLogFile)
		}
		if !os.IsNotExist(err) {
			log.Debugf("Cannot get file info for %s: %v", v110Dir, err)
		}

		v19Files := filepath.Join(oldDirectory, fmt.Sprintf(anyV19LogFile, containerName))
		files, err := filepath.Glob(v19Files)
		if err == nil && len(files) > 0 {
			log.Debugf("Logs path found for container %s, kubernetes version <= v1.9", containerName)
			return v19Files
		}
		if err != nil {
			log.Debugf("Cannot get file info for %s: %v", v19Files, err)
		}
		if len(files) == 0 {
			log.Debugf("Files matching %s not found", v19Files)
		}
	}

	log.Debugf("Using the latest kubernetes logs path for container %s", containerName)
	return filepath.Join(basePath, l.getPodDirectorySince1_14(pod), containerName, anyLogFile)
}

// getPodDirectoryUntil1_13 returns the name of the directory of pod containers until Kubernetes v1.13.
func (l *Launcher) getPodDirectoryUntil1_13(pod *workloadmeta.KubernetesPod) string {
	return pod.ID
}

// getPodDirectorySince1_14 returns the name of the directory of pod containers since Kubernetes v1.14.
func (l *Launcher) getPodDirectorySince1_14(pod *workloadmeta.KubernetesPod) string {
	return fmt.Sprintf("%s_%s_%s", pod.Namespace, pod.Name, pod.ID)
}
