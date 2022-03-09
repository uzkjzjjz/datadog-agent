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
	"strings"
	"time"

	"github.com/DataDog/datadog-agent/pkg/autodiscovery/integration"
	coreConfig "github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/errors"
	"github.com/DataDog/datadog-agent/pkg/logs/config"
	"github.com/DataDog/datadog-agent/pkg/logs/internal/util"
	"github.com/DataDog/datadog-agent/pkg/logs/internal/util/adlistener"
	"github.com/DataDog/datadog-agent/pkg/logs/schedulers"
	"github.com/DataDog/datadog-agent/pkg/logs/service"
	"github.com/DataDog/datadog-agent/pkg/util/containers"
	"github.com/DataDog/datadog-agent/pkg/util/kubernetes/kubelet"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/DataDog/datadog-agent/pkg/util/retry"
	"github.com/cenkalti/backoff"
)

const (
	basePath      = "/var/log/pods"
	anyLogFile    = "*.log"
	anyV19LogFile = "%s_*.log"
)

var errCollectAllDisabled = fmt.Errorf("%s disabled", config.ContainerCollectAll)

type retryOps struct {
	cfg              integration.Config
	backoff          backoff.BackOff
	removalScheduled bool
}

// kubeUtilGetter is the type of kubelet.GetKubeUtilWithRetrier, here so that
// tests can substitute a fake version.
type kubeUtilGetter func() (kubelet.KubeUtilInterface, *retry.Retrier)

// Scheduler monitors for new and removed services (containers).  It consults
// the corresponding pods for AD annotations, parsing them if found and
// creating log sources with type=File.
//
// If container_collect_all is enabled, then log sources are also generated for
// un-annotated containers.
type Scheduler struct {
	// mgr is the SourceManager to which we will send new sources. It is set in Start()
	mgr schedulers.SourceManager

	// listener handles listening for Schedule and Unschedule's from the AD MetaScheduler
	listener *adlistener.ADListener

	// stop is closed when the background goroutine should stop
	stop chan struct{}

	// stopped is closed whent he background goroutine has stopped
	stopped chan struct{}

	// collectAll reflects the logs_config.container_collect_all config
	collectAll bool

	// scheduled carries configs scheduled by the AD MetaScheduler
	scheduled chan []integration.Config

	// unscheduled carries configs uns heduled byt he AD MetaScheduler
	unscheduled chan []integration.Config

	// sourcesByContainer holds the sources created by this scheduler, keyed by
	// the service ID.
	sourcesByContainer map[string]*config.LogSource

	// kubeutil is the active interface to kubelet.  This is set in the `run()` goroutine.
	kubeutil kubelet.KubeUtilInterface

	// retryOperations carries services for which schedule should be retried after failure.
	// Values are added to this channel when they should be retried.
	retryOperations chan *retryOps

	// pendingRetries contains all schedule operations that are still being retried.
	pendingRetries map[string]*retryOps

	// serviceNameFunc returns the standard tag 'service' corresponding to a
	// container It returns an empty string if tag not found.  This is
	// `util.ServiceNameFromTags` but wrapped in a function pointer to support
	// testing.
	serviceNameFunc func(containerName, serviceID string) string
}

var _ schedulers.Scheduler = &Scheduler{}

// New creates a new scheduler.
func New() schedulers.Scheduler {
	// if this scheduler is not enabled, return an empty object that will do nothing.
	if util.DockerOrKubernetes() != coreConfig.Kubernetes {
		return &Scheduler{}
	}

	return new()
}

func new() *Scheduler {
	collectAll := coreConfig.Datadog.GetBool("logs_config.container_collect_all")
	scheduled := make(chan []integration.Config, 1)
	unscheduled := make(chan []integration.Config, 1)
	sch := &Scheduler{
		listener: adlistener.NewADListener("logs-agent Kubernetes scheduler",
			func(configs []integration.Config) { scheduled <- configs },
			func(configs []integration.Config) { unscheduled <- configs }),
		stop:               make(chan struct{}),
		stopped:            make(chan struct{}),
		collectAll:         collectAll,
		scheduled:          scheduled,
		unscheduled:        unscheduled,
		sourcesByContainer: make(map[string]*config.LogSource),
		retryOperations:    make(chan *retryOps),
		pendingRetries:     make(map[string]*retryOps),
		serviceNameFunc:    util.ServiceNameFromTags,
	}
	return sch
}

// Start implements schedulers.Scheduler#Start.
func (s *Scheduler) Start(sourceMgr schedulers.SourceManager) {
	s.mgr = sourceMgr
	if s.listener != nil {
		log.Info("Starting Kubernetes log scheduler")
		s.listener.StartListener()
		go s.run()
	}
}

// Stop implements schedulers.Scheduler#Stop.
func (s *Scheduler) Stop() {
	if s.listener != nil {
		log.Info("Stopping Kubernetes log scheduler")
		s.listener.StopListener()
		close(s.stop)
		<-s.stopped
	}
	s.mgr = nil
}

func (s *Scheduler) run() {
	defer func() { close(s.stopped) }()

	s.kubeutil = s.getKubeUtil(nil)
	if s.kubeutil == nil {
		// the scheduler has been stopped, so bail out
		return
	}

	// handle adding/removing services and retries in the same loop, avoiding
	// the need to synchronize data structures.
	for {
		select {
		case configs := <-s.scheduled:
			for _, config := range configs {
				s.schedule(config)
			}
		case configs := <-s.unscheduled:
			for _, config := range configs {
				s.unschedule(config)
			}
		case ops := <-s.retryOperations:
			s.schedule(ops.cfg)
		case <-s.stop:
			log.Info("Kubernetes log scheduler stopped")
			return
		}
	}
}

// getKubeUtil gets a KubeUtil instance, retrying as necessary.  If s.stop is closed,
// it will return nil.
func (s *Scheduler) getKubeUtil(getter kubeUtilGetter) kubelet.KubeUtilInterface {
	if getter == nil {
		getter = kubelet.GetKubeUtilWithRetrier
	}
	for {
		kubeutil, retrier := getter()
		if kubeutil != nil {
			return kubeutil
		}

		retryAfter := time.After(time.Until(retrier.NextRetry()))

		select {
		case <-retryAfter:
		case <-s.stop:
			return nil
		}
	}
}

// toService creates a new service for an integrationConfig.
func (s *Scheduler) toService(config integration.Config) (*service.Service, error) {
	provider, identifier, err := s.parseServiceID(config.ServiceID)
	if err != nil {
		return nil, err
	}
	return service.NewService(provider, identifier), nil
}

// parseEntity breaks down an entity into a service provider and a service identifier.
func (s *Scheduler) parseEntity(entity string) (string, string, error) {
	components := strings.Split(entity, containers.EntitySeparator)
	if len(components) != 2 {
		return "", "", fmt.Errorf("entity is malformed : %v", entity)
	}
	return components[0], components[1], nil
}

// parseServiceID breaks down an AD service ID, assuming it is formatted
// as `something://something-else`, into its consituent parts.
func (s *Scheduler) parseServiceID(serviceID string) (string, string, error) {
	components := strings.Split(serviceID, containers.EntitySeparator)
	if len(components) != 2 {
		return "", "", fmt.Errorf("service ID does not have the form `xxx://yyy`: %v", serviceID)
	}
	return components[0], components[1], nil
}

func (s *Scheduler) scheduleForRetry(cfg integration.Config) {
	containerID := cfg.ServiceID
	ops, exists := s.pendingRetries[containerID]
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
			cfg:              cfg,
			backoff:          b,
			removalScheduled: false,
		}
		s.pendingRetries[containerID] = ops
	}
	s.delayRetry(ops)
}

func (s *Scheduler) delayRetry(ops *retryOps) {
	delay := ops.backoff.NextBackOff()
	if delay == backoff.Stop {
		log.Warnf("Unable to add source for container %v", ops.cfg.ServiceID)
		delete(s.pendingRetries, ops.cfg.ServiceID)
		return
	}
	go func() {
		<-time.After(delay)
		s.retryOperations <- ops
	}()
}

// schedule handles configs scheduled by the AD MetaScheduler.  It is called in
// the run() goroutine and can access scheduler data structures without
// locking.
func (s *Scheduler) schedule(cfg integration.Config) {
	if !cfg.IsLogConfig() {
		return
	}
	if cfg.HasFilter(containers.LogsFilter) {
		return
	}

	// if this is not a service config, ignore it, as the AD logs scheduler will
	// handle it
	if cfg.Provider != "" || cfg.ServiceID == "" {
		return
	}

	entityType, _, err := s.parseEntity(cfg.TaggerEntity)
	if err != nil {
		log.Warnf("Invalid service: %v", err)
		return
	}
	// logs only consider container services
	if entityType != containers.ContainerEntityName {
		return
	}
	svc, err := s.toService(cfg)
	if err != nil {
		log.Warnf("Invalid service: %v", err)
		return
	}

	// If the container is already tailed, we don't do anything
	// That shoudn't happen
	if _, exists := s.sourcesByContainer[svc.GetEntityID()]; exists {
		log.Warnf("A source already exist for container %v", svc.GetEntityID())
		return
	}

	pod, err := s.kubeutil.GetPodForEntityID(context.TODO(), svc.GetEntityID())
	if err != nil {
		if errors.IsRetriable(err) {
			// Attempt to reschedule the source later
			log.Debugf("Failed to fetch pod info for container %v, will retry: %v", svc.Identifier, err)
			s.scheduleForRetry(cfg)
			return
		}
		log.Warnf("Could not add source for container %v: %v", svc.Identifier, err)
		return
	}
	container, err := s.kubeutil.GetStatusForContainerID(pod, svc.GetEntityID())
	if err != nil {
		log.Warn(err)
		return
	}
	source, err := s.getSource(pod, container)
	if err != nil {
		if err != errCollectAllDisabled {
			log.Warnf("Invalid configuration for pod %v, container %v: %v", pod.Metadata.Name, container.Name, err)
		}
		return
	}

	switch svc.Type {
	case config.DockerType:
		source.SetSourceType(config.DockerSourceType)
	default:
		source.SetSourceType(config.KubernetesSourceType)
	}

	s.sourcesByContainer[svc.GetEntityID()] = source
	s.mgr.AddSource(source)

	// Clean-up retry logic
	if ops, exists := s.pendingRetries[svc.GetEntityID()]; exists {
		if ops.removalScheduled {
			// A removal was emitted while scheduling was being retried
			s.unschedule(ops.cfg)
		}
		delete(s.pendingRetries, svc.GetEntityID())
	}
}

// unschedule handles configs unscheduled by the AD MetaScheduler.  It is
// called in the run() goroutine and can access scheduler data structures
// without locking.
func (s *Scheduler) unschedule(cfg integration.Config) {
	if !cfg.IsLogConfig() || cfg.HasFilter(containers.LogsFilter) {
		return
	}

	// if this is not a service config, ignore it, as the AD logs scheduler will
	// handle it
	if cfg.Provider != "" || cfg.ServiceID == "" {
		return
	}

	// new service to remove
	entityType, _, err := s.parseEntity(cfg.TaggerEntity)
	if err != nil {
		log.Warnf("Invalid service: %v", err)
		return
	}
	// logs only consider container services
	if entityType != containers.ContainerEntityName {
		return
	}
	svc, err := s.toService(cfg)
	if err != nil {
		log.Warnf("Invalid service: %v", err)
		return
	}

	containerID := svc.GetEntityID()
	if ops, exists := s.pendingRetries[containerID]; exists {
		// Service was added unsuccessfully and is being retried
		ops.removalScheduled = true
		return
	}
	if source, exists := s.sourcesByContainer[containerID]; exists {
		delete(s.sourcesByContainer, containerID)
		s.mgr.RemoveSource(source)
	}
}

// kubernetesIntegration represents the name of the integration.
const kubernetesIntegration = "kubernetes"

// getSource returns a new source for the container in pod.
func (s *Scheduler) getSource(pod *kubelet.Pod, container kubelet.ContainerStatus) (*config.LogSource, error) {
	var cfg *config.LogsConfig
	standardService := s.serviceNameFunc(container.Name, getTaggerEntityID(container.ID))
	if annotation := s.getAnnotation(pod, container); annotation != "" {
		configs, err := config.ParseJSON([]byte(annotation))
		if err != nil || len(configs) == 0 {
			return nil, fmt.Errorf("could not parse kubernetes annotation %v", annotation)
		}
		// We may have more than one log configuration in the annotation, ignore those
		// unrelated to containers
		containerType, _ := containers.SplitEntityName(container.ID)
		for _, c := range configs {
			if c.Type == "" || c.Type == containerType {
				cfg = c
				break
			}
		}
		if cfg == nil {
			log.Debugf("annotation found: %v, for pod %v, container %v, but no config was usable for container log collection", annotation, pod.Metadata.Name, container.Name)
		}
	}

	if cfg == nil {
		if !s.collectAll {
			return nil, errCollectAllDisabled
		}
		// The logs source is the short image name
		logsSource := ""
		shortImageName, err := s.getShortImageName(pod, container.Name)
		if err != nil {
			log.Debugf("Couldn't get short image for container '%s': %v", container.Name, err)
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
	cfg.Path = s.getPath(basePath, pod, container)
	cfg.Identifier = kubelet.TrimRuntimeFromCID(container.ID)
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid kubernetes annotation: %v", err)
	}

	return config.NewLogSource(s.getSourceName(pod, container), cfg), nil
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
func (s *Scheduler) getConfigPath(container kubelet.ContainerStatus) string {
	return fmt.Sprintf("%s/%s.%s", configPathPrefix, container.Name, configPathSuffix)
}

// getAnnotation returns the logs-config annotation for container if present.
// FIXME: Reuse the annotation logic from AD
func (s *Scheduler) getAnnotation(pod *kubelet.Pod, container kubelet.ContainerStatus) string {
	configPath := s.getConfigPath(container)
	if annotation, exists := pod.Metadata.Annotations[configPath]; exists {
		return annotation
	}
	return ""
}

// getSourceName returns the source name of the container to tail.
func (s *Scheduler) getSourceName(pod *kubelet.Pod, container kubelet.ContainerStatus) string {
	return fmt.Sprintf("%s/%s/%s", pod.Metadata.Namespace, pod.Metadata.Name, container.Name)
}

// getPath returns a wildcard matching with any logs file of container in pod.
func (s *Scheduler) getPath(basePath string, pod *kubelet.Pod, container kubelet.ContainerStatus) string {
	// the pattern for container logs is different depending on the version of Kubernetes
	// so we need to try three possbile formats
	// until v1.9 it was `/var/log/pods/{pod_uid}/{container_name_n}.log`,
	// v.1.10 to v1.13 it was `/var/log/pods/{pod_uid}/{container_name}/{n}.log`,
	// since v1.14 it is `/var/log/pods/{pod_namespace}_{pod_name}_{pod_uid}/{container_name}/{n}.log`.
	// see: https://github.com/kubernetes/kubernetes/pull/74441 for more information.
	oldDirectory := filepath.Join(basePath, s.getPodDirectoryUntil1_13(pod))
	if _, err := os.Stat(oldDirectory); err == nil {
		v110Dir := filepath.Join(oldDirectory, container.Name)
		_, err := os.Stat(v110Dir)
		if err == nil {
			log.Debugf("Logs path found for container %s, v1.13 >= kubernetes version >= v1.10", container.Name)
			return filepath.Join(v110Dir, anyLogFile)
		}
		if !os.IsNotExist(err) {
			log.Debugf("Cannot get file info for %s: %v", v110Dir, err)
		}

		v19Files := filepath.Join(oldDirectory, fmt.Sprintf(anyV19LogFile, container.Name))
		files, err := filepath.Glob(v19Files)
		if err == nil && len(files) > 0 {
			log.Debugf("Logs path found for container %s, kubernetes version <= v1.9", container.Name)
			return v19Files
		}
		if err != nil {
			log.Debugf("Cannot get file info for %s: %v", v19Files, err)
		}
		if len(files) == 0 {
			log.Debugf("Files matching %s not found", v19Files)
		}
	}

	log.Debugf("Using the latest kubernetes logs path for container %s", container.Name)
	return filepath.Join(basePath, s.getPodDirectorySince1_14(pod), container.Name, anyLogFile)
}

// getPodDirectoryUntil1_13 returns the name of the directory of pod containers until Kubernetes v1.13.
func (s *Scheduler) getPodDirectoryUntil1_13(pod *kubelet.Pod) string {
	return pod.Metadata.UID
}

// getPodDirectorySince1_14 returns the name of the directory of pod containers since Kubernetes v1.14.
func (s *Scheduler) getPodDirectorySince1_14(pod *kubelet.Pod) string {
	return fmt.Sprintf("%s_%s_%s", pod.Metadata.Namespace, pod.Metadata.Name, pod.Metadata.UID)
}

// getShortImageName returns the short image name of a container
func (s *Scheduler) getShortImageName(pod *kubelet.Pod, containerName string) (string, error) {
	containerSpec, err := s.kubeutil.GetSpecForContainerName(pod, containerName)
	if err != nil {
		return "", err
	}
	_, shortName, _, err := containers.SplitImageName(containerSpec.Image)
	if err != nil {
		log.Debugf("Cannot parse image name: %v", err)
	}
	return shortName, err
}
