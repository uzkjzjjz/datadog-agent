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
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/DataDog/datadog-agent/pkg/autodiscovery/integration"
	"github.com/DataDog/datadog-agent/pkg/errors"
	"github.com/DataDog/datadog-agent/pkg/logs/config"
	"github.com/DataDog/datadog-agent/pkg/logs/schedulers"
	"github.com/DataDog/datadog-agent/pkg/util/kubernetes/kubelet"
	"github.com/DataDog/datadog-agent/pkg/util/retry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetPath(t *testing.T) {
	scheduler := getScheduler(true)
	container := kubelet.ContainerStatus{
		Name:  "foo",
		Image: "bar",
		ID:    "boo",
	}
	pod := &kubelet.Pod{
		Metadata: kubelet.PodMetadata{
			Name:      "fuz",
			Namespace: "buu",
			UID:       "baz",
		},
	}

	basePath, err := ioutil.TempDir("", "")
	defer os.RemoveAll(basePath)
	assert.Nil(t, err)

	// v1.14+ (default)
	podDirectory := "buu_fuz_baz"
	path := scheduler.getPath(basePath, pod, container)
	assert.Equal(t, filepath.Join(basePath, podDirectory, "foo", "*.log"), path)

	// v1.10 - v1.13
	podDirectory = "baz"
	containerDirectory := "foo"

	err = os.MkdirAll(filepath.Join(basePath, podDirectory, containerDirectory), 0777)
	assert.Nil(t, err)

	path = scheduler.getPath(basePath, pod, container)
	assert.Equal(t, filepath.Join(basePath, podDirectory, "foo", "*.log"), path)

	// v1.9
	os.RemoveAll(basePath)
	podDirectory = "baz"
	logFile := "foo_1.log"

	err = os.MkdirAll(filepath.Join(basePath, podDirectory), 0777)
	assert.Nil(t, err)

	_, err = os.Create(filepath.Join(basePath, podDirectory, logFile))
	assert.Nil(t, err)

	path = scheduler.getPath(basePath, pod, container)
	assert.Equal(t, filepath.Join(basePath, podDirectory, "foo_*.log"), path)
}

// Test that getSource correctly assigns the Service and Source fields
func TestGetSourceServiceNameOrder(t *testing.T) {
	tests := []struct {
		name            string
		sFunc           func(string, string) string
		pod             *kubelet.Pod
		container       kubelet.ContainerStatus
		wantServiceName string
		wantSourceName  string
		wantErr         bool
	}{
		{
			name:  "log config",
			sFunc: func(n, e string) string { return "stdServiceName" },
			pod: &kubelet.Pod{
				Metadata: kubelet.PodMetadata{
					Name:      "podName",
					Namespace: "podNamespace",
					UID:       "podUIDFoo",
					Annotations: map[string]string{
						"ad.datadoghq.com/fooName.logs": `[{"source":"foo","service":"annotServiceName"}]`,
					},
				},
			},
			container: kubelet.ContainerStatus{
				Name:  "fooName",
				Image: "fooImage",
				ID:    "docker://fooID",
			},
			wantServiceName: "annotServiceName",
			wantSourceName:  "foo",
			wantErr:         false,
		},
		{
			name:  "standard tags",
			sFunc: func(n, e string) string { return "stdServiceName" },
			pod: &kubelet.Pod{
				Metadata: kubelet.PodMetadata{
					Name:      "podName",
					Namespace: "podNamespace",
					UID:       "podUIDFoo",
					Annotations: map[string]string{
						"ad.datadoghq.com/fooName.logs": `[{"source":"foo"}]`,
					},
				},
			},
			container: kubelet.ContainerStatus{
				Name:  "fooName",
				Image: "fooImage",
				ID:    "docker://fooID",
			},
			wantServiceName: "stdServiceName",
			wantSourceName:  "foo",
			wantErr:         false,
		},
		{
			name:  "standard tags, undefined source, use image as source",
			sFunc: func(n, e string) string { return "stdServiceName" },
			pod: &kubelet.Pod{
				Metadata: kubelet.PodMetadata{
					Name:      "podName",
					Namespace: "podNamespace",
					UID:       "podUIDFoo",
				},
				Spec: kubelet.Spec{
					Containers: []kubelet.ContainerSpec{{
						Name:  "fooName",
						Image: "fooImage",
					}},
				},
			},
			container: kubelet.ContainerStatus{
				Name:  "fooName",
				Image: "fooImage",
				ID:    "docker://fooID",
			},
			wantServiceName: "stdServiceName",
			wantSourceName:  "fooImage",
			wantErr:         false,
		},
		{
			name:  "image name",
			sFunc: func(n, e string) string { return "" },
			pod: &kubelet.Pod{
				Metadata: kubelet.PodMetadata{
					Name:      "podName",
					Namespace: "podNamespace",
					UID:       "podUIDFoo",
				},
				Spec: kubelet.Spec{
					Containers: []kubelet.ContainerSpec{{
						Name:  "fooName",
						Image: "fooImage",
					}},
				},
			},
			container: kubelet.ContainerStatus{
				Name:  "fooName",
				Image: "fooImage",
				ID:    "docker://fooID",
			},
			wantServiceName: "fooImage",
			wantSourceName:  "fooImage",
			wantErr:         false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &Scheduler{
				collectAll:      true,
				kubeutil:        kubelet.NewKubeUtil(),
				serviceNameFunc: tt.sFunc,
			}
			got, err := l.getSource(tt.pod, tt.container)
			if (err != nil) != tt.wantErr {
				t.Errorf("Launcher.getSource() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assert.Equal(t, tt.wantServiceName, got.Config.Service)
			assert.Equal(t, tt.wantSourceName, got.Config.Source)
		})
	}
}

func TestGetShortImageName(t *testing.T) {
	tests := []struct {
		name          string
		pod           *kubelet.Pod
		containerName string
		wantImageName string
		wantErr       bool
	}{
		{
			name: "standard",
			pod: &kubelet.Pod{
				Spec: kubelet.Spec{
					Containers: []kubelet.ContainerSpec{{
						Name:  "fooName",
						Image: "fooImage",
					}},
				},
			},
			containerName: "fooName",
			wantImageName: "fooImage",
			wantErr:       false,
		},
		{
			name: "empty",
			pod: &kubelet.Pod{
				Spec: kubelet.Spec{
					Containers: []kubelet.ContainerSpec{{
						Name:  "fooName",
						Image: "",
					}},
				},
			},
			containerName: "fooName",
			wantImageName: "",
			wantErr:       true,
		},
		{
			name: "with prefix",
			pod: &kubelet.Pod{
				Spec: kubelet.Spec{
					Containers: []kubelet.ContainerSpec{{
						Name:  "fooName",
						Image: "org/fooImage:tag",
					}},
				},
			},
			containerName: "fooName",
			wantImageName: "fooImage",
			wantErr:       false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := getScheduler(true)

			got, err := l.getShortImageName(tt.pod, tt.containerName)
			if got != tt.wantImageName {
				t.Errorf("Launcher.getShortImageName() = %s, want %s", got, tt.wantImageName)
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("Launcher.getShortImageName() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestRetryGettingKubeUtilStops(t *testing.T) {
	s := &Scheduler{stop: make(chan struct{})}

	retryForever := func() (kubelet.KubeUtilInterface, *retry.Retrier) {
		return nil, fastRetrier()
	}

	got := make(chan kubelet.KubeUtilInterface)
	go func() {
		got <- s.getKubeUtil(retryForever)
	}()

	close(s.stop)
	require.Nil(t, <-got)
}

func TestRetryGettingKubeUtilSuccess(t *testing.T) {
	s := &Scheduler{stop: make(chan struct{})}

	var tries int
	retryAFewTimes := func() (kubelet.KubeUtilInterface, *retry.Retrier) {
		tries++
		if tries > 3 {
			return dummyKubeUtil{}, nil
		}
		return nil, fastRetrier()
	}

	require.NotNil(t, s.getKubeUtil(retryAFewTimes))
}

func TestRetryService(t *testing.T) {
	containerName := "fooName"
	containerType := "docker"
	containerID := "123456789abcdefoo"
	imageName := "fooImage"
	serviceName := "fooService"
	serviceID := fmt.Sprintf("%s://%s", containerType, containerID)
	taggerEntity := fmt.Sprintf("%s://%s", "container_id", containerID)

	mgr := &schedulers.MockSourceManager{}
	l := &Scheduler{
		collectAll:         true,
		kubeutil:           dummyKubeUtil{shouldRetryGetPod: true},
		pendingRetries:     make(map[string]*retryOps),
		retryOperations:    make(chan *retryOps),
		serviceNameFunc:    func(n, e string) string { return serviceName },
		mgr:                mgr,
		sourcesByContainer: make(map[string]*config.LogSource),
	}

	l.schedule(integration.Config{
		LogsConfig:   []byte("{}"),
		ServiceID:    serviceID,
		TaggerEntity: taggerEntity,
	})

	ops := <-l.retryOperations

	assert.Equal(t, serviceID, ops.cfg.ServiceID)
	assert.Equal(t, taggerEntity, ops.cfg.TaggerEntity)

	status := kubelet.ContainerStatus{
		Name:  containerName,
		Image: imageName,
		ID:    containerID,
		Ready: true,
		State: kubelet.ContainerState{},
	}
	spec := kubelet.ContainerSpec{
		Name:  containerName,
		Image: imageName,
	}
	pod := kubelet.Pod{
		Metadata: kubelet.PodMetadata{},
		Spec: kubelet.Spec{
			Containers: []kubelet.ContainerSpec{{
				Name:  containerName,
				Image: imageName,
			}},
		},
	}
	l.kubeutil = dummyKubeUtil{status: status, spec: spec, pod: pod}

	mu := sync.Mutex{}
	mu.Lock()
	defer mu.Unlock()
	go func() {
		l.schedule(ops.cfg)
		mu.Unlock()
	}()
	// Ensure l.schedule is completely done
	mu.Lock()

	require.Equal(t, 1, len(mgr.Events))
	require.True(t, mgr.Events[0].Add)
	source := mgr.Events[0].Source

	assert.Equal(t, 1, len(l.sourcesByContainer))

	assert.Equal(t, containerID, source.Config.Identifier)
	assert.Equal(t, serviceName, source.Config.Service)
	assert.Equal(t, imageName, source.Config.Source)

	assert.Equal(t, 0, len(l.pendingRetries))
	assert.Equal(t, 1, len(l.sourcesByContainer))
}

func TestScheduleConfig(t *testing.T) {
	makeScheduler := func() (*Scheduler, *dummyKubeUtil, *schedulers.MockSourceManager) {
		sch := new()
		kubeutil := &dummyKubeUtil{}
		sch.kubeutil = kubeutil
		mgr := &schedulers.MockSourceManager{}
		sch.mgr = mgr
		return sch, kubeutil, mgr
	}

	emptyLogsConfig := []byte("{}")
	serviceID := "evergiven://abcd1234"
	taggerEntity := "container_id://abcd1234"

	t.Run("failure/not a log config", func(t *testing.T) {
		sch, _, mgr := makeScheduler()
		sch.schedule(integration.Config{})
		require.Equal(t, 0, len(mgr.Events))
	})

	t.Run("failure/logs excluded", func(t *testing.T) {
		sch, _, mgr := makeScheduler()
		sch.schedule(integration.Config{LogsConfig: emptyLogsConfig, LogsExcluded: true})
		require.Equal(t, 0, len(mgr.Events))
	})

	t.Run("failure/not a service", func(t *testing.T) {
		sch, _, mgr := makeScheduler()
		sch.schedule(integration.Config{
			LogsConfig: emptyLogsConfig,
			ServiceID:  serviceID,
			Provider:   "mysql",
		})
		require.Equal(t, 0, len(mgr.Events))
	})

	t.Run("failure/bad tagger entity", func(t *testing.T) {
		sch, _, mgr := makeScheduler()
		sch.schedule(integration.Config{
			LogsConfig:   emptyLogsConfig,
			ServiceID:    serviceID,
			TaggerEntity: "INVALID",
		})
		require.Equal(t, 0, len(mgr.Events))
	})

	t.Run("failure/wrong tagger entity type", func(t *testing.T) {
		sch, _, mgr := makeScheduler()
		sch.schedule(integration.Config{
			LogsConfig:   emptyLogsConfig,
			ServiceID:    serviceID,
			TaggerEntity: "ecs_task://foo",
		})
		require.Equal(t, 0, len(mgr.Events))
	})

	t.Run("failure/bad service ID", func(t *testing.T) {
		sch, _, mgr := makeScheduler()
		sch.schedule(integration.Config{
			LogsConfig:   emptyLogsConfig,
			ServiceID:    "INVALID",
			TaggerEntity: taggerEntity,
		})
		require.Equal(t, 0, len(mgr.Events))
	})

	t.Run("failure/source already exists", func(t *testing.T) {
		sch, _, mgr := makeScheduler()
		sch.sourcesByContainer[serviceID] = &config.LogSource{}
		sch.schedule(integration.Config{
			LogsConfig:   emptyLogsConfig,
			ServiceID:    serviceID,
			TaggerEntity: taggerEntity,
		})
		require.Equal(t, 0, len(mgr.Events))
	})

	t.Run("failure/GetPodForEntityID fails", func(t *testing.T) {
		sch, ku, mgr := makeScheduler()
		ku.shouldFailGetPod = true
		sch.schedule(integration.Config{
			LogsConfig:   emptyLogsConfig,
			ServiceID:    serviceID,
			TaggerEntity: taggerEntity,
		})
		require.Equal(t, 0, len(mgr.Events))
	})

	t.Run("failure/GetStatusForContainerID fails", func(t *testing.T) {
		sch, ku, mgr := makeScheduler()
		ku.shouldFailGetStatus = true
		sch.schedule(integration.Config{
			LogsConfig:   emptyLogsConfig,
			ServiceID:    serviceID,
			TaggerEntity: taggerEntity,
		})
		require.Equal(t, 0, len(mgr.Events))
	})

	t.Run("failure/Invalid annotations", func(t *testing.T) {
		sch, ku, mgr := makeScheduler()
		sch.collectAll = true
		ku.status = kubelet.ContainerStatus{
			Name:  "foo",
			Image: "bar",
			ID:    "boo",
		}
		ku.pod = kubelet.Pod{
			Metadata: kubelet.PodMetadata{
				Name:      "fuz",
				Namespace: "buu",
				UID:       "baz",
				Annotations: map[string]string{
					// missing [ ]
					"ad.datadoghq.com/foo.logs": `{"source":"any_source","service":"any_service","tags":["tag1","tag2"]}`,
				},
			},
		}
		sch.schedule(integration.Config{
			LogsConfig:   emptyLogsConfig,
			ServiceID:    serviceID,
			TaggerEntity: taggerEntity,
		})
		require.Equal(t, 0, len(mgr.Events))
	})

	t.Run("success/un-annotated container", func(t *testing.T) {
		setup := func(cca bool) (*Scheduler, *dummyKubeUtil, *schedulers.MockSourceManager) {
			sch, ku, mgr := makeScheduler()
			sch.collectAll = cca
			ku.status = kubelet.ContainerStatus{
				Name:  "foo",
				Image: "bar",
				ID:    "boo",
			}
			ku.spec = kubelet.ContainerSpec{
				Name:  "foo",
				Image: "bar",
			}
			ku.pod = kubelet.Pod{
				Metadata: kubelet.PodMetadata{
					Name:      "fuz",
					Namespace: "buu",
					UID:       "baz",
				},
			}
			return sch, ku, mgr
		}
		t.Run("container_collect_all enabled", func(t *testing.T) {
			sch, _, mgr := setup(true)
			sch.schedule(integration.Config{
				LogsConfig:   emptyLogsConfig,
				ServiceID:    serviceID,
				TaggerEntity: taggerEntity,
			})
			require.Equal(t, 1, len(mgr.Events))
			require.True(t, mgr.Events[0].Add)
			src := mgr.Events[0].Source
			require.Equal(t, config.FileType, src.Config.Type)
			require.Equal(t, "buu/fuz/foo", src.Name)
			assert.Equal(t, "/var/log/pods/buu_fuz_baz/foo/*.log", filepath.ToSlash(src.Config.Path))
			require.Equal(t, "boo", src.Config.Identifier)
			require.Equal(t, "bar", src.Config.Source)
			require.Equal(t, "bar", src.Config.Service)
		})

		t.Run("container_collect_all disabled", func(t *testing.T) {
			sch, _, mgr := setup(false)
			sch.schedule(integration.Config{
				LogsConfig:   emptyLogsConfig,
				ServiceID:    serviceID,
				TaggerEntity: taggerEntity,
			})
			require.Equal(t, 0, len(mgr.Events))
		})
	})

	t.Run("success/container_collect_all overridden by AD annotations", func(t *testing.T) {
		sch, ku, mgr := makeScheduler()
		sch.collectAll = true
		ku.status = kubelet.ContainerStatus{
			Name:  "foo",
			Image: "bar",
			ID:    "boo",
		}
		ku.pod = kubelet.Pod{
			Metadata: kubelet.PodMetadata{
				Name:      "fuz",
				Namespace: "buu",
				UID:       "baz",
				Annotations: map[string]string{
					"ad.datadoghq.com/foo.logs": `[{"source":"custom_src","service":"custom_svc","tags":["tag1","tag2"]}]`,
				},
			},
		}
		sch.schedule(integration.Config{
			LogsConfig:   emptyLogsConfig,
			ServiceID:    serviceID,
			TaggerEntity: taggerEntity,
		})
		require.Equal(t, 1, len(mgr.Events))
		require.True(t, mgr.Events[0].Add)
		src := mgr.Events[0].Source
		require.Equal(t, config.FileType, src.Config.Type)
		require.Equal(t, "buu/fuz/foo", src.Name)
		require.Equal(t, "/var/log/pods/buu_fuz_baz/foo/*.log", filepath.ToSlash(src.Config.Path))
		require.Equal(t, "boo", src.Config.Identifier)
		require.Equal(t, "custom_src", src.Config.Source)
		require.Equal(t, "custom_svc", src.Config.Service)
		require.ElementsMatch(t, []string{"tag1", "tag2"}, src.Config.Tags)
	})
}

func TestUnscheduleConfig(t *testing.T) {
	makeScheduler := func() (*Scheduler, *dummyKubeUtil, *schedulers.MockSourceManager) {
		sch := new()
		kubeutil := &dummyKubeUtil{}
		sch.kubeutil = kubeutil
		mgr := &schedulers.MockSourceManager{}
		sch.mgr = mgr
		return sch, kubeutil, mgr
	}

	emptyLogsConfig := []byte("{}")
	serviceID := "evergiven://abcd1234"
	taggerEntity := "container_id://abcd1234"

	t.Run("failure/not a log config", func(t *testing.T) {
		sch, _, mgr := makeScheduler()
		sch.unschedule(integration.Config{})
		require.Equal(t, 0, len(mgr.Events))
	})

	t.Run("failure/logs excluded", func(t *testing.T) {
		sch, _, mgr := makeScheduler()
		sch.unschedule(integration.Config{LogsConfig: emptyLogsConfig, LogsExcluded: true})
		require.Equal(t, 0, len(mgr.Events))
	})

	t.Run("failure/not a service", func(t *testing.T) {
		sch, _, mgr := makeScheduler()
		sch.unschedule(integration.Config{
			LogsConfig: emptyLogsConfig,
			ServiceID:  serviceID,
			Provider:   "mysql",
		})
		require.Equal(t, 0, len(mgr.Events))
	})

	t.Run("failure/bad tagger entity", func(t *testing.T) {
		sch, _, mgr := makeScheduler()
		sch.unschedule(integration.Config{
			LogsConfig:   emptyLogsConfig,
			ServiceID:    serviceID,
			TaggerEntity: "INVALID",
		})
		require.Equal(t, 0, len(mgr.Events))
	})

	t.Run("failure/wrong tagger entity type", func(t *testing.T) {
		sch, _, mgr := makeScheduler()
		sch.unschedule(integration.Config{
			LogsConfig:   emptyLogsConfig,
			ServiceID:    serviceID,
			TaggerEntity: "ecs_task://foo",
		})
		require.Equal(t, 0, len(mgr.Events))
	})

	t.Run("failure/bad service ID", func(t *testing.T) {
		sch, _, mgr := makeScheduler()
		sch.unschedule(integration.Config{
			LogsConfig:   emptyLogsConfig,
			ServiceID:    "INVALID",
			TaggerEntity: taggerEntity,
		})
		require.Equal(t, 0, len(mgr.Events))
	})

	t.Run("failure/source not found", func(t *testing.T) {
		sch, _, mgr := makeScheduler()
		sch.unschedule(integration.Config{
			LogsConfig:   emptyLogsConfig,
			ServiceID:    serviceID,
			TaggerEntity: taggerEntity,
		})
		require.Equal(t, 0, len(mgr.Events))
	})

	t.Run("failure/source being retried", func(t *testing.T) {
		sch, _, mgr := makeScheduler()
		sch.pendingRetries[serviceID] = &retryOps{removalScheduled: false}
		sch.unschedule(integration.Config{
			LogsConfig:   emptyLogsConfig,
			ServiceID:    serviceID,
			TaggerEntity: taggerEntity,
		})
		require.Equal(t, 0, len(mgr.Events))
		require.True(t, true, sch.pendingRetries[serviceID].removalScheduled)
	})

	t.Run("success/source exists", func(t *testing.T) {
		sch, _, mgr := makeScheduler()
		sch.sourcesByContainer[serviceID] = &config.LogSource{}
		sch.unschedule(integration.Config{
			LogsConfig:   emptyLogsConfig,
			ServiceID:    serviceID,
			TaggerEntity: taggerEntity,
		})
		require.Equal(t, 1, len(mgr.Events))
		require.False(t, mgr.Events[0].Add)
		require.Equal(t, 0, len(sch.sourcesByContainer))
	})
}

type dummyKubeUtil struct {
	shouldFailGetStatus bool
	status              kubelet.ContainerStatus

	shouldFailGetSpec bool
	spec              kubelet.ContainerSpec

	shouldRetryGetPod bool
	shouldFailGetPod  bool
	pod               kubelet.Pod

	// embed a nil interface for all of the other methods not defined here
	kubelet.KubeUtilInterface
}

func (d dummyKubeUtil) GetStatusForContainerID(pod *kubelet.Pod, containerID string) (kubelet.ContainerStatus, error) {
	if d.shouldFailGetStatus {
		return kubelet.ContainerStatus{}, fmt.Errorf("uhoh")
	}
	return d.status, nil
}

func (d dummyKubeUtil) GetSpecForContainerName(pod *kubelet.Pod, containerName string) (kubelet.ContainerSpec, error) {
	if d.shouldFailGetSpec {
		return kubelet.ContainerSpec{}, fmt.Errorf("uhoh")
	}
	return d.spec, nil
}

func (d dummyKubeUtil) GetPodForEntityID(ctx context.Context, entityID string) (*kubelet.Pod, error) {
	if d.shouldRetryGetPod {
		return nil, errors.NewRetriable("dummy error", fmt.Errorf("retriable error"))
	}
	if d.shouldFailGetPod {
		return nil, fmt.Errorf("uhoh")
	}
	return &d.pod, nil
}

func getScheduler(collectAll bool) *Scheduler {
	k := kubelet.NewKubeUtil()
	return &Scheduler{
		collectAll:      collectAll,
		kubeutil:        k,
		serviceNameFunc: func(string, string) string { return "" },
	}
}

func fastRetrier() *retry.Retrier {
	retr := &retry.Retrier{}
	retr.SetupRetrier(&retry.Config{
		Strategy:          retry.Backoff,
		InitialRetryDelay: 1 * time.Millisecond,
		MaxRetryDelay:     1 * time.Millisecond,
	})
	return retr
}
