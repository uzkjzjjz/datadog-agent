// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build !kubelet
// +build !kubelet

package kubernetes

import (
	"github.com/DataDog/datadog-agent/pkg/logs/schedulers"
)

// Scheduler is not supported on no kubelet environment
type Scheduler struct{}

var _ schedulers.Scheduler = &Scheduler{}

// New returns a new scheduler.
func New() *Scheduler {
	return &Scheduler{}
}

// Start implements schedulers.Scheduler#Start.
func (s *Scheduler) Start(sourceMgr schedulers.SourceManager) {}

// Stop implements schedulers.Scheduler#Stop.
func (s *Scheduler) Stop() {}
