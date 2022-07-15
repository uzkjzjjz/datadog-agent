// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-2020 Datadog, Inc.

package probe

import (
	"github.com/DataDog/datadog-agent/pkg/security/secl/compiler/eval"
)

// ProbeContext defines a probe context
type ProbeContext struct {
	Resolvers *Resolvers
}

// NewProbeContext returns a new probe context
func NewProbeContext(resolvers *Resolvers) *ProbeContext {
	return &ProbeContext{
		Resolvers: resolvers,
	}
}

// GetEvent return a Event from the eval.Context
func GetEvent(ctx *eval.Context) *Event {
	return ctx.Event.(*Event)
}
