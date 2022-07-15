// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux
// +build linux

package probe

import (
	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
	"github.com/DataDog/datadog-agent/pkg/security/secl/rules"
	jwriter "github.com/mailru/easyjson/jwriter"
)

// Event defines a probe version of an Event
type Event struct {
	model.Event

	Resolvers *Resolvers
}

// EventHandler represents an handler for the events sent by the probe
type EventHandler interface {
	HandleEvent(probeContext *ProbeContext, event *model.Event)
	HandleCustomEvent(rule *rules.Rule, event *CustomEvent)
}

// RuleHandler is called when there is a rule handler
type RuleHandler interface {
	OnRuleMatch(rule *rules.Rule, event *Event, service string, extTagsCb func() []string)
}

// String returns string representation of the event
func (e *Event) String() string {
	d, err := e.MarshalJSON()
	if err != nil {
		return err.Error()
	}
	return string(d)
}

// MarshalJSON returns the JSON encoding of the event
func (e *Event) MarshalJSON() ([]byte, error) {
	s := NewEventSerializer(e.ProbeContext, e.ModelEvent)
	w := &jwriter.Writer{
		Flags: jwriter.NilSliceAsEmpty | jwriter.NilMapAsEmpty,
	}
	s.MarshalEasyJSON(w)
	return w.BuildBytes()
}
