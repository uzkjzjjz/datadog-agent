// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux
// +build linux

package events

import "time"

// Event holds metadata about an event sent by system-probe
type Event struct {
	Name     string `json:"name"`
	Category string `json:"category"`
	Outcome  string `json:"outcome"`
}

// Executable holds information about the binary executed by a process
type Executable struct {
	Path string `json:"path"`
	Name string `json:"name"`
}

// Process holds metadata about a process
type Process struct {
	PID        int32      `json:"pid"`
	PPID       int32      `json:"ppid"`
	UID        int32      `json:"uid"`
	GID        int32      `json:"gid"`
	User       string     `json:"user"`
	Group      string     `json:"group"`
	ForkTime   time.Time  `json:"fork_time"`
	ExecTime   time.Time  `json:"exec_time"`
	Executable Executable `json:"executable"`
	Argv0      string     `json:"argv0"`
	Args       []string   `json:"args"`
}

// ProcessEvent represents a process event collected by system-probe
type ProcessEvent struct {
	Event   Event     `json:"evt"`
	Process Process   `json:"process"`
	Date    time.Time `json:"date"`
}
