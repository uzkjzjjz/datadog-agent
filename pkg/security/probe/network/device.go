// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux
// +build linux

package network

import manager "github.com/DataDog/ebpf-manager"

// NetDeviceKey is used to uniquely identify a network device
type NetDeviceKey struct {
	IfIndex          uint32
	NetNS            uint32
	NetworkDirection manager.TrafficType
}
