// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux
// +build linux

package probe

import (
	"github.com/DataDog/datadog-agent/pkg/security/probe/network"
	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
	manager "github.com/DataDog/ebpf-manager"
)

// TimeResolver converts kernel monotonic timestamps to absolute times
type NetworkResolver struct {
	ifNames map[network.NetDeviceKey]string
}

// NewTimeResolver returns a new time resolver
func NewNetworkResolver() *NetworkResolver {
	return &NetworkResolver{
		ifNames: make(map[network.NetDeviceKey]string),
	}
}

// AddIfName add an IfName
func (n *NetworkResolver) AddIfName(key network.NetDeviceKey, ifName string) {
	n.ifNames[key] = ifName
}

// DelIfName del an IfName
func (n *NetworkResolver) DelIfName(key network.NetDeviceKey) {
	delete(n.ifNames, key)
}

// ResolveNetworkDeviceIfName returns the network interface name from the network context
func (n *NetworkResolver) ResolveIfName(device *model.NetworkDeviceContext) string {
	key := network.NetDeviceKey{
		NetNS:            device.NetNS,
		IfIndex:          device.IfIndex,
		NetworkDirection: manager.Egress,
	}

	return n.ifNames[key]
}
