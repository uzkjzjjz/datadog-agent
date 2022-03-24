// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package util

import "github.com/DataDog/datadog-agent/pkg/config"

// set in testing to force the result of CcaUseBareConfigs
var forcedCcaUseBareConfigs *bool

// ForceCcaUseBareConfigs forces a choice for CcaUseBareConfigs, and returns
// a function to revert the change, suitable for use in a `defer`.
func ForceCcaUseBareConfigs(use bool) func() {
	forcedCcaUseBareConfigs = &use
	return func() {
		forcedCcaUseBareConfigs = nil
	}
}

// CcaUseBareConfigs returns the value of the logs_config.cca_use_bare_configs
// feature flag.  This is temporary, as this functionality will eventually be
// the only option.
func CcaUseBareConfigs() bool {
	if forcedCcaUseBareConfigs != nil {
		return *forcedCcaUseBareConfigs
	}

	return config.Datadog.GetBool("logs_config.cca_use_bare_configs")
}
