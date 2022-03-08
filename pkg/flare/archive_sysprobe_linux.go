//  Unless explicitly stated otherwise all files in this repository are licensed
//  under the Apache License Version 2.0.
//  This product includes software developed at Datadog (https://www.datadoghq.com/).
//  Copyright 2016-present Datadog, Inc.

package flare

import "github.com/DataDog/datadog-agent/pkg/util/log"

func zipSysprobePlatformFiles(tempDir string, hostname string) error {
	err := zipLinuxKernelSymbols(tempDir, hostname)
	if err != nil {
		return err
	}

	err = zipLinuxPid1MountInfo(tempDir, hostname)
	if err != nil {
		return err
	}

	err = zipLinuxKrobeEvents(tempDir, hostname)
	if err != nil {
		log.Infof("Error while getting kprobe_events: %s", err)
	}

	err = zipLinuxKprobeProfile(tempDir, hostname)
	if err != nil {
		log.Infof("Error while getting kprobe_profile: %s", err)
	}

	err = zipLinuxTracingAvailableEvents(tempDir, hostname)
	if err != nil {
		log.Infof("Error while getting available_events: %s", err)
	}

	err = zipLinuxTracingAvailableFilterFunctions(tempDir, hostname)
	if err != nil {
		log.Infof("Error while getting available_filter_functions: %s", err)
	}

	err = zipLinuxKernelConfig(tempDir, hostname)
	if err != nil {
		log.Infof("Error while getting kernel config: %s", err)
	}

	return nil
}
