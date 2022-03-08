//  Unless explicitly stated otherwise all files in this repository are licensed
//  under the Apache License Version 2.0.
//  This product includes software developed at Datadog (https://www.datadoghq.com/).
//  Copyright 2016-present Datadog, Inc.

package flare

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/DataDog/datadog-agent/pkg/status"

	"github.com/DataDog/datadog-agent/pkg/util"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/mholt/archiver/v3"
)

// CreateSystemProbeArchive packages up the files
func CreateSystemProbeArchive(local bool, logFilePath string, ipcError error, status map[string]interface{}) (string, error) {
	zipFilePath := getArchivePath()

	tempDir, err := createTempDir()
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tempDir)

	// Get hostname, if there's an error in getting the hostname,
	// set the hostname to unknown
	hostname, err := util.GetHostname(context.TODO())
	if err != nil {
		hostname = "unknown"
	}
	hostname = cleanDirectoryName(hostname)

	if local {
		err = writeLocal(tempDir, hostname)
		if err != nil {
			return "", err
		}

		if ipcError != nil {
			msg := []byte(fmt.Sprintf("unable to contact the system-probe to retrieve flare: %s", ipcError))
			// Can't reach the system-probe, mention it in those two files
			err = writeStatusFile(tempDir, hostname, msg)
			if err != nil {
				return "", err
			}
		} else {
			err = writeStatusFile(tempDir, hostname, []byte("unable to get the status of the system-probe, is it running?"))
			if err != nil {
				return "", err
			}
		}
	} else {
		// The Status will be unavailable unless the agent is running.
		// Only zip it up if the agent is running
		err = zipSystemProbeStatusFile(tempDir, hostname, status)
		if err != nil {
			log.Infof("Error getting the status of the system-probe, %q", err)
			return "", err
		}
	}

	permsInfos := make(permissionsInfos)

	err = zipLogFiles(tempDir, hostname, logFilePath, permsInfos)
	if err != nil {
		return "", err
	}

	err = zipConfigFiles(tempDir, hostname, SearchPaths{}, permsInfos)
	if err != nil {
		return "", err
	}

	err = zipExpVar(tempDir, hostname)
	if err != nil {
		return "", err
	}

	err = zipEnvvars(tempDir, hostname)
	if err != nil {
		return "", err
	}

	err = zipSysprobePlatformFiles(tempDir, hostname)
	if err != nil {
		return "", err
	}

	err = permsInfos.commit(tempDir, hostname, os.ModePerm)
	if err != nil {
		log.Infof("Error while creating permissions.log infos file: %s", err)
	}

	// File format is determined based on `zipFilePath` extension
	err = archiver.Archive([]string{filepath.Join(tempDir, hostname)}, zipFilePath)
	if err != nil {
		return "", err
	}

	return zipFilePath, nil
}

func zipSystemProbeStatusFile(tempDir, hostname string, spStatus map[string]interface{}) error {
	// Grab the status
	log.Infof("Zipping the status at %s for %s", tempDir, hostname)
	s, err := status.GetAndFormatSystemProbeStatus(spStatus)
	if err != nil {
		log.Infof("Error zipping the status: %q", err)
		return err
	}

	// Clean it up
	cleaned, err := flareScrubber.ScrubBytes(s)
	if err != nil {
		log.Infof("Error redacting the log files: %q", err)
		return err
	}

	f := filepath.Join(tempDir, hostname, "system-probe-status.log")
	log.Infof("Flare status made at %s", tempDir)
	err = ensureParentDirsExist(f)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(f, cleaned, os.ModePerm)
	return err
}
