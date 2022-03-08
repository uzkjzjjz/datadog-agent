//  Unless explicitly stated otherwise all files in this repository are licensed
//  under the Apache License Version 2.0.
//  This product includes software developed at Datadog (https://www.datadoghq.com/).
//  Copyright 2016-present Datadog, Inc.

package agent

import (
	"net/http"

	"github.com/DataDog/datadog-agent/cmd/system-probe/api/module"
	"github.com/DataDog/datadog-agent/pkg/flare"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/gorilla/mux"
)

// Agent handles REST API calls
type Agent struct{}

// New returns a new Agent
func New() *Agent {
	return nil
}

// SetupHandlers adds the specific handlers for /agent endpoints
func (a *Agent) SetupHandlers(r *mux.Router) {
	r.HandleFunc("/flare", a.makeFlare).Methods(http.MethodPost)
}

func (a *Agent) makeFlare(w http.ResponseWriter, r *http.Request) {
	log.Infof("Making a flare")
	logFile := ""
	status := module.GetStatus()

	filePath, err := flare.CreateSystemProbeArchive(false, logFile, nil, status)
	if err != nil || filePath == "" {
		if err != nil {
			log.Errorf("The flare failed to be created: %s", err)
		} else {
			log.Warnf("The flare failed to be created")
		}
		http.Error(w, err.Error(), 500)
	}
	w.Write([]byte(filePath))
}
