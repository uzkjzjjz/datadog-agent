// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package checks

import (
	"os/exec"
	"strings"

	model "github.com/DataDog/agent-payload/v5/process"
	"github.com/DataDog/datadog-agent/pkg/process/procutil"
	"github.com/davecgh/go-spew/spew"
)

func getProcessTags(probe procutil.Probe, pid int32, cmd *model.Command) ([]string, error) {
	if !strings.HasSuffix(cmd.Exe, "/java") {
		return nil, nil
	}

	env, err := probe.EnvironForPid(pid)
	if err == nil {
		if ver, ok := env["JAVA_VERSION"]; ok {
			return []string{"jvm_version:" + ver}, nil
		}
	}

	command := exec.Command(cmd.Exe, "-version")

	out, err := command.CombinedOutput()
	if err != nil {
		return nil, err
	}

	spew.Dump(out)

	ver := strings.Split(string(out), "\n")[0]
	return []string{"jvm_version:" + ver}, nil
}
