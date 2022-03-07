// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package testutil

import (
	"os/exec"
	"strings"

	"github.com/stretchr/testify/require"
)

type tHelper interface {
	Helper()
}

// RunCommands runs each command in cmds individually and returns the output
// as a []string, with each element corresponding to the respective command.
// If ignoreErrors is true, it will fail the test via t.Fatal immediately upon error.
// Otherwise, the output on errors will be logged via t.Log.
func RunCommands(t require.TestingT, cmds []string, ignoreErrors bool) []string {
	if v, ok := t.(tHelper); ok {
		v.Helper()
	}
	var output []string

	for _, c := range cmds {
		args := strings.Split(c, " ")
		c := exec.Command(args[0], args[1:]...)
		out, err := c.CombinedOutput()
		output = append(output, string(out))
		if err != nil && !ignoreErrors {
			t.Errorf("%s returned %s: %s", c, err, out)
			t.FailNow()
			return nil
		}
	}
	return output
}
