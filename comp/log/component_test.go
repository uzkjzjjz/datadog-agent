// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package log

import (
	"testing"

	"go.uber.org/fx"
	"go.uber.org/fx/fxtest"
)

func TestLogging(t *testing.T) {
	var log Logger
	app := fxtest.New(t,
		FxOption,
		fx.Populate(&log),
	)
	defer app.RequireStart().RequireStop()
	log.Debug("hello, world.")
	// TODO: assert that the log succeeded
}
