// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package log

import "go.uber.org/fx"

// Logger is a component for sending messages to a log file.
type Logger interface {
	// Debug logs at the debug level
	Debug(v ...interface{})

	// Flush flushes the underlying inner log
	Flush()

	// ..more methods, obviously :)
}

// FxOption defines the fx options for this component.
var FxOption fx.Option = fx.Provide(NewLogger)
