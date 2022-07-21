// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package log

import "github.com/DataDog/datadog-agent/pkg/util/log"

type logger struct{}

func NewLogger() Logger {
	return &logger{}
}

func (*logger) Debug(v ...interface{}) {
	log.Debug(v...)
}

func (*logger) Flush() {
	log.Flush()
}
