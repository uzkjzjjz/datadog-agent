// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build windows && npm
// +build windows,npm

package network

import (
	"golang.org/x/sys/windows"
)


/// expand above this to actually implement all the windows calls we need

/// for the test code
type TestDriverHandle struct {
	// store some state variables
	hasCalled		bool
	lastReturnBytes	uint32
	lastBufferSize  int
	lastError		error
}

func (tdh *TestDriverHandle) readFile(p []byte, bytesRead *uint32, ol *windows.Overlapped) error {
	// check state in struct to see if we've been called before
	if tdh.hasCalled {
		if tdh.lastReturnBytes == 0 && tdh.lastError == windows.ERROR_MORE_DATA	{
			// last time we returned empty but more...if caller does that twice in a row it's bad
			if len(p) <= tdh.lastBufferSize {
				os.panic()
			}
		}
}