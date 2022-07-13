// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build windows && npm
// +build windows,npm

package network

import (
	"fmt"
	"github.com/DataDog/datadog-agent/pkg/network/config"
	"github.com/DataDog/datadog-agent/pkg/network/driver"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/windows"
	"testing"
)

/// for the test code
type TestDriverHandleFail struct {
	// store some state variables
	hasCalled       bool
	lastReturnBytes uint32
	lastBufferSize  int
	lastError       error
}

func (tdh *TestDriverHandleFail) ReadFile(p []byte, bytesRead *uint32, ol *windows.Overlapped) error {
	// check state in struct to see if we've been called before
	if tdh.hasCalled {
		if tdh.lastReturnBytes == 0 && tdh.lastError == windows.ERROR_MORE_DATA {
			// last time we returned empty but more...if caller does that twice in a row it's bad
			if len(p) <= tdh.lastBufferSize {
				panic(fmt.Errorf("Consecutive calls"))
			}
		}
	}
	return nil
}

func (tdh *TestDriverHandleFail) GetWindowsHandle() windows.Handle {
	return windows.Handle(0)
}

func (tdh *TestDriverHandleFail) DeviceIoControl(ioControlCode uint32, inBuffer *byte, inBufferSize uint32, outBuffer *byte, outBufferSize uint32, bytesReturned *uint32, overlapped *windows.Overlapped) (err error) {
	fmt.Printf("Got test ioctl call")
	if ioControlCode != 0 {
		return fmt.Errorf("wrong ioctl code")
	}
	return nil
}

func (tdh *TestDriverHandleFail) CancelIoEx(ol *windows.Overlapped) error {
	return nil
}

func (tdh *TestDriverHandleFail) GetStatsForHandle() (map[string]map[string]int64, error) {
	return nil, nil
}
func (tdh *TestDriverHandleFail) Close() error {
	return nil
}

func NewFailHandle(flags uint32, handleType driver.HandleType) (driver.Handle, error) {
	return &TestDriverHandleFail{}, nil
}

func TestSetFlowFiltersFail(t *testing.T) {
	CreateDriverHandle = NewFailHandle

	_, err := NewDriverInterface(config.New())
	assert.Error(t, err, "Failed to create new driver interface")
}

/// for the test code
type TestDriverHandleSuccess struct {
	// store some state variables
	hasCalled       bool
	lastReturnBytes uint32
	lastBufferSize  int
	lastError       error

	numcalls		uint32
	minbuffersize   uint32
	maxbuffersize   uint32

	simulatednumberofflows uint32
}

func (tdh *TestDriverHandleSuccess) ReadFile(p []byte, bytesRead *uint32, ol *windows.Overlapped) error {
	// check state in struct to see if we've been called before
	
	tdh->numcalls++;

	// check size of p
	// figure out how many flows will fit
	// generate that many synthetic flows to copy in the buffer
	// copy as many as we can

	tdh->simulatednumberofflows -= <number we fit>

	// fill in as much of the buffer with flows as we can up to simulatednumberofflows
	// and return proper bytesread values


	if len(p) < tdh.minbuffersize {
		minbuffersize = len(p)
	}
	if len(p) > tdh.maxbuffersize {
		maxbuffersize = len(p)
	}
	return nil
}

func (tdh *TestDriverHandleSuccess) GetWindowsHandle() windows.Handle {
	return windows.Handle(0)
}

func (tdh *TestDriverHandleSuccess) DeviceIoControl(ioControlCode uint32, inBuffer *byte, inBufferSize uint32, outBuffer *byte, outBufferSize uint32, bytesReturned *uint32, overlapped *windows.Overlapped) (err error) {
	return nil
}

func (tdh *TestDriverHandleSuccess) CancelIoEx(ol *windows.Overlapped) error {
	return nil
}

func (tdh *TestDriverHandleSuccess) GetStatsForHandle() (map[string]map[string]int64, error) {
	return nil, nil
}
func (tdh *TestDriverHandleSuccess) Close() error {
	return nil
}

func NewSuccessHandle(flags uint32, handleType driver.HandleType) (driver.Handle, error) {
	return &TestDriverHandleSuccess{}, nil
}

func TestSetFlowFiltersSuccess(t *testing.T) {
	//CreateDriverHandle = NewSuccessHandle
	localtdh = &TestDriverHandleSuccess{}

	CreateDriverHandle =  func(flags uint32, handleType driver.HandleType)(driver.Handle, error) {
		return localtdh, nil
	}()

	di, err := NewDriverInterface(config.New())
	
	localtdh.simulatednumberofflows = 500

	di.GetConnectionStats()
	// use some member of di
	assert.NoError(t, err, "Failed to create new driver interface")

	assert.Equal(t, localtdh.numcalls, <expected number>,  "didn't call ReadFile expected number of times")
	assert.Equal(t, localtdh.minbuffersize, <expected size>, "smallest buffer not right")
	assert.Equal(t, localtdh.maxbuffersize, <expected size>, "smallest buffer not right")

	assert.Equal(t, len(di.readBuffer), <expected size>, "wrong ending buffer")
}
