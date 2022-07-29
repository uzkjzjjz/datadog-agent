// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf
// +build linux_bpf

package http

import (
	"errors"
	"unsafe"

	"github.com/cilium/ebpf"
)

/*
#include "../ebpf/c/http-types.h"
*/
import "C"

var errLostBatch = errors.New("http batch lost (not consumed fast enough)")

type batchManager struct {
	numCPUs       int
	offsetManager *offsetManager
	batchReader   *batchReader
	workerPool    *workerPool
}

func newBatchManager(batchMap, batchStateMap *ebpf.Map, numCPUs int) *batchManager {
	// Initialize eBPF maps
	batch := new(httpBatch)
	state := new(C.http_batch_state_t)
	for i := 0; i < numCPUs; i++ {
		batchStateMap.Put(unsafe.Pointer(&i), unsafe.Pointer(state))
		for j := 0; j < HTTPBatchPages; j++ {
			key := &httpBatchKey{cpu: C.uint(i), page_num: C.uint(j)}
			batchMap.Put(unsafe.Pointer(key), unsafe.Pointer(batch))
		}
	}

	offsetManager := newOffsetManager(numCPUs)
	batchReader := newBatchReader(offsetManager, batchMap)
	workerPool := newWorkerPool(16)

	return &batchManager{
		numCPUs:       numCPUs,
		offsetManager: offsetManager,
		batchReader:   batchReader,
		workerPool:    workerPool,
	}
}

func (m *batchManager) ProcessBatchAsync(notification httpNotification, callback func([]httpTX, error)) {
	m.workerPool.Do(func() {
		callback(m.batchReader.Read(notification, false))
	})
}

func (m *batchManager) ProcessAllBatchesSync(callback func([]httpTX, error)) {
	result := make([]httpTX, 0, HTTPBatchSize*HTTPBatchPages/2)
	for i := 0; i < m.numCPUs; i++ {
		batchID := m.offsetManager.NextBatchID(i)
		notification := httpNotification{cpu: C.uint(i), batch_idx: C.ulonglong(batchID)}
		transactions, _ := m.batchReader.Read(notification, true)
		result = append(result, transactions...)
	}

	callback(result, nil)
}
