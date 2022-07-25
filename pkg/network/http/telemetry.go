// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf
// +build linux_bpf

package http

import (
	"fmt"
	"time"

	"github.com/DataDog/datadog-agent/pkg/network/stats"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"go.uber.org/atomic"
)

type telemetry struct {
	then    int64
	elapsed int64

	hits1XX, hits2XX, hits3XX, hits4XX, hits5XX *atomic.Int64
	misses                                      *atomic.Int64 // this happens when we can't cope with the rate of events
	dropped                                     *atomic.Int64 // this happens when httpStatKeeper reaches capacity
	rejected                                    *atomic.Int64 // this happens when an user-defined reject-filter matches a request
	malformed                                   *atomic.Int64 // this happens when the request doesn't have the expected format
	aggregations                                *atomic.Int64
}

func newTelemetry() (*telemetry, error) {
	t := &telemetry{
		then:         time.Now().Unix(),
		hits1XX:      telemetry.All.HTTPHits1XX,
		hits2XX:      telemetry.All.HTTPHits2XX,
		hits3XX:      telemetry.All.HTTPHits3XX,
		hits4XX:      telemetry.All.HTTPHits4XX,
		hits5XX:      telemetry.All.HTTPHits5XX,
		misses:       telemetry.All.HTTPMisses,
		dropped:      telemetry.All.HTTPDropped,
		rejected:     telemetry.All.HTTPRejected,
		malformed:    telemetry.All.HTTPMalformed,
		aggregations: telemetry.All.HTTPAggregations,
	}

	var err error
	t.reporter, err = stats.NewReporter(t)
	if err != nil {
		return nil, fmt.Errorf("error creating stats reporter: %w", err)
	}

	return t, nil
}

func (t *telemetry) aggregate(txs []httpTX, err error) {
	for _, tx := range txs {
		switch tx.StatusClass() {
		case 100:
			t.hits1XX.Add(1)
		case 200:
			t.hits2XX.Add(1)
		case 300:
			t.hits3XX.Add(1)
		case 400:
			t.hits4XX.Add(1)
		case 500:
			t.hits5XX.Add(1)
		}
	}

	if err == errLostBatch {
		atomic.AddInt64(&t.misses, int64(HTTPBatchSize))
	}
}

func (t *telemetry) reset() telemetry {
	now := time.Now().Unix()
	then := atomic.SwapInt64(&t.then, now)

	delta, _ := newTelemetry()
	delta.hits1XX = atomic.SwapInt64(&t.hits1XX, 0)
	delta.hits2XX = atomic.SwapInt64(&t.hits2XX, 0)
	delta.hits3XX = atomic.SwapInt64(&t.hits3XX, 0)
	delta.hits4XX = atomic.SwapInt64(&t.hits4XX, 0)
	delta.hits5XX = atomic.SwapInt64(&t.hits5XX, 0)
	delta.misses = atomic.SwapInt64(&t.misses, 0)
	delta.dropped = atomic.SwapInt64(&t.dropped, 0)
	delta.rejected = atomic.SwapInt64(&t.rejected, 0)
	delta.malformed = atomic.SwapInt64(&t.malformed, 0)
	delta.aggregations = atomic.SwapInt64(&t.aggregations, 0)
	delta.elapsed = now - then

	totalRequests := delta.hits1XX + delta.hits2XX + delta.hits3XX + delta.hits4XX + delta.hits5XX
	log.Debugf(
		"http stats summary: requests_processed=%d(%.2f/s) requests_missed=%d(%.2f/s) requests_dropped=%d(%.2f/s) requests_rejected=%d(%.2f/s) requests_malformed=%d(%.2f/s) aggregations=%d",
		totalRequests,
		float64(totalRequests)/float64(delta.elapsed),
		delta.misses,
		float64(delta.misses)/float64(delta.elapsed),
		delta.dropped,
		float64(delta.dropped)/float64(delta.elapsed),
		delta.rejected,
		float64(delta.rejected)/float64(delta.elapsed),
		delta.malformed,
		float64(delta.malformed)/float64(delta.elapsed),
		delta.aggregations,
	)

	return *delta
}
