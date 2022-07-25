package telemetry

import "go.uber.org/atomic"

const BackendMetric = "backend"

var All *metricIndex

type metricIndex struct {
	// HTTP Metrics
	HTTPHits1XX      *atomic.Int64 `stats:"",tag:"backend"`
	HTTPHits2XX      *atomic.Int64 `stats:"",tag:"backend"`
	HTTPHits3XX      *atomic.Int64 `stats:""`
	HTTPHits4XX      *atomic.Int64 `stats:""`
	HTTPHits5XX      *atomic.Int64 `stats:""`
	HTTPMisses       *atomic.Int64 `stats:""`
	HTTPDropped      *atomic.Int64 `stats:""`
	HTTPRejected     *atomic.Int64 `stats:""`
	HTTPMalformed    *atomic.Int64 `stats:""`
	HTTPAggregations *atomic.Int64 `stats:""`

	// DNS Metrics
	// ...
}

func Report(tags ...string) map[string]interface{} {
	return atomicstats.Report(All, tags)
}

func init() {
	All = &metricIndex{
		HTTPHits1XX:      atomic.NewInt64(0),
		HTTPHits2XX:      atomic.NewInt64(0),
		HTTPHits3XX:      atomic.NewInt64(0),
		HTTPHits4XX:      atomic.NewInt64(0),
		HTTPHits5XX:      atomic.NewInt64(0),
		HTTPMisses:       atomic.NewInt64(0),
		HTTPDropped:      atomic.NewInt64(0),
		HTTPRejected:     atomic.NewInt64(0),
		HTTPMalformed:    atomic.NewInt64(0),
		HTTPAggregations: atomic.NewInt64(0),
	}
}
