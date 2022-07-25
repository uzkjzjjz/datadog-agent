package telemetry

import (
	"sync"
)

var r *repository

type repository struct {
	sync.Mutex
	metrics []*Metric
}

// GetMetrics returns all metrics matching a certain set of tags
// TODO: double-check if the result type plays well with JSON marshaling
// otherwise consider adding a `ReportJSON` method in exporters.go
func GetMetrics(tags ...[]string) []*Metric {
	filterIndex := make(map[string]struct{}, len(tags))
	for _, f := range filters {
		filterIndex[f] = struct{}{}
	}

	r.Lock()
	defer r.Unlock()
	result := make([]*Metric, 0, len(r.metrics))
	for _, m := range r.metrics {
		if matches(filterIndex, m) {
			result = append(result, m)
		}
	}

	return result
}

func matches(filters map[string]struct{}, metric *Metric) bool {
	var totalMatches int

	for _, tag := range metric.Tags {
		if _, ok := filters[tag]; ok {
			totalMatches++
			if totalMatches == len(filters) {
				return true
			}

		}
	}

	return false
}

func init() {
	r := &repository{
		metrics: make([]*Metric),
	}
}
