package telemetry

import "github.com/DataDog/datadog-go/v5/statsd"

const (
	ReportStatsd    = "report:statsd"
	ReportExpvar    = "report:expvar"
	ReportTelemetry = "report:telemetry"

	// common prefix used across all statsd metric
	statsdPrefix = "datadog.system_probe.network_tracer."
)

// ReportStatsd flushes all metrics tagged with `ReportStatsd` using the given `statsdClient`
// TODOS:
// * Consider replacing argument by package-level client
// * Consider infering metric type using tags (eg. type:gauge/type:counter)
func ReportStatsd(statsdClient statsd.ClientInterface) {
	metrics := GetMetrics(ReportStats)
	for _, metric := range metrics {
		statsdClient.Count(statsdPrefix+metric.Name, float64(metric.Value()), metric.Tags(), 1.0)
	}
}

// ReportTelemetry returns a map with all metrics tagged with `ReportTelemetry`
// The return format is consistent with what we use in the protobuf messages send to the backend
func ReportTelemetry() map[string]int64 {
	metrics := GetMetrics(ReportTelemetry)
	result := make(map[string]int64, len(metrics))
	for _, metric := range metrics {
		result[metric.Name] = metric.Value()
	}
	return result
}
