package telemetry

import "go.uber.org/atomic"

// Metric represents a named piece of telemetry
type Metric struct {
	Name  string
	Tags  []string
	value atomic.Int64
}

// NewMetric returns a new `Metric` instance
func NewMetric(name string, tags ...string) *Metric {
	r.Lock()
	defer r.Unlock()

	m := &Metric{
		Name: name,
		Tags: tags,
	}

	r.metrics = append(r.metrics, m)
	return m
}

// Set value atomically
func (m *Metric) Set(v int64) {
	m.value.Store(v)
}

// Add value atomically
func (m *Metric) Add(v int64) {
	m.value.Add(v)
}

// Get value atomically
func (m *Metric) Value() int64 {
	return m.value.Load()
}
