// Package telemetry holds the Prometheus instrumentation for the ingest
// service.
//
// The metrics here are chosen to answer the questions you actually have at 3am:
// is the queue draining, are envelopes being rejected, and is any of this
// getting slower. Counters of things that only ever go up and are never alerted
// on are left out.
package telemetry

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Outcome labels for the envelope counter.
const (
	OutcomeWritten    = "written"
	OutcomeDuplicate  = "duplicate"
	OutcomeDeadLetter = "dead_letter"
	OutcomeRetry      = "retry"
)

// Metrics is the instrument set. A nil *Metrics is safe to use — every method
// checks — so tests and one-shot commands do not have to build one.
type Metrics struct {
	Envelopes      *prometheus.CounterVec
	Records        *prometheus.CounterVec
	RecordsDropped *prometheus.CounterVec
	Sightings      *prometheus.CounterVec
	WriteDuration  *prometheus.HistogramVec
	BatchSize      prometheus.Histogram
	QueueBacklog   prometheus.Gauge
	QueuePending   prometheus.Gauge
	CacheFailures  prometheus.Counter
	ArchiveBytes   prometheus.Counter
}

// New registers the instrument set. Passing nil registers with the default
// registerer.
func New(reg prometheus.Registerer) *Metrics {
	if reg == nil {
		reg = prometheus.DefaultRegisterer
	}
	f := promauto(reg)

	return &Metrics{
		Envelopes: f.counterVec(prometheus.CounterOpts{
			Name: "hoardcti_ingest_envelopes_total",
			Help: "Envelopes processed, by source and outcome.",
		}, []string{"source", "outcome"}),

		Records: f.counterVec(prometheus.CounterOpts{
			Name: "hoardcti_ingest_records_total",
			Help: "Records written, by source and entity kind.",
		}, []string{"source", "kind"}),

		RecordsDropped: f.counterVec(prometheus.CounterOpts{
			Name: "hoardcti_ingest_records_dropped_total",
			Help: "Records discarded during canonicalisation, by source and reason. " +
				"A rising rate on one source means its feed format has changed.",
		}, []string{"source", "reason"}),

		Sightings: f.counterVec(prometheus.CounterOpts{
			Name: "hoardcti_ingest_sightings_total",
			Help: "Sighting rows appended, by source.",
		}, []string{"source"}),

		WriteDuration: f.histogramVec(prometheus.HistogramOpts{
			Name: "hoardcti_ingest_write_duration_seconds",
			Help: "Time to write one batch to Postgres.",
			// From a handful of records to a fifty-thousand-row bulk load.
			Buckets: []float64{0.005, 0.025, 0.1, 0.25, 1, 2.5, 10, 30, 60},
		}, []string{"source"}),

		BatchSize: f.histogram(prometheus.HistogramOpts{
			Name:    "hoardcti_ingest_batch_records",
			Help:    "Records per envelope.",
			Buckets: []float64{1, 10, 100, 1000, 5000, 20000, 50000},
		}),

		QueueBacklog: f.gauge(prometheus.GaugeOpts{
			Name: "hoardcti_ingest_queue_backlog",
			Help: "Messages published but never delivered to the consumer group.",
		}),

		QueuePending: f.gauge(prometheus.GaugeOpts{
			Name: "hoardcti_ingest_queue_pending",
			Help: "Messages delivered but not yet acknowledged. Sustained growth " +
				"means consumers are dying mid-batch.",
		}),

		CacheFailures: f.counter(prometheus.CounterOpts{
			Name: "hoardcti_ingest_cache_failures_total",
			Help: "Cache write-through failures. These do not fail ingest — the " +
				"cache is a projection — but a sustained rate means lookups are stale.",
		}),

		ArchiveBytes: f.counter(prometheus.CounterOpts{
			Name: "hoardcti_ingest_archive_bytes_total",
			Help: "Raw payload bytes written to the archive.",
		}),
	}
}

// ObserveEnvelope records one envelope outcome.
func (m *Metrics) ObserveEnvelope(source, outcome string) {
	if m == nil {
		return
	}
	m.Envelopes.WithLabelValues(source, outcome).Inc()
}

// ObserveRecords records n written records of one kind.
func (m *Metrics) ObserveRecords(source, kind string, n int) {
	if m == nil || n == 0 {
		return
	}
	m.Records.WithLabelValues(source, kind).Add(float64(n))
}

// ObserveDropped records a record discarded during canonicalisation.
func (m *Metrics) ObserveDropped(source, reason string, n int) {
	if m == nil || n == 0 {
		return
	}
	m.RecordsDropped.WithLabelValues(source, reason).Add(float64(n))
}

// ObserveWrite records the size and duration of one batch write.
func (m *Metrics) ObserveWrite(source string, records, sightings int, seconds float64) {
	if m == nil {
		return
	}
	m.WriteDuration.WithLabelValues(source).Observe(seconds)
	m.BatchSize.Observe(float64(records))
	if sightings > 0 {
		m.Sightings.WithLabelValues(source).Add(float64(sightings))
	}
}

// ObserveQueue records the current queue depths.
func (m *Metrics) ObserveQueue(backlog, pending int64) {
	if m == nil {
		return
	}
	m.QueueBacklog.Set(float64(backlog))
	m.QueuePending.Set(float64(pending))
}

// ObserveCacheFailure records a failed cache write-through.
func (m *Metrics) ObserveCacheFailure() {
	if m == nil {
		return
	}
	m.CacheFailures.Inc()
}

// ObserveArchive records bytes written to the archive.
func (m *Metrics) ObserveArchive(n int) {
	if m == nil || n <= 0 {
		return
	}
	m.ArchiveBytes.Add(float64(n))
}

// promauto is a tiny local factory. The upstream promauto package panics on a
// duplicate registration, which is fine in main but hostile in tests that build
// a service twice; registering explicitly keeps the choice here.
type factory struct{ reg prometheus.Registerer }

func promauto(reg prometheus.Registerer) factory { return factory{reg: reg} }

func (f factory) counter(o prometheus.CounterOpts) prometheus.Counter {
	c := prometheus.NewCounter(o)
	f.register(c)
	return c
}

func (f factory) counterVec(o prometheus.CounterOpts, labels []string) *prometheus.CounterVec {
	c := prometheus.NewCounterVec(o, labels)
	f.register(c)
	return c
}

func (f factory) gauge(o prometheus.GaugeOpts) prometheus.Gauge {
	g := prometheus.NewGauge(o)
	f.register(g)
	return g
}

func (f factory) histogram(o prometheus.HistogramOpts) prometheus.Histogram {
	h := prometheus.NewHistogram(o)
	f.register(h)
	return h
}

func (f factory) histogramVec(o prometheus.HistogramOpts, labels []string) *prometheus.HistogramVec {
	h := prometheus.NewHistogramVec(o, labels)
	f.register(h)
	return h
}

// register tolerates a collector that is already registered, returning the
// existing one's behaviour rather than panicking.
func (f factory) register(c prometheus.Collector) {
	if err := f.reg.Register(c); err != nil {
		var are prometheus.AlreadyRegisteredError
		if ok := asAlreadyRegistered(err, &are); !ok {
			panic(err)
		}
	}
}

func asAlreadyRegistered(err error, target *prometheus.AlreadyRegisteredError) bool {
	are, ok := err.(prometheus.AlreadyRegisteredError)
	if ok {
		*target = are
	}
	return ok
}
