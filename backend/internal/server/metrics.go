package server

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var httpDurationBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60}
var syncDurationBuckets = []float64{0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 20, 30, 60, 120, 300}

type statusCaptureWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusCaptureWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusCaptureWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(p)
}

func (w *statusCaptureWriter) Status() int {
	if w.status == 0 {
		return http.StatusOK
	}
	return w.status
}

type histogramSample struct {
	count       uint64
	sum         float64
	bucketCount []uint64
}

type serverMetrics struct {
	mu sync.Mutex

	httpRequests  map[string]uint64
	httpDurations map[string]*histogramSample

	syncUpstreamRuns     map[string]uint64
	syncUpstreamRetries  map[string]uint64
	syncUpstreamDuration map[string]*histogramSample

	syncBatchRuns     map[string]uint64
	syncBatchDuration map[string]*histogramSample

	strategyPreviewRuns  map[string]uint64
	strategyApplyRuns    map[string]uint64
	strategyConflicts    map[string]uint64
	strategyDroppedNodes map[string]uint64
}

func newServerMetrics() *serverMetrics {
	return &serverMetrics{
		httpRequests:         make(map[string]uint64),
		httpDurations:        make(map[string]*histogramSample),
		syncUpstreamRuns:     make(map[string]uint64),
		syncUpstreamRetries:  make(map[string]uint64),
		syncUpstreamDuration: make(map[string]*histogramSample),
		syncBatchRuns:        make(map[string]uint64),
		syncBatchDuration:    make(map[string]*histogramSample),
		strategyPreviewRuns:  make(map[string]uint64),
		strategyApplyRuns:    make(map[string]uint64),
		strategyConflicts:    make(map[string]uint64),
		strategyDroppedNodes: make(map[string]uint64),
	}
}

func (m *serverMetrics) observeHTTPRequest(method, route string, status int, duration time.Duration) {
	method = sanitizeMetricLabel(method, "UNKNOWN")
	route = sanitizeMetricLabel(route, "unknown")
	statusText := strconv.Itoa(status)

	counterKey := fmt.Sprintf("method=%s|route=%s|status=%s", method, route, statusText)
	durationKey := fmt.Sprintf("method=%s|route=%s", method, route)

	m.mu.Lock()
	defer m.mu.Unlock()
	m.httpRequests[counterKey]++
	m.observeHistogram(m.httpDurations, durationKey, httpDurationBuckets, duration.Seconds())
}

func (m *serverMetrics) observeSyncUpstream(trigger, status, errorClass string, retries int, duration time.Duration) {
	trigger = sanitizeMetricLabel(trigger, "unknown")
	status = sanitizeMetricLabel(status, "unknown")
	errorClass = sanitizeMetricLabel(errorClass, "none")
	if retries < 0 {
		retries = 0
	}

	runKey := fmt.Sprintf("trigger=%s|status=%s|error_class=%s", trigger, status, errorClass)
	durationKey := fmt.Sprintf("trigger=%s|status=%s", trigger, status)
	retryKey := fmt.Sprintf("trigger=%s|error_class=%s", trigger, errorClass)

	m.mu.Lock()
	defer m.mu.Unlock()
	m.syncUpstreamRuns[runKey]++
	if retries > 0 {
		m.syncUpstreamRetries[retryKey] += uint64(retries)
	}
	m.observeHistogram(m.syncUpstreamDuration, durationKey, syncDurationBuckets, duration.Seconds())
}

func (m *serverMetrics) observeSyncBatch(trigger, status string, duration time.Duration) {
	trigger = sanitizeMetricLabel(trigger, "unknown")
	status = sanitizeMetricLabel(status, "unknown")

	runKey := fmt.Sprintf("trigger=%s|status=%s", trigger, status)
	durationKey := runKey

	m.mu.Lock()
	defer m.mu.Unlock()
	m.syncBatchRuns[runKey]++
	m.observeHistogram(m.syncBatchDuration, durationKey, syncDurationBuckets, duration.Seconds())
}

func (m *serverMetrics) observeStrategyPreview(strategyMode string, summary StrategySummary) {
	m.observeStrategyOperation("preview", strategyMode, summary)
}

func (m *serverMetrics) observeStrategyApply(strategyMode string, summary StrategySummary) {
	m.observeStrategyOperation("apply", strategyMode, summary)
}

func (m *serverMetrics) observeStrategyOperation(operation, strategyMode string, summary StrategySummary) {
	operation = sanitizeMetricLabel(operation, "unknown")
	strategyMode = sanitizeMetricLabel(strategyMode, defaultStrategyMode)

	runKey := fmt.Sprintf("strategy_mode=%s", strategyMode)
	summaryKey := fmt.Sprintf("operation=%s|strategy_mode=%s", operation, strategyMode)

	m.mu.Lock()
	defer m.mu.Unlock()

	switch operation {
	case "preview":
		m.strategyPreviewRuns[runKey]++
	case "apply":
		m.strategyApplyRuns[runKey]++
	}
	if summary.ConflictGroups > 0 {
		m.strategyConflicts[summaryKey] += uint64(summary.ConflictGroups)
	}
	if summary.DroppedNodes > 0 {
		m.strategyDroppedNodes[summaryKey] += uint64(summary.DroppedNodes)
	}
}

func (m *serverMetrics) observeHistogram(store map[string]*histogramSample, key string, buckets []float64, value float64) {
	sample, ok := store[key]
	if !ok {
		sample = &histogramSample{
			bucketCount: make([]uint64, len(buckets)),
		}
		store[key] = sample
	}
	sample.count++
	sample.sum += value
	for idx, bound := range buckets {
		if value <= bound {
			sample.bucketCount[idx]++
		}
	}
}

func (m *serverMetrics) renderPrometheus() string {
	m.mu.Lock()
	defer m.mu.Unlock()

	var out strings.Builder
	out.WriteString("# HELP subadmin_http_requests_total Total HTTP requests.\n")
	out.WriteString("# TYPE subadmin_http_requests_total counter\n")
	out.WriteString(formatCounterLines("subadmin_http_requests_total", m.httpRequests))

	out.WriteString("# HELP subadmin_http_request_duration_seconds HTTP request latency.\n")
	out.WriteString("# TYPE subadmin_http_request_duration_seconds histogram\n")
	out.WriteString(formatHistogramLines("subadmin_http_request_duration_seconds", m.httpDurations, httpDurationBuckets))

	out.WriteString("# HELP subadmin_sync_upstream_runs_total Upstream sync runs by status.\n")
	out.WriteString("# TYPE subadmin_sync_upstream_runs_total counter\n")
	out.WriteString(formatCounterLines("subadmin_sync_upstream_runs_total", m.syncUpstreamRuns))

	out.WriteString("# HELP subadmin_sync_upstream_retries_total Upstream sync retry attempts.\n")
	out.WriteString("# TYPE subadmin_sync_upstream_retries_total counter\n")
	out.WriteString(formatCounterLines("subadmin_sync_upstream_retries_total", m.syncUpstreamRetries))

	out.WriteString("# HELP subadmin_sync_upstream_duration_seconds Upstream sync latency.\n")
	out.WriteString("# TYPE subadmin_sync_upstream_duration_seconds histogram\n")
	out.WriteString(formatHistogramLines("subadmin_sync_upstream_duration_seconds", m.syncUpstreamDuration, syncDurationBuckets))

	out.WriteString("# HELP subadmin_sync_batch_runs_total Batch sync runs.\n")
	out.WriteString("# TYPE subadmin_sync_batch_runs_total counter\n")
	out.WriteString(formatCounterLines("subadmin_sync_batch_runs_total", m.syncBatchRuns))

	out.WriteString("# HELP subadmin_sync_batch_duration_seconds Batch sync latency.\n")
	out.WriteString("# TYPE subadmin_sync_batch_duration_seconds histogram\n")
	out.WriteString(formatHistogramLines("subadmin_sync_batch_duration_seconds", m.syncBatchDuration, syncDurationBuckets))

	out.WriteString("# HELP subadmin_strategy_preview_total Strategy preview executions.\n")
	out.WriteString("# TYPE subadmin_strategy_preview_total counter\n")
	out.WriteString(formatCounterLines("subadmin_strategy_preview_total", m.strategyPreviewRuns))

	out.WriteString("# HELP subadmin_strategy_apply_total Strategy apply executions.\n")
	out.WriteString("# TYPE subadmin_strategy_apply_total counter\n")
	out.WriteString(formatCounterLines("subadmin_strategy_apply_total", m.strategyApplyRuns))

	out.WriteString("# HELP subadmin_strategy_conflicts_total Strategy conflict groups observed.\n")
	out.WriteString("# TYPE subadmin_strategy_conflicts_total counter\n")
	out.WriteString(formatCounterLines("subadmin_strategy_conflicts_total", m.strategyConflicts))

	out.WriteString("# HELP subadmin_strategy_dropped_nodes_total Strategy dropped nodes observed.\n")
	out.WriteString("# TYPE subadmin_strategy_dropped_nodes_total counter\n")
	out.WriteString(formatCounterLines("subadmin_strategy_dropped_nodes_total", m.strategyDroppedNodes))

	return out.String()
}

func formatCounterLines(metric string, samples map[string]uint64) string {
	lines := make([]string, 0, len(samples))
	for labelSet, value := range samples {
		lines = append(lines, fmt.Sprintf("%s{%s} %d", metric, renderLabelSet(labelSet), value))
	}
	sort.Strings(lines)
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n") + "\n"
}

func formatHistogramLines(metric string, samples map[string]*histogramSample, buckets []float64) string {
	lines := make([]string, 0, len(samples)*(len(buckets)+3))
	for labelSet, sample := range samples {
		labels := renderLabelSet(labelSet)
		for idx, bound := range buckets {
			lines = append(lines, fmt.Sprintf(`%s_bucket{%s,le="%s"} %d`, metric, labels, trimFloat(bound), sample.bucketCount[idx]))
		}
		lines = append(lines, fmt.Sprintf(`%s_bucket{%s,le="+Inf"} %d`, metric, labels, sample.count))
		lines = append(lines, fmt.Sprintf("%s_sum{%s} %s", metric, labels, strconv.FormatFloat(sample.sum, 'f', -1, 64)))
		lines = append(lines, fmt.Sprintf("%s_count{%s} %d", metric, labels, sample.count))
	}
	sort.Strings(lines)
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n") + "\n"
}

func renderLabelSet(encoded string) string {
	parts := strings.Split(encoded, "|")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		out = append(out, fmt.Sprintf(`%s="%s"`, kv[0], escapePromLabel(kv[1])))
	}
	return strings.Join(out, ",")
}

func sanitizeMetricLabel(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func trimFloat(value float64) string {
	return strconv.FormatFloat(value, 'f', -1, 64)
}

func escapePromLabel(value string) string {
	replacer := strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`)
	return replacer.Replace(value)
}
