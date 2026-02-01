package security

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/jurajpiar/devkit/internal/monitor"
)

// AnomalyDetector detects unusual patterns in metrics and events
// This is feature-flagged and only active when anomaly_detection is enabled
type AnomalyDetector struct {
	enabled         bool
	containerName   string
	interval        time.Duration
	mu              sync.RWMutex

	// Baseline statistics (rolling averages)
	cpuBaseline     *RollingStats
	memBaseline     *RollingStats
	netInBaseline   *RollingStats
	netOutBaseline  *RollingStats
	pidsBaseline    *RollingStats

	// Event rate tracking
	eventRates      map[string]*RollingStats
	eventRatesMu    sync.RWMutex

	// Configuration
	stdDevThreshold float64 // Number of standard deviations for anomaly
	minSamples      int     // Minimum samples before detecting anomalies
	warmupPeriod    time.Duration
	startTime       time.Time
}

// RollingStats maintains rolling statistics for anomaly detection
type RollingStats struct {
	values    []float64
	windowSize int
	sum       float64
	sumSq     float64
	count     int
	mu        sync.Mutex
}

// NewRollingStats creates a new rolling statistics tracker
func NewRollingStats(windowSize int) *RollingStats {
	return &RollingStats{
		values:     make([]float64, 0, windowSize),
		windowSize: windowSize,
	}
}

// Add adds a new value to the rolling stats
func (rs *RollingStats) Add(value float64) {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	// Add new value
	rs.values = append(rs.values, value)
	rs.sum += value
	rs.sumSq += value * value
	rs.count++

	// Remove oldest if over window size
	if len(rs.values) > rs.windowSize {
		oldest := rs.values[0]
		rs.values = rs.values[1:]
		rs.sum -= oldest
		rs.sumSq -= oldest * oldest
		rs.count--
	}
}

// Mean returns the current mean
func (rs *RollingStats) Mean() float64 {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	if rs.count == 0 {
		return 0
	}
	return rs.sum / float64(rs.count)
}

// StdDev returns the current standard deviation
func (rs *RollingStats) StdDev() float64 {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	if rs.count < 2 {
		return 0
	}

	mean := rs.sum / float64(rs.count)
	variance := (rs.sumSq / float64(rs.count)) - (mean * mean)
	if variance < 0 {
		variance = 0
	}
	return math.Sqrt(variance)
}

// Count returns the number of samples
func (rs *RollingStats) Count() int {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return rs.count
}

// AnomalyConfig holds anomaly detection configuration
type AnomalyConfig struct {
	Enabled         bool
	ContainerName   string
	Interval        time.Duration
	StdDevThreshold float64       // Default: 3.0 (3 sigma)
	WindowSize      int           // Rolling window size (default: 60 samples)
	MinSamples      int           // Minimum samples before detection (default: 10)
	WarmupPeriod    time.Duration // Warmup before alerting (default: 5 min)
}

// DefaultAnomalyConfig returns default anomaly detection configuration
func DefaultAnomalyConfig() AnomalyConfig {
	return AnomalyConfig{
		Enabled:         false, // Feature-flagged off by default
		Interval:        5 * time.Second,
		StdDevThreshold: 3.0,
		WindowSize:      60,
		MinSamples:      10,
		WarmupPeriod:    5 * time.Minute,
	}
}

// NewAnomalyDetector creates a new anomaly detector
func NewAnomalyDetector(cfg AnomalyConfig) *AnomalyDetector {
	if cfg.WindowSize == 0 {
		cfg.WindowSize = 60
	}
	if cfg.StdDevThreshold == 0 {
		cfg.StdDevThreshold = 3.0
	}
	if cfg.MinSamples == 0 {
		cfg.MinSamples = 10
	}
	if cfg.WarmupPeriod == 0 {
		cfg.WarmupPeriod = 5 * time.Minute
	}
	if cfg.Interval == 0 {
		cfg.Interval = 5 * time.Second
	}

	return &AnomalyDetector{
		enabled:         cfg.Enabled,
		containerName:   cfg.ContainerName,
		interval:        cfg.Interval,
		cpuBaseline:     NewRollingStats(cfg.WindowSize),
		memBaseline:     NewRollingStats(cfg.WindowSize),
		netInBaseline:   NewRollingStats(cfg.WindowSize),
		netOutBaseline:  NewRollingStats(cfg.WindowSize),
		pidsBaseline:    NewRollingStats(cfg.WindowSize),
		eventRates:      make(map[string]*RollingStats),
		stdDevThreshold: cfg.StdDevThreshold,
		minSamples:      cfg.MinSamples,
		warmupPeriod:    cfg.WarmupPeriod,
		startTime:       time.Now(),
	}
}

// Name returns the detector's identifier
func (a *AnomalyDetector) Name() string {
	return "anomaly"
}

// Interval returns how often the detector should run
func (a *AnomalyDetector) Interval() time.Duration {
	return a.interval
}

// Start initializes the detector
func (a *AnomalyDetector) Start(ctx context.Context) error {
	a.startTime = time.Now()
	return nil
}

// Stop cleans up the detector
func (a *AnomalyDetector) Stop() error {
	return nil
}

// Collect is not used for anomaly detection (it processes events instead)
func (a *AnomalyDetector) Collect(ctx context.Context) ([]monitor.Event, error) {
	return nil, nil
}

// ProcessEvent analyzes an event for anomalies
func (a *AnomalyDetector) ProcessEvent(event monitor.Event) []monitor.Event {
	if !a.enabled {
		return nil
	}

	// Skip during warmup period
	if time.Since(a.startTime) < a.warmupPeriod {
		// Still collect baseline data
		a.updateBaseline(event)
		return nil
	}

	var anomalies []monitor.Event

	switch event.Type {
	case monitor.EventTypePerformance:
		anomalies = a.checkPerformanceAnomalies(event)
	case monitor.EventTypeSecurity, monitor.EventTypeNetwork,
		monitor.EventTypeProcess, monitor.EventTypeFileAccess:
		anomalies = a.checkEventRateAnomalies(event)
	}

	// Update baseline with new data
	a.updateBaseline(event)

	return anomalies
}

// updateBaseline updates baseline statistics
func (a *AnomalyDetector) updateBaseline(event monitor.Event) {
	if event.Type != monitor.EventTypePerformance {
		// Track event rates
		a.eventRatesMu.Lock()
		key := string(event.Type)
		if _, ok := a.eventRates[key]; !ok {
			a.eventRates[key] = NewRollingStats(60)
		}
		a.eventRates[key].Add(1)
		a.eventRatesMu.Unlock()
		return
	}

	// Update performance baselines
	if cpu, ok := event.Data["cpu_percent"].(float64); ok {
		a.cpuBaseline.Add(cpu)
	}
	if mem, ok := event.Data["mem_percent"].(float64); ok {
		a.memBaseline.Add(mem)
	}
	if netIn, ok := event.Data["net_input"].(uint64); ok {
		a.netInBaseline.Add(float64(netIn))
	}
	if netOut, ok := event.Data["net_output"].(uint64); ok {
		a.netOutBaseline.Add(float64(netOut))
	}
	if pids, ok := event.Data["pids"].(int); ok {
		a.pidsBaseline.Add(float64(pids))
	}
}

// checkPerformanceAnomalies checks for anomalies in performance metrics
func (a *AnomalyDetector) checkPerformanceAnomalies(event monitor.Event) []monitor.Event {
	var anomalies []monitor.Event

	// Check CPU
	if cpu, ok := event.Data["cpu_percent"].(float64); ok {
		if anomaly := a.checkAnomaly("CPU", cpu, a.cpuBaseline); anomaly != nil {
			anomalies = append(anomalies, *anomaly)
		}
	}

	// Check Memory
	if mem, ok := event.Data["mem_percent"].(float64); ok {
		if anomaly := a.checkAnomaly("Memory", mem, a.memBaseline); anomaly != nil {
			anomalies = append(anomalies, *anomaly)
		}
	}

	// Check Network Input
	if netIn, ok := event.Data["net_input"].(uint64); ok {
		if anomaly := a.checkAnomaly("Network Input", float64(netIn), a.netInBaseline); anomaly != nil {
			anomalies = append(anomalies, *anomaly)
		}
	}

	// Check Network Output (potential exfiltration)
	if netOut, ok := event.Data["net_output"].(uint64); ok {
		if anomaly := a.checkAnomaly("Network Output", float64(netOut), a.netOutBaseline); anomaly != nil {
			// Network output anomaly is more suspicious
			anomaly.Severity = monitor.SeverityWarning
			anomalies = append(anomalies, *anomaly)
		}
	}

	// Check PIDs (potential fork bomb)
	if pids, ok := event.Data["pids"].(int); ok {
		if anomaly := a.checkAnomaly("Process Count", float64(pids), a.pidsBaseline); anomaly != nil {
			// Sudden process spawning is suspicious
			anomaly.Severity = monitor.SeverityWarning
			anomalies = append(anomalies, *anomaly)
		}
	}

	return anomalies
}

// checkAnomaly checks if a value is anomalous compared to baseline
func (a *AnomalyDetector) checkAnomaly(metric string, value float64, baseline *RollingStats) *monitor.Event {
	// Need minimum samples
	if baseline.Count() < a.minSamples {
		return nil
	}

	mean := baseline.Mean()
	stdDev := baseline.StdDev()

	// Avoid division by zero
	if stdDev == 0 {
		return nil
	}

	// Calculate z-score
	zScore := (value - mean) / stdDev

	// Check if anomalous (both high and low)
	if math.Abs(zScore) >= a.stdDevThreshold {
		direction := "high"
		if zScore < 0 {
			direction = "low"
		}

		event := monitor.NewEvent(
			monitor.EventTypeAnomaly,
			a.Name(),
			monitor.SeverityInfo,
			fmt.Sprintf("Anomalous %s %s: %.2f (baseline: %.2f ± %.2f, z=%.2f)",
				direction, metric, value, mean, stdDev, zScore),
		).WithContainer(a.containerName).
			WithData("metric", metric).
			WithData("value", value).
			WithData("mean", mean).
			WithData("std_dev", stdDev).
			WithData("z_score", zScore).
			WithData("threshold", a.stdDevThreshold)

		return &event
	}

	return nil
}

// checkEventRateAnomalies checks for anomalies in event rates
func (a *AnomalyDetector) checkEventRateAnomalies(event monitor.Event) []monitor.Event {
	a.eventRatesMu.RLock()
	defer a.eventRatesMu.RUnlock()

	key := string(event.Type)
	baseline, ok := a.eventRates[key]
	if !ok {
		return nil
	}

	// Get current rate (events in last interval)
	// This is simplified - in production you'd track actual rates
	currentRate := 1.0

	if anomaly := a.checkAnomaly(fmt.Sprintf("%s Event Rate", key), currentRate, baseline); anomaly != nil {
		return []monitor.Event{*anomaly}
	}

	return nil
}

// IsEnabled returns whether anomaly detection is enabled
func (a *AnomalyDetector) IsEnabled() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.enabled
}

// SetEnabled enables or disables anomaly detection
func (a *AnomalyDetector) SetEnabled(enabled bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.enabled = enabled
	if enabled {
		a.startTime = time.Now() // Reset warmup
	}
}

// GetStats returns current baseline statistics
func (a *AnomalyDetector) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"enabled":        a.enabled,
		"warmup_remaining": a.warmupPeriod - time.Since(a.startTime),
		"cpu_baseline": map[string]float64{
			"mean":    a.cpuBaseline.Mean(),
			"std_dev": a.cpuBaseline.StdDev(),
			"samples": float64(a.cpuBaseline.Count()),
		},
		"mem_baseline": map[string]float64{
			"mean":    a.memBaseline.Mean(),
			"std_dev": a.memBaseline.StdDev(),
			"samples": float64(a.memBaseline.Count()),
		},
		"pids_baseline": map[string]float64{
			"mean":    a.pidsBaseline.Mean(),
			"std_dev": a.pidsBaseline.StdDev(),
			"samples": float64(a.pidsBaseline.Count()),
		},
	}
}
