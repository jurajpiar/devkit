package egressproxy

import (
	"log"
	"sync"
	"time"
)

// AuditLogger handles audit logging for the egress proxy
type AuditLogger struct {
	logger  *log.Logger
	enabled bool
	stats   AuditStats
	mu      sync.Mutex
}

// AuditStats holds proxy statistics
type AuditStats struct {
	TotalRequests   int64
	AllowedRequests int64
	BlockedRequests int64
	Errors          int64
	StartTime       time.Time
}

// NewAuditLogger creates a new audit logger
func NewAuditLogger(logger *log.Logger, enabled bool) *AuditLogger {
	if logger == nil {
		logger = log.Default()
	}
	return &AuditLogger{
		logger:  logger,
		enabled: enabled,
		stats: AuditStats{
			StartTime: time.Now(),
		},
	}
}

// SetEnabled enables or disables audit logging
func (a *AuditLogger) SetEnabled(enabled bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.enabled = enabled
}

// LogRequest logs a proxy request
func (a *AuditLogger) LogRequest(method, host string, allowed bool, matchedPattern string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.stats.TotalRequests++
	if allowed {
		a.stats.AllowedRequests++
	} else {
		a.stats.BlockedRequests++
	}

	if !a.enabled {
		return
	}

	status := "ALLOWED"
	if !allowed {
		status = "BLOCKED"
	}

	if matchedPattern != "" {
		a.logger.Printf("[EGRESS] %s %s %s (matched: %s)", status, method, host, matchedPattern)
	} else {
		a.logger.Printf("[EGRESS] %s %s %s", status, method, host)
	}
}

// LogError logs a proxy error
func (a *AuditLogger) LogError(host string, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.stats.Errors++

	if !a.enabled {
		return
	}

	a.logger.Printf("[EGRESS] ERROR %s: %v", host, err)
}

// GetStats returns a copy of the current statistics
func (a *AuditLogger) GetStats() AuditStats {
	a.mu.Lock()
	defer a.mu.Unlock()

	return AuditStats{
		TotalRequests:   a.stats.TotalRequests,
		AllowedRequests: a.stats.AllowedRequests,
		BlockedRequests: a.stats.BlockedRequests,
		Errors:          a.stats.Errors,
		StartTime:       a.stats.StartTime,
	}
}

// ResetStats resets the statistics
func (a *AuditLogger) ResetStats() {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.stats = AuditStats{
		StartTime: time.Now(),
	}
}
