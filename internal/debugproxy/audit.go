package debugproxy

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// AuditEventType represents the type of audit event
type AuditEventType string

const (
	AuditEventConnect    AuditEventType = "connect"
	AuditEventDisconnect AuditEventType = "disconnect"
	AuditEventRequest    AuditEventType = "request"
	AuditEventResponse   AuditEventType = "response"
	AuditEventBlocked    AuditEventType = "blocked"
	AuditEventError      AuditEventType = "error"
)

// AuditEvent represents a single audit log entry
type AuditEvent struct {
	Timestamp  time.Time      `json:"timestamp"`
	Type       AuditEventType `json:"type"`
	ClientAddr string         `json:"client_addr,omitempty"`
	Method     string         `json:"method,omitempty"`
	MessageID  int            `json:"message_id,omitempty"`
	Expression string         `json:"expression,omitempty"`
	Reason     string         `json:"reason,omitempty"`
	Error      string         `json:"error,omitempty"`
}

// AuditLogger handles audit logging for the debug proxy
type AuditLogger struct {
	writer  io.Writer
	mu      sync.Mutex
	enabled bool
}

// NewAuditLogger creates a new audit logger
func NewAuditLogger(writer io.Writer) *AuditLogger {
	if writer == nil {
		writer = os.Stdout
	}
	return &AuditLogger{
		writer:  writer,
		enabled: true,
	}
}

// SetEnabled enables or disables audit logging
func (a *AuditLogger) SetEnabled(enabled bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.enabled = enabled
}

// Log writes an audit event
func (a *AuditLogger) Log(event AuditEvent) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.enabled {
		return
	}

	event.Timestamp = time.Now()

	data, err := json.Marshal(event)
	if err != nil {
		fmt.Fprintf(a.writer, "[AUDIT ERROR] Failed to marshal event: %v\n", err)
		return
	}

	fmt.Fprintf(a.writer, "[AUDIT] %s\n", string(data))
}

// LogConnect logs a client connection
func (a *AuditLogger) LogConnect(clientAddr string) {
	a.Log(AuditEvent{
		Type:       AuditEventConnect,
		ClientAddr: clientAddr,
	})
}

// LogDisconnect logs a client disconnection
func (a *AuditLogger) LogDisconnect(clientAddr string) {
	a.Log(AuditEvent{
		Type:       AuditEventDisconnect,
		ClientAddr: clientAddr,
	})
}

// LogRequest logs an incoming CDP request
func (a *AuditLogger) LogRequest(clientAddr string, msg *CDPMessage) {
	event := AuditEvent{
		Type:       AuditEventRequest,
		ClientAddr: clientAddr,
		Method:     msg.Method,
		MessageID:  msg.ID,
	}

	// Extract expression if present
	if HighRiskMethods[msg.Method] {
		event.Expression = extractExpression(msg)
	}

	a.Log(event)
}

// LogResponse logs an outgoing CDP response
func (a *AuditLogger) LogResponse(clientAddr string, msg *CDPMessage) {
	a.Log(AuditEvent{
		Type:       AuditEventResponse,
		ClientAddr: clientAddr,
		MessageID:  msg.ID,
	})
}

// LogBlocked logs a blocked request
func (a *AuditLogger) LogBlocked(clientAddr string, msg *CDPMessage, reason string) {
	event := AuditEvent{
		Type:       AuditEventBlocked,
		ClientAddr: clientAddr,
		Method:     msg.Method,
		MessageID:  msg.ID,
		Reason:     reason,
	}

	if HighRiskMethods[msg.Method] {
		event.Expression = extractExpression(msg)
	}

	a.Log(event)
}

// LogError logs an error
func (a *AuditLogger) LogError(clientAddr string, err error) {
	a.Log(AuditEvent{
		Type:       AuditEventError,
		ClientAddr: clientAddr,
		Error:      err.Error(),
	})
}

// extractExpression extracts the expression from high-risk CDP messages
func extractExpression(msg *CDPMessage) string {
	if msg.Params == nil {
		return ""
	}

	// Try to extract expression field
	var params struct {
		Expression          string `json:"expression"`
		FunctionDeclaration string `json:"functionDeclaration"`
		ScriptSource        string `json:"scriptSource"`
	}

	if err := json.Unmarshal(msg.Params, &params); err != nil {
		return ""
	}

	// Return first non-empty field
	if params.Expression != "" {
		return truncate(params.Expression, 500)
	}
	if params.FunctionDeclaration != "" {
		return truncate(params.FunctionDeclaration, 500)
	}
	if params.ScriptSource != "" {
		return truncate(params.ScriptSource, 500)
	}

	return ""
}

// truncate truncates a string to maxLen characters
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// AuditStats tracks statistics for audit purposes
type AuditStats struct {
	TotalRequests   int64
	TotalBlocked    int64
	BlockedByMethod map[string]int64
	BlockedByReason map[string]int64
	mu              sync.Mutex
}

// NewAuditStats creates a new AuditStats
func NewAuditStats() *AuditStats {
	return &AuditStats{
		BlockedByMethod: make(map[string]int64),
		BlockedByReason: make(map[string]int64),
	}
}

// RecordRequest records a request
func (s *AuditStats) RecordRequest() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.TotalRequests++
}

// RecordBlocked records a blocked request
func (s *AuditStats) RecordBlocked(method, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.TotalBlocked++
	s.BlockedByMethod[method]++
	s.BlockedByReason[reason]++
}

// GetStats returns a copy of the current stats
func (s *AuditStats) GetStats() map[string]interface{} {
	s.mu.Lock()
	defer s.mu.Unlock()

	methodCopy := make(map[string]int64)
	for k, v := range s.BlockedByMethod {
		methodCopy[k] = v
	}

	reasonCopy := make(map[string]int64)
	for k, v := range s.BlockedByReason {
		reasonCopy[k] = v
	}

	return map[string]interface{}{
		"total_requests":    s.TotalRequests,
		"total_blocked":     s.TotalBlocked,
		"blocked_by_method": methodCopy,
		"blocked_by_reason": reasonCopy,
	}
}
