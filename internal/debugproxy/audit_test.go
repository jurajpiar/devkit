package debugproxy

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestAuditLogger(t *testing.T) {
	var buf bytes.Buffer
	logger := NewAuditLogger(&buf)

	// Log a connect event
	logger.LogConnect("127.0.0.1:54321")

	output := buf.String()
	if !strings.Contains(output, "[AUDIT]") {
		t.Error("Output should contain [AUDIT] prefix")
	}
	if !strings.Contains(output, "connect") {
		t.Error("Output should contain event type 'connect'")
	}
	if !strings.Contains(output, "127.0.0.1:54321") {
		t.Error("Output should contain client address")
	}
}

func TestAuditLoggerDisabled(t *testing.T) {
	var buf bytes.Buffer
	logger := NewAuditLogger(&buf)
	logger.SetEnabled(false)

	logger.LogConnect("127.0.0.1:54321")

	if buf.Len() > 0 {
		t.Error("Disabled logger should not produce output")
	}
}

func TestAuditLoggerRequest(t *testing.T) {
	var buf bytes.Buffer
	logger := NewAuditLogger(&buf)

	msg := &CDPMessage{
		ID:     1,
		Method: "Debugger.pause",
	}

	logger.LogRequest("127.0.0.1:54321", msg)

	output := buf.String()
	if !strings.Contains(output, "request") {
		t.Error("Output should contain event type 'request'")
	}
	if !strings.Contains(output, "Debugger.pause") {
		t.Error("Output should contain method name")
	}
}

func TestAuditLoggerHighRiskRequest(t *testing.T) {
	var buf bytes.Buffer
	logger := NewAuditLogger(&buf)

	params, _ := json.Marshal(EvaluateParams{Expression: "process.env.SECRET"})
	msg := &CDPMessage{
		ID:     1,
		Method: "Runtime.evaluate",
		Params: params,
	}

	logger.LogRequest("127.0.0.1:54321", msg)

	output := buf.String()
	if !strings.Contains(output, "Runtime.evaluate") {
		t.Error("Output should contain method name")
	}
	if !strings.Contains(output, "process.env.SECRET") {
		t.Error("Output should contain expression for high-risk methods")
	}
}

func TestAuditLoggerBlocked(t *testing.T) {
	var buf bytes.Buffer
	logger := NewAuditLogger(&buf)

	params, _ := json.Marshal(EvaluateParams{Expression: "require('child_process')"})
	msg := &CDPMessage{
		ID:     1,
		Method: "Runtime.evaluate",
		Params: params,
	}

	logger.LogBlocked("127.0.0.1:54321", msg, "child_process blocked")

	output := buf.String()
	if !strings.Contains(output, "blocked") {
		t.Error("Output should contain event type 'blocked'")
	}
	if !strings.Contains(output, "child_process blocked") {
		t.Error("Output should contain block reason")
	}
	if !strings.Contains(output, "require('child_process')") {
		t.Error("Output should contain the blocked expression")
	}
}

func TestAuditLoggerError(t *testing.T) {
	var buf bytes.Buffer
	logger := NewAuditLogger(&buf)

	logger.LogError("127.0.0.1:54321", &testError{"connection reset"})

	output := buf.String()
	if !strings.Contains(output, "error") {
		t.Error("Output should contain event type 'error'")
	}
	if !strings.Contains(output, "connection reset") {
		t.Error("Output should contain error message")
	}
}

type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}

func TestAuditLoggerJSONFormat(t *testing.T) {
	var buf bytes.Buffer
	logger := NewAuditLogger(&buf)

	logger.LogConnect("127.0.0.1:54321")

	// Extract JSON part from output
	output := buf.String()
	jsonStart := strings.Index(output, "{")
	if jsonStart == -1 {
		t.Fatal("Output should contain JSON")
	}
	jsonStr := output[jsonStart:]
	jsonStr = strings.TrimSpace(jsonStr)

	// Verify it's valid JSON
	var event AuditEvent
	if err := json.Unmarshal([]byte(jsonStr), &event); err != nil {
		t.Fatalf("Output should be valid JSON: %v", err)
	}

	if event.Type != AuditEventConnect {
		t.Errorf("Event type = %s, want %s", event.Type, AuditEventConnect)
	}
	if event.ClientAddr != "127.0.0.1:54321" {
		t.Errorf("ClientAddr = %s, want 127.0.0.1:54321", event.ClientAddr)
	}
	if event.Timestamp.IsZero() {
		t.Error("Timestamp should be set")
	}
}

func TestAuditStats(t *testing.T) {
	stats := NewAuditStats()

	// Record some requests
	stats.RecordRequest()
	stats.RecordRequest()
	stats.RecordRequest()

	// Record some blocks
	stats.RecordBlocked("Runtime.evaluate", "child_process blocked")
	stats.RecordBlocked("Runtime.evaluate", "eval blocked")
	stats.RecordBlocked("Runtime.compileScript", "method blocked")

	result := stats.GetStats()

	totalRequests := result["total_requests"].(int64)
	if totalRequests != 3 {
		t.Errorf("total_requests = %d, want 3", totalRequests)
	}

	totalBlocked := result["total_blocked"].(int64)
	if totalBlocked != 3 {
		t.Errorf("total_blocked = %d, want 3", totalBlocked)
	}

	blockedByMethod := result["blocked_by_method"].(map[string]int64)
	if blockedByMethod["Runtime.evaluate"] != 2 {
		t.Errorf("blocked_by_method[Runtime.evaluate] = %d, want 2", blockedByMethod["Runtime.evaluate"])
	}
	if blockedByMethod["Runtime.compileScript"] != 1 {
		t.Errorf("blocked_by_method[Runtime.compileScript] = %d, want 1", blockedByMethod["Runtime.compileScript"])
	}

	blockedByReason := result["blocked_by_reason"].(map[string]int64)
	if blockedByReason["child_process blocked"] != 1 {
		t.Errorf("blocked_by_reason[child_process blocked] = %d, want 1", blockedByReason["child_process blocked"])
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		input    string
		maxLen   int
		expected string
	}{
		{"short", 10, "short"},
		{"exactly10!", 10, "exactly10!"},
		{"this is a long string", 10, "this is a ..."}, // 10 chars + "..."
		{"", 10, ""},
	}

	for _, tt := range tests {
		result := truncate(tt.input, tt.maxLen)
		if result != tt.expected {
			t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.maxLen, result, tt.expected)
		}
	}
}

func TestExtractExpression(t *testing.T) {
	tests := []struct {
		name     string
		msg      *CDPMessage
		expected string
	}{
		{
			name: "evaluate expression",
			msg: func() *CDPMessage {
				params, _ := json.Marshal(EvaluateParams{Expression: "1+1"})
				return &CDPMessage{Method: "Runtime.evaluate", Params: params}
			}(),
			expected: "1+1",
		},
		{
			name: "callFunctionOn",
			msg: func() *CDPMessage {
				params, _ := json.Marshal(CallFunctionOnParams{FunctionDeclaration: "function() { return 42; }"})
				return &CDPMessage{Method: "Runtime.callFunctionOn", Params: params}
			}(),
			expected: "function() { return 42; }",
		},
		{
			name: "no params",
			msg: &CDPMessage{
				Method: "Runtime.evaluate",
				Params: nil,
			},
			expected: "",
		},
		{
			name: "empty expression",
			msg: func() *CDPMessage {
				params, _ := json.Marshal(EvaluateParams{Expression: ""})
				return &CDPMessage{Method: "Runtime.evaluate", Params: params}
			}(),
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractExpression(tt.msg)
			if result != tt.expected {
				t.Errorf("extractExpression() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestAuditLoggerConcurrency(t *testing.T) {
	var buf bytes.Buffer
	logger := NewAuditLogger(&buf)

	// Spawn multiple goroutines logging concurrently
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				logger.LogConnect("127.0.0.1:54321")
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Should have logged 1000 events
	output := buf.String()
	count := strings.Count(output, "[AUDIT]")
	if count != 1000 {
		t.Errorf("Expected 1000 log entries, got %d", count)
	}
}

func TestAuditStatsConcurrency(t *testing.T) {
	stats := NewAuditStats()

	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				stats.RecordRequest()
				stats.RecordBlocked("test", "reason")
			}
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	result := stats.GetStats()
	totalRequests := result["total_requests"].(int64)
	totalBlocked := result["total_blocked"].(int64)

	if totalRequests != 1000 {
		t.Errorf("total_requests = %d, want 1000", totalRequests)
	}
	if totalBlocked != 1000 {
		t.Errorf("total_blocked = %d, want 1000", totalBlocked)
	}
}
