package debugproxy

import (
	"encoding/json"
)

// CDPMessage represents a Chrome DevTools Protocol message
type CDPMessage struct {
	ID     int             `json:"id,omitempty"`
	Method string          `json:"method,omitempty"`
	Params json.RawMessage `json:"params,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *CDPError       `json:"error,omitempty"`
}

// CDPError represents an error in CDP
type CDPError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// EvaluateParams represents parameters for Runtime.evaluate
type EvaluateParams struct {
	Expression            string `json:"expression"`
	ObjectGroup           string `json:"objectGroup,omitempty"`
	IncludeCommandLineAPI bool   `json:"includeCommandLineAPI,omitempty"`
	Silent                bool   `json:"silent,omitempty"`
	ContextID             int    `json:"contextId,omitempty"`
	ReturnByValue         bool   `json:"returnByValue,omitempty"`
	GeneratePreview       bool   `json:"generatePreview,omitempty"`
	UserGesture           bool   `json:"userGesture,omitempty"`
	AwaitPromise          bool   `json:"awaitPromise,omitempty"`
}

// CompileScriptParams represents parameters for Runtime.compileScript
type CompileScriptParams struct {
	Expression         string `json:"expression"`
	SourceURL          string `json:"sourceURL"`
	PersistScript      bool   `json:"persistScript,omitempty"`
	ExecutionContextID int    `json:"executionContextId,omitempty"`
}

// SetScriptSourceParams represents parameters for Debugger.setScriptSource
type SetScriptSourceParams struct {
	ScriptID     string `json:"scriptId"`
	ScriptSource string `json:"scriptSource"`
	DryRun       bool   `json:"dryRun,omitempty"`
}

// CallFunctionOnParams represents parameters for Runtime.callFunctionOn
type CallFunctionOnParams struct {
	FunctionDeclaration string `json:"functionDeclaration"`
	ObjectID            string `json:"objectId,omitempty"`
	Arguments           []any  `json:"arguments,omitempty"`
	Silent              bool   `json:"silent,omitempty"`
	ReturnByValue       bool   `json:"returnByValue,omitempty"`
	GeneratePreview     bool   `json:"generatePreview,omitempty"`
	UserGesture         bool   `json:"userGesture,omitempty"`
	AwaitPromise        bool   `json:"awaitPromise,omitempty"`
}

// ParseMessage parses a CDP message from JSON
func ParseMessage(data []byte) (*CDPMessage, error) {
	var msg CDPMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, err
	}
	return &msg, nil
}

// ToJSON serializes a CDP message to JSON
func (m *CDPMessage) ToJSON() ([]byte, error) {
	return json.Marshal(m)
}

// CreateErrorResponse creates a CDP error response
func CreateErrorResponse(id int, code int, message string) *CDPMessage {
	return &CDPMessage{
		ID: id,
		Error: &CDPError{
			Code:    code,
			Message: message,
		},
	}
}

// HighRiskMethods are CDP methods that can execute arbitrary code
var HighRiskMethods = map[string]bool{
	"Runtime.evaluate":           true,
	"Runtime.compileScript":      true,
	"Runtime.runScript":          true,
	"Runtime.callFunctionOn":     true,
	"Debugger.setScriptSource":   true,
	"Debugger.evaluateOnCallFrame": true,
}

// BlockedMethods are CDP methods that should be completely blocked
var BlockedMethods = map[string]bool{
	"Runtime.compileScript":    true,
	"Runtime.runScript":        true,
	"Debugger.setScriptSource": true,
}

// SafeMethods are CDP methods that are always allowed
var SafeMethods = map[string]bool{
	"Debugger.enable":                  true,
	"Debugger.disable":                 true,
	"Debugger.pause":                   true,
	"Debugger.resume":                  true,
	"Debugger.stepOver":                true,
	"Debugger.stepInto":                true,
	"Debugger.stepOut":                 true,
	"Debugger.setBreakpoint":           true,
	"Debugger.setBreakpointByUrl":      true,
	"Debugger.removeBreakpoint":        true,
	"Debugger.getPossibleBreakpoints": true,
	"Debugger.continueToLocation":      true,
	"Debugger.getScriptSource":         true,
	"Runtime.enable":                   true,
	"Runtime.disable":                  true,
	"Runtime.getProperties":            true,
	"Runtime.releaseObject":            true,
	"Runtime.releaseObjectGroup":       true,
	"Runtime.getHeapUsage":             true,
	"Profiler.enable":                  true,
	"Profiler.disable":                 true,
	"Profiler.start":                   true,
	"Profiler.stop":                    true,
	"Console.enable":                   true,
	"Console.disable":                  true,
	"Console.clearMessages":            true,
}
