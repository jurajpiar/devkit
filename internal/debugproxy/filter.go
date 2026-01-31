package debugproxy

import (
	"encoding/json"
	"regexp"
	"strings"
	"sync"
	"time"
)

// FilterLevel defines the strictness of filtering
type FilterLevel int

const (
	// FilterLevelStrict blocks all evaluate/execute operations
	FilterLevelStrict FilterLevel = iota
	// FilterLevelFiltered blocks dangerous patterns, rate-limits
	FilterLevelFiltered
	// FilterLevelAudit logs only, allows all
	FilterLevelAudit
	// FilterLevelPassthrough no filtering at all
	FilterLevelPassthrough
)

// FilterResult represents the result of filtering a message
type FilterResult struct {
	Allowed bool
	Reason  string
	Message *CDPMessage // Potentially modified message
}

// Filter handles CDP message filtering
type Filter struct {
	level       FilterLevel
	rateLimiter *RateLimiter
	mu          sync.RWMutex
}

// NewFilter creates a new Filter with the specified level
func NewFilter(level FilterLevel) *Filter {
	return &Filter{
		level:       level,
		rateLimiter: NewRateLimiter(10, time.Second), // 10 evaluates per second
	}
}

// SetLevel changes the filter level
func (f *Filter) SetLevel(level FilterLevel) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.level = level
}

// FilterMessage filters a CDP message and returns whether it should be allowed
func (f *Filter) FilterMessage(msg *CDPMessage) FilterResult {
	f.mu.RLock()
	level := f.level
	f.mu.RUnlock()

	// Passthrough mode - allow everything
	if level == FilterLevelPassthrough {
		return FilterResult{Allowed: true, Message: msg}
	}

	// Always allow safe methods
	if SafeMethods[msg.Method] {
		return FilterResult{Allowed: true, Message: msg}
	}

	// Block completely blocked methods
	if BlockedMethods[msg.Method] {
		return FilterResult{
			Allowed: false,
			Reason:  "method blocked for security",
		}
	}

	// Handle high-risk methods
	if HighRiskMethods[msg.Method] {
		return f.filterHighRiskMethod(msg, level)
	}

	// Default: allow unknown methods in audit/passthrough, block in strict
	if level == FilterLevelStrict {
		return FilterResult{
			Allowed: false,
			Reason:  "unknown method blocked in strict mode",
		}
	}

	return FilterResult{Allowed: true, Message: msg}
}

// filterHighRiskMethod handles filtering of high-risk CDP methods
func (f *Filter) filterHighRiskMethod(msg *CDPMessage, level FilterLevel) FilterResult {
	switch msg.Method {
	case "Runtime.evaluate":
		return f.filterEvaluate(msg, level)
	case "Runtime.callFunctionOn":
		return f.filterCallFunctionOn(msg, level)
	case "Debugger.evaluateOnCallFrame":
		return f.filterEvaluateOnCallFrame(msg, level)
	default:
		if level == FilterLevelStrict {
			return FilterResult{Allowed: false, Reason: "high-risk method blocked in strict mode"}
		}
		return FilterResult{Allowed: true, Message: msg}
	}
}

// filterEvaluate filters Runtime.evaluate calls
func (f *Filter) filterEvaluate(msg *CDPMessage, level FilterLevel) FilterResult {
	// Strict mode: block all evaluate
	if level == FilterLevelStrict {
		return FilterResult{
			Allowed: false,
			Reason:  "Runtime.evaluate blocked in strict mode",
		}
	}

	// Parse params
	var params EvaluateParams
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		return FilterResult{
			Allowed: false,
			Reason:  "failed to parse evaluate params",
		}
	}

	// Filtered mode: check for dangerous patterns
	if level == FilterLevelFiltered {
		// Rate limit
		if !f.rateLimiter.Allow() {
			return FilterResult{
				Allowed: false,
				Reason:  "rate limited",
			}
		}

		// Check for dangerous patterns
		if blocked, reason := checkDangerousPatterns(params.Expression); blocked {
			return FilterResult{
				Allowed: false,
				Reason:  reason,
			}
		}
	}

	return FilterResult{Allowed: true, Message: msg}
}

// filterCallFunctionOn filters Runtime.callFunctionOn calls
func (f *Filter) filterCallFunctionOn(msg *CDPMessage, level FilterLevel) FilterResult {
	if level == FilterLevelStrict {
		return FilterResult{
			Allowed: false,
			Reason:  "Runtime.callFunctionOn blocked in strict mode",
		}
	}

	var params CallFunctionOnParams
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		return FilterResult{
			Allowed: false,
			Reason:  "failed to parse callFunctionOn params",
		}
	}

	if level == FilterLevelFiltered {
		if !f.rateLimiter.Allow() {
			return FilterResult{
				Allowed: false,
				Reason:  "rate limited",
			}
		}

		if blocked, reason := checkDangerousPatterns(params.FunctionDeclaration); blocked {
			return FilterResult{
				Allowed: false,
				Reason:  reason,
			}
		}
	}

	return FilterResult{Allowed: true, Message: msg}
}

// filterEvaluateOnCallFrame filters Debugger.evaluateOnCallFrame calls
func (f *Filter) filterEvaluateOnCallFrame(msg *CDPMessage, level FilterLevel) FilterResult {
	if level == FilterLevelStrict {
		return FilterResult{
			Allowed: false,
			Reason:  "Debugger.evaluateOnCallFrame blocked in strict mode",
		}
	}

	// Parse params to get expression
	var params struct {
		Expression string `json:"expression"`
	}
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		return FilterResult{
			Allowed: false,
			Reason:  "failed to parse evaluateOnCallFrame params",
		}
	}

	if level == FilterLevelFiltered {
		if !f.rateLimiter.Allow() {
			return FilterResult{
				Allowed: false,
				Reason:  "rate limited",
			}
		}

		if blocked, reason := checkDangerousPatterns(params.Expression); blocked {
			return FilterResult{
				Allowed: false,
				Reason:  reason,
			}
		}
	}

	return FilterResult{Allowed: true, Message: msg}
}

// Dangerous patterns to block
var dangerousPatterns = []struct {
	pattern *regexp.Regexp
	reason  string
}{
	// Child process / command execution
	{regexp.MustCompile(`require\s*\(\s*['"]child_process['"]\s*\)`), "child_process module blocked"},
	{regexp.MustCompile(`require\s*\(\s*['"]node:child_process['"]\s*\)`), "child_process module blocked"},
	{regexp.MustCompile(`child_process`), "child_process reference blocked"},
	{regexp.MustCompile(`\bexec\s*\(`), "exec() blocked"},
	{regexp.MustCompile(`\bexecSync\s*\(`), "execSync() blocked"},
	{regexp.MustCompile(`\bspawn\s*\(`), "spawn() blocked"},
	{regexp.MustCompile(`\bspawnSync\s*\(`), "spawnSync() blocked"},
	{regexp.MustCompile(`\bfork\s*\(`), "fork() blocked"},

	// Process/system access
	{regexp.MustCompile(`process\.binding\s*\(`), "process.binding blocked"},
	{regexp.MustCompile(`process\.dlopen\s*\(`), "process.dlopen blocked"},
	{regexp.MustCompile(`process\.kill\s*\(`), "process.kill blocked"},
	{regexp.MustCompile(`process\.exit\s*\(`), "process.exit blocked"},

	// File system writes
	{regexp.MustCompile(`fs\.writeFile`), "fs.writeFile blocked"},
	{regexp.MustCompile(`fs\.writeFileSync`), "fs.writeFileSync blocked"},
	{regexp.MustCompile(`fs\.appendFile`), "fs.appendFile blocked"},
	{regexp.MustCompile(`fs\.unlink`), "fs.unlink blocked"},
	{regexp.MustCompile(`fs\.rmdir`), "fs.rmdir blocked"},
	{regexp.MustCompile(`fs\.rm\s*\(`), "fs.rm blocked"},
	{regexp.MustCompile(`fs\.rename`), "fs.rename blocked"},
	{regexp.MustCompile(`fs\.chmod`), "fs.chmod blocked"},
	{regexp.MustCompile(`fs\.chown`), "fs.chown blocked"},

	// Network operations
	{regexp.MustCompile(`require\s*\(\s*['"]https?['"]\s*\)`), "http/https module blocked"},
	{regexp.MustCompile(`require\s*\(\s*['"]node:https?['"]\s*\)`), "http/https module blocked"},
	{regexp.MustCompile(`require\s*\(\s*['"]net['"]\s*\)`), "net module blocked"},
	{regexp.MustCompile(`require\s*\(\s*['"]dgram['"]\s*\)`), "dgram module blocked"},
	{regexp.MustCompile(`fetch\s*\(`), "fetch() blocked"},
	{regexp.MustCompile(`XMLHttpRequest`), "XMLHttpRequest blocked"},
	{regexp.MustCompile(`WebSocket`), "WebSocket blocked"},

	// Dynamic code execution
	{regexp.MustCompile(`\beval\s*\(`), "eval() blocked"},
	{regexp.MustCompile(`\bFunction\s*\(`), "Function constructor blocked"},
	{regexp.MustCompile(`new\s+Function\s*\(`), "Function constructor blocked"},
	{regexp.MustCompile(`vm\.runIn`), "vm module blocked"},
	{regexp.MustCompile(`require\s*\(\s*['"]vm['"]\s*\)`), "vm module blocked"},

	// Native addons
	{regexp.MustCompile(`\.node['"]\s*\)`), "native addon loading blocked"},
	{regexp.MustCompile(`process\.dlopen`), "dlopen blocked"},

	// Obfuscation attempts
	{regexp.MustCompile(`\\x[0-9a-fA-F]{2}`), "hex escape sequences blocked"},
	{regexp.MustCompile(`\\u\{[0-9a-fA-F]+\}`), "unicode escape sequences blocked"},
	{regexp.MustCompile(`atob\s*\(`), "base64 decode blocked"},
	{regexp.MustCompile(`Buffer\.from\s*\([^)]+,\s*['"]base64['"]\)`), "base64 decode blocked"},
}

// Additional string patterns (case-insensitive simple contains)
var dangerousStrings = []struct {
	pattern string
	reason  string
}{
	{"child_process", "child_process reference blocked"},
	{"shelljs", "shelljs blocked"},
	{"execa", "execa blocked"},
	{"/bin/sh", "shell path blocked"},
	{"/bin/bash", "shell path blocked"},
	{"cmd.exe", "cmd.exe blocked"},
	{"powershell", "powershell blocked"},
}

// checkDangerousPatterns checks if an expression contains dangerous patterns
func checkDangerousPatterns(expr string) (bool, string) {
	// Check regex patterns
	for _, p := range dangerousPatterns {
		if p.pattern.MatchString(expr) {
			return true, p.reason
		}
	}

	// Check simple string patterns (case-insensitive)
	lowerExpr := strings.ToLower(expr)
	for _, s := range dangerousStrings {
		if strings.Contains(lowerExpr, strings.ToLower(s.pattern)) {
			return true, s.reason
		}
	}

	return false, ""
}

// RateLimiter implements a simple token bucket rate limiter
type RateLimiter struct {
	tokens     int
	maxTokens  int
	refillRate time.Duration
	lastRefill time.Time
	mu         sync.Mutex
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(maxTokens int, refillRate time.Duration) *RateLimiter {
	return &RateLimiter{
		tokens:     maxTokens,
		maxTokens:  maxTokens,
		refillRate: refillRate,
		lastRefill: time.Now(),
	}
}

// Allow checks if an operation is allowed under the rate limit
func (r *RateLimiter) Allow() bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Refill tokens
	now := time.Now()
	elapsed := now.Sub(r.lastRefill)
	tokensToAdd := int(elapsed / r.refillRate)
	if tokensToAdd > 0 {
		r.tokens = min(r.tokens+tokensToAdd, r.maxTokens)
		r.lastRefill = now
	}

	// Check if we have tokens
	if r.tokens > 0 {
		r.tokens--
		return true
	}

	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
