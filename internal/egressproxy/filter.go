package egressproxy

import (
	"net"
	"strings"
	"sync"
)

// Filter handles domain-based filtering for the egress proxy
type Filter struct {
	allowedPatterns []string
	mu              sync.RWMutex
}

// NewFilter creates a new domain filter with the given allowed patterns
// Patterns can include wildcards:
//   - "*.example.com" matches "api.example.com", "www.example.com", etc.
//   - "example.com" matches exactly "example.com"
//   - "*" matches everything (effectively disables filtering)
func NewFilter(allowedHosts []string) *Filter {
	return &Filter{
		allowedPatterns: allowedHosts,
	}
}

// SetAllowedHosts updates the allowed host patterns
func (f *Filter) SetAllowedHosts(hosts []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.allowedPatterns = hosts
}

// GetAllowedHosts returns a copy of the allowed host patterns
func (f *Filter) GetAllowedHosts() []string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	result := make([]string, len(f.allowedPatterns))
	copy(result, f.allowedPatterns)
	return result
}

// IsAllowed reports whether host, given as "host" or "host:port", may be
// reached. A pattern without a port allows the web ports only, 80 and 443;
// a pattern written "host:port" allows exactly that port. A host with no
// port is taken as a web-port request.
func (f *Filter) IsAllowed(host string) bool {
	return f.CheckWithDetails(host).Allowed
}

// webPorts are what an allow entry permits when it names no port. Anything
// else on an allowed host (SSH, a database, an arbitrary TCP service) is a
// tunnel, not a web request, and needs an explicit "host:port" entry.
var webPorts = map[string]bool{"80": true, "443": true}

// splitPattern separates an allow entry into its host pattern and the port
// it names, "" when it names none.
func splitPattern(pattern string) (string, string) {
	if i := strings.LastIndex(pattern, ":"); i > 0 && !strings.Contains(pattern[i+1:], "]") {
		return strings.ToLower(pattern[:i]), pattern[i+1:]
	}
	return strings.ToLower(pattern), ""
}

// portAllowed applies the port policy for one matched pattern.
func portAllowed(patternPort, port string) bool {
	if patternPort != "" {
		return port == patternPort
	}
	return port == "" || webPorts[port]
}

// normalizeHost removes port from host if present and lowercases it
func normalizeHost(host string) string {
	h, _ := splitHostPort(host)
	return h
}

// splitHostPort returns the lowercased host and the port ("" when absent)
// of "host", "host:port", "[v6]" or "[v6]:port".
func splitHostPort(hostport string) (string, string) {
	if h, p, err := net.SplitHostPort(hostport); err == nil {
		return strings.ToLower(h), p
	}
	return strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(hostport, "["), "]")), ""
}

// matchPattern checks if a host matches a pattern
// Supported patterns:
//   - "*" matches everything
//   - "*.example.com" matches subdomains of example.com
//   - "**.example.com" matches any depth of subdomains
//   - "example.com" matches exactly example.com
func matchPattern(pattern, host string) bool {
	pattern = strings.ToLower(pattern)
	host = strings.ToLower(host)

	// Wildcard matches everything
	if pattern == "*" {
		return true
	}

	// Double wildcard: **.example.com matches any depth of subdomains
	if strings.HasPrefix(pattern, "**.") {
		suffix := pattern[2:] // ".example.com"
		// Match exact domain or any subdomain
		baseDomain := pattern[3:] // "example.com"
		return host == baseDomain || strings.HasSuffix(host, suffix)
	}

	// Single wildcard prefix: *.example.com matches immediate subdomains
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:]     // ".example.com"
		baseDomain := pattern[2:] // "example.com"

		// Match the base domain itself
		if host == baseDomain {
			return true
		}

		// Match immediate subdomain (exactly one level)
		if strings.HasSuffix(host, suffix) {
			// Count dots to ensure it's only one level deeper
			prefix := strings.TrimSuffix(host, suffix)
			// No dots in prefix means it's an immediate subdomain
			return !strings.Contains(prefix, ".")
		}
		return false
	}

	// Exact match
	return pattern == host
}

// FilterResult represents the result of a filter check
type FilterResult struct {
	Host    string
	Allowed bool
	Pattern string // The pattern that matched (empty if not allowed)
}

// CheckWithDetails checks if a host is allowed and returns detailed result
func (f *Filter) CheckWithDetails(host string) FilterResult {
	f.mu.RLock()
	defer f.mu.RUnlock()

	result := FilterResult{
		Host:    host,
		Allowed: false,
	}

	if len(f.allowedPatterns) == 0 {
		return result
	}

	h, port := splitHostPort(host)

	for _, pattern := range f.allowedPatterns {
		ph, pport := splitPattern(pattern)
		if matchPattern(ph, h) && portAllowed(pport, port) {
			result.Allowed = true
			result.Pattern = pattern
			return result
		}
	}

	return result
}

// DefaultAllowedHosts returns a list of commonly needed hosts for development
// These are typically safe to allow for most Node.js/web development
func DefaultAllowedHosts() []string {
	return []string{
		// Package registries
		"registry.npmjs.org",
		"registry.yarnpkg.com",
		"*.npmjs.org",

		// GitHub (for git operations and raw content)
		"github.com",
		"*.github.com",
		"*.githubusercontent.com",

		// Common CDNs
		"cdn.jsdelivr.net",
		"unpkg.com",
		"cdnjs.cloudflare.com",
	}
}
