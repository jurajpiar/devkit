package egressproxy

import "testing"

func TestFilterIsAllowed(t *testing.T) {
	tests := []struct {
		name           string
		allowedHosts   []string
		host           string
		expectedResult bool
	}{
		// Empty allowlist blocks everything
		{
			name:           "empty allowlist blocks all",
			allowedHosts:   []string{},
			host:           "example.com",
			expectedResult: false,
		},

		// Exact match
		{
			name:           "exact match allowed",
			allowedHosts:   []string{"api.example.com"},
			host:           "api.example.com",
			expectedResult: true,
		},
		{
			name:           "exact match case insensitive",
			allowedHosts:   []string{"API.Example.COM"},
			host:           "api.example.com",
			expectedResult: true,
		},
		{
			name:           "exact match with port",
			allowedHosts:   []string{"api.example.com"},
			host:           "api.example.com:443",
			expectedResult: true,
		},
		{
			name:           "no match for different domain",
			allowedHosts:   []string{"api.example.com"},
			host:           "other.example.com",
			expectedResult: false,
		},

		// Single wildcard prefix (*.example.com)
		{
			name:           "wildcard matches subdomain",
			allowedHosts:   []string{"*.example.com"},
			host:           "api.example.com",
			expectedResult: true,
		},
		{
			name:           "wildcard matches base domain",
			allowedHosts:   []string{"*.example.com"},
			host:           "example.com",
			expectedResult: true,
		},
		{
			name:           "wildcard does not match deeper subdomain",
			allowedHosts:   []string{"*.example.com"},
			host:           "a.b.example.com",
			expectedResult: false,
		},
		{
			name:           "wildcard does not match unrelated domain",
			allowedHosts:   []string{"*.example.com"},
			host:           "example.org",
			expectedResult: false,
		},

		// Double wildcard prefix (**.example.com)
		{
			name:           "double wildcard matches subdomain",
			allowedHosts:   []string{"**.example.com"},
			host:           "api.example.com",
			expectedResult: true,
		},
		{
			name:           "double wildcard matches deep subdomain",
			allowedHosts:   []string{"**.example.com"},
			host:           "a.b.c.example.com",
			expectedResult: true,
		},
		{
			name:           "double wildcard matches base domain",
			allowedHosts:   []string{"**.example.com"},
			host:           "example.com",
			expectedResult: true,
		},

		// Global wildcard
		{
			name:           "global wildcard matches everything",
			allowedHosts:   []string{"*"},
			host:           "anything.example.com",
			expectedResult: true,
		},

		// Multiple patterns
		{
			name:           "multiple patterns - first matches",
			allowedHosts:   []string{"api.example.com", "cdn.example.org"},
			host:           "api.example.com",
			expectedResult: true,
		},
		{
			name:           "multiple patterns - second matches",
			allowedHosts:   []string{"api.example.com", "cdn.example.org"},
			host:           "cdn.example.org",
			expectedResult: true,
		},
		{
			name:           "multiple patterns - none match",
			allowedHosts:   []string{"api.example.com", "cdn.example.org"},
			host:           "other.example.net",
			expectedResult: false,
		},

		// Real-world patterns
		{
			name:           "npm registry",
			allowedHosts:   []string{"registry.npmjs.org"},
			host:           "registry.npmjs.org",
			expectedResult: true,
		},
		{
			name:           "github wildcard",
			allowedHosts:   []string{"*.github.com"},
			host:           "api.github.com",
			expectedResult: true,
		},
		{
			name:           "github raw content",
			allowedHosts:   []string{"*.githubusercontent.com"},
			host:           "raw.githubusercontent.com",
			expectedResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := NewFilter(tt.allowedHosts)
			result := f.IsAllowed(tt.host)
			if result != tt.expectedResult {
				t.Errorf("IsAllowed(%q) = %v, want %v", tt.host, result, tt.expectedResult)
			}
		})
	}
}

func TestFilterCheckWithDetails(t *testing.T) {
	f := NewFilter([]string{"api.example.com", "*.github.com"})

	// Test allowed request
	result := f.CheckWithDetails("api.example.com:443")
	if !result.Allowed {
		t.Error("Expected api.example.com to be allowed")
	}
	if result.Pattern != "api.example.com" {
		t.Errorf("Expected pattern 'api.example.com', got '%s'", result.Pattern)
	}

	// Test wildcard match
	result = f.CheckWithDetails("raw.github.com")
	if !result.Allowed {
		t.Error("Expected raw.github.com to be allowed")
	}
	if result.Pattern != "*.github.com" {
		t.Errorf("Expected pattern '*.github.com', got '%s'", result.Pattern)
	}

	// Test blocked request
	result = f.CheckWithDetails("evil.com")
	if result.Allowed {
		t.Error("Expected evil.com to be blocked")
	}
	if result.Pattern != "" {
		t.Errorf("Expected empty pattern for blocked request, got '%s'", result.Pattern)
	}
}

func TestFilterSetAllowedHosts(t *testing.T) {
	f := NewFilter([]string{"original.com"})

	if !f.IsAllowed("original.com") {
		t.Error("original.com should be allowed initially")
	}

	// Update allowed hosts
	f.SetAllowedHosts([]string{"new.com"})

	if f.IsAllowed("original.com") {
		t.Error("original.com should not be allowed after update")
	}
	if !f.IsAllowed("new.com") {
		t.Error("new.com should be allowed after update")
	}
}

func TestFilterGetAllowedHosts(t *testing.T) {
	hosts := []string{"a.com", "b.com", "c.com"}
	f := NewFilter(hosts)

	got := f.GetAllowedHosts()
	if len(got) != len(hosts) {
		t.Errorf("GetAllowedHosts() returned %d hosts, want %d", len(got), len(hosts))
	}

	// Verify it's a copy, not the original slice
	got[0] = "modified.com"
	original := f.GetAllowedHosts()
	if original[0] == "modified.com" {
		t.Error("GetAllowedHosts() should return a copy, not the original slice")
	}
}

func TestMatchPattern(t *testing.T) {
	tests := []struct {
		pattern string
		host    string
		want    bool
	}{
		// Global wildcard
		{"*", "anything.com", true},
		{"*", "a.b.c.d.com", true},

		// Exact match
		{"example.com", "example.com", true},
		{"example.com", "Example.COM", true},
		{"example.com", "other.com", false},
		{"example.com", "subdomain.example.com", false},

		// Single wildcard
		{"*.example.com", "example.com", true},
		{"*.example.com", "api.example.com", true},
		{"*.example.com", "www.example.com", true},
		{"*.example.com", "a.b.example.com", false},
		{"*.example.com", "notexample.com", false},

		// Double wildcard
		{"**.example.com", "example.com", true},
		{"**.example.com", "api.example.com", true},
		{"**.example.com", "a.b.example.com", true},
		{"**.example.com", "a.b.c.d.example.com", true},
		{"**.example.com", "notexample.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.host, func(t *testing.T) {
			got := matchPattern(tt.pattern, tt.host)
			if got != tt.want {
				t.Errorf("matchPattern(%q, %q) = %v, want %v", tt.pattern, tt.host, got, tt.want)
			}
		})
	}
}

func TestNormalizeHost(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"example.com", "example.com"},
		{"EXAMPLE.COM", "example.com"},
		{"Example.Com", "example.com"},
		{"example.com:443", "example.com"},
		{"example.com:8080", "example.com"},
		{"api.example.com:443", "api.example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeHost(tt.input)
			if got != tt.want {
				t.Errorf("normalizeHost(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestDefaultAllowedHosts(t *testing.T) {
	hosts := DefaultAllowedHosts()
	if len(hosts) == 0 {
		t.Error("DefaultAllowedHosts() should return non-empty list")
	}

	// Check for expected common hosts
	f := NewFilter(hosts)
	expectedAllowed := []string{
		"registry.npmjs.org",
		"github.com",
		"api.github.com",
		"raw.githubusercontent.com",
	}

	for _, host := range expectedAllowed {
		if !f.IsAllowed(host) {
			t.Errorf("DefaultAllowedHosts should allow %s", host)
		}
	}
}
