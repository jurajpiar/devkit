package detector

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectNodeJS(t *testing.T) {
	// Create a temporary directory with package.json
	tmpDir, err := os.MkdirTemp("", "devkit-detector-test-")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	packageJSON := `{
		"name": "test-project",
		"version": "1.0.0",
		"dependencies": {
			"express": "^4.18.0"
		},
		"devDependencies": {
			"typescript": "^5.0.0"
		}
	}`

	if err := os.WriteFile(filepath.Join(tmpDir, "package.json"), []byte(packageJSON), 0644); err != nil {
		t.Fatalf("Failed to write package.json: %v", err)
	}

	det := New(tmpDir)
	result, err := det.Detect()

	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}

	if result.Type != TypeNodeJS {
		t.Errorf("Type = %s, want %s", result.Type, TypeNodeJS)
	}

	if result.DebugPort != 9229 {
		t.Errorf("DebugPort = %d, want 9229", result.DebugPort)
	}

	if result.PackageManager != "npm" {
		t.Errorf("PackageManager = %s, want npm", result.PackageManager)
	}

	// Should detect 2 dependencies
	if len(result.Dependencies) != 2 {
		t.Errorf("len(Dependencies) = %d, want 2", len(result.Dependencies))
	}
}

func TestDetectNodeJSWithYarn(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "devkit-detector-test-")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create package.json
	packageJSON := `{"name": "test", "version": "1.0.0"}`
	if err := os.WriteFile(filepath.Join(tmpDir, "package.json"), []byte(packageJSON), 0644); err != nil {
		t.Fatalf("Failed to write package.json: %v", err)
	}

	// Create yarn.lock
	if err := os.WriteFile(filepath.Join(tmpDir, "yarn.lock"), []byte("# yarn.lock"), 0644); err != nil {
		t.Fatalf("Failed to write yarn.lock: %v", err)
	}

	det := New(tmpDir)
	result, err := det.Detect()

	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}

	if result.PackageManager != "yarn" {
		t.Errorf("PackageManager = %s, want yarn", result.PackageManager)
	}

	if result.InstallCommand != "yarn install" {
		t.Errorf("InstallCommand = %s, want 'yarn install'", result.InstallCommand)
	}
}

func TestDetectNodeJSWithPnpm(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "devkit-detector-test-")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	packageJSON := `{"name": "test", "version": "1.0.0"}`
	if err := os.WriteFile(filepath.Join(tmpDir, "package.json"), []byte(packageJSON), 0644); err != nil {
		t.Fatalf("Failed to write package.json: %v", err)
	}

	// Create pnpm-lock.yaml
	if err := os.WriteFile(filepath.Join(tmpDir, "pnpm-lock.yaml"), []byte("lockfileVersion: 5.4"), 0644); err != nil {
		t.Fatalf("Failed to write pnpm-lock.yaml: %v", err)
	}

	det := New(tmpDir)
	result, err := det.Detect()

	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}

	if result.PackageManager != "pnpm" {
		t.Errorf("PackageManager = %s, want pnpm", result.PackageManager)
	}

	if result.InstallCommand != "pnpm install" {
		t.Errorf("InstallCommand = %s, want 'pnpm install'", result.InstallCommand)
	}
}

func TestDetectNodeJSWithBun(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "devkit-detector-test-")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	packageJSON := `{"name": "test", "version": "1.0.0"}`
	if err := os.WriteFile(filepath.Join(tmpDir, "package.json"), []byte(packageJSON), 0644); err != nil {
		t.Fatalf("Failed to write package.json: %v", err)
	}

	// Create bun.lockb
	if err := os.WriteFile(filepath.Join(tmpDir, "bun.lockb"), []byte{}, 0644); err != nil {
		t.Fatalf("Failed to write bun.lockb: %v", err)
	}

	det := New(tmpDir)
	result, err := det.Detect()

	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}

	if result.PackageManager != "bun" {
		t.Errorf("PackageManager = %s, want bun", result.PackageManager)
	}

	if result.InstallCommand != "bun install" {
		t.Errorf("InstallCommand = %s, want 'bun install'", result.InstallCommand)
	}
}

func TestDetectNodeJSWithNvmrc(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "devkit-detector-test-")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	packageJSON := `{"name": "test", "version": "1.0.0"}`
	if err := os.WriteFile(filepath.Join(tmpDir, "package.json"), []byte(packageJSON), 0644); err != nil {
		t.Fatalf("Failed to write package.json: %v", err)
	}

	// Create .nvmrc with specific version
	if err := os.WriteFile(filepath.Join(tmpDir, ".nvmrc"), []byte("18"), 0644); err != nil {
		t.Fatalf("Failed to write .nvmrc: %v", err)
	}

	det := New(tmpDir)
	result, err := det.Detect()

	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}

	if result.Runtime != "node:18-alpine" {
		t.Errorf("Runtime = %s, want node:18-alpine", result.Runtime)
	}
}

func TestDetectNodeJSWithEngines(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "devkit-detector-test-")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	packageJSON := `{
		"name": "test",
		"version": "1.0.0",
		"engines": {
			"node": ">=20.0.0"
		}
	}`
	if err := os.WriteFile(filepath.Join(tmpDir, "package.json"), []byte(packageJSON), 0644); err != nil {
		t.Fatalf("Failed to write package.json: %v", err)
	}

	det := New(tmpDir)
	result, err := det.Detect()

	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}

	// Should extract major version 20
	if result.Runtime != "node:20-alpine" {
		t.Errorf("Runtime = %s, want node:20-alpine", result.Runtime)
	}
}

func TestDetectUnknownProject(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "devkit-detector-test-")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Empty directory - no project files
	det := New(tmpDir)
	result, err := det.Detect()

	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}

	if result.Type != TypeUnknown {
		t.Errorf("Type = %s, want %s", result.Type, TypeUnknown)
	}
}

func TestSanitizeVersion(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"18", "18"},
		{"v18", "18"},
		{"18.0.0", "18"},
		{">=18.0.0", "18"},
		{"^18.0.0", "18"},
		{"~18.0.0", "18"},
		{"lts", "lts"},
		{"", "lts"},
		{">=18", "18"},
		{"20.10.0", "20"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := sanitizeVersion(tt.input)
			if result != tt.expected {
				t.Errorf("sanitizeVersion(%s) = %s, want %s", tt.input, result, tt.expected)
			}
		})
	}
}

func TestDetectFromRepo(t *testing.T) {
	// DetectFromRepo should return a generic Node.js result
	result, err := DetectFromRepo("git@github.com:user/repo.git")

	if err != nil {
		t.Fatalf("DetectFromRepo() error: %v", err)
	}

	if result.Type != TypeNodeJS {
		t.Errorf("Type = %s, want %s", result.Type, TypeNodeJS)
	}

	if result.Runtime != "node:22-alpine" {
		t.Errorf("Runtime = %s, want node:22-alpine", result.Runtime)
	}

	if result.InstallCommand != "npm install" {
		t.Errorf("InstallCommand = %s, want 'npm install'", result.InstallCommand)
	}
}

func TestDetectInvalidPackageJSON(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "devkit-detector-test-")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Write invalid JSON
	if err := os.WriteFile(filepath.Join(tmpDir, "package.json"), []byte("invalid json"), 0644); err != nil {
		t.Fatalf("Failed to write package.json: %v", err)
	}

	det := New(tmpDir)
	result, err := det.Detect()

	// Should fall back to unknown, not error
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}

	if result.Type != TypeUnknown {
		t.Errorf("Type = %s, want %s for invalid package.json", result.Type, TypeUnknown)
	}
}

func TestCollectDependencies(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "devkit-detector-test-")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	packageJSON := `{
		"name": "test",
		"version": "1.0.0",
		"dependencies": {
			"express": "^4.18.0",
			"lodash": "^4.17.0"
		},
		"devDependencies": {
			"typescript": "^5.0.0",
			"jest": "^29.0.0"
		}
	}`
	if err := os.WriteFile(filepath.Join(tmpDir, "package.json"), []byte(packageJSON), 0644); err != nil {
		t.Fatalf("Failed to write package.json: %v", err)
	}

	det := New(tmpDir)
	result, err := det.Detect()

	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}

	// Should have 4 dependencies total
	if len(result.Dependencies) != 4 {
		t.Errorf("len(Dependencies) = %d, want 4", len(result.Dependencies))
	}

	// Check that all expected deps are present
	deps := make(map[string]bool)
	for _, d := range result.Dependencies {
		deps[d] = true
	}

	expected := []string{"express", "lodash", "typescript", "jest"}
	for _, e := range expected {
		if !deps[e] {
			t.Errorf("Missing dependency: %s", e)
		}
	}
}
