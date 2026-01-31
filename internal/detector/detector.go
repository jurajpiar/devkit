package detector

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ProjectType represents a detected project type
type ProjectType string

const (
	TypeNodeJS  ProjectType = "nodejs"
	TypeUnknown ProjectType = "unknown"
)

// DetectionResult holds the result of project detection
type DetectionResult struct {
	Type           ProjectType
	Runtime        string
	InstallCommand string
	DebugPort      int
	PackageManager string
	Dependencies   []string
}

// Detector detects project type and configuration
type Detector struct {
	projectPath string
}

// New creates a new Detector for the given project path
func New(projectPath string) *Detector {
	return &Detector{projectPath: projectPath}
}

// Detect analyzes the project and returns detection results
func (d *Detector) Detect() (*DetectionResult, error) {
	// Try Node.js detection first
	if result, err := d.detectNodeJS(); err == nil {
		return result, nil
	}

	// Return unknown if no project type detected
	return &DetectionResult{
		Type:    TypeUnknown,
		Runtime: "alpine:latest",
	}, nil
}

// detectNodeJS checks for Node.js project indicators
func (d *Detector) detectNodeJS() (*DetectionResult, error) {
	packageJSONPath := filepath.Join(d.projectPath, "package.json")

	// Check if package.json exists
	if _, err := os.Stat(packageJSONPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("not a Node.js project: package.json not found")
	}

	// Read and parse package.json
	data, err := os.ReadFile(packageJSONPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read package.json: %w", err)
	}

	var pkg PackageJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, fmt.Errorf("failed to parse package.json: %w", err)
	}

	result := &DetectionResult{
		Type:      TypeNodeJS,
		Runtime:   d.detectNodeVersion(&pkg),
		DebugPort: 9229, // Default Node.js debug port
	}

	// Detect package manager
	result.PackageManager = d.detectPackageManager()
	result.InstallCommand = d.getInstallCommand(result.PackageManager)

	// Collect dependencies
	result.Dependencies = d.collectDependencies(&pkg)

	return result, nil
}

// PackageJSON represents the structure of package.json
type PackageJSON struct {
	Name            string            `json:"name"`
	Version         string            `json:"version"`
	Engines         EnginesConfig     `json:"engines"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
	Scripts         map[string]string `json:"scripts"`
	PackageManager  string            `json:"packageManager"`
}

// EnginesConfig represents the engines field in package.json
type EnginesConfig struct {
	Node string `json:"node"`
	NPM  string `json:"npm"`
}

// detectNodeVersion determines the appropriate Node.js version
func (d *Detector) detectNodeVersion(pkg *PackageJSON) string {
	// Check for .nvmrc file
	nvmrcPath := filepath.Join(d.projectPath, ".nvmrc")
	if data, err := os.ReadFile(nvmrcPath); err == nil {
		version := string(data)
		return fmt.Sprintf("node:%s-alpine", sanitizeVersion(version))
	}

	// Check engines.node in package.json
	if pkg.Engines.Node != "" {
		return fmt.Sprintf("node:%s-alpine", sanitizeVersion(pkg.Engines.Node))
	}

	// Default to LTS
	return "node:22-alpine"
}

// detectPackageManager determines which package manager to use
func (d *Detector) detectPackageManager() string {
	// Check for lock files in order of preference
	if _, err := os.Stat(filepath.Join(d.projectPath, "pnpm-lock.yaml")); err == nil {
		return "pnpm"
	}
	if _, err := os.Stat(filepath.Join(d.projectPath, "yarn.lock")); err == nil {
		return "yarn"
	}
	if _, err := os.Stat(filepath.Join(d.projectPath, "bun.lockb")); err == nil {
		return "bun"
	}
	if _, err := os.Stat(filepath.Join(d.projectPath, "package-lock.json")); err == nil {
		return "npm"
	}

	// Default to npm
	return "npm"
}

// getInstallCommand returns the install command for the package manager
func (d *Detector) getInstallCommand(pm string) string {
	switch pm {
	case "pnpm":
		return "pnpm install"
	case "yarn":
		return "yarn install"
	case "bun":
		return "bun install"
	default:
		return "npm install"
	}
}

// collectDependencies gathers all dependencies from package.json
func (d *Detector) collectDependencies(pkg *PackageJSON) []string {
	deps := make([]string, 0)

	for name := range pkg.Dependencies {
		deps = append(deps, name)
	}
	for name := range pkg.DevDependencies {
		deps = append(deps, name)
	}

	return deps
}

// sanitizeVersion cleans up version strings for use in image tags
func sanitizeVersion(version string) string {
	// Trim whitespace and newlines
	v := strings.TrimSpace(version)
	if len(v) > 0 && (v[0] == 'v' || v[0] == '=' || v[0] == '^' || v[0] == '~' || v[0] == '>') {
		v = v[1:]
	}
	// Handle ranges like ">=18.0.0"
	if len(v) > 0 && v[0] == '=' {
		v = v[1:]
	}
	// Take only major version for broader compatibility
	for i, c := range v {
		if c == '.' || c == ' ' || c == '-' {
			// Return "lts" for complex version specs
			if i == 0 {
				return "lts"
			}
			return v[:i]
		}
	}
	if v == "" {
		return "lts"
	}
	return v
}

// DetectFromRepo performs detection from a git repository URL
// This is used when we don't have local files yet
func DetectFromRepo(repoURL string) (*DetectionResult, error) {
	// For now, return a generic Node.js result
	// In the future, we could clone the repo to a temp dir and inspect
	return &DetectionResult{
		Type:           TypeNodeJS,
		Runtime:        "node:22-alpine",
		InstallCommand: "npm install",
		DebugPort:      9229,
		PackageManager: "npm",
	}, nil
}
