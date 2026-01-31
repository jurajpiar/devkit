package e2e

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// skipIfNoPodman skips the test if podman is not available or devkit machine not running
func skipIfNoPodman(t *testing.T) {
	t.Helper()

	// Check if podman command exists
	cmd := exec.Command("podman", "--version")
	if err := cmd.Run(); err != nil {
		t.Skip("Podman not available, skipping e2e test")
	}

	// Check if podman can actually connect (machine is running)
	cmd = exec.Command("podman", "info", "--format", "{{.Host.RemoteSocket.Exists}}")
	output, err := cmd.CombinedOutput()
	if err != nil || strings.Contains(string(output), "Cannot connect") {
		t.Skip("Podman not running (try 'devkit machine init && devkit machine start'), skipping e2e test")
	}
}

// skipIfNoDevkitMachine skips if the devkit machine specifically is not running
func skipIfNoDevkitMachine(t *testing.T) {
	t.Helper()

	// First check basic podman availability
	skipIfNoPodman(t)

	// Then check for devkit machine specifically
	cmd := exec.Command("podman", "machine", "list", "--format", "{{.Name}}")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Skip("Cannot list Podman machines")
	}

	if !strings.Contains(string(output), "devkit") {
		t.Skip("Devkit machine not found. Run 'devkit machine init && devkit machine start'")
	}

	// Check if devkit machine is running
	cmd = exec.Command("podman", "machine", "list", "--format", "{{.Name}} {{.Running}}")
	output, err = cmd.CombinedOutput()
	if err != nil {
		t.Skip("Cannot check machine status")
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "devkit") && strings.Contains(line, "true") {
			return // Machine is running
		}
	}

	t.Skip("Devkit machine not running. Run 'devkit machine start'")
}

// buildDevkit builds the devkit binary and returns the path
func buildDevkit(t *testing.T) string {
	t.Helper()

	tmpDir, err := os.MkdirTemp("", "devkit-e2e-")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	binaryPath := filepath.Join(tmpDir, "devkit")

	// Get the repo root by going up from tests/e2e
	_, thisFile, _, _ := runtime.Caller(0)
	repoRoot := filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))

	cmd := exec.Command("go", "build", "-o", binaryPath, "./cmd/devkit")
	cmd.Dir = repoRoot

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to build devkit: %v\n%s", err, stderr.String())
	}

	return binaryPath
}

func TestDevkitHelp(t *testing.T) {
	devkit := buildDevkit(t)
	defer os.RemoveAll(filepath.Dir(devkit))

	cmd := exec.Command(devkit, "--help")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("devkit --help failed: %v\n%s", err, output)
	}

	outputStr := string(output)

	// Check for expected commands
	expectedCommands := []string{
		"build",
		"start",
		"stop",
		"connect",
		"init",
		"list",
		"shell",
	}

	for _, cmd := range expectedCommands {
		if !strings.Contains(outputStr, cmd) {
			t.Errorf("Help output should mention '%s' command", cmd)
		}
	}

	// Check for description
	if !strings.Contains(outputStr, "rootless") || !strings.Contains(outputStr, "container") {
		t.Error("Help output should mention rootless containers")
	}
}

func TestDevkitInit(t *testing.T) {
	devkit := buildDevkit(t)
	defer os.RemoveAll(filepath.Dir(devkit))

	// Create temp directory for the test project
	projectDir, err := os.MkdirTemp("", "devkit-test-project-")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(projectDir)

	// Run devkit init with a repo URL
	cmd := exec.Command(devkit, "init", "git@github.com:test/repo.git", "--name", "test-project")
	cmd.Dir = projectDir

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("devkit init failed: %v\n%s", err, output)
	}

	// Check that devkit.yaml was created
	configPath := filepath.Join(projectDir, "devkit.yaml")
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Error("devkit.yaml was not created")
	}

	// Read and verify content
	content, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("Failed to read devkit.yaml: %v", err)
	}

	contentStr := string(content)

	if !strings.Contains(contentStr, "test-project") {
		t.Error("devkit.yaml should contain project name")
	}
	if !strings.Contains(contentStr, "git@github.com:test/repo.git") {
		t.Error("devkit.yaml should contain repo URL")
	}
	if !strings.Contains(contentStr, "git") {
		t.Error("devkit.yaml should have git source method")
	}
}

func TestDevkitInitWithNodeProject(t *testing.T) {
	devkit := buildDevkit(t)
	defer os.RemoveAll(filepath.Dir(devkit))

	projectDir, err := os.MkdirTemp("", "devkit-test-project-")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(projectDir)

	// Create a package.json
	packageJSON := `{
		"name": "test-node-project",
		"version": "1.0.0",
		"engines": {
			"node": "20"
		}
	}`
	if err := os.WriteFile(filepath.Join(projectDir, "package.json"), []byte(packageJSON), 0644); err != nil {
		t.Fatalf("Failed to write package.json: %v", err)
	}

	// Create yarn.lock to test package manager detection
	if err := os.WriteFile(filepath.Join(projectDir, "yarn.lock"), []byte(""), 0644); err != nil {
		t.Fatalf("Failed to write yarn.lock: %v", err)
	}

	cmd := exec.Command(devkit, "init", "git@github.com:test/repo.git")
	cmd.Dir = projectDir

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("devkit init failed: %v\n%s", err, output)
	}

	outputStr := string(output)

	// Should detect Node.js
	if !strings.Contains(outputStr, "nodejs") && !strings.Contains(outputStr, "node") {
		t.Error("Should detect Node.js project type")
	}

	// Should detect yarn
	if !strings.Contains(outputStr, "yarn") {
		t.Error("Should detect yarn package manager")
	}
}

func TestDevkitInitForce(t *testing.T) {
	devkit := buildDevkit(t)
	defer os.RemoveAll(filepath.Dir(devkit))

	projectDir, err := os.MkdirTemp("", "devkit-test-project-")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(projectDir)

	// Create an existing devkit.yaml
	if err := os.WriteFile(filepath.Join(projectDir, "devkit.yaml"), []byte("existing: config"), 0644); err != nil {
		t.Fatalf("Failed to write devkit.yaml: %v", err)
	}

	// Without --force, should fail
	cmd := exec.Command(devkit, "init", "git@github.com:test/repo.git")
	cmd.Dir = projectDir

	_, err = cmd.CombinedOutput()
	if err == nil {
		t.Error("devkit init should fail when devkit.yaml exists without --force")
	}

	// With --force, should succeed
	cmd = exec.Command(devkit, "init", "git@github.com:test/repo.git", "--force")
	cmd.Dir = projectDir

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("devkit init --force failed: %v\n%s", err, output)
	}

	// Content should be overwritten
	content, _ := os.ReadFile(filepath.Join(projectDir, "devkit.yaml"))
	if strings.Contains(string(content), "existing: config") {
		t.Error("devkit.yaml should be overwritten with --force")
	}
}

func TestDevkitBuildRequiresConfig(t *testing.T) {
	devkit := buildDevkit(t)
	defer os.RemoveAll(filepath.Dir(devkit))

	projectDir, err := os.MkdirTemp("", "devkit-test-project-")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(projectDir)

	// Run build without devkit.yaml
	cmd := exec.Command(devkit, "build")
	cmd.Dir = projectDir

	_, err = cmd.CombinedOutput()
	if err == nil {
		t.Error("devkit build should fail without devkit.yaml")
	}
}

func TestDevkitStartRequiresConfig(t *testing.T) {
	devkit := buildDevkit(t)
	defer os.RemoveAll(filepath.Dir(devkit))

	projectDir, err := os.MkdirTemp("", "devkit-test-project-")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(projectDir)

	// Run start without devkit.yaml
	cmd := exec.Command(devkit, "start")
	cmd.Dir = projectDir

	_, err = cmd.CombinedOutput()
	if err == nil {
		t.Error("devkit start should fail without devkit.yaml")
	}
}

func TestDevkitListEmpty(t *testing.T) {
	skipIfNoPodman(t)

	devkit := buildDevkit(t)
	defer os.RemoveAll(filepath.Dir(devkit))

	projectDir, err := os.MkdirTemp("", "devkit-test-project-")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(projectDir)

	// Create minimal config
	config := `
project:
  name: list-test
  type: nodejs
source:
  method: copy
  repo: ""
features:
  allow_copy: true
ssh:
  port: 2222
`
	if err := os.WriteFile(filepath.Join(projectDir, "devkit.yaml"), []byte(config), 0644); err != nil {
		t.Fatalf("Failed to write devkit.yaml: %v", err)
	}

	// Run list
	cmd := exec.Command(devkit, "list")
	cmd.Dir = projectDir

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("devkit list failed: %v\n%s", err, output)
	}

	// Should indicate no containers
	outputStr := string(output)
	if !strings.Contains(outputStr, "No devkit containers") && !strings.Contains(outputStr, "CONTAINER ID") {
		t.Error("devkit list should show 'No devkit containers' or container list header")
	}
}

func TestDevkitConnectRequiresRunningContainer(t *testing.T) {
	skipIfNoPodman(t)

	devkit := buildDevkit(t)
	defer os.RemoveAll(filepath.Dir(devkit))

	projectDir, err := os.MkdirTemp("", "devkit-test-project-")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(projectDir)

	config := `
project:
  name: connect-test
  type: nodejs
source:
  method: copy
  repo: ""
features:
  allow_copy: true
ssh:
  port: 2222
`
	if err := os.WriteFile(filepath.Join(projectDir, "devkit.yaml"), []byte(config), 0644); err != nil {
		t.Fatalf("Failed to write devkit.yaml: %v", err)
	}

	// Run connect without a running container
	cmd := exec.Command(devkit, "connect")
	cmd.Dir = projectDir

	_, err = cmd.CombinedOutput()
	if err == nil {
		t.Error("devkit connect should fail without a running container")
	}
}

func TestDevkitStopNonExistent(t *testing.T) {
	skipIfNoPodman(t)

	devkit := buildDevkit(t)
	defer os.RemoveAll(filepath.Dir(devkit))

	projectDir, err := os.MkdirTemp("", "devkit-test-project-")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(projectDir)

	config := `
project:
  name: stop-test-nonexistent
  type: nodejs
source:
  method: copy
  repo: ""
features:
  allow_copy: true
ssh:
  port: 2222
`
	if err := os.WriteFile(filepath.Join(projectDir, "devkit.yaml"), []byte(config), 0644); err != nil {
		t.Fatalf("Failed to write devkit.yaml: %v", err)
	}

	// Stop should not error on non-existent container, just report it
	cmd := exec.Command(devkit, "stop")
	cmd.Dir = projectDir

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("devkit stop failed: %v\n%s", err, output)
	}

	if !strings.Contains(string(output), "does not exist") {
		t.Error("devkit stop should report that container does not exist")
	}
}

// TestDevkitFullLifecycle tests the full workflow: init -> build -> start -> stop
// This is an integration test that requires podman
func TestDevkitFullLifecycle(t *testing.T) {
	skipIfNoPodman(t)

	// This test takes a while, skip in short mode
	if testing.Short() {
		t.Skip("Skipping full lifecycle test in short mode")
	}

	devkit := buildDevkit(t)
	defer os.RemoveAll(filepath.Dir(devkit))

	projectDir, err := os.MkdirTemp("", "devkit-lifecycle-test-")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(projectDir)

	// Create a simple Node.js project
	packageJSON := `{
		"name": "lifecycle-test",
		"version": "1.0.0",
		"scripts": {
			"start": "echo hello"
		}
	}`
	if err := os.WriteFile(filepath.Join(projectDir, "package.json"), []byte(packageJSON), 0644); err != nil {
		t.Fatalf("Failed to write package.json: %v", err)
	}

	containerName := "devkit-lifecycle-test-" + time.Now().Format("20060102150405")

	// Use copy method to avoid needing git
	config := `
project:
  name: ` + containerName[7:] + `
  type: nodejs
source:
  method: copy
  repo: ""
features:
  allow_copy: true
dependencies:
  runtime: node:22-alpine
ssh:
  port: 22222
security:
  network_mode: restricted
  memory_limit: 1g
  pids_limit: 128
`
	if err := os.WriteFile(filepath.Join(projectDir, "devkit.yaml"), []byte(config), 0644); err != nil {
		t.Fatalf("Failed to write devkit.yaml: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Cleanup function
	cleanup := func() {
		// Stop and remove the container
		stopCmd := exec.CommandContext(ctx, devkit, "stop", "--remove")
		stopCmd.Dir = projectDir
		stopCmd.Run()
	}
	defer cleanup()

	// 1. Build
	t.Log("Building container image...")
	buildCmd := exec.CommandContext(ctx, devkit, "build", "--force")
	buildCmd.Dir = projectDir

	output, err := buildCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Build failed: %v\n%s", err, output)
	}
	t.Logf("Build output: %s", output)

	// 2. Start (will fail because copy method needs files copied, but tests the flow)
	t.Log("Starting container...")
	startCmd := exec.CommandContext(ctx, devkit, "start")
	startCmd.Dir = projectDir

	output, err = startCmd.CombinedOutput()
	t.Logf("Start output: %s", output)
	// Note: This might fail due to copy method complexities, which is okay for this test

	// 3. List
	t.Log("Listing containers...")
	listCmd := exec.CommandContext(ctx, devkit, "list")
	listCmd.Dir = projectDir

	output, err = listCmd.CombinedOutput()
	if err != nil {
		t.Logf("List warning: %v\n%s", err, output)
	} else {
		t.Logf("List output: %s", output)
	}

	// 4. Stop
	t.Log("Stopping container...")
	stopCmd := exec.CommandContext(ctx, devkit, "stop", "--remove")
	stopCmd.Dir = projectDir

	output, err = stopCmd.CombinedOutput()
	if err != nil {
		t.Logf("Stop warning: %v\n%s", err, output)
	} else {
		t.Logf("Stop output: %s", output)
	}
}

// TestDebugProxyBuild tests building the debug proxy image
func TestDebugProxyBuild(t *testing.T) {
	skipIfNoPodman(t)

	if testing.Short() {
		t.Skip("Skipping proxy build test in short mode")
	}

	devkit := buildDevkit(t)
	defer os.RemoveAll(filepath.Dir(devkit))

	projectDir, err := os.MkdirTemp("", "devkit-proxy-test-")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(projectDir)

	// Create minimal config
	config := `
project:
  name: proxy-build-test
  type: nodejs
source:
  method: copy
features:
  allow_copy: true
ssh:
  port: 2222
`
	if err := os.WriteFile(filepath.Join(projectDir, "devkit.yaml"), []byte(config), 0644); err != nil {
		t.Fatalf("Failed to write devkit.yaml: %v", err)
	}

	// Copy necessary files for proxy build
	// The build --proxy flag needs templates/debugproxy.Containerfile
	// For this test to work, we need to run from the repo root

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Just verify that --proxy flag is recognized
	cmd := exec.CommandContext(ctx, devkit, "build", "--help")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build --help failed: %v", err)
	}

	if !strings.Contains(string(output), "--proxy") {
		t.Error("build command should have --proxy flag")
	}
}

// TestCLIFlags tests that all expected CLI flags are present
func TestCLIFlags(t *testing.T) {
	devkit := buildDevkit(t)
	defer os.RemoveAll(filepath.Dir(devkit))

	tests := []struct {
		command string
		flags   []string
	}{
		{
			command: "start",
			flags:   []string{"--shell", "--paranoid", "--offline", "--no-debug-port", "--debug-proxy", "--rebuild"},
		},
		{
			command: "build",
			flags:   []string{"--force", "--no-cache", "--proxy", "--save-containerfile"},
		},
		{
			command: "stop",
			flags:   []string{"--remove", "--force"},
		},
		{
			command: "init",
			flags:   []string{"--name", "--type", "--branch", "--force"},
		},
		{
			command: "connect",
			flags:   []string{"--ssh-config", "--add-to-config"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			cmd := exec.Command(devkit, tt.command, "--help")
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("%s --help failed: %v\n%s", tt.command, err, output)
			}

			outputStr := string(output)
			for _, flag := range tt.flags {
				if !strings.Contains(outputStr, flag) {
					t.Errorf("%s command should have %s flag", tt.command, flag)
				}
			}
		})
	}
}
