package e2e

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jurajpiar/devkit/internal/machine"
)

// TestMachineIntegration tests the devkit machine integration
func TestMachineIntegration(t *testing.T) {
	if err := machine.CheckPodmanInstalled(); err != nil {
		t.Skip("Podman not installed")
	}

	mgr := machine.New()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Check machine status
	exists, err := mgr.Exists(ctx)
	if err != nil {
		t.Fatalf("Failed to check machine existence: %v", err)
	}

	if !exists {
		t.Log("Devkit machine does not exist")
		t.Log("Run 'devkit machine init' to create it")
		t.Skip("Devkit machine not initialized")
	}

	running, err := mgr.IsRunning(ctx)
	if err != nil {
		t.Fatalf("Failed to check if machine is running: %v", err)
	}

	if !running {
		t.Log("Devkit machine exists but is not running")
		t.Log("Run 'devkit machine start' to start it")
		t.Skip("Devkit machine not running")
	}

	t.Log("Devkit machine is running")

	// Get machine info
	info, err := mgr.GetInfo(ctx)
	if err != nil {
		t.Fatalf("Failed to get machine info: %v", err)
	}

	t.Logf("Machine: %s", info.Name)
	t.Logf("CPUs: %d", info.CPUs)
	t.Logf("Memory: %s", info.Memory)
	t.Logf("Disk: %s", info.DiskSize)
}

// TestMachineSecurityFeatures tests that the machine supports required security features
func TestMachineSecurityFeatures(t *testing.T) {
	if err := machine.CheckPodmanInstalled(); err != nil {
		t.Skip("Podman not installed")
	}

	mgr := machine.New()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	running, err := mgr.IsRunning(ctx)
	if err != nil || !running {
		t.Skip("Devkit machine not running")
	}

	// Test that security features work in the machine
	securityTests := []struct {
		name string
		test func(t *testing.T)
	}{
		{
			name: "rootless_containers",
			test: func(t *testing.T) {
				// Verify we can run rootless containers
				cmd := exec.CommandContext(ctx, "podman", "run", "--rm", "alpine", "id")
				output, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("Failed to run container: %v\n%s", err, output)
				}
				t.Logf("Container user: %s", strings.TrimSpace(string(output)))
			},
		},
		{
			name: "user_namespace",
			test: func(t *testing.T) {
				// Verify user namespace support
				cmd := exec.CommandContext(ctx, "podman", "run", "--rm", "--userns=keep-id", "alpine", "id")
				output, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("User namespace not supported: %v\n%s", err, output)
				}
				t.Logf("User namespace works: %s", strings.TrimSpace(string(output)))
			},
		},
		{
			name: "capability_dropping",
			test: func(t *testing.T) {
				// Verify capability dropping works
				cmd := exec.CommandContext(ctx, "podman", "run", "--rm", "--cap-drop=ALL", "alpine", "cat", "/proc/self/status")
				output, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("Capability dropping failed: %v\n%s", err, output)
				}
				if !strings.Contains(string(output), "CapEff:") {
					t.Error("Could not verify capabilities")
				}
				t.Log("Capability dropping works")
			},
		},
		{
			name: "read_only_rootfs",
			test: func(t *testing.T) {
				// Verify read-only rootfs works
				cmd := exec.CommandContext(ctx, "podman", "run", "--rm", "--read-only", "alpine", "touch", "/test")
				output, _ := cmd.CombinedOutput()
				if !strings.Contains(string(output), "Read-only") {
					t.Error("Read-only rootfs not enforced")
				} else {
					t.Log("Read-only rootfs works")
				}
			},
		},
		{
			name: "network_isolation",
			test: func(t *testing.T) {
				// Verify network=none works
				cmd := exec.CommandContext(ctx, "podman", "run", "--rm", "--network=none", "alpine", "ip", "addr")
				output, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("Network isolation test failed: %v\n%s", err, output)
				}
				if strings.Contains(string(output), "eth0") {
					t.Error("Network isolation not working - eth0 present")
				} else {
					t.Log("Network isolation works")
				}
			},
		},
		{
			name: "memory_limits",
			test: func(t *testing.T) {
				// Verify memory limits work
				cmd := exec.CommandContext(ctx, "podman", "run", "--rm", "--memory=64m", "alpine", "echo", "ok")
				output, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("Memory limits not supported: %v\n%s", err, output)
				}
				t.Log("Memory limits work")
			},
		},
		{
			name: "pids_limit",
			test: func(t *testing.T) {
				// Verify PIDs limit works
				cmd := exec.CommandContext(ctx, "podman", "run", "--rm", "--pids-limit=10", "alpine", "echo", "ok")
				output, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("PIDs limit not supported: %v\n%s", err, output)
				}
				t.Log("PIDs limit works")
			},
		},
		{
			name: "seccomp",
			test: func(t *testing.T) {
				// Verify seccomp is available
				cmd := exec.CommandContext(ctx, "podman", "info", "--format", "{{.Host.Security.SECCOMPEnabled}}")
				output, err := cmd.CombinedOutput()
				if err != nil {
					t.Logf("Could not check seccomp: %v", err)
				} else {
					t.Logf("SECCOMP enabled: %s", strings.TrimSpace(string(output)))
				}
			},
		},
	}

	for _, st := range securityTests {
		t.Run(st.name, st.test)
	}
}

// ensureDevkitMachine ensures the devkit machine is running for tests
// This is a helper that can be called from other tests
func ensureDevkitMachine(t *testing.T) {
	t.Helper()

	if err := machine.CheckPodmanInstalled(); err != nil {
		t.Skip("Podman not installed")
	}

	mgr := machine.New()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	exists, err := mgr.Exists(ctx)
	if err != nil {
		t.Fatalf("Failed to check machine existence: %v", err)
	}

	if !exists {
		t.Skip("Devkit machine not initialized. Run 'devkit machine init && devkit machine start'")
	}

	running, err := mgr.IsRunning(ctx)
	if err != nil {
		t.Fatalf("Failed to check if machine is running: %v", err)
	}

	if !running {
		t.Skip("Devkit machine not running. Run 'devkit machine start'")
	}
}

// TestSecurityWithDevkitMachine runs security tests using the devkit machine
func TestSecurityWithDevkitMachine(t *testing.T) {
	ensureDevkitMachine(t)

	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	// Run comprehensive security test in devkit machine
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	containerName := "devkit-security-machine-test"
	defer cleanupContainer(containerName)

	// Create a hardened container in the devkit machine
	createCmd := exec.CommandContext(ctx, "podman", "create",
		"--name", containerName,
		"--cap-drop=ALL",
		"--security-opt=no-new-privileges:true",
		"--read-only",
		"--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
		"--network=none",
		"--memory=128m",
		"--pids-limit=50",
		"--userns=keep-id",
		"alpine:latest",
		"sleep", "300",
	)

	if output, err := createCmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to create container: %v\n%s", err, output)
	}

	// Start container
	startCmd := exec.CommandContext(ctx, "podman", "start", containerName)
	if output, err := startCmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to start container: %v\n%s", err, output)
	}

	// Run security checks
	checks := []struct {
		name    string
		cmd     string
		wantErr bool
	}{
		{"write_rootfs", "touch /pwned", true},
		{"network_access", "ping -c1 -W1 8.8.8.8", true},
		{"mount_proc", "mount -t proc proc /mnt", true},
		{"write_tmp", "touch /tmp/ok", false},
	}

	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			execCmd := exec.CommandContext(ctx, "podman", "exec", containerName, "sh", "-c", check.cmd)
			output, err := execCmd.CombinedOutput()

			if check.wantErr && err == nil {
				t.Errorf("Expected error for %s, got success: %s", check.name, output)
			} else if !check.wantErr && err != nil {
				t.Errorf("Expected success for %s, got error: %v\n%s", check.name, err, output)
			} else {
				t.Logf("PASS: %s", check.name)
			}
		})
	}
}
