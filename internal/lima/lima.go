// Package lima is a thin wrapper around the limactl command line.
package lima

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Instance is the subset of `limactl list --format json` devkit needs.
type Instance struct {
	Name         string `json:"name"`
	Status       string `json:"status"`
	Dir          string `json:"dir"`
	SSHLocalPort int    `json:"sshLocalPort"`
	CPUs         int    `json:"cpus"`
	Memory       int64  `json:"memory"`
	Disk         int64  `json:"disk"`
	VMType       string `json:"vmType"`
}

// Running reports whether the instance is up.
func (i Instance) Running() bool { return i.Status == "Running" }

// ErrNotInstalled is returned when limactl cannot be found.
var ErrNotInstalled = errors.New("Lima is not installed. Install it with: brew install lima")

// CheckInstalled verifies limactl is on PATH.
func CheckInstalled() error {
	if _, err := exec.LookPath("limactl"); err != nil {
		return ErrNotInstalled
	}
	return nil
}

// Version returns the limactl version string.
func Version(ctx context.Context) (string, error) {
	out, err := run(ctx, "--version")
	return strings.TrimSpace(out), err
}

// List returns all Lima instances.
func List(ctx context.Context) ([]Instance, error) {
	out, err := run(ctx, "list", "--format", "json")
	if err != nil {
		return nil, err
	}
	var result []Instance
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var inst Instance
		if err := json.Unmarshal([]byte(line), &inst); err != nil {
			continue
		}
		result = append(result, inst)
	}
	return result, nil
}

// Get returns one instance by name.
func Get(ctx context.Context, name string) (*Instance, error) {
	list, err := List(ctx)
	if err != nil {
		return nil, err
	}
	for _, i := range list {
		if i.Name == name {
			return &i, nil
		}
	}
	return nil, nil
}

// Dir returns the instance directory (~/.lima/<name>).
func Dir(name string) string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".lima", name)
}

// ConfigPath returns the instance's lima.yaml.
func ConfigPath(name string) string {
	return filepath.Join(Dir(name), "lima.yaml")
}

// Create registers a new instance from a config file without starting it.
func Create(ctx context.Context, name, configPath string) error {
	return stream(ctx, "create", "--tty=false", "--name", name, configPath)
}

// Start boots an instance, streaming Lima's progress to the terminal.
func Start(ctx context.Context, name string) error {
	return stream(ctx, "start", "--tty=false", name)
}

// Stop shuts an instance down.
func Stop(ctx context.Context, name string) error {
	return stream(ctx, "stop", name)
}

// Delete removes an instance and its disk.
func Delete(ctx context.Context, name string, force bool) error {
	args := []string{"delete", name}
	if force {
		args = append(args, "--force")
	}
	return stream(ctx, args...)
}

// Validate checks a config file with limactl.
func Validate(ctx context.Context, configPath string) error {
	_, err := run(ctx, "validate", configPath)
	return err
}

// WriteConfig replaces an existing instance's lima.yaml. Lima re-reads it on
// the next start, so callers must stop the instance first.
func WriteConfig(name, content string) error {
	return os.WriteFile(ConfigPath(name), []byte(content), 0o644)
}

// Exec runs a login shell command in the VM and returns its output.
func Exec(ctx context.Context, name, command string) (string, error) {
	return run(ctx, "shell", name, "--", "bash", "-lc", command)
}

// ExecStream runs a login shell command in the VM with output on the terminal.
func ExecStream(ctx context.Context, name, command string) error {
	return stream(ctx, "shell", name, "--", "bash", "-lc", command)
}

// Shell opens an interactive shell in the VM.
func Shell(ctx context.Context, name, workdir string, args ...string) error {
	full := []string{"shell"}
	if workdir != "" {
		full = append(full, "--workdir", workdir)
	}
	full = append(full, name)
	if len(args) > 0 {
		full = append(full, "--")
		full = append(full, args...)
	}
	cmd := exec.CommandContext(ctx, "limactl", full...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// CopyTo copies a host file into the VM.
func CopyTo(ctx context.Context, name, src, dst string) error {
	_, err := run(ctx, "copy", src, name+":"+dst)
	return err
}

// PipeTar streams a tar archive from the host into a directory in the VM.
// The archive is produced by `tar -C srcDir -cf - .` with the given excludes.
func PipeTar(ctx context.Context, name, srcDir, guestDir string, excludes []string) error {
	tarArgs := []string{"-C", srcDir, "-cf", "-"}
	for _, e := range excludes {
		tarArgs = append(tarArgs, "--exclude="+e)
	}
	tarArgs = append(tarArgs, ".")
	tarCmd := exec.CommandContext(ctx, "tar", tarArgs...)
	tarCmd.Env = append(os.Environ(), "COPYFILE_DISABLE=1")

	guestCmd := fmt.Sprintf("mkdir -p %q && tar -C %q -xf -", guestDir, guestDir)
	limaCmd := exec.CommandContext(ctx, "limactl", "shell", name, "--", "bash", "-lc", guestCmd)

	pipe, err := tarCmd.StdoutPipe()
	if err != nil {
		return err
	}
	limaCmd.Stdin = pipe
	var tarErr, limaErr bytes.Buffer
	tarCmd.Stderr = &tarErr
	limaCmd.Stderr = &limaErr

	if err := tarCmd.Start(); err != nil {
		return fmt.Errorf("start tar: %w", err)
	}
	if err := limaCmd.Start(); err != nil {
		_ = tarCmd.Process.Kill()
		return fmt.Errorf("start limactl: %w", err)
	}
	e1 := tarCmd.Wait()
	e2 := limaCmd.Wait()
	if e1 != nil {
		return fmt.Errorf("tar: %w: %s", e1, tarErr.String())
	}
	if e2 != nil {
		return fmt.Errorf("extract in VM: %w: %s", e2, limaErr.String())
	}
	return nil
}

func run(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "limactl", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return stdout.String(), fmt.Errorf("limactl %s: %s", args[0], msg)
	}
	return stdout.String(), nil
}

func stream(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, "limactl", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("limactl %s failed: %w", args[0], err)
	}
	return nil
}
