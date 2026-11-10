// Package lima is a thin wrapper around the limactl command line.
package lima

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
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

// Dir returns the instance directory under Lima's home.
func Dir(name string) string {
	return filepath.Join(Home(), name)
}

// Home is Lima's data directory, resolved the way limactl's LimaDir does it:
// LIMA_HOME when set, otherwise ~/.lima, returned as given when it does not
// exist yet and with symlinks resolved when it does. Every path devkit
// derives from it must agree with limactl, or a check reads one file while
// Lima uses another.
func Home() string {
	dir := os.Getenv("LIMA_HOME")
	if dir == "" {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".lima")
	}
	// Symlinks first, as limactl does, because Abs cleans ".." before any
	// symlink in the path is followed: a/link/.. must land where the link's
	// target's parent is, not in a. Then absolute, so nothing derived from it
	// and persisted (the SSH config block) depends on the current directory.
	if _, err := os.Stat(dir); err == nil {
		if real, err := filepath.EvalSymlinks(dir); err == nil {
			dir = real
		}
	}
	if abs, err := filepath.Abs(dir); err == nil {
		dir = abs
	}
	return dir
}

// HostAgentPID is the pid of the instance's host agent, the Mac process that
// carries the VM's network, from the ha.pid Lima writes while it runs.
func HostAgentPID(name string) (int, error) {
	data, err := os.ReadFile(filepath.Join(Dir(name), "ha.pid"))
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid < 1 {
		return 0, fmt.Errorf("%s/ha.pid does not hold a pid", Dir(name))
	}
	return pid, nil
}

// ConfigPath is the instance's lima.yaml.
func ConfigPath(name string) string {
	return filepath.Join(Home(), name, "lima.yaml")
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

// StopForce stops an instance without asking the guest to shut down, for
// one whose kernel can no longer answer.
func StopForce(ctx context.Context, name string) error {
	return stream(ctx, "stop", "--force", name)
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

// CopyTo copies a host file into the VM. There is deliberately no CopyFrom:
// nothing the guest writes is ever placed on the host by devkit on its own.
// The one exception is ReadGuestFile, used only by "devkit push".
func CopyTo(ctx context.Context, name, src, dst string) error {
	_, err := run(ctx, "copy", src, name+":"+dst)
	return err
}

// ReadGuestFile streams a file from the VM into w and fails if it is larger
// than max bytes. Its only caller is "devkit push", which reads a git bundle
// into a private temporary file and has git check every object in it before
// anything is stored; the bytes are untrusted.
func ReadGuestFile(ctx context.Context, name, guestPath string, w io.Writer, max int64) error {
	cmd := exec.CommandContext(ctx, "limactl", "shell", name, "--", "cat", "--", guestPath)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	n, copyErr := io.Copy(w, io.LimitReader(out, max+1))
	if copyErr != nil || n > max {
		// Stop cat before waiting: nothing reads the pipe any more.
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if copyErr != nil {
			return copyErr
		}
		return fmt.Errorf("%s is larger than %d MiB", guestPath, max>>20)
	}
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("read %s from the VM: %w: %s", guestPath, err, strings.TrimSpace(stderr.String()))
	}
	return nil
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
	// Once ctx is done, stop waiting for output: killing limactl can leave its
	// ssh child holding the pipes open for as long as the guest keeps it.
	cmd.WaitDelay = time.Second
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
