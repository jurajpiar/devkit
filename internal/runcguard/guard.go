// Package runcguard is devkit's runtime guard: registered with the Docker
// daemon as the runtime devkit-runc, it stands in for runc. The API filter
// judges a request, but the daemon resolves bind sources later, when runc
// mounts them, and the workspace is the sandbox user's to rearrange in
// between: a directory that passed the filter can be a symlink to the
// daemon's own sockets by the time it is mounted. The guard checks the
// mounts as made. It wraps "runc create", which sets up a container's
// mounts and stops before the container's process starts, reads the mount
// table of the waiting process, and deletes the container unless every
// mount of an existing filesystem comes from where mounts may come from.
// Mounts are bound to inodes, so what the user rearranges afterwards does
// not matter.
package runcguard

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ProgramName is the name the guest binary runs the guard under; the daemon
// knows it as the runtime RuntimeName.
const (
	ProgramName = "devkit-runc-guard"
	RuntimeName = "devkit-runc"
)

// DefaultConfigPath is where provisioning writes the guard's settings. The
// guard takes nothing from its environment or working directory.
const DefaultConfigPath = "/etc/devkit/docker/guard.json"

// Config is the guard's root-owned configuration.
type Config struct {
	// Runc is the real runc, at the path Ubuntu's AppArmor profile exempts.
	Runc       string `json:"runc"`
	Workspace  string `json:"workspace"`
	DataRoot   string `json:"data_root"`
	DockerInit string `json:"docker_init"`
}

func loadConfig(data []byte) (*Config, error) {
	var c Config
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, err
	}
	for name, p := range map[string]string{"runc": c.Runc, "workspace": c.Workspace, "data_root": c.DataRoot, "docker_init": c.DockerInit} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p || p == "/" {
			return nil, fmt.Errorf("%s must be a clean absolute path other than /", name)
		}
	}
	return &c, nil
}

// Guard is the guard with what it touches made replaceable for tests.
type Guard struct {
	ConfigPath string
	// Self is the guard's own executable, resolved.
	Self func() (string, error)
	// Exec replaces the process (syscall.Exec).
	Exec func(path string, argv, env []string) error
	// Run runs a command with the guard's stdio and the given extra file
	// descriptors, and returns its exit code.
	Run      func(path string, args []string, extra []*os.File) (int, error)
	ReadFile func(string) ([]byte, error)
	Stderr   io.Writer
}

// New returns the guard as installed.
func New() *Guard {
	return &Guard{
		ConfigPath: DefaultConfigPath,
		Self: func() (string, error) {
			p, err := os.Executable()
			if err != nil {
				return "", err
			}
			return filepath.EvalSymlinks(p)
		},
		Exec:     syscall.Exec,
		Run:      run,
		ReadFile: os.ReadFile,
		Stderr:   os.Stderr,
	}
}

func run(path string, args []string, extra []*os.File) (int, error) {
	cmd := exec.Command(path, args...)
	cmd.Args[0] = path
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.ExtraFiles = extra
	cmd.Env = os.Environ()
	err := cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), nil
	}
	if err != nil {
		return 1, err
	}
	return 0, nil
}

// Main runs the guard with runc's argument list (without the program
// name) and returns the exit code, unless it execs runc.
func (g *Guard) Main(args []string) int {
	cfg, real, err := g.setup()
	if err != nil {
		fmt.Fprintf(g.Stderr, "devkit: refused: the runtime guard is not usable: %v\n", err)
		return 1
	}
	inv, err := Parse(args)
	if err != nil {
		fmt.Fprintf(g.Stderr, "devkit: refused: the runtime guard cannot read the runc command line: %v\n", err)
		return 1
	}
	switch inv.Sub {
	case "run", "restore":
		g.fail(inv, fmt.Sprintf("devkit: refused: runc %s is not allowed: the guard checks mounts only between create and start", inv.Sub))
		return 1
	case "create":
		return g.create(cfg, real, inv, args)
	}
	err = g.Exec(real, append([]string{real}, args...), os.Environ())
	fmt.Fprintf(g.Stderr, "devkit: the runtime guard could not run runc: %v\n", err)
	return 1
}

// setup reads the configuration and refuses to work when runc would be the
// guard itself.
func (g *Guard) setup() (*Config, string, error) {
	data, err := g.ReadFile(g.ConfigPath)
	if err != nil {
		return nil, "", err
	}
	cfg, err := loadConfig(data)
	if err != nil {
		return nil, "", fmt.Errorf("%s: %v", g.ConfigPath, err)
	}
	real, err := filepath.EvalSymlinks(cfg.Runc)
	if err != nil {
		return nil, "", fmt.Errorf("runc: %v", err)
	}
	self, err := g.Self()
	if err != nil {
		return nil, "", err
	}
	if real == self {
		return nil, "", fmt.Errorf("the configured runc %s is the guard itself", cfg.Runc)
	}
	return cfg, real, nil
}

func (g *Guard) create(cfg *Config, real string, inv *Invocation, args []string) int {
	extra := make([]*os.File, inv.PreserveFDs)
	for i := range extra {
		extra[i] = os.NewFile(uintptr(3+i), "preserved")
	}
	code, err := g.Run(real, args, extra)
	if err != nil {
		fmt.Fprintf(g.Stderr, "devkit: the runtime guard could not run runc: %v\n", err)
		return 1
	}
	if code != 0 {
		return code
	}
	bad, err := g.check(cfg, inv)
	if err == nil && bad == nil {
		return 0
	}
	g.Run(real, append(append([]string{}, inv.Global...), "delete", "--force", inv.ID), nil)
	msg := "devkit: refused: the runtime guard could not check the container's mounts: "
	if err != nil {
		msg += err.Error()
	} else {
		msg = fmt.Sprintf("devkit: refused: a mount comes from outside the workspace: %s %s at %s", bad.FSType, printable(bad.Root), printable(bad.Point))
	}
	g.fail(inv, msg)
	return 1
}

func (g *Guard) check(cfg *Config, inv *Invocation) (*MountEntry, error) {
	pidData, err := g.ReadFile(inv.PidFile)
	if err != nil {
		return nil, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(pidData)))
	if err != nil || pid <= 0 {
		return nil, fmt.Errorf("the pid file holds %q", pidData)
	}
	host, err := g.mountinfo("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}
	ctr, err := g.mountinfo(fmt.Sprintf("/proc/%d/mountinfo", pid))
	if err != nil {
		return nil, err
	}
	// The container's cgroup as the guard sees it, which is how the
	// guard's mount table writes the root of a cgroup2 mount. Without it,
	// no cgroup2 mount passes.
	cg, err := g.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return nil, err
	}
	return Check(host, ctr, Policy{Workspace: cfg.Workspace, DataRoot: cfg.DataRoot, DockerInit: cfg.DockerInit,
		ContainerID: inv.ID, Cgroup: unifiedCgroup(cg)}), nil
}

// unifiedCgroup is the cgroup2 path of a /proc/<pid>/cgroup table (its
// "0::" line), or "" if it has none.
func unifiedCgroup(data []byte) string {
	for _, l := range strings.Split(string(data), "\n") {
		if p, ok := strings.CutPrefix(l, "0::"); ok && strings.HasPrefix(p, "/") {
			return p
		}
	}
	return ""
}

func (g *Guard) mountinfo(p string) ([]MountEntry, error) {
	data, err := g.ReadFile(p)
	if err != nil {
		return nil, err
	}
	return ParseMountinfo(bytes.NewReader(data))
}

// fail reports a refusal where containerd looks for the runtime's error,
// the --log file in its format, and on stderr.
func (g *Guard) fail(inv *Invocation, msg string) {
	if inv != nil && inv.Log != "" {
		var line []byte
		now := time.Now().UTC().Format(time.RFC3339Nano)
		if inv.LogFormat == "json" {
			line, _ = json.Marshal(map[string]string{"level": "error", "msg": msg, "time": now})
		} else {
			line = []byte(fmt.Sprintf("time=%q level=error msg=%q", now, msg))
		}
		if f, err := os.OpenFile(inv.Log, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644); err == nil {
			f.Write(append(line, '\n'))
			f.Close()
		}
	}
	fmt.Fprintln(g.Stderr, msg)
}

func printable(s string) string {
	q := strconv.QuoteToASCII(s)
	return q[1 : len(q)-1]
}
