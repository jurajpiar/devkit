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
//
// The same guard stands in front of gVisor's runsc. There the container's
// bind mounts are made by runsc's gofer, a host process that serves the
// container's files to the sandbox. "runsc create" returns while the gofer
// and the sandbox are still building their mount tables, so the guard waits
// a bounded time for each to reach its final form, then checks the gofer's
// by the same rules and that the sandbox has no host mount of its own. It
// checks both again when the shim asks runsc to start the container.
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

// RunscPrograms are the names the guest binary runs the guard under in
// front of runsc, each for the Docker runtime it is registered as. The
// name says which runtime's arguments to expect: Docker gives the guard
// the arguments daemon.json lists for the runtime and nothing that says
// which runtime it is, and the guard takes nothing from its environment.
// Both names are links root installs, and daemon.json, root's, names them.
var RunscPrograms = map[string]string{
	"devkit-runsc-guard":         "runsc",
	"devkit-runsc-hostnet-guard": "runsc-hostnet",
}

// DefaultConfigPath is where provisioning writes the guard's settings. The
// guard takes nothing from its environment or working directory.
const DefaultConfigPath = "/etc/devkit/docker/guard.json"

// Config is the guard's root-owned configuration.
type Config struct {
	// Runc is the real runc, at the path Ubuntu's AppArmor profile exempts.
	Runc string `json:"runc"`
	// Runsc is present when the guard also stands in front of runsc.
	Runsc      *RunscConfig `json:"runsc,omitempty"`
	Workspace  string       `json:"workspace"`
	DataRoot   string       `json:"data_root"`
	DockerInit string       `json:"docker_init"`
}

// RunscConfig is the real runsc and, for each runtime the guard fronts,
// the arguments daemon.json gives it: the only global flags the guard
// passes to runsc beyond the shim's own.
type RunscConfig struct {
	Path        string              `json:"path"`
	RuntimeArgs map[string][]string `json:"runtime_args"`
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
	if r := c.Runsc; r != nil {
		if !filepath.IsAbs(r.Path) || filepath.Clean(r.Path) != r.Path || r.Path == "/" {
			return nil, errors.New("runsc.path must be a clean absolute path other than /")
		}
		for name, args := range r.RuntimeArgs {
			if name == "" {
				return nil, errors.New("runsc.runtime_args has a runtime without a name")
			}
			for _, a := range args {
				if !strings.HasPrefix(a, "--") {
					return nil, fmt.Errorf("runsc.runtime_args: %q is not a flag", a)
				}
			}
		}
	}
	return &c, nil
}

// Guard is the guard with what it touches made replaceable for tests.
type Guard struct {
	// Runtime is the runsc runtime the guard stands in for, or "" for
	// runc.
	Runtime    string
	ConfigPath string
	// Self is the guard's own executable, resolved.
	Self func() (string, error)
	// Exec replaces the process (syscall.Exec).
	Exec func(path string, argv, env []string) error
	// Run runs a command with the guard's stdio and the given extra file
	// descriptors, and returns its exit code.
	Run func(path string, args []string, extra []*os.File) (int, error)
	// Output runs a command and returns what it wrote to stdout; its
	// stderr is the guard's.
	Output   func(path string, args []string) ([]byte, error)
	ReadFile func(string) ([]byte, error)
	Stderr   io.Writer
	// Proc is where the processes are, read for runsc's gofer and sandbox.
	Proc   string
	Getuid func() int
	// Clock is what the guard waits by for runsc's mounts; nil is the real
	// clock.
	Clock clock
}

// New returns the guard as installed in front of runc.
func New() *Guard { return NewFor("") }

// NewFor returns the guard as installed in front of the given runsc
// runtime, or of runc for "".
func NewFor(runtime string) *Guard {
	return &Guard{
		Runtime:    runtime,
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
		Output:   output,
		ReadFile: os.ReadFile,
		Stderr:   os.Stderr,
		Proc:     "/proc",
		Getuid:   os.Getuid,
		Clock:    realClock{},
	}
}

func output(path string, args []string) ([]byte, error) {
	cmd := exec.Command(path, args...)
	cmd.Args[0] = path
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	return cmd.Output()
}

func (g *Guard) clock() clock {
	if g.Clock == nil {
		return realClock{}
	}
	return g.Clock
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
	if g.Runtime != "" {
		return g.mainRunsc(cfg, real, args)
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
		return g.create(cfg, real, inv, args, g.check)
	}
	err = g.Exec(real, append([]string{real}, args...), os.Environ())
	fmt.Fprintf(g.Stderr, "devkit: the runtime guard could not run runc: %v\n", err)
	return 1
}

// runscPassThrough are the subcommands containerd's runc shim gives a
// runtime besides create, run, checkpoint and restore, and "" for
// --version. They make no mounts. runsc's other subcommands (do, boot,
// gofer, debug, install, ...) are no business of the shim's and are
// refused.
var runscPassThrough = map[string]bool{
	"": true, "start": true, "state": true, "kill": true, "delete": true, "exec": true, "ps": true,
	"events": true, "wait": true, "pause": true, "resume": true, "update": true, "features": true,
}

func (g *Guard) mainRunsc(cfg *Config, real string, args []string) int {
	inv, err := ParseRunsc(args, cfg.Runsc.RuntimeArgs[g.Runtime])
	if err != nil {
		fmt.Fprintf(g.Stderr, "devkit: refused: the runtime guard cannot read the runsc command line: %v\n", err)
		return 1
	}
	switch {
	case inv.Sub == "run" || inv.Sub == "restore":
		g.fail(inv, fmt.Sprintf("devkit: refused: runsc %s is not allowed: the guard checks mounts only between create and start", inv.Sub))
		return 1
	case inv.Sub == "checkpoint":
		g.fail(inv, "devkit: refused: runsc checkpoint is not allowed: a checkpoint is only of use to restore, which the guard refuses")
		return 1
	case inv.Sub == "create":
		return g.create(cfg, real, inv, args, g.checkRunsc)
	case inv.Sub == "start":
		// The check at create waited for the tables to be final, and the
		// gofer is not known to mount anything once its table is. That is
		// runsc's behaviour as observed, not a promise; so the tables are
		// judged again, as they are now, before the container's first
		// process may run.
		if bad, err := g.checkStart(cfg, real, inv); err != nil || bad != nil {
			g.refuse(real, inv, bad, err)
			return 1
		}
	case !runscPassThrough[inv.Sub]:
		g.fail(inv, fmt.Sprintf("devkit: refused: runsc %s is not a subcommand the guard passes", printable(inv.Sub)))
		return 1
	}
	err = g.Exec(real, append([]string{real}, args...), os.Environ())
	fmt.Fprintf(g.Stderr, "devkit: the runtime guard could not run runsc: %v\n", err)
	return 1
}

// setup reads the configuration and refuses to work when the runtime would
// be the guard itself, or when the guard is to front a runsc runtime the
// configuration does not describe.
func (g *Guard) setup() (*Config, string, error) {
	data, err := g.ReadFile(g.ConfigPath)
	if err != nil {
		return nil, "", err
	}
	cfg, err := loadConfig(data)
	if err != nil {
		return nil, "", fmt.Errorf("%s: %v", g.ConfigPath, err)
	}
	name, path := "runc", cfg.Runc
	if g.Runtime != "" {
		if cfg.Runsc == nil {
			return nil, "", fmt.Errorf("%s: no runsc", g.ConfigPath)
		}
		if _, ok := cfg.Runsc.RuntimeArgs[g.Runtime]; !ok {
			return nil, "", fmt.Errorf("%s: no arguments for the runtime %s", g.ConfigPath, g.Runtime)
		}
		name, path = "runsc", cfg.Runsc.Path
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, "", fmt.Errorf("%s: %v", name, err)
	}
	self, err := g.Self()
	if err != nil {
		return nil, "", err
	}
	if real == self {
		return nil, "", fmt.Errorf("the configured %s %s is the guard itself", name, path)
	}
	return cfg, real, nil
}

// create runs the real runtime's create and then check; unless the check
// passes, it deletes the container and refuses.
func (g *Guard) create(cfg *Config, real string, inv *Invocation, args []string,
	check func(*Config, string, *Invocation) (*MountEntry, error)) int {
	extra := make([]*os.File, inv.PreserveFDs)
	for i := range extra {
		extra[i] = os.NewFile(uintptr(3+i), "preserved")
	}
	code, err := g.Run(real, args, extra)
	if err != nil {
		fmt.Fprintf(g.Stderr, "devkit: the runtime guard could not run %s: %v\n", filepath.Base(real), err)
		return 1
	}
	if code != 0 {
		return code
	}
	bad, err := check(cfg, real, inv)
	if err == nil && bad == nil {
		return 0
	}
	g.refuse(real, inv, bad, err)
	return 1
}

// refuse deletes the container and reports why: a mount, or what kept the
// guard from checking.
func (g *Guard) refuse(real string, inv *Invocation, bad *MountEntry, err error) {
	g.Run(real, append(append([]string{}, inv.Global...), "delete", "--force", inv.ID), nil)
	msg := "devkit: refused: the runtime guard could not check the container's mounts: "
	if err != nil {
		msg += err.Error()
	} else {
		msg = fmt.Sprintf("devkit: refused: a mount comes from outside the workspace: %s %s at %s", bad.FSType, printable(bad.Root), printable(bad.Point))
	}
	g.fail(inv, msg)
}

// readPid reads the pid the runtime wrote: runc's container process, or
// runsc's sandbox.
func (g *Guard) readPid(inv *Invocation) (int, error) {
	pidData, err := g.ReadFile(inv.PidFile)
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(pidData)))
	if err != nil || pid <= 0 {
		return 0, fmt.Errorf("the pid file holds %q", pidData)
	}
	return pid, nil
}

func (g *Guard) check(cfg *Config, _ string, inv *Invocation) (*MountEntry, error) {
	pid, err := g.readPid(inv)
	if err != nil {
		return nil, err
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

// checkRunsc checks what runsc create left: the sandbox, whose pid runsc
// writes to the pid file, and its gofer, which holds the container's bind
// mounts. create returns while both are still setting up, so each table is
// waited for, up to SetupBound, until it is in its final form.
func (g *Guard) checkRunsc(cfg *Config, real string, inv *Invocation) (*MountEntry, error) {
	pid, err := g.readPid(inv)
	if err != nil {
		return nil, err
	}
	return g.inspectRunsc(cfg, real, inv.ID, inv.Bundle, pid, SetupBound)
}

// runscState is what the guard reads of "runsc state": the OCI state of
// the container.
type runscState struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Pid    int    `json:"pid"`
	Bundle string `json:"bundle"`
}

// checkStart checks a container again as runsc start is asked to run it:
// its tables as they are now, with no wait, since they were final at
// create. start names only the container, so its sandbox and bundle are
// read from "runsc state", run with the shim's own global flags. That is
// runsc's record under --root, written by runsc as the Docker account at
// create, in a directory of that account's: nothing in a container and
// nothing the workspace's user owns can write it, and whoever can already
// runs runsc as that account. What it names must still pass everything
// create checked: the bundle named after the container, a sandbox of the
// guard's uid, and exactly one gofer that runs the real runsc, as that
// uid, under the sandbox's parent, with that bundle on its command line.
func (g *Guard) checkStart(cfg *Config, real string, inv *Invocation) (*MountEntry, error) {
	out, err := g.Output(real, append(append([]string{}, inv.Global...), "state", inv.ID))
	if err != nil {
		return nil, fmt.Errorf("runsc state: %v", err)
	}
	var st runscState
	if err := json.Unmarshal(out, &st); err != nil {
		return nil, fmt.Errorf("runsc state: %v", err)
	}
	if st.ID != inv.ID || st.Status != "created" || st.Pid <= 0 {
		return nil, fmt.Errorf("runsc state gives container %q, status %q, pid %d", st.ID, st.Status, st.Pid)
	}
	return g.inspectRunsc(cfg, real, inv.ID, st.Bundle, st.Pid, 0)
}

// inspectRunsc checks the sandbox whose pid is pid and its gofer, the
// container's whose ID and bundle are given. Both are held open while they
// are read, so that neither can be swapped for another process under the
// same pid in between. Each table is read until it is in its final form or
// bound has passed, and judged once it is.
func (g *Guard) inspectRunsc(cfg *Config, real, id, bundle string, pid int, bound time.Duration) (*MountEntry, error) {
	// containerd's bundle directory is named after the container, and the
	// gofer is recognised by its bundle: the two must agree.
	if !validID(id) || filepath.Base(bundle) != id {
		return nil, fmt.Errorf("the bundle %q is not the container %q's", bundle, id)
	}
	fi, err := os.Stat(real)
	if err != nil {
		return nil, err
	}
	runsc, err := statID(fi)
	if err != nil {
		return nil, err
	}
	host, err := g.mountinfo("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}
	uid := g.Getuid()
	sb, err := openProc(g.Proc, pid)
	if err != nil {
		return nil, fmt.Errorf("the sandbox: %v", err)
	}
	defer sb.Close()
	sbInfo, err := readProcInfo(sb)
	if err != nil {
		return nil, fmt.Errorf("the sandbox: %v", err)
	}
	if sbInfo.UID != uid {
		return nil, fmt.Errorf("the sandbox %d is not the guard's uid's", pid)
	}
	gofer, err := findGofer(g.Proc, pid, sbInfo.PPid, uid, runsc, bundle)
	if err != nil {
		return nil, err
	}
	defer gofer.Close()
	notFinal := func(who string) error {
		if bound == 0 {
			return fmt.Errorf("the mounts of %s are not in their final form at start", who)
		}
		return fmt.Errorf("%s never finished setting up its mounts (waited %v)", who, bound)
	}
	readGofer := func() ([]MountEntry, error) {
		t, err := tableOf(gofer)
		if err != nil {
			return nil, fmt.Errorf("the gofer: %v", err)
		}
		// The descriptor keeps the process, but a process can exec: what
		// was read must still be the gofer's once it has been read.
		if !isGofer(gofer, sbInfo.PPid, uid, runsc, bundle) {
			return nil, errors.New("the gofer changed while its mounts were read")
		}
		return t, nil
	}
	policy := Policy{Workspace: cfg.Workspace, DataRoot: cfg.DataRoot, DockerInit: cfg.DockerInit, ContainerID: id, Gofer: true}
	bad, err := awaitFinal(readGofer, GoferFinal, func(t []MountEntry) *MountEntry { return Check(host, t, policy) }, g.clock(), bound)
	if errors.Is(err, errNotFinal) {
		return nil, notFinal("gVisor's gofer")
	}
	if err != nil || bad != nil {
		return bad, err
	}
	readSandbox := func() ([]MountEntry, error) {
		t, err := tableOf(sb)
		if err != nil {
			return nil, fmt.Errorf("the sandbox: %v", err)
		}
		return t, nil
	}
	bad, err = awaitFinal(readSandbox, func(t []MountEntry) bool { return SandboxFinal(host, t) },
		func(t []MountEntry) *MountEntry { return CheckSandbox(host, t) }, g.clock(), bound)
	if errors.Is(err, errNotFinal) {
		return nil, notFinal("gVisor's sandbox")
	}
	return bad, err
}

func tableOf(e procEntry) ([]MountEntry, error) {
	data, err := e.ReadFile("mountinfo")
	if err != nil {
		return nil, err
	}
	return ParseMountinfo(bytes.NewReader(data))
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
