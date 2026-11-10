package app

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jurajpiar/devkit/internal/egressproxy"
	"github.com/jurajpiar/devkit/internal/hostenforce"
	"github.com/jurajpiar/devkit/internal/lima"
	"github.com/jurajpiar/devkit/internal/project"
	"github.com/jurajpiar/devkit/internal/provision"
	"github.com/spf13/cobra"
)

// Host-side state for network.enforce: host, in vmStateDir: ~/.devkit/<vm>/
// for Lima's default home.
const (
	hostProxyPortFile  = "hostproxy.port"  // the proxy's port, chosen once per VM
	hostProxyStateFile = "hostproxy.json"  // the running proxy: pid, port, health token
	hostProxyAllowFile = "hostproxy.allow" // the allowlist it was started with
	hostProxyLog       = "hostproxy.log"   // its audit log, the authoritative one
	hostAgentPIDFile   = "hostagent.pid"   // Lima's host agent at the last sandboxed start
)

// hostGateway is the Mac as the guest reaches it on Lima's user-mode network.
const hostGateway = "192.168.5.2"

// Seams for tests: the platform check and the sandboxed start command.
var (
	hostEnforceCheck = hostenforce.Check
	sandboxStartArgs = hostenforce.StartArgs
)

// executableID identifies the devkit binary that runs: the SHA-256 of its
// executable, symlinks resolved, computed once per process. A host proxy
// runs the code of the binary that started it, so up restarts one started
// by any other binary, a rebuild at the same path included. A seam for
// tests.
var executableID = sync.OnceValues(func() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return "", err
	}
	f, err := os.Open(exe)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
})

// vmStateDir is devkit's host-side state for one VM. Lima keys an instance
// by its home as well as its name, so two VMs of one name can exist under
// different LIMA_HOME directories; each gets its own state, or starting one
// would replace the other's proxy policy and down or rm would stop it. The
// default home keeps ~/.devkit/<vm>/; any other adds the first 8 hex digits
// of the SHA-256 of its canonical path.
func vmStateDir(name string) string {
	home := canonicalPath(lima.Home())
	def, _ := os.UserHomeDir()
	if home == canonicalPath(filepath.Join(def, ".lima")) {
		return filepath.Join(devkitHome(), name)
	}
	sum := sha256.Sum256([]byte(home))
	return filepath.Join(devkitHome(), name+"-"+hex.EncodeToString(sum[:])[:8])
}

// VMStateDir is vmStateDir, for the end-to-end tests, which read the host
// proxy's port and log from it.
func VMStateDir(name string) string { return vmStateDir(name) }

// canonicalPath is path absolute with every symlink resolved, also when it
// does not exist yet: its nearest existing ancestor is resolved and the
// rest appended, so the key does not change once Lima creates its home
// (devkit up chooses the proxy port before limactl create runs).
func canonicalPath(path string) string {
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	rest := ""
	for dir := path; ; dir = filepath.Dir(dir) {
		if real, err := filepath.EvalSymlinks(dir); err == nil {
			return filepath.Join(real, rest)
		}
		if filepath.Dir(dir) == dir {
			return path
		}
		rest = filepath.Join(filepath.Base(dir), rest)
	}
}

var hostproxyCmd = &cobra.Command{
	Use:    "hostproxy",
	Short:  "Run a VM's egress proxy on the Mac (started by devkit up under network.enforce: host)",
	Hidden: true,
	Args:   cobra.NoArgs,
	RunE:   runHostProxy,
}

func init() {
	rootCmd.AddCommand(hostproxyCmd)
	hostproxyCmd.Flags().String("listen", "", "127.0.0.1:<port> to listen on")
	hostproxyCmd.Flags().String("allow-file", "", "file with one allowlist entry per line")
	hostproxyCmd.Flags().String("log", "", "audit log file")
	hostproxyCmd.Flags().String("health", "", "body returned for "+egressproxy.HealthPath)
}

// runHostProxy serves the egress proxy in the foreground on the Mac's
// loopback, where the sandboxed host agent may reach it, until signalled.
func runHostProxy(cmd *cobra.Command, _ []string) error {
	listen, _ := cmd.Flags().GetString("listen")
	allowFile, _ := cmd.Flags().GetString("allow-file")
	logPath, _ := cmd.Flags().GetString("log")
	health, _ := cmd.Flags().GetString("health")
	if host, _, err := net.SplitHostPort(listen); err != nil || host != "127.0.0.1" {
		return fmt.Errorf("hostproxy: --listen must be 127.0.0.1:<port>, got %q", listen)
	}
	allow, err := readAllowFile(allowFile)
	if err != nil {
		return err
	}
	out := io.Writer(os.Stderr)
	if logPath != "" {
		f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		defer f.Close()
		out = f
	}
	logger := log.New(out, "", log.LstdFlags)
	p := egressproxy.NewProxy(egressproxy.ProxyConfig{
		ListenAddr:   listen,
		AllowedHosts: allow,
		AuditLog:     true,
		Logger:       logger,
		// On the Mac: never a way into the Mac's own addresses, and the
		// in-guest proxy (or apt) decides about redirects itself.
		RefuseLocal:     true,
		ReturnRedirects: true,
		Health:          health,
	})
	logger.Printf("devkit host proxy on %s, %d allowlist entries", listen, len(allow))
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	if err := p.Start(ctx); err != nil {
		logger.Printf("devkit host proxy: %v", err)
		return err
	}
	return nil
}

func readAllowFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("hostproxy: %w", err)
	}
	var out []string
	for _, l := range strings.Split(string(data), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out, nil
}

// hostAllowlist is what the proxy on the Mac allows: the project's hosts
// plus what root's provisioning fetches, since root's downloads go through
// it too. In open mode, everything (still web ports only, as in the guest).
func hostAllowlist(cfg *project.Config) []string {
	if cfg.Network.Mode == project.NetworkOpen {
		return []string{"*"}
	}
	var out []string
	seen := map[string]bool{}
	for _, h := range append(append([]string{}, cfg.Network.Allow...), provision.RootHosts(cfg)...) {
		if !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	return out
}

// hostProxyPort is the VM's host proxy port: chosen free the first time and
// kept, because it is part of the VM's provisioning and its profile.
func hostProxyPort(name string) (int, error) {
	dir := vmStateDir(name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return 0, err
	}
	_ = os.Chmod(dir, 0o700)
	path := filepath.Join(dir, hostProxyPortFile)
	if data, err := os.ReadFile(path); err == nil {
		if p, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && p > 0 && p < 65536 {
			return p, nil
		}
		return 0, fmt.Errorf("%s does not hold a port; delete it to choose a new one", path)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	if err := os.WriteFile(path, []byte(strconv.Itoa(port)+"\n"), 0o600); err != nil {
		return 0, err
	}
	return port, nil
}

// hostProxyState is a running host proxy.
type hostProxyState struct {
	PID    int    `json:"pid"`
	Port   int    `json:"port"`
	Health string `json:"health"`
	// Exe is the executableID of the devkit that started it; empty in
	// state an older devkit wrote, which then counts as another binary.
	Exe string `json:"exe,omitempty"`
}

// runningHostProxy returns the recorded proxy if it answers its health
// check with the token it was started with, which also proves the pid is
// still that process rather than a reused one.
func runningHostProxy(name string) (hostProxyState, bool) {
	var st hostProxyState
	data, err := os.ReadFile(filepath.Join(vmStateDir(name), hostProxyStateFile))
	if err != nil || json.Unmarshal(data, &st) != nil || st.PID < 1 || st.Port < 1 {
		return st, false
	}
	return st, healthy(st)
}

func healthy(st hostProxyState) bool {
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d%s", st.Port, egressproxy.HealthPath))
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
	return resp.StatusCode == http.StatusOK && string(body) == st.Health
}

// ensureHostProxy makes sure the VM's host proxy runs with the current
// allowlist, starting or restarting it, and returns its port. It fails if
// the proxy cannot be brought up: in host mode the VM must not start
// without it.
func ensureHostProxy(ctx context.Context, cfg *project.Config) (int, error) {
	name := cfg.VMName()
	port, err := hostProxyPort(name)
	if err != nil {
		return 0, err
	}
	dir := vmStateDir(name)
	allow := strings.Join(hostAllowlist(cfg), "\n") + "\n"
	allowPath := filepath.Join(dir, hostProxyAllowFile)
	// Unknown when it cannot be computed: then no recorded one matches, and
	// the proxy is restarted with this binary's code.
	exeID, _ := executableID()
	if st, ok := runningHostProxy(name); ok {
		prev, _ := os.ReadFile(allowPath)
		sameExe := exeID != "" && st.Exe == exeID
		if st.Port == port && string(prev) == allow && sameExe {
			return port, nil
		}
		if sameExe {
			fmt.Println("The allowlist changed; restarting the host proxy")
		} else {
			fmt.Println("The host proxy was started by another devkit binary; restarting it")
		}
		if err := stopHostProxy(name); err != nil {
			return 0, err
		}
	}
	if err := os.WriteFile(allowPath, []byte(allow), 0o600); err != nil {
		return 0, err
	}
	logPath := filepath.Join(dir, hostProxyLog)
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, err
	}
	defer logFile.Close()
	exe, err := os.Executable()
	if err != nil {
		return 0, fmt.Errorf("host proxy: %w", err)
	}
	token := make([]byte, 12)
	if _, err := rand.Read(token); err != nil {
		return 0, err
	}
	st := hostProxyState{Port: port, Health: hex.EncodeToString(token), Exe: exeID}
	listen := fmt.Sprintf("127.0.0.1:%d", port)
	cmd := exec.Command(exe, "hostproxy", "--listen", listen, "--allow-file", allowPath, "--log", logPath, "--health", st.Health)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	// Its own session, so it outlives devkit up and the terminal's signals.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("host proxy did not start: %w", err)
	}
	st.PID = cmd.Process.Pid
	exited := make(chan struct{})
	go func() { _ = cmd.Wait(); close(exited) }()

	deadline := time.Now().Add(10 * time.Second)
	for !healthy(st) {
		select {
		case <-exited:
			return 0, fmt.Errorf("host proxy exited at once; refusing to start the VM without it (is port %d in use? see %s):\n%s", port, logPath, tailFile(logPath, 5))
		case <-ctx.Done():
			_ = cmd.Process.Kill()
			return 0, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			return 0, fmt.Errorf("host proxy did not answer on %s; refusing to start the VM without it (see %s)", listen, logPath)
		}
	}
	data, _ := json.Marshal(st)
	if err := os.WriteFile(filepath.Join(dir, hostProxyStateFile), data, 0o600); err != nil {
		_ = cmd.Process.Kill()
		return 0, err
	}
	fmt.Printf("Host proxy running on %s (pid %d); log: %s\n", listen, st.PID, logPath)
	return port, nil
}

// stopHostProxy ends the VM's host proxy, if one runs. It signals only a
// process that answered its health check, never a pid alone.
func stopHostProxy(name string) error {
	statePath := filepath.Join(vmStateDir(name), hostProxyStateFile)
	st, ok := runningHostProxy(name)
	if !ok {
		_ = os.Remove(statePath)
		return nil
	}
	proc, err := os.FindProcess(st.PID)
	if err == nil {
		_ = proc.Signal(syscall.SIGTERM)
	}
	deadline := time.Now().Add(5 * time.Second)
	for processAlive(st.PID) && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if processAlive(st.PID) && proc != nil {
		_ = proc.Kill()
		time.Sleep(100 * time.Millisecond)
	}
	if processAlive(st.PID) {
		return fmt.Errorf("host proxy (pid %d) did not stop", st.PID)
	}
	_ = os.Remove(statePath)
	return nil
}

// processAlive reports whether pid exists and is not a zombie of ours
// already reaped.
func processAlive(pid int) bool {
	if pid < 1 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

func tailFile(path string, n int) string {
	data, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return printable(strings.Join(lines, "\n"))
}

// startSandboxed returns the start function for network.enforce: host: it
// writes the VM's profile and runs limactl start under sandbox-exec, then
// records Lima's host agent, the process the profile confines.
func startSandboxed(cfg *project.Config, proxyPort int) func(ctx context.Context, name string) error {
	return func(ctx context.Context, name string) error {
		// limactl create made it; it must exist so that Home has resolved
		// its symlinks, or the profile would name a path the kernel never
		// reports and Lima's own sockets would be refused.
		home := lima.Home()
		if _, err := os.Stat(home); err != nil {
			return fmt.Errorf("Lima's home %s: %w", home, err)
		}
		path, err := hostenforce.WriteProfile(vmStateDir(name), hostenforce.Profile{
			LimaHome:  home,
			SSHPort:   cfg.SSHPort,
			ProxyPort: proxyPort,
		})
		if err != nil {
			return err
		}
		_ = os.Remove(filepath.Join(vmStateDir(name), hostAgentPIDFile))
		args := sandboxStartArgs(path, name)
		cmd := exec.CommandContext(ctx, args[0], args[1:]...)
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("limactl start under the sandbox profile failed: %w", err)
		}
		pid, err := lima.HostAgentPID(name)
		if err != nil {
			return fmt.Errorf("VM started, but its host agent could not be identified, so devkit cannot vouch that it runs under the profile: %w", err)
		}
		return os.WriteFile(filepath.Join(vmStateDir(name), hostAgentPIDFile), []byte(strconv.Itoa(pid)+"\n"), 0o600)
	}
}

// warnIfUnconfined warns, loudly, when a host-enforced VM's network process
// is not the one devkit started under the profile: limactl start run by
// hand, or a restart from Lima's own tooling, leaves it unconfined.
func warnIfUnconfined(ctx context.Context, cfg *project.Config) {
	warnIfUnconfinedTo(ctx, cfg, os.Stderr)
}

func warnIfUnconfinedTo(_ context.Context, cfg *project.Config, w io.Writer) {
	if !cfg.HostEnforced() {
		return
	}
	name := cfg.VMName()
	current, err := lima.HostAgentPID(name)
	if err != nil {
		return // not running: nothing is unconfined
	}
	recorded := 0
	if data, err := os.ReadFile(filepath.Join(vmStateDir(name), hostAgentPIDFile)); err == nil {
		recorded, _ = strconv.Atoi(strings.TrimSpace(string(data)))
	}
	if recorded == current {
		return
	}
	why := fmt.Sprintf("Lima's host agent is pid %d; devkit started pid %d under the sandbox profile", current, recorded)
	if recorded == 0 {
		why = fmt.Sprintf("Lima's host agent is pid %d; devkit has no record of starting it under the sandbox profile", current)
	}
	fmt.Fprintf(w, "\nWARNING: host enforcement is off for %s.\n"+
		"  The VM was started outside devkit (%s), so the Mac does not\n"+
		"  confine its network: root in the guest can reach the internet and your Mac.\n"+
		"  Fix: run 'devkit down', then 'devkit up'.\n\n", name, why)
}

// hostLogs is 'devkit logs' under network.enforce: host: the warnings about
// the VM, then the host proxy's log. Nothing the guest does can keep the log
// from being shown: the guest gets guestCheckTimeout to answer, and when
// following, the warnings are checked while the log is already streaming.
func hostLogs(cmd *cobra.Command, cfg *project.Config, n int, follow bool) error {
	ctx := cmd.Context()
	out, errw := cmd.OutOrStdout(), cmd.ErrOrStderr()
	warn := func(ctx context.Context, w io.Writer) {
		if inst, _ := instance(ctx, cfg); inst == nil || !inst.Running() {
			// Crash reports already found stay saved on the Mac after the
			// VM stops; only a running VM's serial log is scanned again.
			fmt.Fprint(w, crashWarning(cfg.VMName(), loadCrashState(cfg.VMName()), false))
			return
		}
		if !warnCrashes(w, cfg.VMName(), true) {
			warnRunningWithin(ctx, cfg, w, guestCheckTimeout)
		}
	}
	if !follow {
		warn(ctx, errw)
		return showHostLog(ctx, out, errw, cfg.VMName(), n, false)
	}
	// The warnings and the log's tail write at once.
	var mu sync.Mutex
	out, errw = &lockedWriter{mu: &mu, w: out}, &lockedWriter{mu: &mu, w: errw}
	wctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		warn(wctx, errw)
	}()
	err := showHostLog(ctx, out, errw, cfg.VMName(), n, true)
	cancel()
	<-done
	return err
}

// lockedWriter serialises writes to w with the writers that share mu.
type lockedWriter struct {
	mu *sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// showHostLog prints the last n lines of the host proxy's log, or follows it.
func showHostLog(ctx context.Context, out, errw io.Writer, name string, n int, follow bool) error {
	path := filepath.Join(vmStateDir(name), hostProxyLog)
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("no host proxy log at %s yet; run 'devkit up'", path)
	}
	if follow {
		tail := exec.CommandContext(ctx, "tail", "-n", strconv.Itoa(n), "-f", path)
		tail.Stdout, tail.Stderr = out, errw
		return tail.Run()
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		lines = append(lines, sc.Text())
		if len(lines) > n {
			lines = lines[1:]
		}
	}
	for _, l := range lines {
		fmt.Fprintln(out, l)
	}
	return sc.Err()
}
