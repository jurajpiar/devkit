package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/jurajpiar/devkit/internal/embedded"
	"github.com/jurajpiar/devkit/internal/lima"
	"github.com/jurajpiar/devkit/internal/project"
	"github.com/jurajpiar/devkit/internal/provision"
	"github.com/spf13/cobra"
)

var upCmd = &cobra.Command{
	Use:   "up",
	Short: "Create or start the sandbox VM, copy the code in and install dependencies",
	Long: `Create or start the sandbox VM for this project.

The first run downloads Ubuntu and provisions the VM, which takes a few
minutes. Later runs take seconds. Re-running 'devkit up' after editing
devkit.yaml applies the new configuration, restarting the VM if needed.

Examples:
  devkit up                    # start, sync source, install dependencies
  devkit up --network none     # air-gap the VM (after dependencies are installed)
  devkit up --no-sync          # keep the workspace as it is inside the VM`,
	RunE: runUp,
}

func init() {
	rootCmd.AddCommand(upCmd)
	upCmd.Flags().String("network", "", "set network.mode in devkit.yaml before starting: allowlist, open or none")
	upCmd.Flags().Bool("no-sync", false, "do not copy or clone the source into the VM")
	upCmd.Flags().Bool("no-install", false, "do not install project dependencies")
	upCmd.Flags().Bool("relock", false, "resolve toolchain versions again and rewrite the VM's mise.lock")
	upCmd.Flags().Bool("no-security-updates", false, "set vm.security_updates: false in devkit.yaml before starting: skip Ubuntu's security pocket at boot (faster first boots, older guest)")
	_ = upCmd.RegisterFlagCompletionFunc("network", completeValues(project.NetworkAllowlist, project.NetworkOpen, project.NetworkNone))
}

func runUp(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	if err := requireLima(); err != nil {
		return err
	}
	configPath, _ := cmd.Flags().GetString("config")

	if mode, _ := cmd.Flags().GetString("network"); mode != "" {
		if err := setNetworkMode(configPath, mode); err != nil {
			return err
		}
		fmt.Printf("Set network.mode to %s in %s\n", mode, configPath)
	}
	if off, _ := cmd.Flags().GetBool("no-security-updates"); off {
		if err := setSecurityUpdates(configPath, false); err != nil {
			return err
		}
		fmt.Printf("Set vm.security_updates to false in %s (the guest will no longer apply Ubuntu's security pocket at boot)\n", configPath)
	}

	cfg, err := loadConfig(cmd)
	if err != nil {
		return err
	}
	// Host enforcement is never dropped silently: without its tools the VM
	// does not start at all.
	if cfg.HostEnforced() {
		if err := hostEnforceCheck(); err != nil {
			return err
		}
	}
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}

	// The egress proxy is mandatory for allowlist mode and provides the audit
	// log in open mode. Air-gapped VMs do not need it.
	var proxyBin []byte
	var proxySHA string
	if cfg.Network.Mode != project.NetworkNone {
		proxyBin, err = egressProxyBinary(ctx)
		if err != nil {
			if cfg.Network.Mode == project.NetworkAllowlist {
				return err
			}
			fmt.Printf("Warning: %v\nContinuing without the audit log.\n", err)
		} else {
			proxySHA = embedded.SHA256(proxyBin)
		}
	}

	// network.enforce: host: the proxy on the Mac comes first, because the
	// first boot's provisioning already downloads through it, and the VM
	// then starts under the sandbox profile.
	start := lima.Start
	hostProxy := ""
	if cfg.HostEnforced() {
		port, err := ensureHostProxy(ctx, cfg)
		if err != nil {
			return err
		}
		hostProxy = fmt.Sprintf("%s:%d", hostGateway, port)
		start = startSandboxed(cfg, port)
	} else if err := stopHostProxy(cfg.VMName()); err != nil {
		// Left over from an earlier host-mode config.
		fmt.Printf("Warning: %v\n", err)
	}

	rendered, err := lima.Render(lima.TemplateInput{
		Config:       cfg,
		User:         hostUser(),
		HostDir:      cwd,
		EgressSHA256: proxySHA,
		HostProxy:    hostProxy,
	})
	if err != nil {
		return err
	}

	// A global Lima override outranks the rendered config and could reinsert
	// a host proxy into the guest's environment block.
	if err := lima.CheckOverride(); err != nil {
		return err
	}
	name := cfg.VMName()
	inst, err := instance(ctx, cfg)
	if err != nil {
		return err
	}
	if inst != nil {
		// Crash reports from this log, before a start replaces it. A
		// panicked kernel cannot shut down or answer: it is forced off and
		// started again below.
		st, err := scanCrashes(name)
		if err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Warning: could not read VM %s's serial log for kernel crash reports: %v\n", name, err)
		}
		if st.panicked(inst.Running()) {
			fmt.Printf("The kernel of VM %s has panicked; forcing it off to start it again\n", name)
			if err := lima.StopForce(ctx, name); err != nil {
				return err
			}
			inst.Status = "Stopped"
		}
		fmt.Fprint(cmd.ErrOrStderr(), crashWarning(name, st, false))
	}
	if err := reconcileVM(ctx, name, rendered, inst, start); err != nil {
		return err
	}
	warnIfUnconfined(ctx, cfg)

	if proxyBin != nil {
		if err := installProxy(ctx, name, proxyBin, proxySHA); err != nil {
			return err
		}
	}

	if err := writeSSHConfig(cfg); err != nil {
		fmt.Printf("Warning: could not update ~/.ssh/config: %v\n", err)
	}

	noSync, _ := cmd.Flags().GetBool("no-sync")
	if !noSync {
		if err := syncSource(ctx, cfg, cwd); err != nil {
			return err
		}
	}

	noInstall, _ := cmd.Flags().GetBool("no-install")
	if cfg.Network.Mode != project.NetworkNone {
		relock, _ := cmd.Flags().GetBool("relock")
		if err := installToolchains(ctx, cfg, relock); err != nil {
			return err
		}
	}
	// Services are local to the VM, so they start in every network mode.
	if err := startServices(ctx, cfg); err != nil {
		return err
	}
	if !noInstall && cfg.Network.Mode != project.NetworkNone {
		fmt.Println("Installing dependencies")
		if err := lima.ExecStream(ctx, name, installScript(cfg)); err != nil {
			fmt.Printf("Warning: dependency installation failed: %v\n", err)
		}
		printBlocked(ctx, name)
	}
	// Stale trust is worth a few seconds on every up: a bundled root list in
	// a runtime or a vendored bundle in the repo does not update itself.
	fmt.Println()
	switch err := lima.ExecStream(ctx, name, shellScript(cfg, []string{"devkit-audit"})); auditExit(err) {
	case auditClean:
	case auditStale:
		fmt.Println("Run 'devkit audit --deep' for the full scan.")
	default:
		fmt.Printf("Warning: the trust audit did not complete: %v\n", err)
	}

	fmt.Println()
	fmt.Printf("Ready. Network: %s\n", describeNetwork(cfg))
	fmt.Printf("  Shell:   devkit shell\n")
	fmt.Printf("  IDE:     ssh %s   (VS Code / Cursor Remote-SSH, folder ~/%s)\n", cfg.SSHHost(), provision.WorkspaceDir)
	fmt.Printf("  Audit:   devkit logs\n")
	return nil
}

// installProxy drops the proxy binary where root picks it up, then waits
// for the service. Skipped when the VM already runs this exact binary.
func installProxy(ctx context.Context, name string, bin []byte, sha string) error {
	out, _ := lima.Exec(ctx, name, fmt.Sprintf("sha256sum %s 2>/dev/null | cut -d' ' -f1", provision.EgressBinary))
	if strings.TrimSpace(out) == sha {
		return waitForService(ctx, name)
	}

	tmp, err := os.CreateTemp("", "devkit-egressproxy-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(bin); err != nil {
		return err
	}
	_ = tmp.Close()

	guestTmp := "/tmp/devkit-egressproxy." + sha[:12]
	if err := lima.CopyTo(ctx, name, tmp.Name(), guestTmp); err != nil {
		return fmt.Errorf("copy egress proxy into VM: %w", err)
	}
	// Rename is atomic, so root never sees a half-written file.
	if _, err := lima.Exec(ctx, name, fmt.Sprintf("mv %s %s/egressproxy", guestTmp, provision.DropDir)); err != nil {
		return fmt.Errorf("stage egress proxy: %w", err)
	}
	return waitForService(ctx, name)
}

func waitForService(ctx context.Context, name string) error {
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		out, _ := lima.Exec(ctx, name, "systemctl is-active "+provision.EgressService)
		if strings.TrimSpace(out) == "active" {
			return nil
		}
		time.Sleep(time.Second)
	}
	out, _ := lima.Exec(ctx, name, "systemctl status --no-pager "+provision.EgressService+" 2>&1 | tail -n 15; tail -n 20 "+provision.EgressLog+" 2>/dev/null")
	return fmt.Errorf("egress proxy did not start inside the VM:\n%s", out)
}

// syncSource puts the project code into ~/workspace in the VM.
func syncSource(ctx context.Context, cfg *project.Config, cwd string) error {
	name := cfg.VMName()
	ws := "$HOME/" + provision.WorkspaceDir
	switch cfg.Source {
	case project.SourceCopy:
		fmt.Printf("Copying %s into the VM\n", cwd)
		if err := lima.PipeTar(ctx, name, cwd, ws, cfg.Exclude); err != nil {
			return err
		}
		return syncGit(ctx, name, cwd, ws, false, cfg.Exclude)
	case project.SourceGit:
		if isDir(bareRepo(cwd)) {
			return syncGit(ctx, name, bareRepo(cwd), ws, true, nil)
		}
		// A devkit.yaml written by "devkit init <url>" before devkit clone:
		// the VM clones a public repository itself, through the proxy.
		out, _ := lima.Exec(ctx, name, fmt.Sprintf("test -d %s/.git && echo yes", ws))
		if strings.TrimSpace(out) == "yes" {
			fmt.Println("Repository already cloned; run 'devkit sync' to pull")
			return nil
		}
		fmt.Printf("Cloning %s (%s) inside the VM\n", cfg.Repo, cfg.Branch)
		return lima.ExecStream(ctx, name, fmt.Sprintf("rm -rf %s && git clone --branch %q %q %s", ws, cfg.Branch, cfg.Repo, ws))
	case project.SourceMount:
		fmt.Println("Host directory is mounted at ~/workspace")
		return nil
	}
	return nil
}

// installToolchains makes the toolchains from devkit.yaml available in the
// VM. Everything here runs as the sandbox user through the audited proxy,
// and nothing is ever copied back to the host.
//
// mise: the first run resolves tools.versions and records every download's
// URL and checksum in the VM's lockfile. Later runs install with --locked,
// so nothing newer or different can slip in until --relock is asked for.
// The lock lives with the VM and goes when the VM goes.
//
// nix: the project's flake.nix provides the dev shell. The closure is fetched
// now so that later commands start instantly. A flake.lock written by the
// first evaluation stays in the VM; commit one from the host when you want
// the inputs pinned for everyone.
func installToolchains(ctx context.Context, cfg *project.Config, relock bool) error {
	name := cfg.VMName()
	switch cfg.Tools.Manager {
	case project.ManagerMise:
		if len(cfg.Tools.Versions) == 0 {
			return nil
		}
		lock := "$HOME/.config/mise/mise.lock"
		if relock {
			_, _ = lima.Exec(ctx, name, "rm -f "+lock)
		}
		out, _ := lima.Exec(ctx, name, "test -s "+lock+" && echo yes")
		if strings.TrimSpace(out) == "yes" {
			fmt.Println("Installing toolchains pinned by the VM's mise.lock")
			if err := lima.ExecStream(ctx, name, "mise install --locked"); err != nil {
				return fmt.Errorf("mise install --locked failed (run 'devkit up --relock' after changing tools.versions): %w", err)
			}
			return nil
		}
		fmt.Println("Installing toolchains and recording their checksums")
		if err := lima.ExecStream(ctx, name, "mise install && mise lock --global"); err != nil {
			return fmt.Errorf("mise install failed: %w", err)
		}
		fmt.Println("Recorded toolchain checksums in the VM; later runs refuse anything else")
	case project.ManagerNix:
		ws := "$HOME/" + provision.WorkspaceDir
		out, _ := lima.Exec(ctx, name, "test -f "+ws+"/flake.nix && echo yes")
		if strings.TrimSpace(out) != "yes" {
			fmt.Println("No flake.nix in the workspace; 'devkit init --toolchain nix' writes a starting point")
			return nil
		}
		fmt.Println("Fetching the dev shell from flake.nix")
		if err := lima.ExecStream(ctx, name, "cd "+ws+" && nix develop --command true"); err != nil {
			return fmt.Errorf("nix develop failed: %w", err)
		}
		if _, err := os.Stat("flake.lock"); err != nil && cfg.Source == project.SourceCopy {
			fmt.Println("No flake.lock in the project; the inputs are pinned only inside this VM. Run 'nix flake lock' on the host to commit one")
		}
	}
	return nil
}

// installScript installs project dependencies from the lockfile that is
// present, or runs the configured install command. With manager: nix it
// runs inside the dev shell.
func installScript(cfg *project.Config) string {
	body := cfg.Install
	if body == "" {
		body = genericInstall
	}
	script := "cd \"$HOME/" + provision.WorkspaceDir + "\" 2>/dev/null || exit 0\n"
	if cfg.Tools.Manager == project.ManagerNix {
		script += "if [ -f flake.nix ]; then exec nix develop --command bash -lc " + shellQuote(body) + "; fi\n"
	}
	return script + body
}

// genericInstall picks the install command from the lockfile. Every branch
// installs exactly what the lockfile says and nothing newer.
const genericInstall = `if [ -f package.json ]; then
  if   [ -f pnpm-lock.yaml ]; then command -v pnpm >/dev/null || corepack enable; pnpm install --frozen-lockfile
  elif [ -f yarn.lock ];      then command -v yarn >/dev/null || corepack enable; yarn install --frozen-lockfile
  elif [ -f bun.lockb ] || [ -f bun.lock ]; then
    if command -v bun >/dev/null; then bun install --frozen-lockfile
    else echo "bun lockfile found but bun is not installed (add bun to tools.versions); skipping"; fi
  elif [ -f package-lock.json ]; then npm ci
  else echo "no lockfile; running npm install (commit the lockfile it writes)"; npm install; fi
elif [ -f go.sum ];           then go mod download
elif [ -f Cargo.lock ];       then cargo fetch --locked
elif [ -f uv.lock ];          then uv sync --frozen
elif [ -f poetry.lock ];      then poetry install
elif [ -f requirements.txt ]; then python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
elif [ -f Gemfile.lock ];     then bundle install
elif [ -f gradlew ];          then ./gradlew --no-daemon dependencies >/dev/null && echo "gradle dependencies resolved"
elif [ -f pom.xml ];          then mvn -B -q dependency:resolve
else echo "nothing to install (set install: in devkit.yaml to override)"; fi`

// shellQuote wraps s in single quotes for bash.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

// printBlocked summarises hosts the proxy refused during this run.
func printBlocked(ctx context.Context, name string) {
	out, err := lima.Exec(ctx, name,
		"grep '\\[EGRESS\\] BLOCKED' "+provision.EgressLog+" 2>/dev/null | awk '{print $6}' | sort | uniq -c | sort -rn | head -n 10")
	if err != nil || strings.TrimSpace(out) == "" {
		return
	}
	fmt.Println("\nBlocked by the allowlist (add to network.allow if legitimate):")
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		fmt.Println("  " + printable(strings.TrimSpace(l)))
	}
}

// printable strips control characters from guest output before it reaches
// the terminal, so a hostname in the audit log cannot carry escape sequences.
func printable(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

func describeNetwork(cfg *project.Config) string {
	if cfg.HostEnforced() {
		return describeGuestNetwork(cfg) + ", enforced on the Mac"
	}
	return describeGuestNetwork(cfg)
}

func describeGuestNetwork(cfg *project.Config) string {
	switch cfg.Network.Mode {
	case project.NetworkAllowlist:
		return fmt.Sprintf("allowlist (%d hosts), audited", len(cfg.Network.Allow))
	case project.NetworkOpen:
		return "open, audited"
	default:
		return "none (air-gapped)"
	}
}

var modeLine = regexp.MustCompile(`(?m)^(\s*mode:\s*)(\S+)`)

// setNetworkMode edits the mode line in place so comments survive.
func setNetworkMode(path, mode string) error {
	switch mode {
	case project.NetworkOpen, project.NetworkAllowlist, project.NetworkNone:
	default:
		return fmt.Errorf("network mode must be allowlist, open or none (got %q)", mode)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !modeLine.Match(data) {
		return fmt.Errorf("could not find network.mode in %s", path)
	}
	updated := modeLine.ReplaceAll(data, []byte("${1}"+mode))
	return os.WriteFile(path, updated, 0o644)
}

var (
	securityUpdatesLine = regexp.MustCompile(`(?m)^(\s*security_updates:\s*)(\S+)`)
	diskLine            = regexp.MustCompile(`(?m)^(\s*disk_gb:.*)$`)
)

// setSecurityUpdates writes vm.security_updates into devkit.yaml, replacing
// the line if present and otherwise adding it after disk_gb in the vm block.
func setSecurityUpdates(path string, on bool) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	val := "false"
	if on {
		val = "true"
	}
	var updated []byte
	switch {
	case securityUpdatesLine.Match(data):
		updated = securityUpdatesLine.ReplaceAll(data, []byte("${1}"+val))
	case diskLine.Match(data):
		updated = diskLine.ReplaceAll(data, []byte("${1}\n  security_updates: "+val))
	default:
		return fmt.Errorf("could not find the vm block in %s", path)
	}
	return os.WriteFile(path, updated, 0o644)
}

// reconcileVM brings the Lima instance in line with the rendered config:
// create it if it does not exist; if its stored config differs, stop it when
// running and write the new config; then start it unless it is already
// running with the current config. Provisioning runs on that start. A VM
// whose provisioning did not finish is stopped, with an error.
//
// start boots the instance: lima.Start, or under network.enforce: host the
// sandboxed start. limactl create always runs unsandboxed, since it
// downloads the image.
func reconcileVM(ctx context.Context, name, rendered string, inst *lima.Instance, start func(context.Context, string) error) error {
	renderedPath := filepath.Join(devkitHome(), "instances", name+".yaml")
	if err := os.MkdirAll(filepath.Dir(renderedPath), 0o755); err != nil {
		return err
	}

	switch {
	case inst == nil:
		fmt.Printf("Creating VM %s (first boot downloads Ubuntu and installs tools; a few minutes)\n", name)
		if err := os.WriteFile(renderedPath, []byte(rendered), 0o644); err != nil {
			return err
		}
		if err := lima.Validate(ctx, renderedPath); err != nil {
			return err
		}
		if err := lima.Create(ctx, name, renderedPath); err != nil {
			return err
		}
	default:
		// Compare with the instance's own lima.yaml, which Lima stores
		// verbatim, rather than a cache keyed by name: two Lima homes can
		// hold same-named instances.
		prev, _ := os.ReadFile(lima.ConfigPath(name))
		if string(prev) != rendered {
			if inst.Running() {
				fmt.Println("devkit.yaml changed; restarting VM to apply it")
				if err := lima.Stop(ctx, name); err != nil {
					return err
				}
				inst.Status = "Stopped"
			}
			if err := os.WriteFile(renderedPath, []byte(rendered), 0o644); err != nil {
				return err
			}
			if err := lima.WriteConfig(name, rendered); err != nil {
				return err
			}
		}
	}

	// Whether it starts now or was running already, a VM is used only once
	// its provisioning has finished: otherwise it may have no firewall, and
	// it is stopped instead.
	serial := serialLog(name)
	if inst == nil || !inst.Running() {
		fmt.Printf("Starting VM %s\n", name)
		// Lima begins a new serial log: keep this one's crash reports.
		_, _ = scanCrashes(name)
		expectNewCrashLog(name)
		from := fileSize(serial)
		stopWatch := watchProvisioning(ctx, name)
		err := start(ctx, name)
		stopWatch()
		return confirmProvisioned(ctx, name, err, serial, from)
	}
	fmt.Printf("VM %s is running\n", name)
	return confirmProvisioned(ctx, name, nil, serial, 0)
}
