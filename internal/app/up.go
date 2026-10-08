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

	cfg, err := loadConfig(cmd)
	if err != nil {
		return err
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

	rendered, err := lima.Render(lima.TemplateInput{
		Config:       cfg,
		User:         hostUser(),
		HostDir:      cwd,
		EgressSHA256: proxySHA,
	})
	if err != nil {
		return err
	}

	name := cfg.VMName()
	inst, err := instance(ctx, cfg)
	if err != nil {
		return err
	}
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
		prev, _ := os.ReadFile(renderedPath)
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

	if inst == nil || !inst.Running() {
		fmt.Printf("Starting VM %s\n", name)
		if err := lima.Start(ctx, name); err != nil {
			return err
		}
	} else {
		fmt.Printf("VM %s is running\n", name)
	}

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
	if !noInstall && cfg.Network.Mode != project.NetworkNone {
		fmt.Println("Installing dependencies")
		if err := lima.ExecStream(ctx, name, installScript); err != nil {
			fmt.Printf("Warning: dependency installation failed: %v\n", err)
		}
		printBlocked(ctx, name)
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
		return lima.PipeTar(ctx, name, cwd, ws, cfg.Exclude)
	case project.SourceGit:
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

const installScript = `cd "$HOME/workspace" 2>/dev/null || exit 0
if [ -f package.json ]; then
  if   [ -f pnpm-lock.yaml ]; then pnpm install
  elif [ -f yarn.lock ];      then yarn install
  elif [ -f bun.lockb ] || [ -f bun.lock ]; then echo "bun lockfile found but bun is not installed; skipping"
  else npm install; fi
else
  echo "no package.json; nothing to install"
fi`

// printBlocked summarises hosts the proxy refused during this run.
func printBlocked(ctx context.Context, name string) {
	out, err := lima.Exec(ctx, name,
		"grep '\\[EGRESS\\] BLOCKED' "+provision.EgressLog+" 2>/dev/null | awk '{print $6}' | sort | uniq -c | sort -rn | head -n 10")
	if err != nil || strings.TrimSpace(out) == "" {
		return
	}
	fmt.Println("\nBlocked by the allowlist (add to network.allow if legitimate):")
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		fmt.Println("  " + strings.TrimSpace(l))
	}
}

func describeNetwork(cfg *project.Config) string {
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
