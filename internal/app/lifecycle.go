package app

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/jurajpiar/devkit/internal/lima"
	"github.com/jurajpiar/devkit/internal/project"
	"github.com/jurajpiar/devkit/internal/provision"
	"github.com/spf13/cobra"
)

var downCmd = &cobra.Command{
	Use:               "down [name]",
	Short:             "Stop the sandbox VM (keeps its disk)",
	Args:              cobra.MaximumNArgs(1),
	ValidArgsFunction: completeVMs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireLima(); err != nil {
			return err
		}
		cfg, err := targetConfig(cmd, args)
		if err != nil {
			return err
		}
		inst, err := instance(cmd.Context(), cfg)
		if err != nil {
			return err
		}
		name := cfg.VMName()
		// Lima begins a new serial log at the next start: record its crash
		// reports now, and again once the guest has stopped writing.
		if inst == nil || !inst.Running() {
			fmt.Printf("VM %s is not running\n", name)
			if inst != nil {
				_, _ = scanCrashes(name)
			}
		} else {
			st, _ := scanCrashes(name)
			stop := lima.Stop
			if st.panicked(true) {
				// A panicked kernel cannot shut down; waiting for it only
				// times out.
				fmt.Printf("The kernel of VM %s has panicked; forcing it off\n", name)
				stop = lima.StopForce
			}
			if err := stop(cmd.Context(), name); err != nil {
				return err
			}
			_, _ = scanCrashes(name)
		}
		// The host proxy goes with the VM; its port stays the VM's.
		_ = os.Remove(filepath.Join(vmStateDir(name), hostAgentPIDFile))
		return stopHostProxy(name)
	},
}

var rmCmd = &cobra.Command{
	Use:               "rm [name]",
	Aliases:           []string{"remove", "destroy"},
	Short:             "Delete the sandbox VM and everything inside it",
	Long:              "Delete the sandbox VM and everything inside it.\n\nWithout a name, the VM for the devkit.yaml in the current directory. With one, any devkit VM, which lets you clean up after a project directory is gone.",
	Args:              cobra.MaximumNArgs(1),
	ValidArgsFunction: completeVMs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireLima(); err != nil {
			return err
		}
		cfg, err := targetConfig(cmd, args)
		if err != nil {
			return err
		}
		name := cfg.VMName()
		inst, err := instance(cmd.Context(), cfg)
		if err != nil {
			return err
		}
		if inst == nil {
			fmt.Printf("VM %s does not exist\n", name)
			_ = removeSSHConfig(cfg.Name)
			return removeHostState(name)
		}
		force, _ := cmd.Flags().GetBool("force")
		if !force && !confirm(fmt.Sprintf("Delete VM %s and all data inside it?", name)) {
			return nil
		}
		if err := lima.Delete(cmd.Context(), name, true); err != nil {
			return err
		}
		_ = os.Remove(filepath.Join(devkitHome(), "instances", name+".yaml"))
		if err := removeHostState(name); err != nil {
			fmt.Printf("Warning: %v\n", err)
		}
		if err := removeSSHConfig(cfg.Name); err != nil {
			fmt.Printf("Warning: could not clean ~/.ssh/config: %v\n", err)
		}
		fmt.Printf("Deleted VM %s\n", name)
		return nil
	},
}

var lsCmd = &cobra.Command{
	Use:     "ls",
	Aliases: []string{"list"},
	Short:   "List devkit VMs",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireLima(); err != nil {
			return err
		}
		list, err := lima.List(cmd.Context())
		if err != nil {
			return err
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "NAME\tSTATUS\tSSH\tCPUS\tMEMORY\tDISK")
		n := 0
		for _, i := range list {
			if !strings.HasPrefix(i.Name, "devkit-") {
				continue
			}
			n++
			status := i.Status
			if st, err := scanCrashes(i.Name); err == nil {
				switch {
				case st.panicked(i.Running()):
					status += " (kernel panicked)"
				case len(st.Crashes) > 0:
					status += " (kernel crash reported)"
				}
			}
			fmt.Fprintf(w, "%s\t%s\t127.0.0.1:%d\t%d\t%s\t%s\n",
				i.Name, status, i.SSHLocalPort, i.CPUs, gib(i.Memory), gib(i.Disk))
		}
		if n == 0 {
			fmt.Println("No devkit VMs. Run 'devkit init' then 'devkit up' in a project directory.")
			return nil
		}
		return w.Flush()
	},
}

var shellCmd = &cobra.Command{
	Use:   "shell [command...]",
	Short: "Open a shell in the sandbox (or run a command)",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireLima(); err != nil {
			return err
		}
		cfg, err := loadConfig(cmd)
		if err != nil {
			return err
		}
		if err := mustBeRunning(cmd, cfg); err != nil {
			return err
		}
		if err := checkCrashes(cmd, cfg); err != nil {
			return err
		}
		if err := requireProvisioned(cmd.Context(), cfg); err != nil {
			return err
		}
		warnRunning(cmd.Context(), cfg)
		return lima.Shell(cmd.Context(), cfg.VMName(), "", "bash", "-lc", shellScript(cfg, args))
	},
}

var syncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Copy the current directory into the VM again, or bring in new upstream commits",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireLima(); err != nil {
			return err
		}
		cfg, err := loadConfig(cmd)
		if err != nil {
			return err
		}
		if err := mustBeRunning(cmd, cfg); err != nil {
			return err
		}
		if err := checkCrashes(cmd, cfg); err != nil {
			return err
		}
		if err := requireProvisioned(cmd.Context(), cfg); err != nil {
			return err
		}
		warnRunning(cmd.Context(), cfg)
		cwd, _ := os.Getwd()
		if cfg.Source == project.SourceGit && isDir(bareRepo(cwd)) {
			ws := "$HOME/" + provision.WorkspaceDir
			if err := syncSource(cmd.Context(), cfg, cwd); err != nil {
				return err
			}
			return syncUpstream(cmd.Context(), cfg, cwd, ws)
		}
		if cfg.Source == project.SourceGit {
			return lima.ExecStream(cmd.Context(), cfg.VMName(), "git -C \"$HOME/"+provision.WorkspaceDir+"\" pull --ff-only")
		}
		return syncSource(cmd.Context(), cfg, cwd)
	},
}

var logsCmd = &cobra.Command{
	Use:   "logs",
	Short: "Show the egress audit log (every host the sandbox tried to reach)",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireLima(); err != nil {
			return err
		}
		cfg, err := loadConfig(cmd)
		if err != nil {
			return err
		}
		follow, _ := cmd.Flags().GetBool("follow")
		lines, _ := cmd.Flags().GetInt("lines")
		if cfg.HostEnforced() {
			// The host proxy's log is the authoritative one: it sees every
			// request that leaves, root's included, and nothing in the
			// guest can rewrite it. The VM need not be running.
			if inst, _ := instance(cmd.Context(), cfg); inst != nil && inst.Running() {
				if !warnCrashes(cmd.ErrOrStderr(), cfg.VMName(), true) {
					warnRunning(cmd.Context(), cfg)
				}
			}
			return showHostLog(cmd, cfg.VMName(), lines, follow)
		}
		if err := mustBeRunning(cmd, cfg); err != nil {
			return err
		}
		if err := checkCrashes(cmd, cfg); err != nil {
			return err
		}
		warnRunning(cmd.Context(), cfg)
		tail := fmt.Sprintf("tail -n %d", lines)
		if follow {
			tail += " -f"
		}
		return lima.Shell(cmd.Context(), cfg.VMName(), "", "bash", "-lc", tail+" "+provision.EgressLog)
	},
}

func init() {
	rootCmd.AddCommand(downCmd, rmCmd, lsCmd, shellCmd, syncCmd, logsCmd)
	rmCmd.Flags().BoolP("force", "f", false, "do not ask for confirmation")
	logsCmd.Flags().BoolP("follow", "f", false, "keep following the log")
	logsCmd.Flags().IntP("lines", "n", 100, "number of lines to show")
}

// removeHostState stops the VM's host proxy and deletes devkit's host-side
// state for it, the host log included.
func removeHostState(name string) error {
	if err := stopHostProxy(name); err != nil {
		return err
	}
	return os.RemoveAll(vmStateDir(name))
}

// shellScript opens a login shell in the workspace, or runs a command there.
// With manager: nix and a flake.nix present, both happen inside the dev
// shell so the project's toolchains are on PATH.
func shellScript(cfg *project.Config, args []string) string {
	ws := "$HOME/" + provision.WorkspaceDir
	inner := "exec bash -l"
	if len(args) > 0 {
		inner = strings.Join(args, " ")
	}
	if cfg.Tools.Manager == project.ManagerNix {
		return fmt.Sprintf("cd %s 2>/dev/null; if [ -f flake.nix ]; then exec nix develop --command bash -lc %s; fi; %s",
			ws, shellQuote(inner), inner)
	}
	return fmt.Sprintf("cd %s 2>/dev/null; %s", ws, inner)
}

// targetConfig resolves which VM a command acts on: the named one, or the
// one described by devkit.yaml in the current directory.
func targetConfig(cmd *cobra.Command, args []string) (*project.Config, error) {
	if len(args) == 0 {
		return loadConfig(cmd)
	}
	c := project.Default()
	c.Name = strings.TrimPrefix(args[0], "devkit-")
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("%q is not a devkit VM name", args[0])
	}
	return c, nil
}

// completeVMs offers the names of existing devkit VMs.
func completeVMs(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	list, err := lima.List(cmd.Context())
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	var names []string
	for _, i := range list {
		if strings.HasPrefix(i.Name, "devkit-") {
			names = append(names, i.Name+"\t"+i.Status)
		}
	}
	return names, cobra.ShellCompDirectiveNoFileComp
}

func mustBeRunning(cmd *cobra.Command, cfg *project.Config) error {
	inst, err := instance(cmd.Context(), cfg)
	if err != nil {
		return err
	}
	if inst == nil {
		return fmt.Errorf("VM %s does not exist; run 'devkit up'", cfg.VMName())
	}
	if !inst.Running() {
		return fmt.Errorf("VM %s is %s; run 'devkit up'", cfg.VMName(), strings.ToLower(inst.Status))
	}
	return nil
}

func confirm(prompt string) bool {
	fmt.Printf("%s [y/N] ", prompt)
	r := bufio.NewReader(os.Stdin)
	line, _ := r.ReadString('\n')
	line = strings.ToLower(strings.TrimSpace(line))
	return line == "y" || line == "yes"
}

func gib(b int64) string {
	if b <= 0 {
		return "-"
	}
	return fmt.Sprintf("%dG", b/(1<<30))
}
