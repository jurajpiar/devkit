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
	Use:   "down",
	Short: "Stop the sandbox VM (keeps its disk)",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireLima(); err != nil {
			return err
		}
		cfg, err := loadConfig(cmd)
		if err != nil {
			return err
		}
		inst, err := instance(cmd.Context(), cfg)
		if err != nil {
			return err
		}
		if inst == nil || !inst.Running() {
			fmt.Printf("VM %s is not running\n", cfg.VMName())
			return nil
		}
		return lima.Stop(cmd.Context(), cfg.VMName())
	},
}

var rmCmd = &cobra.Command{
	Use:     "rm",
	Aliases: []string{"remove", "destroy"},
	Short:   "Delete the sandbox VM and everything inside it",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireLima(); err != nil {
			return err
		}
		cfg, err := loadConfig(cmd)
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
			return nil
		}
		force, _ := cmd.Flags().GetBool("force")
		if !force && !confirm(fmt.Sprintf("Delete VM %s and all data inside it?", name)) {
			return nil
		}
		if err := lima.Delete(cmd.Context(), name, true); err != nil {
			return err
		}
		_ = os.Remove(filepath.Join(devkitHome(), "instances", name+".yaml"))
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
			fmt.Fprintf(w, "%s\t%s\t127.0.0.1:%d\t%d\t%s\t%s\n",
				i.Name, i.Status, i.SSHLocalPort, i.CPUs, gib(i.Memory), gib(i.Disk))
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
		ws := "$HOME/" + provision.WorkspaceDir
		script := fmt.Sprintf("cd %s 2>/dev/null; exec bash -l", ws)
		if len(args) > 0 {
			script = fmt.Sprintf("cd %s 2>/dev/null; %s", ws, strings.Join(args, " "))
		}
		return lima.Shell(cmd.Context(), cfg.VMName(), "", "bash", "-lc", script)
	},
}

var syncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Copy the current directory into the VM again (or git pull)",
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
		cwd, _ := os.Getwd()
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
		if err := mustBeRunning(cmd, cfg); err != nil {
			return err
		}
		follow, _ := cmd.Flags().GetBool("follow")
		lines, _ := cmd.Flags().GetInt("lines")
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
