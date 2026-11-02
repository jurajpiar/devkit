package app

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/jurajpiar/devkit/internal/detector"
	"github.com/jurajpiar/devkit/internal/lima"
	"github.com/jurajpiar/devkit/internal/project"
	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init [repo-url]",
	Short: "Write a devkit.yaml for the current directory",
	Long: `Write a devkit.yaml for the current directory.

Project type and Node.js version are detected from package.json and .nvmrc.
With a repository URL the sandbox clones the repo instead of copying files.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runInit,
}

func init() {
	rootCmd.AddCommand(initCmd)
	initCmd.Flags().String("name", "", "project name (default: directory name)")
	initCmd.Flags().String("node", "", "Node.js major version to install (default: detected, or 22)")
	initCmd.Flags().String("network", project.NetworkAllowlist, "network mode: allowlist, open or none")
	initCmd.Flags().Bool("force", false, "overwrite an existing devkit.yaml")
}

func runInit(cmd *cobra.Command, args []string) error {
	path, _ := cmd.Flags().GetString("config")
	force, _ := cmd.Flags().GetBool("force")
	if _, err := os.Stat(path); err == nil && !force {
		return fmt.Errorf("%s already exists (use --force to overwrite)", path)
	}

	cfg := project.Default()
	cwd, _ := os.Getwd()
	cfg.Name, _ = cmd.Flags().GetString("name")
	if cfg.Name == "" {
		cfg.Name = slug(filepath.Base(cwd))
	}

	if len(args) == 1 {
		cfg.Source = project.SourceGit
		cfg.Repo = args[0]
		if n, _ := cmd.Flags().GetString("name"); n == "" {
			cfg.Name = slug(repoName(args[0]))
		}
	}

	cfg.Network.Mode, _ = cmd.Flags().GetString("network")

	// Detect Node.js from the working directory.
	cfg.Tools.Node, _ = cmd.Flags().GetString("node")
	if cfg.Tools.Node == "" {
		cfg.Tools.Node = "22"
		if res, err := detector.New(cwd).Detect(); err == nil && res.Type == detector.TypeNodeJS {
			if m := nodeMajor(res.Runtime); m != "" {
				cfg.Tools.Node = m
			}
		}
	}

	cfg.SSHPort = freeSSHPort(cmd.Context(), 2222)

	if err := cfg.Validate(); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(renderConfig(cfg)), 0o644); err != nil {
		return err
	}

	fmt.Printf("Wrote %s\n\n", path)
	fmt.Printf("  name:     %s\n  source:   %s\n  node:     %s\n  network:  %s\n  ssh port: %d\n\n",
		cfg.Name, cfg.Source, cfg.Tools.Node, cfg.Network.Mode, cfg.SSHPort)
	fmt.Println("Next: devkit up")
	return nil
}

// renderConfig writes the YAML by hand so the file carries comments.
func renderConfig(c *project.Config) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# devkit sandbox for %q. One VM per project; see README.md.\n", c.Name)
	fmt.Fprintf(&b, "name: %s\n", c.Name)
	fmt.Fprintf(&b, "source: %s            # copy | git | mount\n", c.Source)
	if c.Source == project.SourceGit {
		fmt.Fprintf(&b, "repo: %s\nbranch: %s\n", c.Repo, c.Branch)
	} else {
		fmt.Fprintf(&b, "# repo: https://github.com/you/repo.git   # for source: git\n# branch: main\n")
	}
	fmt.Fprintf(&b, "\ntools:\n  node: %q\n  containers: false     # rootless containerd + nerdctl inside the VM\n  # packages: [postgresql-client]\n", c.Tools.Node)
	fmt.Fprintf(&b, "\nvm:\n  cpus: %d\n  memory_gb: %d\n  disk_gb: %d\n", c.VM.CPUs, c.VM.MemoryGB, c.VM.DiskGB)
	fmt.Fprintf(&b, "\nssh_port: %d           # ssh devkit-%s\n", c.SSHPort, c.Name)
	fmt.Fprintf(&b, "\nnetwork:\n  mode: %s       # allowlist | open | none\n  allow:\n", c.Network.Mode)
	for _, h := range c.Network.Allow {
		fmt.Fprintf(&b, "    - %q\n", h)
	}
	fmt.Fprintf(&b, "  allow_host: false     # let the VM reach services on your Mac\n")
	fmt.Fprintf(&b, "\n# sudo: false            # root inside the VM can disable the firewall\n")
	return b.String()
}

var nonSlug = regexp.MustCompile(`[^a-z0-9-]+`)

func slug(s string) string {
	s = strings.ToLower(s)
	s = nonSlug.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if len(s) > 41 {
		s = s[:41]
	}
	if s == "" {
		s = "sandbox"
	}
	return s
}

func repoName(url string) string {
	url = strings.TrimSuffix(url, ".git")
	url = strings.TrimSuffix(url, "/")
	if i := strings.LastIndexAny(url, "/:"); i >= 0 {
		return url[i+1:]
	}
	return url
}

// nodeMajor extracts "22" from strings such as "node:22-alpine" or "22.4.1".
func nodeMajor(s string) string {
	s = strings.TrimPrefix(s, "node:")
	m := regexp.MustCompile(`^(\d{1,3})`).FindStringSubmatch(s)
	if m == nil {
		return ""
	}
	return m[1]
}

// freeSSHPort picks a port that is free on the host and not claimed by
// another devkit VM, which may be stopped and therefore not bound right now.
func freeSSHPort(ctx context.Context, from int) int {
	taken := map[int]bool{}
	if ctx == nil {
		ctx = context.Background()
	}
	if list, err := lima.List(ctx); err == nil {
		for _, i := range list {
			if strings.HasPrefix(i.Name, "devkit-") {
				taken[i.SSHLocalPort] = true
			}
		}
	}
	for p := from; p < from+200; p++ {
		if taken[p] {
			continue
		}
		l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
		if err == nil {
			_ = l.Close()
			return p
		}
	}
	return from
}
