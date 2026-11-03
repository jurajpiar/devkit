package app

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"sort"

	"github.com/jurajpiar/devkit/internal/detect"
	"github.com/jurajpiar/devkit/internal/lima"
	"github.com/jurajpiar/devkit/internal/project"
	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init [repo-url]",
	Short: "Write a devkit.yaml for the current directory",
	Long: `Write a devkit.yaml for the current directory.

Languages are detected from marker files (package.json, go.mod, Cargo.toml,
pyproject.toml, Gemfile, pom.xml, ...) and their version files, which seeds
tools.versions, the egress allowlist and apt packages. With a repository URL
the sandbox clones the repo instead of copying files.

Toolchains come from mise by default. --toolchain nix writes a flake.nix
instead; --toolchain none installs apt packages only. See README.md for the
trade-offs.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runInit,
}

func init() {
	rootCmd.AddCommand(initCmd)
	initCmd.Flags().String("name", "", "project name (default: directory name)")
	initCmd.Flags().String("node", "", "Node.js major version to install (default: detected, or 22)")
	initCmd.Flags().String("toolchain", envOr("DEVKIT_TOOLCHAIN", project.ManagerMise), "toolchain manager: mise, nix or none")
	initCmd.Flags().String("network", project.NetworkAllowlist, "network mode: allowlist, open or none")
	initCmd.Flags().Bool("force", false, "overwrite an existing devkit.yaml")
	_ = initCmd.RegisterFlagCompletionFunc("network", completeValues(project.NetworkAllowlist, project.NetworkOpen, project.NetworkNone))
	_ = initCmd.RegisterFlagCompletionFunc("toolchain", completeValues(project.ManagerMise, project.ManagerNix, project.ManagerNone))
}

// completeValues completes a flag from a fixed set of values.
func completeValues(values ...string) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return values, cobra.ShellCompDirectiveNoFileComp
	}
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

	// Seed toolchains, registries and packages from what the directory uses.
	// A git source has nothing to scan on the host.
	var ecos []detect.Ecosystem
	if cfg.Source != project.SourceGit {
		ecos = detect.Scan(cwd)
	}
	cfg.Tools.Manager, _ = cmd.Flags().GetString("toolchain")
	cfg.Tools.Versions = detect.Versions(ecos)
	if node, _ := cmd.Flags().GetString("node"); node != "" {
		cfg.Tools.Versions["node"] = node
	}
	cfg.Tools.Packages = detect.Packages(ecos)
	cfg.Network.Allow = append(append(append([]string{}, project.DefaultAllow...),
		project.ManagerHosts[cfg.Tools.Manager]...), detect.Hosts(ecos)...)
	switch cfg.Tools.Manager {
	case project.ManagerNix:
		flakePath := filepath.Join(cwd, "flake.nix")
		if _, err := os.Stat(flakePath); err != nil && cfg.Source != project.SourceGit {
			if err := os.WriteFile(flakePath, []byte(renderFlake(cfg.Tools.Versions)), 0o644); err != nil {
				return err
			}
			fmt.Printf("Wrote flake.nix (edit the packages list; commit it with flake.lock)\n")
		}
		cfg.Tools.Versions = nil
	case project.ManagerNone:
		cfg.Tools.Versions = nil
	}

	cfg.SSHPort = freeSSHPort(cmd.Context(), 2222)

	if err := cfg.Validate(); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(renderConfig(cfg)), 0o644); err != nil {
		return err
	}

	fmt.Printf("Wrote %s\n\n", path)
	fmt.Printf("  name:       %s\n  source:     %s\n  toolchains: %s\n  network:    %s\n  ssh port:   %d\n\n",
		cfg.Name, cfg.Source, describeTools(cfg), cfg.Network.Mode, cfg.SSHPort)
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
	fmt.Fprintf(&b, "\ntools:\n  manager: %-13s# mise | nix | none (see README: Toolchains)\n", c.Tools.Manager)
	if len(c.Tools.Versions) > 0 {
		fmt.Fprintf(&b, "  versions:             # mise tool: version; a mise.toml in the repo layers on top\n")
		for _, tool := range sortedKeys(c.Tools.Versions) {
			fmt.Fprintf(&b, "    %s: %q\n", tool, c.Tools.Versions[tool])
		}
	} else if c.Tools.Manager == project.ManagerMise {
		fmt.Fprintf(&b, "  # versions: { node: \"22\", go: \"1.27\" }\n")
	}
	fmt.Fprintf(&b, "  containers: false     # rootless containerd + nerdctl inside the VM\n")
	if len(c.Tools.Packages) > 0 {
		fmt.Fprintf(&b, "  packages: [%s]\n", strings.Join(c.Tools.Packages, ", "))
	} else {
		fmt.Fprintf(&b, "  # packages: [postgresql-client]\n")
	}
	fmt.Fprintf(&b, "\n# install: npm ci        # replaces the lockfile-based install devkit picks\n")
	fmt.Fprintf(&b, "\nvm:\n  cpus: %d\n  memory_gb: %d\n  disk_gb: %d\n", c.VM.CPUs, c.VM.MemoryGB, c.VM.DiskGB)
	fmt.Fprintf(&b, "\nssh_port: %d           # ssh devkit-%s\n", c.SSHPort, c.Name)
	fmt.Fprintf(&b, "\nnetwork:\n  mode: %s       # allowlist | open | none\n  allow:\n", c.Network.Mode)
	for _, h := range c.Network.Allow {
		fmt.Fprintf(&b, "    - %q\n", h)
	}
	fmt.Fprintf(&b, "  allow_host: false     # let the VM reach services on your Mac\n")
	fmt.Fprintf(&b, "  # dns: proxy          # only the proxy resolves names; resolvers opens DNS to the VM\n")
	fmt.Fprintf(&b, "  # forward: [3000]     # guest ports exposed on 127.0.0.1; none otherwise\n")
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

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func describeTools(c *project.Config) string {
	switch c.Tools.Manager {
	case project.ManagerMise:
		if len(c.Tools.Versions) == 0 {
			return "mise (no versions detected; add tools.versions)"
		}
		parts := []string{}
		for _, k := range sortedKeys(c.Tools.Versions) {
			parts = append(parts, k+" "+c.Tools.Versions[k])
		}
		return "mise: " + strings.Join(parts, ", ")
	case project.ManagerNix:
		return "nix (flake.nix)"
	}
	return "none (apt packages only)"
}

// nixAttrs maps a detected tool version to nixpkgs attribute names. It is a
// starting point for the generated flake.nix, not a promise that the
// attribute exists in the pinned nixpkgs.
func nixAttrs(tool, version string) []string {
	major := strings.SplitN(version, ".", 2)[0]
	mm := strings.Join(strings.SplitN(version, ".", 3)[:min(2, strings.Count(version, ".")+1)], "_")
	switch tool {
	case "node":
		return []string{"nodejs_" + major}
	case "go":
		if version == "latest" {
			return []string{"go"}
		}
		return []string{"go_" + mm}
	case "python":
		return []string{"python" + strings.ReplaceAll(mm, "_", "")}
	case "ruby":
		return []string{"ruby_" + mm}
	case "java":
		return []string{"jdk" + major}
	case "rust":
		return []string{"cargo", "rustc", "rustfmt", "clippy"}
	}
	return nil
}

// renderFlake writes a dev shell for the detected toolchains. nixpkgs is
// pinned to a release branch here and to a commit by flake.lock.
func renderFlake(versions map[string]string) string {
	var pkgs []string
	for _, tool := range sortedKeys(versions) {
		pkgs = append(pkgs, nixAttrs(tool, versions[tool])...)
	}
	if len(pkgs) == 0 {
		pkgs = []string{"git"}
	}
	return `{
  # Written by devkit init. Edit freely; devkit only runs "nix develop" here.
  description = "devkit dev shell";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

  outputs = { self, nixpkgs }:
    let
      systems = [ "aarch64-linux" "x86_64-linux" ];
      forAll = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in {
      devShells = forAll (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [ ` + strings.Join(pkgs, " ") + ` ];
        };
      });
    };
}
`
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
