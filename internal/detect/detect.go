// Package detect looks at a project directory and reports which language
// ecosystems it uses, so devkit init can seed toolchain versions, the egress
// allowlist and apt packages. It never runs anything; it only reads marker
// files.
package detect

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Ecosystem is one detected language or build system.
type Ecosystem struct {
	Name string
	// Tool is the mise tool name providing the toolchain, empty if none.
	Tool string
	// Version is the version spec for Tool, read from the project's version
	// file where one exists, otherwise a current default.
	Version string
	// Hosts are the registries and download hosts the ecosystem needs.
	Hosts []string
	// Packages are apt packages the ecosystem needs.
	Packages []string
}

// Scan returns the ecosystems found in dir, sorted by name.
func Scan(dir string) []Ecosystem {
	exists := func(names ...string) bool {
		for _, n := range names {
			if _, err := os.Stat(filepath.Join(dir, n)); err == nil {
				return true
			}
		}
		return false
	}
	var out []Ecosystem
	if exists("package.json") {
		out = append(out, Ecosystem{
			Name: "node", Tool: "node", Version: nodeVersion(dir),
			Hosts: []string{"registry.npmjs.org", "registry.yarnpkg.com", "nodejs.org"},
		})
	}
	if usesBun(dir, exists) {
		// With a manifest, bun sits beside node, not instead of it: tools
		// such as vite and vitest still start through node shebangs. A script
		// project bun runs directly has no manifest and gets bun alone.
		out = append(out, Ecosystem{
			Name: "bun", Tool: "bun", Version: bunVersion(dir),
			Hosts: []string{"registry.npmjs.org"},
		})
	}
	if exists("go.mod") {
		out = append(out, Ecosystem{
			Name: "go", Tool: "go", Version: goVersion(dir),
			Hosts: []string{"proxy.golang.org", "sum.golang.org", "dl.google.com"},
		})
	}
	if exists("Cargo.toml") {
		out = append(out, Ecosystem{
			Name: "rust", Tool: "rust", Version: rustVersion(dir),
			Hosts: []string{"crates.io", "static.crates.io", "index.crates.io", "static.rust-lang.org", "sh.rustup.rs"},
			// Many crates link against system libraries through pkg-config.
			Packages: []string{"pkg-config", "libssl-dev"},
		})
	}
	if exists("pyproject.toml", "requirements.txt", "setup.py", "Pipfile") {
		out = append(out, Ecosystem{
			Name: "python", Tool: "python", Version: pythonVersion(dir),
			Hosts: []string{"pypi.org", "files.pythonhosted.org"},
		})
	}
	if exists("Gemfile") {
		out = append(out, Ecosystem{
			Name: "ruby", Tool: "ruby", Version: firstLine(dir, ".ruby-version", "3.4"),
			Hosts: []string{"rubygems.org", "**.rubygems.org"},
		})
	}
	if exists("pom.xml", "build.gradle", "build.gradle.kts") {
		out = append(out, Ecosystem{
			Name: "java", Tool: "java", Version: firstLine(dir, ".java-version", "21"),
			Hosts: []string{"repo1.maven.org", "repo.maven.apache.org", "**.maven.org", "plugins.gradle.org", "services.gradle.org", "mise-java.jdx.dev"},
		})
	}
	if exists("foundry.toml", "hardhat.config.js", "hardhat.config.ts") {
		// Hardhat comes from npm; Foundry is installed by the project. Both
		// fetch solc builds from the same host and verify the published hash.
		out = append(out, Ecosystem{
			Name:  "solidity",
			Hosts: []string{"binaries.soliditylang.org"},
		})
	}
	if exists("CMakeLists.txt", "meson.build", "configure.ac") {
		out = append(out, Ecosystem{
			Name:     "c",
			Packages: []string{"cmake", "ninja-build", "pkg-config"},
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Versions collects tool versions from the ecosystems, for tools.versions.
func Versions(ecos []Ecosystem) map[string]string {
	m := map[string]string{}
	for _, e := range ecos {
		if e.Tool != "" {
			m[e.Tool] = e.Version
		}
	}
	return m
}

// Hosts returns the union of the ecosystems' hosts, in order, without
// duplicates.
func Hosts(ecos []Ecosystem) []string {
	return unionOf(ecos, func(e Ecosystem) []string { return e.Hosts })
}

// Packages returns the union of the ecosystems' apt packages.
func Packages(ecos []Ecosystem) []string {
	return unionOf(ecos, func(e Ecosystem) []string { return e.Packages })
}

func unionOf(ecos []Ecosystem, f func(Ecosystem) []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range ecos {
		for _, h := range f(e) {
			if !seen[h] {
				seen[h] = true
				out = append(out, h)
			}
		}
	}
	return out
}

var leadingVersion = regexp.MustCompile(`^v?(\d+(?:\.\d+)*)`)

// nodeVersion returns the Node.js major from .nvmrc, .node-version or
// package.json engines.node, else the current LTS.
func nodeVersion(dir string) string {
	for _, f := range []string{".nvmrc", ".node-version"} {
		if v := majorOf(firstLine(dir, f, "")); v != "" {
			return v
		}
	}
	var pkg struct {
		Engines struct {
			Node string `json:"node"`
		} `json:"engines"`
	}
	if data, err := os.ReadFile(filepath.Join(dir, "package.json")); err == nil && json.Unmarshal(data, &pkg) == nil {
		if v := majorOf(inclusiveBound(pkg.Engines.Node)); v != "" {
			return v
		}
	}
	return "22"
}

// packageJSON holds the package.json fields detection reads.
type packageJSON struct {
	PackageManager string `json:"packageManager"`
	Engines        struct {
		Bun string `json:"bun"`
	} `json:"engines"`
}

func readPackageJSON(dir string) packageJSON {
	var pkg packageJSON
	if data, err := os.ReadFile(filepath.Join(dir, "package.json")); err == nil {
		_ = json.Unmarshal(data, &pkg)
	}
	return pkg
}

// usesBun reports a Bun project: a Bun lockfile, .bun-version, bunfig.toml,
// or packageManager naming bun.
func usesBun(dir string, exists func(...string) bool) bool {
	return exists("bun.lock", "bun.lockb", ".bun-version", "bunfig.toml") ||
		strings.HasPrefix(readPackageJSON(dir).PackageManager, "bun@")
}

// bunVersion reads .bun-version, then packageManager ("bun@1.4.4", with or
// without corepack's "+sha512..." suffix), then engines.bun, else latest.
// Only a leading dotted number is kept, so another manager's "pnpm@9" or a
// crafted value never reaches devkit.yaml.
func bunVersion(dir string) string {
	pkg := readPackageJSON(dir)
	for _, s := range []string{
		firstLine(dir, ".bun-version", ""),
		strings.TrimPrefix(pkg.PackageManager, "bun@"),
		inclusiveBound(pkg.Engines.Bun),
	} {
		if v := leadingVersion.FindStringSubmatch(strings.TrimSpace(s)); v != nil {
			return v[1]
		}
	}
	return "latest"
}

// inclusiveBound returns the version an engines constraint itself admits:
// "1.4", "=1.4", ">=1.4", "^1.4" and "~1.4" all admit 1.4. Anything else, an
// upper or exclusive bound ("<1.4", ">1.4") or a compound range, returns ""
// so the caller falls back to its default rather than pinning a version the
// constraint may exclude.
// npm allows whitespace between an operator and its version (">= 24").
func inclusiveBound(c string) string {
	m := singleBound.FindStringSubmatch(c)
	if m == nil {
		return ""
	}
	return m[1]
}

// singleBound matches one optional inclusive operator, optional whitespace,
// and a version with no further comparators.
var singleBound = regexp.MustCompile(`^\s*(?:>=|\^|~|=)?\s*([vV]?\d[^\s|<>=^~]*)\s*$`)

// goVersion returns major.minor from the go directive in go.mod.
func goVersion(dir string) string {
	data, err := os.ReadFile(filepath.Join(dir, "go.mod"))
	if err == nil {
		for _, l := range strings.Split(string(data), "\n") {
			if f := strings.Fields(l); len(f) == 2 && f[0] == "go" {
				if v := leadingVersion.FindStringSubmatch(f[1]); v != nil {
					parts := strings.Split(v[1], ".")
					if len(parts) >= 2 {
						return parts[0] + "." + parts[1]
					}
					return v[1]
				}
			}
		}
	}
	return "latest"
}

// rustVersion reads the channel from rust-toolchain.toml or rust-toolchain.
func rustVersion(dir string) string {
	if data, err := os.ReadFile(filepath.Join(dir, "rust-toolchain.toml")); err == nil {
		if m := regexp.MustCompile(`(?m)^\s*channel\s*=\s*"([^"]+)"`).FindStringSubmatch(string(data)); m != nil {
			return m[1]
		}
	}
	return firstLine(dir, "rust-toolchain", "latest")
}

// pythonVersion returns major.minor from .python-version, else a current
// release.
func pythonVersion(dir string) string {
	if v := leadingVersion.FindStringSubmatch(firstLine(dir, ".python-version", "")); v != nil {
		parts := strings.Split(v[1], ".")
		if len(parts) >= 2 {
			return parts[0] + "." + parts[1]
		}
	}
	return "3.13"
}

func majorOf(s string) string {
	if v := leadingVersion.FindStringSubmatch(strings.TrimSpace(s)); v != nil {
		return strings.Split(v[1], ".")[0]
	}
	return ""
}

// firstLine returns the first non-empty, non-comment line of a file, or def.
func firstLine(dir, name, def string) string {
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return def
	}
	for _, l := range strings.Split(string(data), "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			return l
		}
	}
	return def
}

// MarkerFiles are the top-level files detection reads, for callers that
// have to fetch them before Scan can look (devkit clone reads them from
// git objects instead of checking the repository out on the host).
var MarkerFiles = []string{
	"package.json", ".nvmrc", ".node-version", "bun.lock", "bun.lockb", ".bun-version", "bunfig.toml",
	"go.mod", "Cargo.toml", "rust-toolchain.toml", "rust-toolchain",
	"pyproject.toml", "requirements.txt", "setup.py", "Pipfile", ".python-version",
	"Gemfile", ".ruby-version", "pom.xml", "build.gradle", "build.gradle.kts", ".java-version",
	"foundry.toml", "hardhat.config.js", "hardhat.config.ts",
	"CMakeLists.txt", "meson.build", "configure.ac",
}
