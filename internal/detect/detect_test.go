package detect

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestScanEmpty(t *testing.T) {
	if got := Scan(t.TempDir()); len(got) != 0 {
		t.Fatalf("expected nothing, got %+v", got)
	}
}

func TestScanNodeVersionSources(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "package.json", `{"name":"x","engines":{"node":">=20.1"}}`)
	if v := Versions(Scan(dir))["node"]; v != "20" {
		t.Errorf("engines.node: got %q, want 20", v)
	}
	write(t, dir, ".nvmrc", "v24.1.0\n")
	if v := Versions(Scan(dir))["node"]; v != "24" {
		t.Errorf(".nvmrc should win: got %q", v)
	}
	write(t, dir, ".nvmrc", "lts/iron\n")
	if v := Versions(Scan(dir))["node"]; v != "20" {
		t.Errorf("unparseable .nvmrc should fall through to engines: got %q", v)
	}
}

func TestScanPolyglot(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "go.mod", "module x\n\ngo 1.27.3\n")
	write(t, dir, "Cargo.toml", "[package]\nname = \"x\"\n")
	write(t, dir, "rust-toolchain.toml", "[toolchain]\nchannel = \"1.91.0\"\n")
	write(t, dir, "pyproject.toml", "[project]\n")
	write(t, dir, ".python-version", "3.12.4\n")
	write(t, dir, "Gemfile", "source 'https://rubygems.org'\n")
	write(t, dir, ".ruby-version", "# comment\n3.3.6\n")
	write(t, dir, "build.gradle.kts", "")
	write(t, dir, "foundry.toml", "")
	write(t, dir, "CMakeLists.txt", "")

	ecos := Scan(dir)
	names := []string{}
	for _, e := range ecos {
		names = append(names, e.Name)
	}
	want := []string{"c", "go", "java", "python", "ruby", "rust", "solidity"}
	if len(names) != len(want) {
		t.Fatalf("names = %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("names = %v, want %v", names, want)
		}
	}
	v := Versions(ecos)
	for tool, exp := range map[string]string{"go": "1.27", "rust": "1.91.0", "python": "3.12", "ruby": "3.3.6", "java": "21"} {
		if v[tool] != exp {
			t.Errorf("version[%s] = %q, want %q", tool, v[tool], exp)
		}
	}
	if _, ok := v["solidity"]; ok {
		t.Error("solidity has no mise tool")
	}
	hosts := Hosts(ecos)
	seen := map[string]int{}
	for _, h := range hosts {
		seen[h]++
	}
	for _, h := range []string{"proxy.golang.org", "crates.io", "pypi.org", "rubygems.org", "repo1.maven.org", "binaries.soliditylang.org"} {
		if seen[h] != 1 {
			t.Errorf("host %s appears %d times", h, seen[h])
		}
	}
	pk := Packages(ecos)
	if len(pk) == 0 || seen["pkg-config"] != 0 {
		t.Errorf("packages = %v", pk)
	}
	count := 0
	for _, p := range pk {
		if p == "pkg-config" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("pkg-config should be listed once, got %d in %v", count, pk)
	}
}

func TestScanBun(t *testing.T) {
	cases := []struct {
		name     string
		files    map[string]string
		want     string
		wantNode bool
	}{
		{"packageManager", map[string]string{"package.json": `{"packageManager":"bun@1.4.4"}`}, "1.4.4", true},
		{"packageManager with corepack hash", map[string]string{"package.json": `{"packageManager":"bun@1.4.4+sha512.abc"}`}, "1.4.4", true},
		{".bun-version wins", map[string]string{"package.json": `{"packageManager":"bun@1.4.4"}`, ".bun-version": "1.3.2\n"}, "1.3.2", true},
		{"engines.bun lower bound", map[string]string{"package.json": `{"engines":{"bun":">=1.4.0"}}`, "bun.lock": "{}"}, "1.4.0", true},
		{"engines.bun caret", map[string]string{"package.json": `{"engines":{"bun":"^1.4.0"}}`, "bun.lock": "{}"}, "1.4.0", true},
		{"engines.bun upper bound is not a version", map[string]string{"package.json": `{"engines":{"bun":"<1.4.0"}}`, "bun.lock": "{}"}, "latest", true},
		{"engines.bun exclusive lower bound", map[string]string{"package.json": `{"engines":{"bun":">1.4.0"}}`, "bun.lock": "{}"}, "latest", true},
		{"engines.bun range", map[string]string{"package.json": `{"engines":{"bun":">=1.4.0 <2"}}`, "bun.lock": "{}"}, "latest", true},
		{"lockfile only", map[string]string{"package.json": `{}`, "bun.lock": "{}"}, "latest", true},
		{"legacy binary lockfile", map[string]string{"package.json": `{}`, "bun.lockb": ""}, "latest", true},
		{"bunfig.toml", map[string]string{"package.json": `{}`, "bunfig.toml": ""}, "latest", true},
		{"hostile version is not copied", map[string]string{"package.json": `{"packageManager":"bun@$(id)"}`}, "latest", true},
		// A script project run by bun directly has no manifest and needs no
		// node.
		{".bun-version without a manifest", map[string]string{".bun-version": "1.4.4\n"}, "1.4.4", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			for n, body := range c.files {
				write(t, dir, n, body)
			}
			ecos := Scan(dir)
			v := Versions(ecos)
			if v["bun"] != c.want {
				t.Errorf("bun = %q, want %q", v["bun"], c.want)
			}
			// Bun projects with a manifest still run tools that expect node
			// (vitest, vite's bin scripts).
			if _, ok := v["node"]; ok != c.wantNode {
				t.Errorf("node detected = %v, want %v", ok, c.wantNode)
			}
			hosts := map[string]bool{}
			for _, h := range Hosts(ecos) {
				hosts[h] = true
			}
			if !hosts["registry.npmjs.org"] {
				t.Error("bun needs the npm registry")
			}
		})
	}
}

func TestScanNodeEnginesExclusiveBounds(t *testing.T) {
	for engines, want := range map[string]string{"<20": "22", ">20": "22", ">=20 <23": "22", "^20.1": "20", ">=20.1": "20", "20.x": "20"} {
		dir := t.TempDir()
		write(t, dir, "package.json", `{"engines":{"node":"`+engines+`"}}`)
		if v := Versions(Scan(dir))["node"]; v != want {
			t.Errorf("engines.node %q: got %q, want %q", engines, v, want)
		}
	}
}

func TestScanNoBunForPlainNode(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "package.json", `{"packageManager":"pnpm@9.1.0"}`)
	write(t, dir, "pnpm-lock.yaml", "")
	if _, ok := Versions(Scan(dir))["bun"]; ok {
		t.Error("a pnpm project must not get bun")
	}
}
