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
