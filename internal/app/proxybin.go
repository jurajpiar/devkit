package app

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"

	"github.com/jurajpiar/devkit/internal/embedded"
)

// egressProxyBinary returns the Linux egress proxy binary for the guest
// architecture. Order: embedded in devkit, then a cached build, then a fresh
// cross-compile with the host Go toolchain from the devkit source tree.
func egressProxyBinary(ctx context.Context) ([]byte, error) {
	arch := goruntime.GOARCH // the VM has the same architecture as the host
	if data, ok := embedded.EgressProxy(arch); ok {
		return data, nil
	}

	cache := filepath.Join(devkitHome(), "cache", "egressproxy-linux-"+arch)
	if data, err := os.ReadFile(cache); err == nil && len(data) > 0 {
		return data, nil
	}

	src, err := findSource()
	if err != nil {
		return nil, fmt.Errorf("egress proxy binary not available: %w\n"+
			"Build devkit with 'make build', or set DEVKIT_SRC to the devkit checkout", err)
	}
	if _, err := exec.LookPath("go"); err != nil {
		return nil, fmt.Errorf("egress proxy binary not embedded and Go is not installed; run 'make build' in %s", src)
	}
	if err := os.MkdirAll(filepath.Dir(cache), 0o755); err != nil {
		return nil, err
	}
	fmt.Println("Building egress proxy for the VM (one-time)...")
	cmd := exec.CommandContext(ctx, "go", "build", "-trimpath", "-ldflags=-s -w", "-o", cache, "./cmd/egressproxy")
	cmd.Dir = src
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("build egress proxy: %w", err)
	}
	return os.ReadFile(cache)
}

// findSource locates a devkit checkout containing cmd/egressproxy.
func findSource() (string, error) {
	candidates := []string{os.Getenv("DEVKIT_SRC")}
	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates, ancestors(cwd)...)
	}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, ancestors(filepath.Dir(exe))...)
	}
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if _, err := os.Stat(filepath.Join(c, "cmd", "egressproxy", "main.go")); err == nil {
			return c, nil
		}
	}
	return "", fmt.Errorf("devkit source tree not found")
}

func ancestors(dir string) []string {
	var out []string
	for i := 0; i < 6; i++ {
		out = append(out, dir)
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return out
}

// devkitHome is ~/.devkit, used for caches and rendered VM configs.
func devkitHome() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".devkit")
}
