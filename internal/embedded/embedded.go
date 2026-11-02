// Package embedded carries the Linux egress proxy binary inside the devkit
// binary so it can be dropped into a sandbox VM without a toolchain there.
//
// `make build` cross-compiles bin/egressproxy-linux-<arch> before building
// devkit. A plain `go build` still works; the CLI then falls back to building
// the proxy with the host Go toolchain on first use.
package embedded

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
)

//go:embed bin
var files embed.FS

// EgressProxy returns the embedded proxy binary for a Linux architecture
// ("arm64" or "amd64"), or false if none was embedded.
func EgressProxy(arch string) ([]byte, bool) {
	data, err := files.ReadFile("bin/egressproxy-linux-" + arch)
	if err != nil || len(data) == 0 {
		return nil, false
	}
	return data, true
}

// SHA256 returns the lowercase hex digest of data.
func SHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
