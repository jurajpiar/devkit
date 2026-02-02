package embedded

import (
	"embed"
	"fmt"
	"io"
	"os"
	"runtime"
)

// The egress proxy binaries are embedded at build time.
// Build with: ./scripts/build.sh (which generates the Linux binaries first)
//
// For development without the embedded binaries, run:
//   touch internal/embedded/egressproxy-linux-amd64
//   touch internal/embedded/egressproxy-linux-arm64
//   go build ./cmd/devkit
//
// Then the egress proxy will gracefully fail with a helpful message.

//go:embed egressproxy-linux-amd64
var egressProxyAmd64 []byte

//go:embed egressproxy-linux-arm64
var egressProxyArm64 []byte

//go:embed *.md
var docs embed.FS

// GetEgressProxyBinary returns the egress proxy binary for the current architecture
func GetEgressProxyBinary() ([]byte, error) {
	arch := runtime.GOARCH
	
	switch arch {
	case "amd64":
		if len(egressProxyAmd64) == 0 || isPlaceholder(egressProxyAmd64) {
			return nil, fmt.Errorf("egress proxy binary for amd64 not embedded\n\n" +
				"Rebuild devkit with embedded binaries:\n" +
				"  cd /path/to/devkit && ./scripts/build.sh\n" +
				"  sudo cp devkit /usr/local/bin/")
		}
		return egressProxyAmd64, nil
	case "arm64":
		if len(egressProxyArm64) == 0 || isPlaceholder(egressProxyArm64) {
			return nil, fmt.Errorf("egress proxy binary for arm64 not embedded\n\n" +
				"Rebuild devkit with embedded binaries:\n" +
				"  cd /path/to/devkit && ./scripts/build.sh\n" +
				"  sudo cp devkit /usr/local/bin/")
		}
		return egressProxyArm64, nil
	default:
		return nil, fmt.Errorf("unsupported architecture: %s", arch)
	}
}

// isPlaceholder checks if the embedded data is just a placeholder (not a real binary)
func isPlaceholder(data []byte) bool {
	// A real ELF binary starts with 0x7f 'E' 'L' 'F'
	if len(data) < 4 {
		return true
	}
	return !(data[0] == 0x7f && data[1] == 'E' && data[2] == 'L' && data[3] == 'F')
}

// WriteEgressProxyTo writes the egress proxy binary to the given path
func WriteEgressProxyTo(path string) error {
	binary, err := GetEgressProxyBinary()
	if err != nil {
		return err
	}
	
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer f.Close()
	
	_, err = f.Write(binary)
	if err != nil {
		return fmt.Errorf("failed to write binary: %w", err)
	}
	
	return nil
}

// WriteEgressProxyToWriter writes the egress proxy binary to an io.Writer
func WriteEgressProxyToWriter(w io.Writer) error {
	binary, err := GetEgressProxyBinary()
	if err != nil {
		return err
	}
	
	_, err = w.Write(binary)
	return err
}
