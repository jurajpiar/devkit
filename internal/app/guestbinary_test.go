package app

import (
	"testing"

	"github.com/jurajpiar/devkit/internal/project"
)

// The guest binary goes into every VM with network, and into an air-gapped
// one with Docker, whose API filter and runtime guard it carries.
func TestNeedsGuestBinary(t *testing.T) {
	for _, c := range []struct {
		mode       string
		containers project.Containers
		want       bool
	}{
		{project.NetworkAllowlist, project.ContainersOff, true},
		{project.NetworkOpen, project.ContainersOff, true},
		{project.NetworkNone, project.ContainersOff, false},
		{project.NetworkNone, project.ContainersContainerd, false},
		{project.NetworkNone, project.ContainersDocker, true},
		{project.NetworkAllowlist, project.ContainersDocker, true},
	} {
		cfg := &project.Config{}
		cfg.Network.Mode, cfg.Tools.Containers = c.mode, c.containers
		if got := needsGuestBinary(cfg); got != c.want {
			t.Errorf("%s/%q: %v, want %v", c.mode, c.containers, got, c.want)
		}
	}
}
