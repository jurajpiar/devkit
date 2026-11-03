package app

import (
	"errors"
	"fmt"
	"os/exec"
	"testing"
)

func TestAuditExit(t *testing.T) {
	stale := exec.Command("sh", "-c", "exit 1").Run()
	crashed := exec.Command("sh", "-c", "exit 2").Run()
	cases := []struct {
		err  error
		want int
	}{
		{nil, 0},
		{stale, 1},
		{fmt.Errorf("limactl shell failed: %w", stale), 1},
		{crashed, 2},
		{errors.New("ssh: connect to host"), -1},
	}
	for _, c := range cases {
		if got := auditExit(c.err); got != c.want {
			t.Errorf("auditExit(%v) = %d, want %d", c.err, got, c.want)
		}
	}
}
