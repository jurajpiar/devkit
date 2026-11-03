package app

import (
	"errors"
	"fmt"
	"os/exec"
	"testing"
)

func TestAuditExit(t *testing.T) {
	stale := exec.Command("sh", "-c", "exit 3").Run()
	crashed := exec.Command("sh", "-c", "exit 2").Run()
	wrapper := exec.Command("sh", "-c", "exit 1").Run() // nix develop failing before the audit
	cases := []struct {
		err  error
		want int
	}{
		{nil, auditClean},
		{stale, auditStale},
		{fmt.Errorf("limactl shell failed: %w", stale), auditStale},
		{crashed, auditIncomplete},
		{wrapper, auditIncomplete},
		{errors.New("ssh: connect to host"), auditIncomplete},
	}
	for _, c := range cases {
		if got := auditExit(c.err); got != c.want {
			t.Errorf("auditExit(%v) = %d, want %d", c.err, got, c.want)
		}
	}
}

func TestAuditBadFlagExitsTwo(t *testing.T) {
	rootCmd.SetArgs([]string{"audit", "--deep=invalid"})
	defer rootCmd.SetArgs(nil)
	err := rootCmd.Execute()
	var coded interface{ ExitCode() int }
	if err == nil || !errors.As(err, &coded) || coded.ExitCode() != 2 {
		t.Fatalf("a flag error should exit 2 (incomplete), got %v", err)
	}
}
