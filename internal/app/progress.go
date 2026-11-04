package app

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jurajpiar/devkit/internal/lima"
)

// progressHeartbeat is how long a provisioning step may run before devkit up
// says it is still on it, so a slow step never looks like a hang.
const progressHeartbeat = 20 * time.Second

// watchProvisioning reports the guest's provisioning steps while Lima waits
// on the boot scripts, which it does silently. The system script appends a
// step name to /run/devkit/progress as each block starts; this polls that
// file over SSH every two seconds and prints new steps with the elapsed time,
// plus a heartbeat when one step runs long. Polling errors are ignored: SSH
// is not up for the first seconds of a boot, and that is expected.
// The returned function stops the watcher and waits for it.
func watchProvisioning(parent context.Context, name string) func() {
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	go func() {
		defer close(done)
		start := time.Now()
		seen, current := 0, ""
		changed, beat := time.Now(), time.Now()
		announcedLima := false
		tick := time.NewTicker(2 * time.Second)
		defer tick.Stop()
		elapsed := func() string { return fmt.Sprintf("%ds", int(time.Since(start).Seconds())) }
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
			pctx, pcancel := context.WithTimeout(ctx, 5*time.Second)
			out, err := lima.Exec(pctx, name, "cat /run/devkit/progress 2>/dev/null || true")
			pcancel()
			if ctx.Err() != nil {
				return
			}
			if err == nil {
				var lines []string
				for _, l := range strings.Split(out, "\n") {
					if l = strings.TrimSpace(l); l != "" {
						lines = append(lines, l)
					}
				}
				if len(lines) == 0 && !announcedLima {
					fmt.Printf("devkit: guest is up; Lima is running its own boot scripts (%s)\n", elapsed())
					announcedLima, beat = true, time.Now()
				}
				if len(lines) < seen {
					seen = 0 // a reboot cleared /run
				}
				for _, l := range lines[seen:] {
					if l == "done" {
						fmt.Printf("devkit: provisioning finished (%s); Lima is finishing up\n", elapsed())
					} else {
						fmt.Printf("devkit: %s (%s)\n", l, elapsed())
					}
					current, changed, beat = l, time.Now(), time.Now()
				}
				seen = len(lines)
			}
			if current != "done" && time.Since(changed) >= progressHeartbeat && time.Since(beat) >= progressHeartbeat {
				what := current
				if what == "" {
					what = "booting"
				}
				fmt.Printf("devkit: still %s (%s)\n", what, elapsed())
				beat = time.Now()
			}
		}
	}()
	return func() { cancel(); <-done }
}
