package app

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jurajpiar/devkit/internal/lima"
)

// progressHeartbeat is how long a provisioning step may run before devkit up
// says it is still on it, so a slow step never looks like a hang.
const progressHeartbeat = 20 * time.Second

// progressPrefix marks the lines the system script writes to the serial
// console (see step() in the provisioning script).
const progressPrefix = "devkit-progress: "

// watchProvisioning reports the guest's provisioning steps while Lima waits
// on the boot scripts, which it does silently. The system script writes each
// step to the serial console; Lima records that console on the host, so this
// only reads a local file: nothing runs in the guest, in particular no SSH
// session as the sandbox user, which would execute files the sandbox can
// write. Lines are sanitised before they reach the terminal.
// The returned function stops the watcher and waits for it.
func watchProvisioning(parent context.Context, name string) func() {
	return watchSerial(parent, filepath.Join(lima.Dir(name), "serialv.log"), os.Stdout, 2*time.Second)
}

func watchSerial(parent context.Context, path string, w io.Writer, every time.Duration) func() {
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	// Start from the end of what is already there: earlier boots' lines are
	// not this boot's progress.
	var offset int64
	if fi, err := os.Stat(path); err == nil {
		offset = fi.Size()
	}
	go func() {
		defer close(done)
		start := time.Now()
		current := ""
		changed, beat := time.Now(), time.Now()
		announced := false
		partial := ""
		elapsed := func() string { return fmt.Sprintf("%ds", int(time.Since(start).Seconds())) }
		announce := func(l string) {
			// The getty prompt means the guest is up. Worth saying only before
			// the first step; on a restart it can arrive after.
			if !announced && current == "" && (strings.Contains(l, " login: ") || strings.HasSuffix(strings.TrimRight(l, " "), " login:")) {
				fmt.Fprintf(w, "devkit: guest is up; Lima is running its own boot scripts (%s)\n", elapsed())
				announced, beat = true, time.Now()
			}
		}
		poll := func() {
			if fi, err := os.Stat(path); err == nil && fi.Size() < offset {
				offset = 0 // Lima started a fresh log
			}
			f, err := os.Open(path)
			if err != nil {
				return
			}
			defer f.Close()
			if _, err := f.Seek(offset, io.SeekStart); err != nil {
				return
			}
			data, _ := io.ReadAll(f)
			offset += int64(len(data))
			buf := partial + string(data)
			partial = ""
			// An unterminated last line is held for the next read.
			if i := strings.LastIndexByte(buf, '\n'); i < len(buf)-1 {
				partial, buf = buf[i+1:], buf[:i+1]
			}
			sc := bufio.NewScanner(strings.NewReader(buf))
			for sc.Scan() {
				l := strings.TrimRight(sc.Text(), "\r")
				announce(l) // may share a console line with a step: fall through
				i := strings.Index(l, progressPrefix)
				if i < 0 {
					continue
				}
				step := printable(strings.TrimSpace(l[i+len(progressPrefix):]))
				if step == "" {
					continue
				}
				if step == "done" {
					fmt.Fprintf(w, "devkit: provisioning finished (%s); Lima is finishing up\n", elapsed())
				} else {
					fmt.Fprintf(w, "devkit: %s (%s)\n", step, elapsed())
				}
				current, changed, beat = step, time.Now(), time.Now()
			}
			// getty prints its prompt without a newline; do not wait for one.
			announce(partial)
		}
		tick := time.NewTicker(every)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				poll() // steps written since the last tick, "done" included
				return
			case <-tick.C:
			}
			poll()
			if current != "done" && time.Since(changed) >= progressHeartbeat && time.Since(beat) >= progressHeartbeat {
				what := current
				if what == "" {
					what = "booting"
				}
				fmt.Fprintf(w, "devkit: still %s (%s)\n", what, elapsed())
				beat = time.Now()
			}
		}
	}()
	return func() { cancel(); <-done }
}
