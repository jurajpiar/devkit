package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// Several devkit commands can read and write one VM's crash state at once:
// none may lose another's report or acknowledgement, and none may see a
// partly written file.
func TestCrashStateSurvivesConcurrentCommands(t *testing.T) {
	fakeHome(t)
	must(t, os.MkdirAll(filepath.Dir(serialLog(demoVM)), 0o755))
	writeLog(t, serialLog(demoVM), bootLines)

	const reports = 40
	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		acked  int
		failed []string
	)
	fail := func(format string, a ...any) {
		mu.Lock()
		failed = append(failed, fmt.Sprintf(format, a...))
		mu.Unlock()
	}
	stop := make(chan struct{})
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				switch {
				case g%4 == 0:
					n, err := ackCrashes(demoVM)
					if err != nil {
						fail("ack: %v", err)
					}
					mu.Lock()
					acked += n
					mu.Unlock()
				case g%4 == 1:
					data, err := os.ReadFile(crashStatePath(demoVM))
					if err != nil && !errors.Is(err, os.ErrNotExist) {
						fail("read: %v", err)
					}
					if err == nil && !json.Valid(data) {
						fail("a reader saw invalid JSON: %q", data)
					}
				default:
					if _, err := scanCrashes(demoVM); err != nil {
						fail("scan: %v", err)
					}
				}
			}
		}(g)
	}
	for i := 0; i < reports; i++ {
		appendLog(t, serialLog(demoVM), fmt.Sprintf("[  %d.000001] BUG: bug number %d\n", 200+10*i, i))
		if _, err := scanCrashes(demoVM); err != nil {
			t.Error(err)
		}
	}
	close(stop)
	wg.Wait()
	for _, f := range failed {
		t.Error(f)
	}

	st, err := scanCrashes(demoVM)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(crashStatePath(demoVM))
	if err != nil || !json.Valid(data) {
		t.Fatalf("the state file must be valid JSON: %v %q", err, data)
	}
	if acked+len(st.Crashes) != reports {
		t.Errorf("every report is acknowledged or kept exactly once: %d acknowledged + %d kept, want %d", acked, len(st.Crashes), reports)
	}
	count := map[string]int{}
	for _, r := range st.Crashes {
		count[r.Key]++
	}
	for _, k := range st.Seen {
		count[k] += 100
	}
	for i := 0; i < reports; i++ {
		key := fmt.Sprintf("[  %d.000001] BUG: bug number %d", 200+10*i, i)
		if c := count[key]; c != 100 && c != 101 {
			t.Errorf("report %d must be seen once and kept at most once: %d", i, c)
		}
	}
}

func TestCorruptCrashStateRescansTheLog(t *testing.T) {
	fakeHome(t)
	must(t, os.MkdirAll(filepath.Dir(serialLog(demoVM)), 0o755))
	writeLog(t, serialLog(demoVM), bootLines+oopsLines)
	if st, err := scanCrashes(demoVM); err != nil || len(st.Crashes) != 1 {
		t.Fatalf("%v %+v", err, st)
	}
	// A partly written file, as an older devkit could leave it.
	data, err := os.ReadFile(crashStatePath(demoVM))
	must(t, err)
	must(t, os.WriteFile(crashStatePath(demoVM), data[:len(data)/2], 0o600))

	var stderr bytes.Buffer
	old := crashStderr
	crashStderr = &stderr
	defer func() { crashStderr = old }()
	st, err := scanCrashes(demoVM)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Crashes) != 1 || !strings.Contains(st.Crashes[0].Key, "Unable to handle kernel") {
		t.Errorf("a corrupt state is a rescan from the start, which finds the report again: %+v", st.Crashes)
	}
	if !strings.Contains(stderr.String(), "rescanning") {
		t.Errorf("devkit must say the state was corrupt and is rescanned: %q", stderr.String())
	}
	stderr.Reset()
	if _, err := scanCrashes(demoVM); err != nil || stderr.Len() != 0 {
		t.Errorf("the rescanned state is saved, and the warning is said once: %v %q", err, stderr.String())
	}
}
