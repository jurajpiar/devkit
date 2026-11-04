package app

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// The watcher reads only new serial-log lines, prints the steps, drops other
// console output, and strips terminal control characters from what it shows.
func TestWatchSerial(t *testing.T) {
	path := filepath.Join(t.TempDir(), "serialv.log")
	if err := os.WriteFile(path, []byte("devkit-progress: stale step from the last boot\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out syncBuf
	stop := watchSerial(context.Background(), path, &out, 20*time.Millisecond)
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString("[    1.0] kernel noise\nUbuntu 24.04 lima-x hvc0\n\nlima-x login: \n")
	f.WriteString("lima-x login: devkit-progress: provisioning started\n") // shares a line with the prompt
	f.WriteString("devkit-progress: applying the firewall\x1b[2J\n")
	f.WriteString("lima-x login: \n") // a later prompt: no second announcement
	f.WriteString("devkit-prog")      // unterminated: must wait for the rest
	time.Sleep(100 * time.Millisecond)
	f.WriteString("ress: done\n")
	f.Close()
	time.Sleep(100 * time.Millisecond)
	stop()
	got := out.String()
	if strings.Count(got, "guest is up") != 1 {
		t.Errorf("announce the guest once, before the first step:\n%s", got)
	}
	for _, want := range []string{"guest is up", "devkit: provisioning started (", "devkit: applying the firewall[2J (", "provisioning finished"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	for _, bad := range []string{"stale step", "kernel noise", "\x1b"} {
		if strings.Contains(got, bad) {
			t.Errorf("should not show %q:\n%s", bad, got)
		}
	}
}

// Stopping right after a step is written, before the next tick, still shows
// it: the watcher reads once more on stop. A prompt without a newline, as
// getty prints it, is announced without waiting for another line.
func TestWatchSerialFinalReadAndBarePrompt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "serialv.log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	var out syncBuf
	stop := watchSerial(context.Background(), path, &out, time.Hour) // never ticks
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString("Ubuntu 24.04 lima-x hvc0\n\nlima-x login: ")
	f.Close()
	stop()
	if !strings.Contains(out.String(), "guest is up") {
		t.Errorf("a prompt without a newline should be announced:\n%s", out.String())
	}

	var out2 syncBuf
	stop2 := watchSerial(context.Background(), path, &out2, time.Hour)
	f, _ = os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString("\ndevkit-progress: applying the firewall\ndevkit-progress: done\n")
	f.Close()
	stop2()
	if !strings.Contains(out2.String(), "provisioning finished") {
		t.Errorf("steps written before stop must be shown:\n%s", out2.String())
	}
}
