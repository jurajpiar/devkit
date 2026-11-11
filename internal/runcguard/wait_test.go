package runcguard

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// The gvisor-09-*.rows fixtures are every distinct state of the gofer's and
// the sandbox's mount tables from the instant runsc create returned, for
// three containers (spikes/gvisor/results/09-gofer-timing.log; each file
// names its lines). The earlier fixtures (gvisor-gofer-*.mountinfo,
// gvisor-sandbox.mountinfo) are of running containers. The recorder kept
// "fstype root at mountpoint" only; rowsMountinfo makes mountinfo lines of
// them with the devices they would have: ext4 is the VM's disk as in
// gvisor-guard-host (259:0 for /boot, 253:1 for the rest), and every other
// filesystem a new device of its own, as runsc makes them. The early
// sandbox table is the daemon's and its other filesystems are not new, but
// what decides it is its ext4 root.
const (
	gv09PlainID = "77f0b67aa787936adced40d350391d62f54acee72627a96612d56a4c9f5e3d12"
	gv09BindsID = "da4e917141e1c0eea95362dc30ac691e0f1dcdb33533ed6a51496bc48a9c4e24"
	gv09SwapID  = "a8cb54ed3a84308a682808c5b67e6987c3756a48096fe78bd1ece772df8883e3"
)

func rowsMountinfo(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	n := 0
	for _, l := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(l, "#") || strings.TrimSpace(l) == "" {
			continue
		}
		f := strings.Fields(l)
		if len(f) != 4 || f[2] != "at" {
			t.Fatalf("%s: cannot read %q", name, l)
		}
		dev := fmt.Sprintf("0:%d", 200+n)
		if f[0] == "ext4" {
			dev = "253:1"
			if f[3] == "/boot" {
				dev = "259:0"
			}
		}
		fmt.Fprintf(&b, "%d 599 %s %s %s rw - %s none rw\n", 600+n, dev, f[1], f[3], f[0])
		n++
	}
	return b.String()
}

func rowsTable(t *testing.T, name string) []MountEntry {
	t.Helper()
	m, err := ParseMountinfo(strings.NewReader(rowsMountinfo(t, name)))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestFinalForm(t *testing.T) {
	host := readTable(t, "gvisor-guard-host.mountinfo")
	tables := map[string][]MountEntry{
		"09 gofer swap intermediate": rowsTable(t, "gvisor-09-gofer-swap-intermediate.rows"),
		"09 sandbox early":           rowsTable(t, "gvisor-09-sandbox-early.rows"),
		"09 sandbox at create":       rowsTable(t, "gvisor-09-sandbox-create.rows"),
		"sandbox running":            readTable(t, "gvisor-sandbox.mountinfo"),
		"09 gofer plain final":       rowsTable(t, "gvisor-09-gofer-plain-final.rows"),
		"09 gofer binds final":       rowsTable(t, "gvisor-09-gofer-binds-final.rows"),
		"09 gofer swap final":        rowsTable(t, "gvisor-09-gofer-swap-final.rows"),
		"gofer plain running":        readTable(t, "gvisor-gofer-plain.mountinfo"),
		"gofer binds running":        readTable(t, "gvisor-gofer-binds.mountinfo"),
		"gofer init running":         readTable(t, "gvisor-gofer-init.mountinfo"),
		"gofer network running":      readTable(t, "gvisor-gofer-network.mountinfo"),
		// 07's tables were filtered to their ext4 lines: no root, so never
		// final, though Check passes the ordinary one.
		"07 gofer ordinary, filtered": readTable(t, "gvisor-gofer-ordinary.mountinfo"),
		"the guard's own table":       host,
		"two overlays at the root": append(rowsTable(t, "gvisor-09-gofer-plain-final.rows"),
			line(t, "700 600 0:250 / / rw - overlay overlay rw")),
		"a tmpfs over the gofer's root": append(rowsTable(t, "gvisor-09-gofer-plain-final.rows"),
			line(t, "700 600 0:250 / / rw - tmpfs tmpfs rw")),
		"part of an overlay at the root": {line(t, "700 600 0:250 /etc / rw - overlay overlay rw")},
		"a tmpfs over the sandbox's root": append(rowsTable(t, "gvisor-09-sandbox-create.rows"),
			line(t, "700 600 0:251 / / rw - tmpfs tmpfs rw")),
		"the old root under the sandbox's": append(rowsTable(t, "gvisor-09-sandbox-create.rows"),
			line(t, "700 600 253:1 / / rw - ext4 /dev/root rw")),
		"a sandbox root of the VM's tmpfs":      {line(t, "700 600 0:77 / / rw - tmpfs tmpfs rw")},
		"part of a tmpfs at the sandbox's root": {line(t, "700 600 0:251 /x / rw - tmpfs tmpfs rw")},
	}
	goferFinal := map[string]bool{"09 gofer plain final": true, "09 gofer binds final": true, "09 gofer swap final": true,
		"gofer plain running": true, "gofer binds running": true, "gofer init running": true, "gofer network running": true}
	// Final says only that the root is settled, which the gofer's
	// intermediate table, with its own new tmpfs at "/", would be in a
	// sandbox: judged, it is refused for its overlay at /root.
	sandboxFinal := map[string]bool{"09 sandbox at create": true, "sandbox running": true, "09 gofer swap intermediate": true}
	if bad := CheckSandbox(host, tables["09 gofer swap intermediate"]); bad == nil || bad.Point != "/root" {
		t.Errorf("the gofer's intermediate table as a sandbox's should be refused at /root, got %+v", bad)
	}
	hostWithTmpfs := append(append([]MountEntry{}, host...), line(t, "700 65 0:77 / /run/x rw - tmpfs tmpfs rw"))
	for what, tbl := range tables {
		if got := GoferFinal(tbl); got != goferFinal[what] {
			t.Errorf("%s: GoferFinal %v", what, got)
		}
		if got := SandboxFinal(hostWithTmpfs, tbl); got != sandboxFinal[what] {
			t.Errorf("%s: SandboxFinal %v", what, got)
		}
	}
}

func TestRecordedFinalStates(t *testing.T) {
	host := readTable(t, "gvisor-guard-host.mountinfo")
	for file, id := range map[string]string{
		"gvisor-09-gofer-plain-final.rows": gv09PlainID,
		"gvisor-09-gofer-binds-final.rows": gv09BindsID,
	} {
		if bad := Check(host, rowsTable(t, file), goferPolicy(id)); bad != nil {
			t.Errorf("%s should pass, refused at %+v", file, *bad)
		}
	}
	bad := Check(host, rowsTable(t, "gvisor-09-gofer-swap-final.rows"), goferPolicy(gv09SwapID))
	if bad == nil || bad.FSType != "ext4" || bad.Root != "/var/lib/devkit-docker/run" || bad.Point != "/s" {
		t.Errorf("the swap should be refused at /var/lib/devkit-docker/run on /s, got %+v", bad)
	}
	if bad := CheckSandbox(host, rowsTable(t, "gvisor-09-sandbox-create.rows")); bad != nil {
		t.Errorf("the sandbox at create should pass, refused at %+v", *bad)
	}
}

// The sandbox at create holds a tmpfs at /proc and a proc below it; only
// those, new, where they were recorded, once each.
func TestCheckSandboxAtCreate(t *testing.T) {
	host := readTable(t, "gvisor-guard-host.mountinfo")
	const root = "600 599 0:200 / / rw - tmpfs none rw\n"
	for what, tbl := range map[string]string{
		"the root alone":     root,
		"with the tmpfs":     root + "601 599 0:201 / /proc rw - tmpfs none rw\n",
		"with both":          root + "601 599 0:201 / /proc rw - tmpfs none rw\n602 599 0:202 / /proc/sandbox-proc rw - proc none rw\n",
		"with the proc only": root + "602 599 0:202 / /proc/sandbox-proc rw - proc none rw\n",
	} {
		sb, err := ParseMountinfo(strings.NewReader(tbl))
		if err != nil {
			t.Fatal(err)
		}
		if bad := CheckSandbox(host, sb); bad != nil {
			t.Errorf("%s should pass, refused at %+v", what, *bad)
		}
	}
	withProc := append(append([]MountEntry{}, host...), line(t, "700 65 0:22 / /proc rw - proc proc rw"),
		line(t, "701 65 0:23 / /run rw - tmpfs tmpfs rw"))
	for what, l := range map[string]string{
		"the VM's proc at sandbox-proc": "602 599 0:22 / /proc/sandbox-proc rw - proc none rw",
		"a VM's tmpfs at /proc":         "601 599 0:23 / /proc rw - tmpfs none rw",
		"a proc at /proc":               "601 599 0:202 / /proc rw - proc none rw",
		"a proc elsewhere":              "601 599 0:202 / /p rw - proc none rw",
		"a tmpfs at sandbox-proc":       "601 599 0:202 / /proc/sandbox-proc rw - tmpfs none rw",
		"a tmpfs elsewhere":             "601 599 0:202 / /t rw - tmpfs none rw",
		"part of a proc":                "601 599 0:202 /1 /proc/sandbox-proc rw - proc none rw",
		"the VM's disk":                 "603 599 253:1 /var/lib/devkit-docker/run /s rw - ext4 /dev/root rw",
		"a namespace file":              "603 599 0:4 net:[4026531840] /n rw - nsfs nsfs rw",
		"a sysfs":                       "603 599 0:204 / /sys rw - sysfs none rw",
	} {
		// After the root alone, so that nothing else can be what refuses it.
		sb := append(rowsTable(t, "gvisor-09-sandbox-create.rows")[:1:1], line(t, l))
		if bad := CheckSandbox(withProc, sb); bad == nil || bad.Point != sb[1].Point {
			t.Errorf("%s should be refused, got %+v", what, bad)
		}
	}
	for what, l := range map[string]string{
		"a second tmpfs at /proc":       "603 599 0:203 / /proc rw - tmpfs none rw",
		"a second proc at sandbox-proc": "603 599 0:203 / /proc/sandbox-proc rw - proc none rw",
	} {
		if bad := CheckSandbox(host, append(rowsTable(t, "gvisor-09-sandbox-create.rows"), line(t, l))); bad == nil || bad.Dev != "0:203" {
			t.Errorf("%s should be refused, got %+v", what, bad)
		}
	}
	// The root must come first.
	sb := rowsTable(t, "gvisor-09-sandbox-create.rows")
	sb[0], sb[1] = sb[1], sb[0]
	if CheckSandbox(host, sb) == nil {
		t.Error("a sandbox table that does not start with its root should be refused")
	}
}

// fakeClock moves only when slept on.
type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time        { return c.now }
func (c *fakeClock) Sleep(d time.Duration) { c.now = c.now.Add(d) }

// sequence reads the tables in turn and then the last one forever.
func sequence(tables ...[]MountEntry) (func() ([]MountEntry, error), *int) {
	n := new(int)
	return func() ([]MountEntry, error) {
		i := min(*n, len(tables)-1)
		*n++
		return tables[i], nil
	}, n
}

func TestAwaitFinal(t *testing.T) {
	host := readTable(t, "gvisor-guard-host.mountinfo")
	inter := rowsTable(t, "gvisor-09-gofer-swap-intermediate.rows")
	plain := rowsTable(t, "gvisor-09-gofer-plain-final.rows")
	swap := rowsTable(t, "gvisor-09-gofer-swap-final.rows")
	ordinary := readTable(t, "gvisor-gofer-ordinary.mountinfo")
	judge := func(id string) func([]MountEntry) *MountEntry {
		return func(tbl []MountEntry) *MountEntry { return Check(host, tbl, goferPolicy(id)) }
	}

	read, n := sequence(inter, inter, plain)
	if bad, err := awaitFinal(read, GoferFinal, judge(gv09PlainID), &fakeClock{}, SetupBound); bad != nil || err != nil || *n != 3 {
		t.Errorf("ending in a passing final form: %+v %v after %d reads", bad, err, *n)
	}

	// The first final table is judged and the wait ends there, even though
	// a later table would pass.
	read, n = sequence(inter, swap, plain)
	if bad, err := awaitFinal(read, GoferFinal, judge(gv09SwapID), &fakeClock{}, SetupBound); err != nil || bad == nil || bad.Point != "/s" || *n != 2 {
		t.Errorf("reaching a failing final form: %+v %v after %d reads", bad, err, *n)
	}

	c := &fakeClock{}
	read, n = sequence(inter)
	if bad, err := awaitFinal(read, GoferFinal, judge(gv09SwapID), c, SetupBound); !errors.Is(err, errNotFinal) || bad != nil ||
		c.now.Sub(time.Time{}) < SetupBound || *n < 2 {
		t.Errorf("never final: %+v %v after %d reads and %v", bad, err, *n, c.now.Sub(time.Time{}))
	}

	// A table the rules would pass is not passed while it is not final: the
	// filtered ordinary table has no root, and a judge that passes
	// everything is never asked.
	for what, j := range map[string]func([]MountEntry) *MountEntry{
		"the rules":      judge(gvOrdinaryID),
		"a judge of nil": func([]MountEntry) *MountEntry { return nil },
	} {
		if bad := Check(host, ordinary, goferPolicy(gvOrdinaryID)); bad != nil {
			t.Fatalf("the ordinary table should pass the rules, refused at %+v", *bad)
		}
		read, _ = sequence(ordinary, inter)
		if bad, err := awaitFinal(read, GoferFinal, j, &fakeClock{}, SetupBound); !errors.Is(err, errNotFinal) || bad != nil {
			t.Errorf("%s: a table that is not final passed: %+v %v", what, bad, err)
		}
	}

	// A bound of 0 reads once.
	read, n = sequence(inter, plain)
	if _, err := awaitFinal(read, GoferFinal, judge(gv09PlainID), &fakeClock{}, 0); !errors.Is(err, errNotFinal) || *n != 1 {
		t.Errorf("bound 0: %v after %d reads", err, *n)
	}

	// A failed read ends the wait.
	boom := errors.New("gone")
	if _, err := awaitFinal(func() ([]MountEntry, error) { return nil, boom }, GoferFinal, judge(gv09PlainID), &fakeClock{}, SetupBound); err != boom {
		t.Errorf("a failed read: %v", err)
	}

	// The early sandbox, then the sandbox at create.
	read, n = sequence(rowsTable(t, "gvisor-09-sandbox-early.rows"), rowsTable(t, "gvisor-09-sandbox-create.rows"))
	if bad, err := awaitFinal(read, func(tbl []MountEntry) bool { return SandboxFinal(host, tbl) },
		func(tbl []MountEntry) *MountEntry { return CheckSandbox(host, tbl) }, &fakeClock{}, SetupBound); bad != nil || err != nil || *n != 2 {
		t.Errorf("the sandbox: %+v %v after %d reads", bad, err, *n)
	}
}

// The guard as the shim runs it, with tables that are not yet final.
func TestRunscGuardCreateWaits(t *testing.T) {
	inter := rowsMountinfo(t, "gvisor-09-gofer-swap-intermediate.rows")
	for what, c := range map[string]struct {
		gofer, sandbox, want string
	}{
		"a gofer that never finishes": {inter, "", "devkit: refused: the runtime guard could not check the container's mounts: gVisor's gofer never finished setting up its mounts (waited 5s)"},
		"a failing gofer, judged before the sandbox": {rowsMountinfo(t, "gvisor-09-gofer-swap-final.rows"), rowsMountinfo(t, "gvisor-09-sandbox-early.rows"),
			"devkit: refused: a mount comes from outside the workspace: ext4 /var/lib/devkit-docker/run at /s"},
		"a passing gofer and a sandbox that never finishes": {strings.ReplaceAll(rowsMountinfo(t, "gvisor-09-gofer-swap-final.rows"), "/var/lib/devkit-docker/run", "/home/jurajpiar.guest/workspace/s"),
			rowsMountinfo(t, "gvisor-09-sandbox-early.rows"), "gVisor's sandbox never finished setting up its mounts (waited 5s)"},
	} {
		e := newRunscEnv(t, gv09SwapID, c.gofer)
		if c.sandbox != "" {
			os.WriteFile(filepath.Join(e.proc.dir, fmt.Sprint(sbPid), "mountinfo"), []byte(c.sandbox), 0o644)
		}
		e.clock = &fakeClock{}
		if code := e.run(t); code != 1 || len(e.ran) != 2 || e.ran[1][len(e.ran[1])-3] != "delete" || !strings.Contains(e.stderr.String(), c.want) {
			t.Errorf("%s: code %d ran %v: %s", what, code, e.ran, e.stderr.String())
		}
	}
	// The sandbox at create, as recorded, passes.
	e := newRunscEnv(t, gv09PlainID, rowsMountinfo(t, "gvisor-09-gofer-plain-final.rows"))
	os.WriteFile(filepath.Join(e.proc.dir, fmt.Sprint(sbPid), "mountinfo"), []byte(rowsMountinfo(t, "gvisor-09-sandbox-create.rows")), 0o644)
	e.clock = &fakeClock{}
	if code := e.run(t); code != 0 || len(e.ran) != 1 {
		t.Errorf("the recorded plain container at create: code %d ran %v: %s", code, e.ran, e.stderr.String())
	}
}

func gvState(id, status string, pid int, bundle string) string {
	return fmt.Sprintf(`{"ociVersion":"1.0.0","id":%q,"status":%q,"pid":%d,"bundle":%q,"annotations":{}}`, id, status, pid, bundle)
}

func TestRunscGuardStart(t *testing.T) {
	start := func(e *runscEnv) {
		e.args = append(append([]string{}, gvArgs["runsc"]...), "--root", gvRoot, "--log", gvTask+e.id+"/log.json", "--log-format", "json", "--systemd-cgroup", "start", e.id)
		e.state = gvState(e.id, "created", sbPid, gvTask+e.id)
	}
	e := newRunscEnv(t, gv09PlainID, rowsMountinfo(t, "gvisor-09-gofer-plain-final.rows"))
	start(e)
	e.run(t)
	wantState := append(append([]string{e.runsc}, e.args[:len(e.args)-2]...), "state", e.id)
	if want := append([]string{e.runsc}, e.args...); !reflect.DeepEqual(e.execed, want) || len(e.ran) != 0 || !reflect.DeepEqual(e.stateArgs, wantState) {
		t.Fatalf("a final passing table: exec'd %v ran %v state %v: %s", e.execed, e.ran, e.stateArgs, e.stderr.String())
	}

	for what, c := range map[string]struct {
		id, gofer string
		edit      func(e *runscEnv)
		want      string
	}{
		"a failing table":   {gv09SwapID, rowsMountinfo(t, "gvisor-09-gofer-swap-final.rows"), nil, "a mount comes from outside the workspace: ext4 /var/lib/devkit-docker/run at /s"},
		"a table not final": {gv09SwapID, rowsMountinfo(t, "gvisor-09-gofer-swap-intermediate.rows"), nil, "the mounts of gVisor's gofer are not in their final form at start"},
		"a sandbox not final": {gv09PlainID, rowsMountinfo(t, "gvisor-09-gofer-plain-final.rows"), func(e *runscEnv) {
			os.WriteFile(filepath.Join(e.proc.dir, fmt.Sprint(sbPid), "mountinfo"), []byte(rowsMountinfo(t, "gvisor-09-sandbox-early.rows")), 0o644)
		}, "the mounts of gVisor's sandbox are not in their final form at start"},
		"no state":        {gv09PlainID, rowsMountinfo(t, "gvisor-09-gofer-plain-final.rows"), func(e *runscEnv) { e.state = "" }, "runsc state"},
		"state not JSON":  {gv09PlainID, rowsMountinfo(t, "gvisor-09-gofer-plain-final.rows"), func(e *runscEnv) { e.state = "created" }, "runsc state"},
		"already running": {gv09PlainID, rowsMountinfo(t, "gvisor-09-gofer-plain-final.rows"), func(e *runscEnv) { e.state = gvState(e.id, "running", sbPid, gvTask+e.id) }, `status "running"`},
		"another ID":      {gv09PlainID, rowsMountinfo(t, "gvisor-09-gofer-plain-final.rows"), func(e *runscEnv) { e.state = gvState(gv09SwapID, "created", sbPid, gvTask+e.id) }, "runsc state gives container"},
		"no pid":          {gv09PlainID, rowsMountinfo(t, "gvisor-09-gofer-plain-final.rows"), func(e *runscEnv) { e.state = gvState(e.id, "created", 0, gvTask+e.id) }, "pid 0"},
		"another bundle":  {gv09PlainID, rowsMountinfo(t, "gvisor-09-gofer-plain-final.rows"), func(e *runscEnv) { e.state = gvState(e.id, "created", sbPid, gvTask+gv09SwapID) }, "is not the container"},
		"a bundle elsewhere": {gv09PlainID, rowsMountinfo(t, "gvisor-09-gofer-plain-final.rows"), func(e *runscEnv) {
			e.state = gvState(e.id, "created", sbPid, "/elsewhere/"+e.id)
		}, "found no gofer"},
		"another sandbox": {gv09PlainID, rowsMountinfo(t, "gvisor-09-gofer-plain-final.rows"), func(e *runscEnv) { e.state = gvState(e.id, "created", sbPid+1, gvTask+e.id) }, "the sandbox"},
	} {
		e := newRunscEnv(t, c.id, c.gofer)
		start(e)
		if c.edit != nil {
			c.edit(e)
		}
		wantDelete := append(append([]string{e.runsc}, e.args[:len(e.args)-2]...), "delete", "--force", c.id)
		if code := e.run(t); code != 1 || e.execed != nil || len(e.ran) != 1 || !reflect.DeepEqual(e.ran[0], wantDelete) || !strings.Contains(e.stderr.String(), c.want) {
			t.Errorf("%s: code %d exec'd %v ran %v: %s", what, code, e.execed, e.ran, e.stderr.String())
		}
	}
}
