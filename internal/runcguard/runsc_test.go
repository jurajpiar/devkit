package runcguard

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The gVisor fixtures are copied verbatim from two recordings on a real VM
// with runsc release-20261102.0 under the rootless daemon:
//
//   - spikes/gvisor/results/08-gofer-tables.log: the complete mount tables
//     of the gofer (gvisor-gofer-plain, -binds, -init, -network) and of the
//     sandbox (gvisor-sandbox, the same for all four shapes) right after
//     runsc create returned.
//   - spikes/gvisor/results/07-mount-guard.log: the ext4 and bind lines only
//     (the recorder filtered the rest) of the table where the runtime runs
//     (gvisor-guard-host), of the gofer of an ordinary container with a
//     workspace bind and a volume (gvisor-gofer-ordinary), and of the gofer
//     of a container whose bind source was a directory at docker create and
//     a symlink to the daemon's socket directory at start
//     (gvisor-gofer-swap). The recorder cut some lines short in their super
//     options; every line still has its device, root, mount point, type and
//     source.
const (
	gvOrdinaryID = "365559744f882dfc1fecfe89b8f41efa52c97db8cc7bb20b73840371b98a1849"
	gvSwapID     = "3838dd52bee162d57bf41f30be092d6cae650bced4ef594c6916ca2bdac1c01d"
	gvPlainID    = "f3f8cc0b7f61fd0c85984035827271c39ffdd6912c7c047f404ff82e2d672003"
	gvBindsID    = "de8b853f56339f7cb1e6b6c8f877686cf925218d701a716a9c0f3b0a4d285e44"
	gvInitID     = "e1ccd62db370b419e76f7f221fe34b75360bbf24c691de8fb4245f91d730c905"
	gvNetworkID  = "6eeada877ce3d56ded3ea625c781552768bf0a0518fa69aa0c1cfd5085b221df"

	gvRoot = "/run/user/999/docker/runtime-runc/moby"
	gvTask = "/run/user/999/docker/containerd/daemon/io.containerd.runtime.v2.task/moby/"
)

func goferPolicy(id string) Policy {
	return Policy{Workspace: spikePolicy.Workspace, DataRoot: spikePolicy.DataRoot, DockerInit: spikePolicy.DockerInit,
		ContainerID: id, Gofer: true}
}

func TestCheckGoferPassesTheRecordedTables(t *testing.T) {
	host := readTable(t, "gvisor-guard-host.mountinfo")
	for file, id := range map[string]string{
		"gvisor-gofer-plain.mountinfo":    gvPlainID,
		"gvisor-gofer-binds.mountinfo":    gvBindsID,
		"gvisor-gofer-init.mountinfo":     gvInitID,
		"gvisor-gofer-network.mountinfo":  gvNetworkID,
		"gvisor-gofer-ordinary.mountinfo": gvOrdinaryID,
	} {
		if bad := Check(host, readTable(t, file), goferPolicy(id)); bad != nil {
			t.Errorf("%s should pass, refused at %+v", file, *bad)
		}
		// The container's own files pass under its own ID only.
		if bad := Check(host, readTable(t, file), goferPolicy("abc")); bad == nil {
			t.Errorf("%s passed for another container's ID", file)
		}
	}
	if bad := CheckSandbox(host, readTable(t, "gvisor-sandbox.mountinfo")); bad != nil {
		t.Errorf("the recorded sandbox should pass, refused at %+v", *bad)
	}
}

// The swap the API filter cannot see: the gofer's table holds the truth.
func TestCheckGoferRefusesTheRecordedSwap(t *testing.T) {
	bad := Check(readTable(t, "gvisor-guard-host.mountinfo"), readTable(t, "gvisor-gofer-swap.mountinfo"), goferPolicy(gvSwapID))
	if bad == nil || bad.Root != "/var/lib/devkit-docker/run" || bad.Point != "/s" {
		t.Fatalf("the swapped bind should be refused at /var/lib/devkit-docker/run, got %+v", bad)
	}
}

func TestCheckGoferRefusesHostileMounts(t *testing.T) {
	host := readTable(t, "gvisor-guard-host.mountinfo")
	plain := readTable(t, "gvisor-gofer-plain.mountinfo")
	d := spikePolicy.DataRoot + "/containers/"
	for what, l := range map[string]string{
		"the daemon's socket directory":       "600 514 253:1 /var/lib/devkit-docker/run /s rw - ext4 /dev/root rw",
		"/etc":                                "600 514 253:1 /etc /e rw - ext4 /dev/root rw",
		"the copied-up /etc":                  "600 514 253:1 /etc /etc/.ro2036018104 rw - ext4 /dev/root rw",
		"another container's hostconfig.json": "600 514 253:1 " + d + gvBindsID + "/hostconfig.json /h rw - ext4 /dev/root rw",
		"another container's hosts":           "600 514 253:1 " + d + gvBindsID + "/hosts /etc/hosts rw - ext4 /dev/root rw",
		"its own hostconfig.json":             "600 514 253:1 " + d + gvPlainID + "/hostconfig.json /h rw - ext4 /dev/root rw",
		"the image store":                     "600 514 253:1 " + spikePolicy.DataRoot + "/rootfs /r rw - ext4 /dev/root rw",
		"/boot":                               "600 514 259:0 / /b rw - ext4 /dev/vda16 rw",
		// runc's exceptions do not carry over to a gofer: a new proc, the
		// VM's proc, devtmpfs nodes, sysfs and mqueue where runc would put
		// them, cgroup2, a tmpfs (new or the container's shm) and an
		// overlay anywhere but the root are refused.
		"a new proc":                      "600 514 0:99 / /proc rw - proc proc rw",
		"the VM's proc":                   "600 514 0:22 / /proc rw - proc proc rw",
		"a devtmpfs node runc would bind": "600 514 0:5 /null /dev/null rw - devtmpfs udev rw",
		"devtmpfs whole":                  "600 514 0:5 / /dev rw - devtmpfs udev rw",
		"sysfs at /sys":                   "600 514 0:21 / /sys ro - sysfs sysfs ro",
		"mqueue at /dev/mqueue":           "600 514 0:57 / /dev/mqueue rw - mqueue mqueue rw",
		"cgroup2":                         "600 514 0:30 / /sys/fs/cgroup ro - cgroup2 cgroup2 rw",
		"a new tmpfs":                     "600 514 0:98 / /t rw - tmpfs tmpfs rw",
		"its own shm":                     "600 514 0:70 / /dev/shm rw - tmpfs shm rw",
		"a new devpts":                    "600 514 0:97 / /dev/pts rw - devpts devpts rw",
		"an overlay elsewhere":            "600 514 0:53 / /o rw - overlay overlay rw",
		"part of an overlay at the root":  "600 514 0:53 /etc / rw - overlay overlay rw",
		"a namespace file":                "600 514 0:4 net:[4026531840] /n rw - nsfs nsfs rw",
	} {
		m := line(t, l)
		bad := Check(shmHost(t, host), append(append([]MountEntry{}, plain...), m), goferPolicy(gvPlainID))
		if bad == nil || bad.Point != m.Point || bad.Root != m.Root {
			t.Errorf("%s: should be refused at %q, got %+v", what, l, bad)
		}
	}
}

func TestCheckSandbox(t *testing.T) {
	host := readTable(t, "gvisor-guard-host.mountinfo")
	sb := readTable(t, "gvisor-sandbox.mountinfo")
	for what, tbl := range map[string]string{
		"an extra mount":               "338 465 0:58 / / ro,relatime - tmpfs runsc-root rw\n339 338 253:1 /var/lib/devkit-docker/run /s rw - ext4 /dev/root rw\n",
		"an extra tmpfs":               "338 465 0:58 / / ro,relatime - tmpfs runsc-root rw\n339 338 0:59 / /t rw - tmpfs tmpfs rw\n",
		"a second tmpfs over its root": "338 465 0:58 / / ro,relatime - tmpfs runsc-root rw\n339 338 0:59 / / rw - tmpfs tmpfs rw\n",
		"the VM's root at its root":    "338 465 253:1 / / rw - ext4 /dev/root rw\n",
		"an overlay at its root":       "338 465 0:53 / / rw - overlay overlay rw\n",
		"a tmpfs of the VM's":          "338 465 253:1 / / rw - tmpfs tmpfs rw\n",
		"part of a tmpfs":              "338 465 0:58 /x / rw - tmpfs tmpfs rw\n",
		"a tmpfs elsewhere":            "338 465 0:58 / /x rw - tmpfs tmpfs rw\n",
	} {
		ctr, err := ParseMountinfo(strings.NewReader(tbl))
		if err != nil {
			t.Fatal(err)
		}
		if bad := CheckSandbox(host, ctr); bad == nil {
			t.Errorf("%s should be refused", what)
		}
	}
	// A tmpfs root whose device the guard's own table has is the VM's.
	withDev := append(append([]MountEntry{}, host...), line(t, "700 65 0:58 / /run/x rw - tmpfs tmpfs rw"))
	if CheckSandbox(withDev, sb) == nil {
		t.Error("a sandbox root of a tmpfs of the VM's should be refused")
	}
}

// The shim's command lines, as recorded: the runtime's arguments from
// daemon.json first, then go-runc's globals.
func gvCreate(prefix []string, id string, systemd bool) []string {
	a := append([]string{}, prefix...)
	a = append(a, "--root", gvRoot, "--log", gvTask+id+"/log.json", "--log-format", "json")
	if systemd {
		a = append(a, "--systemd-cgroup")
	}
	return append(a, "create", "--bundle", gvTask+id, "--pid-file", gvTask+id+"/init.pid", id)
}

var gvArgs = map[string][]string{"runsc": {"--ignore-cgroups"}, "runsc-hostnet": {"--ignore-cgroups", "--network=host"}}

func TestParseRunsc(t *testing.T) {
	for rt, prefix := range gvArgs {
		for _, systemd := range []bool{false, true} {
			args := gvCreate(prefix, gvSwapID, systemd)
			inv, err := ParseRunsc(args, prefix)
			if err != nil {
				t.Fatalf("%s %v: %v", rt, args, err)
			}
			want := Invocation{Global: args[:len(args)-6], Root: gvRoot, Log: gvTask + gvSwapID + "/log.json", LogFormat: "json",
				Sub: "create", Bundle: gvTask + gvSwapID, PidFile: gvTask + gvSwapID + "/init.pid", ID: gvSwapID}
			if !reflect.DeepEqual(*inv, want) {
				t.Errorf("%s:\n got %+v\nwant %+v", rt, *inv, want)
			}
		}
		for _, args := range [][]string{
			append(append([]string{}, prefix...), "--root", gvRoot, "start", gvSwapID),
			append(append([]string{}, prefix...), "--root", gvRoot, "delete", "--force", gvSwapID),
			append(append([]string{}, prefix...), "--version"),
		} {
			if _, err := ParseRunsc(args, prefix); err != nil {
				t.Errorf("%s %v: %v", rt, args, err)
			}
		}
	}
	plain, hostnet := gvArgs["runsc"], gvArgs["runsc-hostnet"]
	for what, c := range map[string]struct {
		args, prefix []string
	}{
		"--network=host on the plain runtime": {gvCreate(hostnet, gvSwapID, false), plain},
		"no runtime arguments":                {gvCreate(nil, gvSwapID, false), plain},
		"the hostnet runtime without them":    {gvCreate(plain, gvSwapID, false), hostnet},
		"the runtime arguments reordered":     {gvCreate([]string{"--network=host", "--ignore-cgroups"}, gvSwapID, false), hostnet},
		"--rootless":                          {gvCreate(append([]string{"--rootless"}, plain...), gvSwapID, false), plain},
		"an unknown global flag":              {append(append([]string{}, plain...), "--overlay2=none", "create", "--bundle", "/b/x", "--pid-file", "/p", "x"), plain},
		"--debug, which runc allows":          {append(append([]string{}, plain...), "--debug", "state", "x"), plain},
		"--directfs=false after the globals":  {append(append([]string{}, plain...), "--root", "/r", "--directfs=false", "create", "--bundle", "/b/x", "--pid-file", "/p", "x"), plain},
		"create without a bundle":             {append(append([]string{}, plain...), "create", "--pid-file", "/p", "x"), plain},
		"create without a pid file":           {append(append([]string{}, plain...), "create", "--bundle", "/b/x", "x"), plain},
		"too short for the prefix":            {[]string{}, hostnet},
	} {
		if inv, err := ParseRunsc(c.args, c.prefix); err == nil {
			t.Errorf("%s: %v should not parse: %+v", what, c.args, inv)
		}
	}
}

func runscConfig(runc, runsc string) string {
	b, _ := json.Marshal(Config{Runc: runc, Runsc: &RunscConfig{Path: runsc, RuntimeArgs: gvArgs},
		Workspace: spikePolicy.Workspace, DataRoot: spikePolicy.DataRoot, DockerInit: spikePolicy.DockerInit})
	return string(b)
}

func TestRunscGuardPassesThroughOtherSubcommands(t *testing.T) {
	runc, runsc := fakeRunc(t), fakeRunc(t)
	for rt, prefix := range gvArgs {
		for _, sub := range [][]string{
			{"start", "x"}, {"state", "x"}, {"kill", "x", "9"}, {"delete", "--force", "x"}, {"exec", "--process", "/p.json", "x"},
			{"ps", "--format", "json", "x"}, {"events", "--stats", "x"}, {"wait", "x"}, {"pause", "x"}, {"resume", "x"},
			{"update", "--resources", "-", "x"}, {"features"},
		} {
			args := append(append(append([]string{}, prefix...), "--root", gvRoot, "--log", "/l", "--log-format", "json"), sub...)
			e := &fakeEnv{}
			g := e.guard(t, runscConfig(runc, runsc))
			g.Runtime = rt
			g.Main(args)
			if want := append([]string{runsc}, args...); !reflect.DeepEqual(e.execed, want) {
				t.Errorf("%s %v: exec'd %v, want %v", rt, args, e.execed, want)
			}
		}
	}
}

func TestRunscGuardRefuses(t *testing.T) {
	runc, runsc := fakeRunc(t), fakeRunc(t)
	for _, c := range []struct {
		rt   string
		args []string
		msg  string
	}{
		{"runsc", []string{"--ignore-cgroups", "--root", "/r", "run", "--bundle", "/b/x", "x"}, "devkit: refused: runsc run"},
		{"runsc", []string{"--ignore-cgroups", "--root", "/r", "restore", "--image-path", "/i", "x"}, "devkit: refused: runsc restore"},
		{"runsc-hostnet", []string{"--ignore-cgroups", "--network=host", "--root", "/r", "checkpoint", "--image-path", "/i", "x"}, "devkit: refused: runsc checkpoint is not allowed: a checkpoint is only of use to restore"},
		{"runsc", []string{"--ignore-cgroups", "--root", "/r", "do", "ls"}, "devkit: refused: runsc do"},
		{"runsc", []string{"--ignore-cgroups", "--root", "/r", "gofer", "--bundle", "/b"}, "devkit: refused: runsc gofer"},
		{"runsc", []string{"--ignore-cgroups", "--root", "/r", "boot", "--bundle", "/b"}, "devkit: refused: runsc boot"},
		{"runsc", []string{"--ignore-cgroups", "--network=host", "--root", "/r", "state", "x"}, "cannot read the runsc command line"},
		{"runsc", []string{"--root", "/r", "state", "x"}, "cannot read the runsc command line"},
	} {
		e := &fakeEnv{}
		g := e.guard(t, runscConfig(runc, runsc))
		g.Runtime = c.rt
		if code := g.Main(c.args); code != 1 || e.execed != nil || len(e.ran) != 0 || !strings.Contains(e.stderr.String(), c.msg) {
			t.Errorf("%s %v: code %d exec %v ran %v: %s", c.rt, c.args, code, e.execed, e.ran, e.stderr.String())
		}
	}
	// Misconfigured for runsc: refused whatever the subcommand.
	for name, cfg := range map[string]string{
		"no runsc section": guardConfig(runc),
		"another runtime":  strings.Replace(runscConfig(runc, runsc), `"runsc-hostnet"`, `"runsc-other"`, 1),
		"runsc missing":    runscConfig(runc, "/nonexistent/runsc"),
		"relative runsc":   runscConfig(runc, "runsc"),
		"a bad argument":   strings.Replace(runscConfig(runc, runsc), `"--network=host"`, `"network=host"`, 1),
	} {
		e := &fakeEnv{}
		g := e.guard(t, cfg)
		g.Runtime = "runsc-hostnet"
		if code := g.Main([]string{"--ignore-cgroups", "--network=host", "--root", "/r", "state", "x"}); code != 1 || e.execed != nil ||
			!strings.Contains(e.stderr.String(), "the runtime guard is not usable") {
			t.Errorf("%s: code %d exec %v: %s", name, code, e.execed, e.stderr.String())
		}
	}
}

// fakeProc is a /proc tree: what the guard reads of each process.
type fakeProc struct {
	t   *testing.T
	dir string
}

func newFakeProc(t *testing.T) *fakeProc {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return &fakeProc{t, dir}
}

func (p *fakeProc) add(pid, ppid, uid int, exe string, argv []string, mountinfo string) {
	d := filepath.Join(p.dir, fmt.Sprint(pid))
	if err := os.MkdirAll(d, 0o755); err != nil {
		p.t.Fatal(err)
	}
	// A command name with spaces and a parenthesis, as a process may give
	// itself, must not move the parent's field.
	os.WriteFile(filepath.Join(d, "stat"), []byte(fmt.Sprintf("%d (exe) x) S %d 1 1 0 -1\n", pid, ppid)), 0o644)
	os.WriteFile(filepath.Join(d, "status"), []byte(fmt.Sprintf("Name:\texe\nPPid:\t%d\nUid:\t%d\t%d\t%d\t%d\n", ppid, uid, uid, uid, uid)), 0o644)
	os.WriteFile(filepath.Join(d, "cmdline"), []byte(strings.Join(argv, "\x00")+"\x00"), 0o644)
	os.WriteFile(filepath.Join(d, "mountinfo"), []byte(mountinfo), 0o644)
	if err := os.Symlink(exe, filepath.Join(d, "exe")); err != nil {
		p.t.Fatal(err)
	}
}

// goferArgv is the recorded gofer command line for a container (the
// recorder cut it short; the arguments after --io-fds do not matter here).
func goferArgv(id string) []string {
	return []string{"runsc-gofer", "--root=" + gvRoot, "--log=" + gvTask + id + "/log.json", "--log-format=json",
		"--ignore-cgroups=true", "--systemd-cgroup=true", "--log-fd=3", "gofer", "--bundle", gvTask + id,
		"--gofer-mount-confs=lisafs:self,lisafs:none,lisafs:none,lisafs:none", "--spec-fd=4", "--mounts-fd=5", "--rpc-fd=6", "--io-fds=7"}
}

const (
	sbPid    = 13106
	goferPid = 13101
	reaper   = 13082
)

// runscEnv is a guard in front of runsc, with a recorded sandbox and gofer
// for the plain container under gvProc, and the container created.
type runscEnv struct {
	fakeEnv
	proc  *fakeProc
	runsc string
	args  []string
	id    string
}

func newRunscEnv(t *testing.T, id, goferTable string) *runscEnv {
	runsc := fakeRunc(t)
	e := &runscEnv{proc: newFakeProc(t), runsc: runsc, id: id}
	host, _ := os.ReadFile("testdata/gvisor-guard-host.mountinfo")
	sb, _ := os.ReadFile("testdata/gvisor-sandbox.mountinfo")
	e.args = gvCreate(gvArgs["runsc"], id, true)
	e.files = map[string]string{gvTask + id + "/init.pid": fmt.Sprint(sbPid), "/proc/self/mountinfo": string(host)}
	e.proc.add(sbPid, reaper, os.Getuid(), "/nonexistent/gvisor_sentry", []string{"runsc-sandbox"}, string(sb))
	e.proc.add(goferPid, reaper, os.Getuid(), runsc, goferArgv(id), goferTable)
	return e
}

func (e *runscEnv) run(t *testing.T) int {
	g := e.guard(t, runscConfig(fakeRunc(t), e.runsc))
	g.Runtime, g.Proc, g.Getuid = "runsc", e.proc.dir, os.Getuid
	return g.Main(e.args)
}

func goferTable(t *testing.T, name string) string {
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestRunscGuardCreate(t *testing.T) {
	plain := goferTable(t, "gvisor-gofer-plain.mountinfo")

	e := newRunscEnv(t, gvPlainID, plain)
	if code := e.run(t); code != 0 || len(e.ran) != 1 || !reflect.DeepEqual(e.ran[0], append([]string{e.runsc}, e.args...)) {
		t.Fatalf("the recorded container: code %d ran %v: %s", code, e.ran, e.stderr.String())
	}

	// The recorded swap: refused, deleted with the same global flags (the
	// runtime's arguments first), the message in the log.
	e = newRunscEnv(t, gvSwapID, goferTable(t, "gvisor-gofer-swap.mountinfo"))
	logf := filepath.Join(t.TempDir(), "log.json")
	e.args[4] = logf
	if code := e.run(t); code != 1 {
		t.Fatalf("the swap: code %d", code)
	}
	wantDelete := []string{e.runsc, "--ignore-cgroups", "--root", gvRoot, "--log", logf, "--log-format", "json", "--systemd-cgroup", "delete", "--force", gvSwapID}
	if len(e.ran) != 2 || !reflect.DeepEqual(e.ran[1], wantDelete) {
		t.Errorf("the swap: ran %v", e.ran)
	}
	const msg = "devkit: refused: a mount comes from outside the workspace: ext4 /var/lib/devkit-docker/run at /s"
	data, _ := os.ReadFile(logf)
	var entry struct{ Level, Msg string }
	if !strings.Contains(e.stderr.String(), msg) || json.Unmarshal(bytes.TrimSpace(data), &entry) != nil || entry.Msg != msg {
		t.Errorf("the swap: stderr %s log %s", e.stderr.String(), data)
	}

	refused := func(what string, e *runscEnv, want string) {
		t.Helper()
		if code := e.run(t); code != 1 || len(e.ran) != 2 || e.ran[1][len(e.ran[1])-3] != "delete" || !strings.Contains(e.stderr.String(), want) {
			t.Errorf("%s: code %d ran %v: %s", what, code, e.ran, e.stderr.String())
		}
	}

	// A sandbox with a mount of its own.
	e = newRunscEnv(t, gvPlainID, plain)
	sbDir := filepath.Join(e.proc.dir, fmt.Sprint(sbPid))
	os.WriteFile(filepath.Join(sbDir, "mountinfo"), []byte(goferTable(t, "gvisor-sandbox.mountinfo")+"339 338 253:1 /etc /e rw - ext4 /dev/root rw\n"), 0o644)
	refused("a sandbox with a host mount", e, "a mount comes from outside the workspace: ext4 /etc at /e")

	// A look-alike with the right name, bundle, uid and parent but another
	// executable is not the gofer: with the real one gone, nothing is.
	e = newRunscEnv(t, gvPlainID, plain)
	os.RemoveAll(filepath.Join(e.proc.dir, fmt.Sprint(goferPid)))
	e.proc.add(20000, reaper, os.Getuid(), fakeRunc(t), goferArgv(gvPlainID), plain)
	refused("a look-alike with another exe", e, "found no gofer")

	// And beside the real gofer, a look-alike with another table is not
	// chosen in its place.
	e = newRunscEnv(t, gvSwapID, goferTable(t, "gvisor-gofer-swap.mountinfo"))
	e.proc.add(20000, reaper, os.Getuid(), fakeRunc(t), goferArgv(gvSwapID), goferTable(t, "gvisor-gofer-plain.mountinfo"))
	refused("the real gofer beside a look-alike", e, "/var/lib/devkit-docker/run at /s")

	// Look-alikes running the real runsc but under another parent, another
	// uid, or for another bundle (one that starts with this one's) are not
	// it either.
	for what, add := range map[string]func(e *runscEnv){
		"another parent": func(e *runscEnv) { e.proc.add(20000, 1, os.Getuid(), e.runsc, goferArgv(gvPlainID), plain) },
		"another uid":    func(e *runscEnv) { e.proc.add(20000, reaper, os.Getuid()+1, e.runsc, goferArgv(gvPlainID), plain) },
		"another bundle": func(e *runscEnv) {
			a := goferArgv(gvPlainID)
			a[9] += "0"
			e.proc.add(20000, reaper, os.Getuid(), e.runsc, a, plain)
		},
		"another name": func(e *runscEnv) {
			a := goferArgv(gvPlainID)
			a[0] = "runsc-gofer2"
			e.proc.add(20000, reaper, os.Getuid(), e.runsc, a, plain)
		},
	} {
		e = newRunscEnv(t, gvPlainID, plain)
		os.RemoveAll(filepath.Join(e.proc.dir, fmt.Sprint(goferPid)))
		add(e)
		refused(what, e, "found no gofer")
	}

	// Two processes that are each the gofer: refused, not a guess.
	e = newRunscEnv(t, gvPlainID, plain)
	e.proc.add(20000, reaper, os.Getuid(), e.runsc, goferArgv(gvPlainID), plain)
	refused("two gofers", e, "found 2 processes")

	// A sandbox that is not the guard's uid's.
	e = newRunscEnv(t, gvPlainID, plain)
	sbDir = filepath.Join(e.proc.dir, fmt.Sprint(sbPid))
	os.WriteFile(filepath.Join(sbDir, "status"), []byte("Uid:\t0\t1\t1\t1\n"), 0o644)
	refused("a sandbox of another uid", e, "not the guard's uid's")

	// No sandbox where the pid file points.
	e = newRunscEnv(t, gvPlainID, plain)
	os.RemoveAll(filepath.Join(e.proc.dir, fmt.Sprint(sbPid)))
	refused("no sandbox", e, "the sandbox")

	// A bundle that is not named for the container.
	e = newRunscEnv(t, gvPlainID, plain)
	e.args[len(e.args)-1] = gvSwapID
	refused("a bundle of another name", e, "is not the container")

	// runsc failing: its code, nothing checked or deleted.
	e = newRunscEnv(t, gvPlainID, plain)
	e.runCode = 3
	if code := e.run(t); code != 3 || len(e.ran) != 1 {
		t.Errorf("runsc failing: code %d ran %v", code, e.ran)
	}
}

func TestGoferFor(t *testing.T) {
	b := gvTask + gvPlainID
	for _, ok := range [][]string{goferArgv(gvPlainID), {"runsc-gofer", "gofer", "--bundle=" + b}} {
		if !goferFor(ok, b) {
			t.Errorf("%v should match", ok)
		}
	}
	for _, bad := range [][]string{
		nil, {"runsc-gofer"}, {"runsc-gofer", "gofer"}, {"runsc-gofer", "gofer", "--bundle"},
		{"runsc-gofer", "--bundle", b, "gofer"}, {"runsc-gofer", "gofer", "--bundle", b + "/x"},
		{"runsc-gofer", "gofer", "--bundle", b[:len(b)-1]}, {"runsc-gofer", "gofer", "--log=" + b + "/log.json"},
		{"/usr/local/bin/runsc", "gofer", "--bundle", b}, {"runsc-gofer", "boot", "--bundle", b},
	} {
		if goferFor(bad, b) {
			t.Errorf("%v should not match", bad)
		}
	}
}
