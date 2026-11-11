package runcguard

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	for _, c := range []struct {
		args []string
		want Invocation
	}{
		{
			[]string{"--root", "/run/user/999/docker/runtime-runc/moby", "--log", "/b/log.json", "--log-format", "json", "--systemd-cgroup", "create", "--bundle", "/b", "--pid-file", "/b/init.pid", "abc"},
			Invocation{Global: []string{"--root", "/run/user/999/docker/runtime-runc/moby", "--log", "/b/log.json", "--log-format", "json", "--systemd-cgroup"},
				Root: "/run/user/999/docker/runtime-runc/moby", Log: "/b/log.json", LogFormat: "json", Sub: "create", Bundle: "/b", PidFile: "/b/init.pid", ID: "abc"},
		},
		{
			[]string{"--root=/r", "--log=/l", "--log-format=json", "--rootless=true", "--debug=false", "create", "-b", "/b", "--console-socket", "/s.sock", "--pid-file=/p", "--no-pivot", "--no-new-keyring", "--preserve-fds", "2", "id1"},
			Invocation{Global: []string{"--root=/r", "--log=/l", "--log-format=json", "--rootless=true", "--debug=false"},
				Root: "/r", Log: "/l", LogFormat: "json", Sub: "create", Bundle: "/b", PidFile: "/p", PreserveFDs: 2, ID: "id1"},
		},
		{
			[]string{"-root", "/r", "--rootless", "auto", "create", "--pid-file", "/p", "--pidfd-socket", "/f", "x"},
			Invocation{Global: []string{"-root", "/r", "--rootless", "auto"}, Root: "/r", Sub: "create", PidFile: "/p", ID: "x"},
		},
		{[]string{"--root", "/r", "start", "abc"}, Invocation{Global: []string{"--root", "/r"}, Root: "/r", Sub: "start"}},
		{[]string{"--root", "/r", "delete", "--force", "abc"}, Invocation{Global: []string{"--root", "/r"}, Root: "/r", Sub: "delete"}},
		{[]string{"--version"}, Invocation{Global: []string{"--version"}}},
		{[]string{"features"}, Invocation{Sub: "features"}},
		{[]string{"run", "--bundle", "/b", "x"}, Invocation{Sub: "run"}},
		{[]string{"--root", "/r", "restore", "x"}, Invocation{Global: []string{"--root", "/r"}, Root: "/r", Sub: "restore"}},
	} {
		got, err := Parse(c.args)
		if err != nil {
			t.Errorf("%v: %v", c.args, err)
			continue
		}
		if !reflect.DeepEqual(*got, c.want) {
			t.Errorf("%v:\n got %+v\nwant %+v", c.args, *got, c.want)
		}
	}
	for _, bad := range [][]string{
		{"--frobnicate", "create", "--pid-file", "/p", "x"},
		{"--root"},
		{"--debug=maybe", "state", "x"},
		{"create", "--pid-file", "/p"},
		{"create", "--pid-file", "/p", "a", "b"},
		{"create", "--pid-file", "/p", "a", "--no-pivot"},
		{"create", "--bundle", "/b", "x"},
		{"create", "--pid-file", "/p", "--frobnicate", "x"},
		{"create", "--pid-file"},
		{"create", "--pid-file", "/p", "--preserve-fds", "-1", "x"},
		{"create", "--pid-file", "/p", "--preserve-fds", "lots", "x"},
		{"create", "--pid-file", "/p", "--no-pivot=yes-please", "x"},
		{"create", "--pid-file", "/p", ""},
	} {
		if inv, err := Parse(bad); err == nil {
			t.Errorf("%v should not parse: %+v", bad, inv)
		}
	}
}

func TestParseMountinfo(t *testing.T) {
	in := "36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue\n" +
		"40 36 0:33 /a\\040b\\011c\\134d /in\\040space rw shared:2 master:3 propagate_from:4 - tmpfs my\\040src rw\n" +
		"41 36 0:34 / /no-optional rw - proc proc rw\n"
	got, err := ParseMountinfo(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	want := []MountEntry{
		{Dev: "98:0", Root: "/mnt1", Point: "/mnt2", FSType: "ext3", Source: "/dev/root"},
		{Dev: "0:33", Root: "/a b\tc\\d", Point: "/in space", FSType: "tmpfs", Source: "my src"},
		{Dev: "0:34", Root: "/", Point: "/no-optional", FSType: "proc", Source: "proc"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
	for _, bad := range []string{
		"", "36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 ext3 /dev/root rw",
		"36 35 98:0 /mnt1 /mnt2 rw - ext3",
		"36 35 980 / / rw - ext3 /dev/root rw",
		"36 35 98:0 /a\\04 / rw - ext3 /dev/root rw",
		"36 35 98:0 /a\\999 / rw - ext3 /dev/root rw",
	} {
		if _, err := ParseMountinfo(strings.NewReader(bad)); err == nil {
			t.Errorf("%q should not parse", bad)
		}
	}
}

func readTable(t *testing.T, name string) []MountEntry {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	m, err := ParseMountinfo(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func line(t *testing.T, s string) MountEntry {
	t.Helper()
	m, err := ParseMountinfo(strings.NewReader(s))
	if err != nil {
		t.Fatal(err)
	}
	return m[0]
}

// spikeID is the recorded container's ID: the name of its directory under
// the data root and of its cgroup scope.
const spikeID = "9f9ae6ce1b9dc301dbdc1f53cb39f0dcd300990f18864d27521a99bdf36bbb1f"

const spikeCgroup = "/user.slice/user-999.slice/user@999.service/user.slice/docker-" + spikeID + ".scope"

var spikePolicy = Policy{
	Workspace:   "/home/jurajpiar.guest/workspace",
	DataRoot:    "/var/lib/devkit-docker/.local/share/docker",
	DockerInit:  "/usr/bin/docker-init",
	ContainerID: spikeID,
	Cgroup:      spikeCgroup,
}

// The container table is the one the shell prototype read on a real VM, for
// a container with a workspace bind, a named volume and --init (from
// spikes/docker-account/results/03-runtime-guard.log; the log cut lines at
// 190 characters, so the cgroup line's tail and three missing super-option
// fields were filled in). The guard's own table was not recorded: the host
// table is constructed to match what the daemon's namespace holds (rootless
// copy-up tmpfs over /etc and /run, the ID-mapped workspace, the
// containers' overlays).
func TestCheckPassesTheRecordedContainer(t *testing.T) {
	host, ctr := readTable(t, "guard-host.mountinfo"), readTable(t, "spike-container.mountinfo")
	if bad := Check(host, ctr, spikePolicy); bad != nil {
		t.Fatalf("the recorded container should pass, refused at %+v", *bad)
	}
}

func TestCheckRefusesHostileMounts(t *testing.T) {
	host, ctr := readTable(t, "guard-host.mountinfo"), readTable(t, "spike-container.mountinfo")
	for what, l := range map[string]string{
		"the daemon's socket directory":            "500 426 253:1 /var/lib/devkit-docker/run /s rw - ext4 /dev/root rw",
		"the daemon's socket":                      "500 426 253:1 /var/lib/devkit-docker/run/docker.sock /var/run/docker.sock rw - ext4 /dev/root rw",
		"the account's runtime directory":          "500 426 0:45 / /r rw - tmpfs tmpfs rw",
		"part of the runtime directory":            "500 426 0:45 /docker/containerd /r rw - tmpfs tmpfs rw",
		"the copied-up /etc":                       "500 426 0:46 / /e rw - tmpfs tmpfs rw",
		"/etc on the root filesystem":              "500 426 253:1 /etc /e rw - ext4 /dev/root rw",
		"the VM's root":                            "500 426 253:1 / /host rw - ext4 /dev/root rw",
		"the user's home":                          "500 426 253:1 /home/jurajpiar.guest /h rw - ext4 /dev/root rw",
		"~/.ssh":                                   "500 426 253:1 /home/jurajpiar.guest/.ssh /s rw - ext4 /dev/root rw",
		"a sibling with the workspace as prefix":   "500 426 253:1 /home/jurajpiar.guest/workspace-evil /w rw - ext4 /dev/root rw",
		"another container's overlay":              "500 426 0:52 / /o rw - overlay overlay rw",
		"this container's overlay elsewhere":       "500 426 0:51 / /o rw - overlay overlay rw",
		"the VM's /proc":                           "500 426 0:22 / /hp rw - proc proc rw",
		"the VM's /proc at /proc":                  "500 426 0:22 / /proc rw - proc proc rw",
		"a subtree of the VM's /proc":              "500 426 0:22 /sys /x rw - proc proc rw",
		"binfmt_misc under /proc":                  "500 426 0:40 / /hp/sys/fs/binfmt_misc rw - autofs systemd-1 rw",
		"the VM's sysfs elsewhere":                 "500 426 0:21 / /s ro - sysfs sysfs ro",
		"a subtree of the VM's sysfs":              "500 426 0:21 /kernel /sys rw - sysfs sysfs rw",
		"securityfs":                               "500 426 0:7 / /sys/kernel/security rw - securityfs securityfs rw",
		"the VM's devpts elsewhere":                "500 426 0:24 / /p rw - devpts devpts rw",
		"devtmpfs whole":                           "500 426 0:5 / /dev rw - devtmpfs devtmpfs rw",
		"devtmpfs with another node":               "500 426 0:5 /vda /dev/x rw - devtmpfs devtmpfs rw",
		"devtmpfs with a node like an allowed one": "500 426 0:5 /null2 /dev/x rw - devtmpfs devtmpfs rw",
		"the image store":                          "500 426 253:1 /var/lib/devkit-docker/.local/share/docker/overlay2 /o rw - ext4 /dev/root rw",
		"every volume":                             "500 426 253:1 /var/lib/devkit-docker/.local/share/docker/volumes /v rw - ext4 /dev/root rw",
		"a volume's directory, not its data":       "500 426 253:1 /var/lib/devkit-docker/.local/share/docker/volumes/v /v rw - ext4 /dev/root rw",
		"the volume database":                      "500 426 253:1 /var/lib/devkit-docker/.local/share/docker/volumes/metadata.db /v rw - ext4 /dev/root rw",
		"every container":                          "500 426 253:1 /var/lib/devkit-docker/.local/share/docker/containers /c rw - ext4 /dev/root rw",
		"a container's directory":                  "500 426 253:1 /var/lib/devkit-docker/.local/share/docker/containers/abc /c rw - ext4 /dev/root rw",
		"the data root":                            "500 426 253:1 /var/lib/devkit-docker/.local/share/docker /d rw - ext4 /dev/root rw",
		"a file beside docker-init":                "500 426 253:1 /usr/bin/docker-init2 /i ro - ext4 /dev/root rw",
		"/usr/bin":                                 "500 426 253:1 /usr/bin /i ro - ext4 /dev/root rw",
		"another filesystem of the VM":             "500 426 254:16 / /b rw - ext4 /dev/vda16 rw",
		"the VM's /dev/shm":                        "500 426 0:25 / /dev/shm rw - tmpfs tmpfs rw",
		"the VM's devpts at /dev/pts":              "500 426 0:24 / /dev/pts rw - devpts devpts rw",
		"the VM's cgroup tree":                     "500 426 0:30 / /sys/fs/cgroup ro - cgroup2 cgroup2 rw",
		"the Docker account's cgroup":              "500 426 0:30 /user.slice/user-999.slice/user@999.service /c rw - cgroup2 cgroup2 rw",
		"a cgroup named like its own":              "500 426 0:30 " + spikeCgroup + "-x /c rw - cgroup2 cgroup2 rw",
		"a namespace file":                         "500 426 0:4 net:[4026531840] /n rw - nsfs nsfs rw",
		"its own hostconfig.json":                  "500 426 253:1 /var/lib/devkit-docker/.local/share/docker/containers/" + spikeID + "/hostconfig.json /h rw - ext4 /dev/root rw",
		"its own config.v2.json":                   "500 426 253:1 /var/lib/devkit-docker/.local/share/docker/containers/" + spikeID + "/config.v2.json /h rw - ext4 /dev/root rw",
		"its own log":                              "500 426 253:1 /var/lib/devkit-docker/.local/share/docker/containers/" + spikeID + "/" + spikeID + "-json.log /h rw - ext4 /dev/root rw",
		"its own directory":                        "500 426 253:1 /var/lib/devkit-docker/.local/share/docker/containers/" + spikeID + " /h rw - ext4 /dev/root rw",
		"its own checkpoints":                      "500 426 253:1 /var/lib/devkit-docker/.local/share/docker/containers/" + spikeID + "/checkpoints /h rw - ext4 /dev/root rw",
		"below its own hosts":                      "500 426 253:1 /var/lib/devkit-docker/.local/share/docker/containers/" + spikeID + "/hosts/x /h rw - ext4 /dev/root rw",
		"another container's hosts":                "500 426 253:1 /var/lib/devkit-docker/.local/share/docker/containers/abc/hosts /etc/hosts rw - ext4 /dev/root rw",
		"another container's hostconfig.json":      "500 426 253:1 /var/lib/devkit-docker/.local/share/docker/containers/abc/hostconfig.json /h rw - ext4 /dev/root rw",
		"an ID with its own as prefix":             "500 426 253:1 /var/lib/devkit-docker/.local/share/docker/containers/" + spikeID + "0/hosts /etc/hosts rw - ext4 /dev/root rw",
		"its own ID as a prefix of the file":       "500 426 253:1 /var/lib/devkit-docker/.local/share/docker/containers/" + spikeID + "-hosts /etc/hosts rw - ext4 /dev/root rw",
		"another container's shm":                  "500 426 0:71 / /dev/shm rw - tmpfs shm rw",
		"part of its own shm":                      "500 426 0:70 /x /dev/shm rw - tmpfs shm rw",
		"its own shm directory on the root fs":     "500 426 253:1 /var/lib/devkit-docker/.local/share/docker/containers/" + spikeID + "/mounts/shm /dev/shm rw - ext4 /dev/root rw",
	} {
		bad := Check(shmHost(t, host), append(append([]MountEntry{}, ctr...), line(t, l)), spikePolicy)
		if bad == nil || bad.Point != line(t, l).Point || bad.Root != line(t, l).Root {
			t.Errorf("%s: should be refused at %q, got %+v", what, l, bad)
		}
	}
	for what, l := range map[string]string{
		"a subdirectory of the workspace":  "500 426 253:1 /home/jurajpiar.guest/workspace/sub/dir /d rw - ext4 /dev/root rw",
		"a file in the workspace":          "500 426 253:1 /home/jurajpiar.guest/workspace/README.md /r ro - ext4 /dev/root rw",
		"a volume's subpath":               "500 426 253:1 /var/lib/devkit-docker/.local/share/docker/volumes/v/_data/sub /v rw - ext4 /dev/root rw",
		"the VM's sysfs where it belongs":  "500 426 0:21 / /sys ro - sysfs sysfs ro",
		"the VM's mqueue where it belongs": "500 426 0:57 / /dev/mqueue rw - mqueue mqueue rw",
		"a tmpfs of its own":               "500 426 0:99 / /t rw - tmpfs tmpfs rw",
		"its own cgroup again":             "500 426 0:30 " + spikeCgroup + " /c ro - cgroup2 cgroup2 rw",
		"a cgroup below its own":           "500 426 0:30 " + spikeCgroup + "/sub /c ro - cgroup2 cgroup2 rw",
		"its own hosts elsewhere":          "500 426 253:1 /var/lib/devkit-docker/.local/share/docker/containers/" + spikeID + "/hosts /h ro - ext4 /dev/root rw",
		"its own shm (--ipc shareable)":    "500 426 0:70 / /dev/shm rw - tmpfs shm rw",
	} {
		if bad := Check(shmHost(t, host), append(append([]MountEntry{}, ctr...), line(t, l)), spikePolicy); bad != nil {
			t.Errorf("%s should pass, refused at %+v", what, *bad)
		}
	}
}

// shmHost is host with the shared-memory tmpfs Docker mounts for --ipc
// shareable, for the recorded container (0:70) and for another (0:71).
func shmHost(t *testing.T, host []MountEntry) []MountEntry {
	d := spikePolicy.DataRoot + "/containers/"
	return append(append([]MountEntry{}, host...),
		line(t, "600 300 0:70 / "+d+spikeID+"/mounts/shm rw - tmpfs shm rw"),
		line(t, "601 300 0:71 / "+d+"abc/mounts/shm rw - tmpfs shm rw"))
}

// Without the container's ID or cgroup, nothing of the data root's
// containers or of cgroup2 passes.
func TestCheckWithoutIDOrCgroup(t *testing.T) {
	host, ctr := readTable(t, "guard-host.mountinfo"), readTable(t, "spike-container.mountinfo")
	for name, p := range map[string]Policy{
		"no ID":       {Workspace: spikePolicy.Workspace, DataRoot: spikePolicy.DataRoot, DockerInit: spikePolicy.DockerInit, Cgroup: spikeCgroup},
		"another ID":  {Workspace: spikePolicy.Workspace, DataRoot: spikePolicy.DataRoot, DockerInit: spikePolicy.DockerInit, Cgroup: spikeCgroup, ContainerID: "abc"},
		"an ID of ..": {Workspace: spikePolicy.Workspace, DataRoot: spikePolicy.DataRoot, DockerInit: spikePolicy.DockerInit, Cgroup: spikeCgroup, ContainerID: ".."},
		"no cgroup":   {Workspace: spikePolicy.Workspace, DataRoot: spikePolicy.DataRoot, DockerInit: spikePolicy.DockerInit, ContainerID: spikeID},
	} {
		if bad := Check(host, ctr, p); bad == nil {
			t.Errorf("%s: the recorded container passed", name)
		}
	}
}

func TestUnifiedCgroup(t *testing.T) {
	for in, want := range map[string]string{
		"0::" + spikeCgroup + "\n":                 spikeCgroup,
		"12:memory:/x\n1:name=systemd:/y\n0::/z\n": "/z",
		"12:memory:/x\n":                           "",
		"":                                         "",
		"0::relative\n":                            "",
	} {
		if got := unifiedCgroup([]byte(in)); got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}

// The root filesystem may be a subvolume: mountinfo then writes paths on it
// relative to the subvolume's root.
func TestCheckRootSubvolume(t *testing.T) {
	host := []MountEntry{{Dev: "0:40", Root: "/@", Point: "/", FSType: "btrfs"}}
	ok := MountEntry{Dev: "0:40", Root: "/@/home/u/workspace/x", Point: "/w", FSType: "btrfs"}
	bad := MountEntry{Dev: "0:40", Root: "/home/u/workspace/x", Point: "/w", FSType: "btrfs"}
	p := Policy{Workspace: "/home/u/workspace", DataRoot: "/d", DockerInit: "/i"}
	if m := Check(host, []MountEntry{ok}, p); m != nil {
		t.Errorf("refused %+v", *m)
	}
	if m := Check(host, []MountEntry{bad}, p); m == nil {
		t.Error("a path outside the subvolume's workspace passed")
	}
}

// fakeEnv runs the guard against files in memory and records what it runs.
type fakeEnv struct {
	files   map[string]string
	ran     [][]string
	execed  []string
	runCode int
	stderr  bytes.Buffer
}

func (e *fakeEnv) guard(t *testing.T, cfg string) *Guard {
	t.Helper()
	if e.files == nil {
		e.files = map[string]string{}
	}
	e.files["/cfg"] = cfg
	return &Guard{
		ConfigPath: "/cfg",
		Self:       func() (string, error) { return "/usr/local/bin/devkit-egressproxy", nil },
		Exec: func(path string, argv, env []string) error {
			e.execed = argv
			return errors.New("exec faked")
		},
		Run: func(path string, args []string, extra []*os.File) (int, error) {
			e.ran = append(e.ran, append([]string{path}, args...))
			if len(e.ran) == 1 {
				return e.runCode, nil
			}
			return 0, nil
		},
		ReadFile: func(p string) ([]byte, error) {
			if s, ok := e.files[p]; ok {
				return []byte(s), nil
			}
			return nil, os.ErrNotExist
		},
		Stderr: &e.stderr,
	}
}

// A runc to point the configuration at: EvalSymlinks needs a real file.
func fakeRunc(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "runc")
	os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755)
	return p
}

func guardConfig(runc string) string {
	b, _ := json.Marshal(Config{Runc: runc, Workspace: spikePolicy.Workspace, DataRoot: spikePolicy.DataRoot, DockerInit: spikePolicy.DockerInit})
	return string(b)
}

func TestGuardPassesThroughOtherSubcommands(t *testing.T) {
	runc := fakeRunc(t)
	for _, args := range [][]string{
		{"--root", "/r", "start", "abc"}, {"--root", "/r", "delete", "--force", "abc"}, {"--root", "/r", "state", "abc"},
		{"--root", "/r", "kill", "abc", "9"}, {"--version"}, {"features"}, {"--root", "/r", "exec", "--process", "/p.json", "abc"},
	} {
		e := &fakeEnv{}
		e.guard(t, guardConfig(runc)).Main(args)
		if want := append([]string{runc}, args...); !reflect.DeepEqual(e.execed, want) {
			t.Errorf("%v: exec'd %v, want %v", args, e.execed, want)
		}
		if len(e.ran) != 0 {
			t.Errorf("%v: ran %v", args, e.ran)
		}
	}
}

func TestGuardRefusesRunAndRestore(t *testing.T) {
	runc := fakeRunc(t)
	for _, args := range [][]string{{"--root", "/r", "run", "--bundle", "/b", "x"}, {"--root", "/r", "--log", "/nonexistent-dir/log", "restore", "x"}} {
		e := &fakeEnv{}
		if code := e.guard(t, guardConfig(runc)).Main(args); code != 1 || e.execed != nil || len(e.ran) != 0 {
			t.Errorf("%v: code %d exec %v ran %v", args, code, e.execed, e.ran)
		}
		if !strings.Contains(e.stderr.String(), "devkit: refused: runc") {
			t.Errorf("%v: %s", args, e.stderr.String())
		}
	}
}

func TestGuardRefusesEverythingWhenMisconfigured(t *testing.T) {
	runc := fakeRunc(t)
	self := filepath.Join(filepath.Dir(runc), "self")
	os.WriteFile(self, nil, 0o755)
	link := filepath.Join(filepath.Dir(runc), "runc-link")
	os.Symlink(self, link)
	for name, cfg := range map[string]string{
		"missing":           "",
		"not JSON":          "{",
		"unknown field":     `{"runc":"` + runc + `","workspace":"/w","data_root":"/d","docker_init":"/i","x":1}`,
		"relative runc":     `{"runc":"runc","workspace":"/w","data_root":"/d","docker_init":"/i"}`,
		"no workspace":      `{"runc":"` + runc + `","data_root":"/d","docker_init":"/i"}`,
		"workspace /":       `{"runc":"` + runc + `","workspace":"/","data_root":"/d","docker_init":"/i"}`,
		"runc missing":      `{"runc":"/nonexistent/runc","workspace":"/w","data_root":"/d","docker_init":"/i"}`,
		"runc is the guard": `{"runc":"` + link + `","workspace":"/w","data_root":"/d","docker_init":"/i"}`,
	} {
		e := &fakeEnv{}
		g := e.guard(t, cfg)
		if name == "missing" {
			delete(e.files, "/cfg")
		}
		g.Self = func() (string, error) { return self, nil }
		for _, args := range [][]string{{"--root", "/r", "state", "x"}, {"--root", "/r", "create", "--pid-file", "/p", "x"}} {
			if code := g.Main(args); code != 1 || e.execed != nil || len(e.ran) != 0 {
				t.Errorf("%s %v: code %d exec %v ran %v", name, args, code, e.execed, e.ran)
			}
		}
		if !strings.Contains(e.stderr.String(), "devkit: refused: the runtime guard is not usable") {
			t.Errorf("%s: %s", name, e.stderr.String())
		}
	}
}

func TestGuardCreate(t *testing.T) {
	runc := fakeRunc(t)
	host, _ := os.ReadFile("testdata/guard-host.mountinfo")
	ctr, _ := os.ReadFile("testdata/spike-container.mountinfo")
	args := []string{"--root", "/r", "--log", "", "--log-format", "json", "--systemd-cgroup", "create", "--bundle", "/b", "--pid-file", "/b/init.pid", spikeID}
	cgroup := "0::" + spikeCgroup + "\n"
	withLog := func(log string) []string {
		a := append([]string{}, args...)
		a[3] = log
		return a
	}

	// Passes: runc ran once with the same arguments, nothing deleted.
	e := &fakeEnv{files: map[string]string{"/b/init.pid": "4242\n", "/proc/self/mountinfo": string(host), "/proc/4242/mountinfo": string(ctr), "/proc/4242/cgroup": cgroup}}
	logf := filepath.Join(t.TempDir(), "log.json")
	if code := e.guard(t, guardConfig(runc)).Main(withLog(logf)); code != 0 {
		t.Fatalf("code %d: %s", code, e.stderr.String())
	}
	if len(e.ran) != 1 || !reflect.DeepEqual(e.ran[0], append([]string{runc}, withLog(logf)...)) {
		t.Errorf("ran %v", e.ran)
	}

	// Refused: deleted with the same global flags, the error in the log
	// as containerd reads it, and on stderr.
	bad := string(ctr) + "500 426 253:1 /var/lib/devkit-docker/run /s rw - ext4 /dev/root rw\n"
	e = &fakeEnv{files: map[string]string{"/b/init.pid": "4242", "/proc/self/mountinfo": string(host), "/proc/4242/mountinfo": bad, "/proc/4242/cgroup": cgroup}}
	if code := e.guard(t, guardConfig(runc)).Main(withLog(logf)); code != 1 {
		t.Fatalf("code %d", code)
	}
	wantDelete := []string{runc, "--root", "/r", "--log", logf, "--log-format", "json", "--systemd-cgroup", "delete", "--force", spikeID}
	if len(e.ran) != 2 || !reflect.DeepEqual(e.ran[1], wantDelete) {
		t.Errorf("ran %v", e.ran)
	}
	const msg = "devkit: refused: a mount comes from outside the workspace: ext4 /var/lib/devkit-docker/run at /s"
	if !strings.Contains(e.stderr.String(), msg) {
		t.Errorf("stderr: %s", e.stderr.String())
	}
	data, _ := os.ReadFile(logf)
	var entry struct{ Level, Msg, Time string }
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil || entry.Level != "error" || entry.Msg != msg || entry.Time == "" {
		t.Errorf("log: %s (%v)", data, err)
	}

	// A text log gets a logrus-style line.
	textLog := filepath.Join(t.TempDir(), "log")
	e = &fakeEnv{files: map[string]string{"/b/init.pid": "4242", "/proc/self/mountinfo": string(host), "/proc/4242/mountinfo": bad, "/proc/4242/cgroup": cgroup}}
	a := withLog(textLog)
	a[5] = "text"
	e.guard(t, guardConfig(runc)).Main(a)
	if data, _ := os.ReadFile(textLog); !strings.Contains(string(data), `level=error msg="devkit: refused: a mount comes from outside the workspace`) {
		t.Errorf("text log: %s", data)
	}

	// runc failing: its code, nothing checked or deleted.
	e = &fakeEnv{runCode: 3}
	if code := e.guard(t, guardConfig(runc)).Main(withLog(logf)); code != 3 || len(e.ran) != 1 {
		t.Errorf("code %d ran %v", code, e.ran)
	}

	// The container's own files pass under its own ID only: the same
	// table for a container of another ID is refused at its files.
	other := withLog(logf)
	other[len(other)-1] = "abc"
	e = &fakeEnv{files: map[string]string{"/b/init.pid": "4242", "/proc/self/mountinfo": string(host), "/proc/4242/mountinfo": string(ctr), "/proc/4242/cgroup": cgroup}}
	if code := e.guard(t, guardConfig(runc)).Main(other); code != 1 || !strings.Contains(e.stderr.String(), "/containers/"+spikeID+"/") {
		t.Errorf("another ID: code %d: %s", code, e.stderr.String())
	}

	// A cgroup table it cannot read refuses.
	e = &fakeEnv{files: map[string]string{"/b/init.pid": "4242", "/proc/self/mountinfo": string(host), "/proc/4242/mountinfo": string(ctr)}}
	if code := e.guard(t, guardConfig(runc)).Main(withLog(logf)); code != 1 || len(e.ran) != 2 {
		t.Errorf("no cgroup table: code %d ran %v", code, e.ran)
	}

	// A mount table it cannot read refuses too.
	e = &fakeEnv{files: map[string]string{"/b/init.pid": "4242", "/proc/self/mountinfo": string(host)}}
	if code := e.guard(t, guardConfig(runc)).Main(withLog(logf)); code != 1 || len(e.ran) != 2 {
		t.Errorf("unreadable table: code %d ran %v", code, e.ran)
	}
	e = &fakeEnv{files: map[string]string{"/b/init.pid": "nonsense", "/proc/self/mountinfo": string(host)}}
	if code := e.guard(t, guardConfig(runc)).Main(withLog(logf)); code != 1 || len(e.ran) != 2 {
		t.Errorf("bad pid file: code %d ran %v", code, e.ran)
	}

	// A create it cannot read is refused before runc runs.
	e = &fakeEnv{}
	if code := e.guard(t, guardConfig(runc)).Main([]string{"--root", "/r", "create", "--bundle", "/b", "abc"}); code != 1 || len(e.ran) != 0 {
		t.Errorf("no pid file: code %d ran %v", code, e.ran)
	}
}
