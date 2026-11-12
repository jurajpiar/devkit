package runcguard

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Invocation is a runc command line as the guard reads it.
type Invocation struct {
	// Global are runc's global flags, as given, before the subcommand.
	Global    []string
	Root      string
	Log       string
	LogFormat string
	// Sub is the subcommand; empty for runc --version and the like.
	Sub string
	// For create: its flags and the container ID.
	Bundle      string
	PidFile     string
	PreserveFDs int
	ID          string
}

// runc's global flags, as containerd's go-runc passes them, and whether
// each takes a value.
var globalFlags = map[string]bool{
	"root": true, "log": true, "log-format": true, "criu": true, "rootless": true,
	"debug": false, "systemd-cgroup": false,
	"help": false, "h": false, "version": false, "v": false,
}

// runsc's global flags as the shim passes them (go-runc with containerd's
// runc shim: --root, --log, --log-format json, and --systemd-cgroup when
// the daemon uses systemd), and --version, which the daemon asks for. The
// arguments daemon.json gives the runtime come before them and are matched
// separately, exactly. runsc has many more global flags (--rootless,
// --network, --overlay2, --directfs, ...), each of which changes how the
// sandbox is built; none of them is passed through.
var runscGlobalFlags = map[string]bool{
	"root": true, "log": true, "log-format": true,
	"systemd-cgroup": false, "version": false,
}

// create's flags, and whether each takes a value.
var createFlags = map[string]bool{
	"bundle": true, "b": true, "console-socket": true, "pidfd-socket": true, "pid-file": true, "preserve-fds": true,
	"no-pivot": false, "no-new-keyring": false,
}

// flag splits "-x", "--x" and "--x=v" into the name and the inline value.
func flag(a string) (name, val string, hasVal, ok bool) {
	if len(a) < 2 || a[0] != '-' || a == "--" {
		return "", "", false, false
	}
	name = strings.TrimPrefix(strings.TrimPrefix(a, "-"), "-")
	name, val, hasVal = strings.Cut(name, "=")
	return name, val, hasVal, name != ""
}

// Parse reads runc's arguments (without the program name). An argument
// list it cannot read is an error, whatever the subcommand.
func Parse(args []string) (*Invocation, error) {
	return parse(args, nil, globalFlags)
}

// ParseRunsc reads runsc's arguments (without the program name). Docker
// runs a runtime with runtimeArgs through a script that puts them first, so
// the list must start with exactly runtimeArgs, the ones devkit wrote into
// daemon.json for this runtime; after them only the shim's own global
// flags may follow. A create must name its bundle, which is how the guard
// recognises the container's gofer.
func ParseRunsc(args, runtimeArgs []string) (*Invocation, error) {
	if len(args) < len(runtimeArgs) {
		return nil, fmt.Errorf("want the runtime's arguments %q first", runtimeArgs)
	}
	for i, a := range runtimeArgs {
		if args[i] != a {
			return nil, fmt.Errorf("want the runtime's arguments %q first, got %q", runtimeArgs, args[:len(runtimeArgs)])
		}
	}
	inv, err := parse(args[len(runtimeArgs):], runtimeArgs, runscGlobalFlags)
	if err != nil {
		return nil, err
	}
	if inv.Sub == "create" && inv.Bundle == "" {
		return nil, errors.New("create: no --bundle, so the container's gofer cannot be recognised")
	}
	// start is checked again, so its container must be known: the shim
	// gives "start <id>" and nothing else. Global holds everything before
	// the subcommand, so what follows it starts one further on.
	if inv.Sub == "start" {
		rest := args[len(inv.Global)+1:]
		if len(rest) != 1 || !validID(rest[0]) || strings.HasPrefix(rest[0], "-") {
			return nil, fmt.Errorf("start: want exactly one container ID, got %q", rest)
		}
		inv.ID = rest[0]
	}
	return inv, nil
}

// parse reads a runtime's arguments after prefix, which it has already
// matched and which stays at the front of Global.
func parse(args, prefix []string, globalFlags map[string]bool) (*Invocation, error) {
	inv := &Invocation{Global: append([]string(nil), prefix...)}
	i := 0
	for ; i < len(args); i++ {
		a := args[i]
		name, val, hasVal, ok := flag(a)
		if !ok {
			break
		}
		takes, known := globalFlags[name]
		if !known {
			return nil, fmt.Errorf("unknown global flag %q", a)
		}
		inv.Global = append(inv.Global, a)
		if takes && !hasVal {
			if i+1 >= len(args) {
				return nil, fmt.Errorf("the flag %q has no value", a)
			}
			i++
			val = args[i]
			inv.Global = append(inv.Global, val)
		} else if !takes && hasVal {
			if _, err := strconv.ParseBool(val); err != nil {
				return nil, fmt.Errorf("the flag %q takes true or false", a)
			}
		}
		switch name {
		case "root":
			inv.Root = val
		case "log":
			inv.Log = val
		case "log-format":
			inv.LogFormat = val
		}
	}
	if i == len(args) {
		return inv, nil
	}
	inv.Sub = args[i]
	if inv.Sub != "create" {
		return inv, nil
	}
	rest := args[i+1:]
	var pos []string
	for j := 0; j < len(rest); j++ {
		a := rest[j]
		name, val, hasVal, ok := flag(a)
		if !ok {
			pos = append(pos, a)
			continue
		}
		if len(pos) > 0 {
			return nil, fmt.Errorf("create: the flag %q comes after the container ID", a)
		}
		takes, known := createFlags[name]
		if !known {
			return nil, fmt.Errorf("create: unknown flag %q", a)
		}
		if takes && !hasVal {
			if j+1 >= len(rest) {
				return nil, fmt.Errorf("create: the flag %q has no value", a)
			}
			j++
			val = rest[j]
		} else if !takes && hasVal {
			if _, err := strconv.ParseBool(val); err != nil {
				return nil, fmt.Errorf("create: the flag %q takes true or false", a)
			}
		}
		switch name {
		case "bundle", "b":
			inv.Bundle = val
		case "pid-file":
			inv.PidFile = val
		case "preserve-fds":
			n, err := strconv.Atoi(val)
			if err != nil || n < 0 || n > 1024 {
				return nil, fmt.Errorf("create: --preserve-fds %q is not a count", val)
			}
			inv.PreserveFDs = n
		}
	}
	if len(pos) != 1 || pos[0] == "" {
		return nil, errors.New("create: want exactly one container ID")
	}
	inv.ID = pos[0]
	if inv.PidFile == "" {
		return nil, errors.New("create: no --pid-file, so the container's mounts cannot be checked")
	}
	return inv, nil
}
