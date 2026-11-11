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
	inv := &Invocation{}
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
