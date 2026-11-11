package dockerfilter

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"
)

// ProgramName is the name the guest binary runs the filter under.
const ProgramName = "devkit-dockerfilter"

// Main runs the filter as devkit-dockerfilter. systemd passes the
// listening socket (socket activation); -listen names one instead, for
// tests.
func Main(args []string) int {
	fs := flag.NewFlagSet("devkit-dockerfilter", flag.ContinueOnError)
	config := fs.String("config", DefaultConfigPath, "the filter's settings")
	listen := fs.String("listen", "", "a Unix socket path to listen on, instead of the socket systemd passes")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	logger := log.New(os.Stderr, "", 0)
	cfg, err := LoadConfig(*config)
	if err != nil {
		logger.Printf("devkit-dockerfilter: %v", err)
		return 1
	}
	var ln net.Listener
	if *listen != "" {
		ln, err = net.Listen("unix", *listen)
	} else {
		ln, err = systemdListener()
	}
	if err != nil {
		logger.Printf("devkit-dockerfilter: %v", err)
		return 1
	}
	srv := &http.Server{
		Handler:           New(cfg, logger),
		ReadHeaderTimeout: 30 * time.Second,
		ErrorLog:          logger,
	}
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Printf("devkit-dockerfilter: %v", err)
		return 1
	}
	return 0
}

// systemdListener takes the one socket systemd passes (fd 3).
func systemdListener() (net.Listener, error) {
	pid, _ := strconv.Atoi(os.Getenv("LISTEN_PID"))
	n, _ := strconv.Atoi(os.Getenv("LISTEN_FDS"))
	os.Unsetenv("LISTEN_PID")
	os.Unsetenv("LISTEN_FDS")
	os.Unsetenv("LISTEN_FDNAMES")
	if pid != os.Getpid() || n != 1 {
		return nil, fmt.Errorf("no socket from systemd (LISTEN_PID=%d LISTEN_FDS=%d); use -listen", pid, n)
	}
	f := os.NewFile(3, "devkit-dockerfilter.socket")
	defer f.Close()
	return net.FileListener(f)
}
