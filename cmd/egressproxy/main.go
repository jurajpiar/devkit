package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/jurajpiar/devkit/internal/dockerfilter"
	"github.com/jurajpiar/devkit/internal/egressproxy"
	"github.com/jurajpiar/devkit/internal/runcguard"
)

func main() {
	// The guest binary is three programs, chosen by the name it is run
	// under: provisioning links devkit-dockerfilter and devkit-runc-guard
	// to it. One binary keeps one embedded file per architecture and one
	// hash that root checks before installing it.
	switch filepath.Base(os.Args[0]) {
	case dockerfilter.ProgramName:
		os.Exit(dockerfilter.Main(os.Args[1:]))
	case runcguard.ProgramName:
		// Invoked by containerd's shim exactly as runc is.
		os.Exit(runcguard.New().Main(os.Args[1:]))
	}
	// Parse command line flags
	listenAddr := flag.String("listen", ":3128", "Address to listen on (e.g., :3128)")
	allowedHosts := flag.String("allowed", "", "Comma-separated list of allowed domains (e.g., api.example.com,*.github.com)")
	auditLog := flag.Bool("audit", false, "Enable audit logging of all requests")
	upstream := flag.String("upstream", "", "Parent proxy as ip:port; allowed requests go through it and nothing is resolved locally")
	showHelp := flag.Bool("help", false, "Show help message")
	showVersion := flag.Bool("version", false, "Show version")

	flag.Parse()

	if *showHelp {
		printUsage()
		os.Exit(0)
	}

	if *showVersion {
		fmt.Println("devkit-egressproxy v1.0.0")
		os.Exit(0)
	}

	// Parse allowed hosts
	var hosts []string
	if *allowedHosts != "" {
		hosts = strings.Split(*allowedHosts, ",")
		// Trim whitespace
		for i, h := range hosts {
			hosts[i] = strings.TrimSpace(h)
		}
	}

	if len(hosts) == 0 {
		log.Println("Warning: No allowed hosts specified. All requests will be blocked.")
		log.Println("Use -allowed flag to specify allowed domains (e.g., -allowed 'api.example.com,*.github.com')")
	}

	// Create proxy configuration
	cfg := egressproxy.ProxyConfig{
		ListenAddr:   *listenAddr,
		AllowedHosts: hosts,
		AuditLog:     *auditLog,
		Logger:       log.Default(),
		Upstream:     *upstream,
	}
	if *upstream != "" {
		if err := egressproxy.ValidateUpstream(*upstream); err != nil {
			log.Fatal(err)
		}
		log.Printf("Chained to upstream proxy %s (no local DNS)", *upstream)
	}

	// Create and start proxy
	proxy := egressproxy.NewProxy(cfg)

	log.Printf("Starting egress proxy on %s", *listenAddr)
	if len(hosts) > 0 {
		log.Printf("Allowed hosts: %v", hosts)
	}
	if *auditLog {
		log.Println("Audit logging enabled")
	}

	// Setup context with signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		log.Printf("Received signal %v, shutting down...", sig)
		cancel()
	}()

	// Start proxy (blocks until context is cancelled)
	if err := proxy.Start(ctx); err != nil && err != context.Canceled {
		log.Fatalf("Proxy error: %v", err)
	}

	// Print stats on shutdown
	stats := proxy.GetStats()
	log.Printf("Proxy stats: total=%d allowed=%d blocked=%d errors=%d",
		stats.TotalRequests, stats.AllowedRequests, stats.BlockedRequests, stats.Errors)
}

func printUsage() {
	fmt.Println(`devkit-egressproxy - HTTP/HTTPS proxy with domain filtering

Usage:
  devkit-egressproxy [flags]

Flags:
  -listen string    Address to listen on (default ":3128")
  -allowed string   Comma-separated list of allowed domains
                    Supports wildcards: *.example.com, **.example.com
  -audit            Enable audit logging of all requests
  -upstream ip:port Send allowed requests through a parent proxy; resolve nothing
  -help             Show this help message
  -version          Show version

Examples:
  # Allow only npm registry and GitHub
  devkit-egressproxy -listen :3128 -allowed 'registry.npmjs.org,*.github.com,*.githubusercontent.com'

  # Allow any subdomain of example.com
  devkit-egressproxy -allowed '*.example.com'

  # Enable audit logging
  devkit-egressproxy -allowed 'api.example.com' -audit

Wildcard Patterns:
  *.example.com     Matches immediate subdomains (api.example.com, www.example.com)
  **.example.com    Matches any depth of subdomains (a.b.c.example.com)
  *                 Matches everything (effectively disables filtering)`)
}
