package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/jurajpiar/devkit/internal/debugproxy"
)

func main() {
	var (
		listenAddr  = flag.String("listen", ":9229", "Address to listen on")
		targetAddr  = flag.String("target", "localhost:9230", "Target debug server address")
		filterLevel = flag.String("filter", "filtered", "Filter level: strict, filtered, audit, passthrough")
		auditLog    = flag.Bool("audit", true, "Enable audit logging")
	)
	flag.Parse()

	config := debugproxy.ProxyConfig{
		ListenAddr:  *listenAddr,
		TargetAddr:  *targetAddr,
		FilterLevel: debugproxy.MustParseFilterLevel(*filterLevel),
		AuditLog:    *auditLog,
	}

	proxy := debugproxy.NewProxy(config)

	// Handle shutdown signals
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Println("Shutting down...")
		cancel()
	}()

	log.Printf("Starting debug proxy: %s -> %s (filter: %s)", *listenAddr, *targetAddr, *filterLevel)

	if err := proxy.Start(ctx); err != nil {
		log.Fatalf("Proxy error: %v", err)
	}
}
