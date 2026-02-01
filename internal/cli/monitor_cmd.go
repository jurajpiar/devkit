package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/jurajpiar/devkit/internal/config"
	"github.com/jurajpiar/devkit/internal/container"
	"github.com/jurajpiar/devkit/internal/monitor"
	"github.com/jurajpiar/devkit/internal/monitor/output"
	"github.com/jurajpiar/devkit/internal/monitor/perf"
	"github.com/jurajpiar/devkit/internal/monitor/security"
	"github.com/spf13/cobra"
)

var monitorCmd = &cobra.Command{
	Use:   "monitor",
	Short: "Manage monitoring daemon",
	Long: `Manage the devkit monitoring daemon.

The monitoring daemon collects performance and security metrics
in the background and writes them to log files.

Subcommands:
  start   - Start the monitoring daemon
  stop    - Stop the monitoring daemon  
  status  - Show monitoring status

Examples:
  devkit monitor start              # Start daemon
  devkit monitor start --web        # Start with web dashboard
  devkit monitor start --prometheus # Start with Prometheus metrics
  devkit monitor status             # Check if running
  devkit monitor stop               # Stop daemon`,
}

var monitorStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the monitoring daemon",
	Long: `Start the monitoring daemon in the foreground.

The daemon will collect metrics and security events and output
them according to the configured outputs.

Press Ctrl+C to stop.`,
	RunE: runMonitorStart,
}

var monitorStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the monitoring daemon",
	Long:  `Stop a running monitoring daemon.`,
	RunE:  runMonitorStop,
}

var monitorStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show monitoring status",
	Long:  `Show the current status of the monitoring system.`,
	RunE:  runMonitorStatus,
}

func init() {
	rootCmd.AddCommand(monitorCmd)
	monitorCmd.AddCommand(monitorStartCmd)
	monitorCmd.AddCommand(monitorStopCmd)
	monitorCmd.AddCommand(monitorStatusCmd)

	// Start command flags
	monitorStartCmd.Flags().Bool("web", false, "Enable web dashboard")
	monitorStartCmd.Flags().Int("web-port", 8080, "Web dashboard port")
	monitorStartCmd.Flags().Bool("prometheus", false, "Enable Prometheus metrics")
	monitorStartCmd.Flags().Int("prometheus-port", 9090, "Prometheus metrics port")
	monitorStartCmd.Flags().Bool("daemon", false, "Enable daemon logging to files")
	monitorStartCmd.Flags().Bool("anomaly", false, "Enable anomaly detection")
	monitorStartCmd.Flags().Int("interval", 5, "Collection interval in seconds")
}

func runMonitorStart(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Check podman is available
	if err := container.CheckPodman(); err != nil {
		return fmt.Errorf("podman is required but not found: %w", err)
	}

	// Load config
	configPath, _ := cmd.Flags().GetString("config")
	if configPath == "" {
		configPath = "devkit.yaml"
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Check if container is running
	mgr := container.New(cfg)
	running, _ := mgr.IsRunning(ctx)
	if !running {
		return fmt.Errorf("container %s is not running\n\nRun 'devkit start' first", cfg.ContainerName())
	}

	// Get flags
	interval, _ := cmd.Flags().GetInt("interval")
	enableWeb, _ := cmd.Flags().GetBool("web")
	webPort, _ := cmd.Flags().GetInt("web-port")
	enableProm, _ := cmd.Flags().GetBool("prometheus")
	promPort, _ := cmd.Flags().GetInt("prometheus-port")
	enableDaemon, _ := cmd.Flags().GetBool("daemon")
	enableAnomaly, _ := cmd.Flags().GetBool("anomaly")

	// Override from config
	if cfg.Monitoring.Outputs.Web {
		enableWeb = true
	}
	if cfg.Monitoring.Outputs.WebPort != 0 {
		webPort = cfg.Monitoring.Outputs.WebPort
	}
	if cfg.Monitoring.Outputs.Prometheus {
		enableProm = true
	}
	if cfg.Monitoring.Outputs.PrometheusPort != 0 {
		promPort = cfg.Monitoring.Outputs.PrometheusPort
	}
	if cfg.Monitoring.Outputs.Daemon {
		enableDaemon = true
	}
	if cfg.Monitoring.SecurityMonitoring.AnomalyDetection {
		enableAnomaly = true
	}

	// Create monitor config
	monitorCfg := monitor.DefaultConfig()
	monitorCfg.Performance.Interval = time.Duration(interval) * time.Second
	monitorCfg.Security.AnomalyDetection = enableAnomaly

	// Create monitor
	mon := monitor.New(monitorCfg)

	// Add collectors
	perfCollector := perf.New(cfg.ContainerName(), time.Duration(interval)*time.Second)
	mon.AddCollector(perfCollector)

	secCollector := security.New(cfg.ContainerName(), time.Duration(interval)*time.Second)
	mon.AddCollector(secCollector)

	// Add outputs
	// CLI output is always enabled
	cliOutput := output.NewCLI(output.CLIConfig{
		Writer:     os.Stdout,
		Enabled:    true,
		Verbose:    false,
		ShowPerf:   true,
		ShowSec:    true,
		ShowAlerts: true,
	})
	mon.AddOutput(cliOutput)

	if enableDaemon {
		homeDir, _ := os.UserHomeDir()
		daemonOutput := output.NewDaemon(output.DaemonConfig{
			LogDir:  filepath.Join(homeDir, ".devkit", "logs"),
			Enabled: true,
		})
		mon.AddOutput(daemonOutput)
		fmt.Printf("Daemon logging enabled: %s\n", filepath.Join(homeDir, ".devkit", "logs"))
	}

	if enableWeb {
		webOutput := output.NewWeb(output.WebConfig{
			Port:    webPort,
			Enabled: true,
		})
		mon.AddOutput(webOutput)
		fmt.Printf("Web dashboard enabled: http://localhost:%d\n", webPort)
	}

	if enableProm {
		promOutput := output.NewPrometheus(output.PrometheusConfig{
			Port:    promPort,
			Enabled: true,
		})
		mon.AddOutput(promOutput)
		fmt.Printf("Prometheus metrics enabled: http://localhost:%d/metrics\n", promPort)
	}

	// Set up anomaly detection
	if enableAnomaly {
		fmt.Println("Anomaly detection enabled (warming up...)")
	}

	// Handle Ctrl+C
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		fmt.Println("\nStopping monitor...")
		cancel()
	}()

	// Start monitor
	fmt.Printf("\nStarting monitor for container %s (interval: %ds)\n", cfg.ContainerName(), interval)
	fmt.Println("Press Ctrl+C to stop\n")

	if err := mon.Start(ctx); err != nil {
		return fmt.Errorf("failed to start monitor: %w", err)
	}

	// Wait for context cancellation
	<-ctx.Done()

	// Stop monitor
	mon.Stop()

	fmt.Println("Monitor stopped")
	return nil
}

func runMonitorStop(cmd *cobra.Command, args []string) error {
	// For now, monitoring runs in foreground, so this is a no-op
	// In a full implementation, this would communicate with a background daemon
	fmt.Println("Monitor is running in foreground mode.")
	fmt.Println("Press Ctrl+C in the monitor window to stop.")
	return nil
}

func runMonitorStatus(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Load config
	configPath, _ := cmd.Flags().GetString("config")
	if configPath == "" {
		configPath = "devkit.yaml"
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	fmt.Println("=== Monitoring Configuration ===")
	fmt.Printf("Enabled: %v\n", cfg.Monitoring.Enabled)
	fmt.Println()
	fmt.Println("Outputs:")
	fmt.Printf("  CLI:        %v\n", cfg.Monitoring.Outputs.CLI)
	fmt.Printf("  Daemon:     %v\n", cfg.Monitoring.Outputs.Daemon)
	fmt.Printf("  Web:        %v (port %d)\n", cfg.Monitoring.Outputs.Web, cfg.Monitoring.Outputs.WebPort)
	fmt.Printf("  Prometheus: %v (port %d)\n", cfg.Monitoring.Outputs.Prometheus, cfg.Monitoring.Outputs.PrometheusPort)
	fmt.Println()
	fmt.Println("Performance:")
	fmt.Printf("  Enabled:  %v\n", cfg.Monitoring.Performance.Enabled)
	fmt.Printf("  Interval: %ds\n", cfg.Monitoring.Performance.IntervalSeconds)
	fmt.Println()
	fmt.Println("Security:")
	fmt.Printf("  Enabled:           %v\n", cfg.Monitoring.SecurityMonitoring.Enabled)
	fmt.Printf("  Anomaly Detection: %v\n", cfg.Monitoring.SecurityMonitoring.AnomalyDetection)
	fmt.Printf("  Alert Threshold:   %s\n", cfg.Monitoring.SecurityMonitoring.AlertThreshold)
	fmt.Println()

	// Check if container is running
	mgr := container.New(cfg)
	running, _ := mgr.IsRunning(ctx)
	fmt.Printf("Container %s: ", cfg.ContainerName())
	if running {
		fmt.Println("running")
	} else {
		fmt.Println("not running")
	}

	// Check log directory
	homeDir, _ := os.UserHomeDir()
	logDir := filepath.Join(homeDir, ".devkit", "logs")
	if _, err := os.Stat(logDir); err == nil {
		fmt.Printf("\nLog directory: %s\n", logDir)
		
		// List log files
		entries, _ := os.ReadDir(logDir)
		if len(entries) > 0 {
			fmt.Println("Log files:")
			for _, entry := range entries {
				if !entry.IsDir() {
					info, _ := entry.Info()
					fmt.Printf("  - %s (%s)\n", entry.Name(), formatSize(info.Size()))
				}
			}
		}
	}

	return nil
}

func formatSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
