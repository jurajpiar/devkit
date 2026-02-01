package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jurajpiar/devkit/internal/config"
	"github.com/jurajpiar/devkit/internal/container"
	"github.com/jurajpiar/devkit/internal/monitor/output"
	"github.com/jurajpiar/devkit/internal/monitor/perf"
	"github.com/spf13/cobra"
)

var statsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show container performance statistics",
	Long: `Display live performance statistics for the running container.

Shows CPU, memory, network I/O, and process count.

Examples:
  devkit stats           # Show current stats
  devkit stats --watch   # Continuously update stats
  devkit stats -w -i 2   # Update every 2 seconds`,
	RunE: runStats,
}

func init() {
	rootCmd.AddCommand(statsCmd)

	statsCmd.Flags().BoolP("watch", "w", false, "Continuously update stats")
	statsCmd.Flags().IntP("interval", "i", 2, "Update interval in seconds (for --watch)")
	statsCmd.Flags().Bool("json", false, "Output in JSON format")
}

func runStats(cmd *cobra.Command, args []string) error {
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

	// Create performance collector
	interval, _ := cmd.Flags().GetInt("interval")
	collector := perf.New(cfg.ContainerName(), time.Duration(interval)*time.Second)

	// Create CLI output
	cliOutput := output.NewCLI(output.DefaultCLIConfig())

	watch, _ := cmd.Flags().GetBool("watch")
	jsonOutput, _ := cmd.Flags().GetBool("json")

	if watch {
		return runWatchStats(ctx, collector, cliOutput, time.Duration(interval)*time.Second, jsonOutput)
	}

	// Single stats fetch
	stats := collector.GetLastStats()
	if stats == nil {
		// Collect once
		_, err := collector.Collect(ctx)
		if err != nil {
			return fmt.Errorf("failed to collect stats: %w", err)
		}
		stats = collector.GetLastStats()
	}

	if stats == nil {
		return fmt.Errorf("failed to get stats for container %s", cfg.ContainerName())
	}

	if jsonOutput {
		fmt.Printf(`{"cpu_percent":%.2f,"mem_percent":%.2f,"mem_usage":%d,"mem_limit":%d,"net_input":%d,"net_output":%d,"pids":%d}`,
			stats.CPUPercent, stats.MemPercent, stats.MemUsage, stats.MemLimit,
			stats.NetInput, stats.NetOutput, stats.PIDs)
		fmt.Println()
		return nil
	}

	cliOutput.PrintStats(map[string]interface{}{
		"cpu_percent": stats.CPUPercent,
		"mem_percent": stats.MemPercent,
		"mem_usage":   stats.MemUsage,
		"mem_limit":   stats.MemLimit,
		"net_input":   stats.NetInput,
		"net_output":  stats.NetOutput,
		"pids":        stats.PIDs,
	})

	return nil
}

func runWatchStats(ctx context.Context, collector *perf.Collector, cliOutput *output.CLIOutput, interval time.Duration, jsonOutput bool) error {
	// Handle Ctrl+C
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		cancel()
	}()

	// Clear screen
	if !jsonOutput {
		fmt.Print("\033[2J\033[H\033[?25l") // Clear, home, hide cursor
		defer fmt.Print("\033[?25h")         // Show cursor on exit
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			_, err := collector.Collect(ctx)
			if err != nil {
				continue
			}

			stats := collector.GetLastStats()
			if stats == nil {
				continue
			}

			if jsonOutput {
				fmt.Printf(`{"cpu_percent":%.2f,"mem_percent":%.2f,"mem_usage":%d,"mem_limit":%d,"net_input":%d,"net_output":%d,"pids":%d,"timestamp":"%s"}`,
					stats.CPUPercent, stats.MemPercent, stats.MemUsage, stats.MemLimit,
					stats.NetInput, stats.NetOutput, stats.PIDs, time.Now().Format(time.RFC3339))
				fmt.Println()
			} else {
				// Move cursor to top
				fmt.Print("\033[H")
				fmt.Printf("=== Container Stats (updated %s) ===\n\n", time.Now().Format("15:04:05"))
				cliOutput.PrintStats(map[string]interface{}{
					"cpu_percent": stats.CPUPercent,
					"mem_percent": stats.MemPercent,
					"mem_usage":   stats.MemUsage,
					"mem_limit":   stats.MemLimit,
					"net_input":   stats.NetInput,
					"net_output":  stats.NetOutput,
					"pids":        stats.PIDs,
				})
				fmt.Println("Press Ctrl+C to exit")
			}
		}
	}
}
