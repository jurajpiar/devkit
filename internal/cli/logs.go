package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/jurajpiar/devkit/internal/monitor/output"
	"github.com/spf13/cobra"
)

var logsCmd = &cobra.Command{
	Use:   "logs",
	Short: "View monitoring logs",
	Long: `View monitoring logs from the daemon log files.

Log files are stored in ~/.devkit/logs/ and include:
  - devkit.log       - All events
  - performance.log  - Performance metrics
  - security.log     - Security events
  - alerts.log       - Alerts and anomalies

Examples:
  devkit logs                    # View recent logs
  devkit logs --security         # View security logs only
  devkit logs --alerts           # View alerts only
  devkit logs --since 1h         # Logs from last hour
  devkit logs --tail 50          # Last 50 log entries
  devkit logs --follow           # Follow logs (like tail -f)`,
	RunE: runLogs,
}

func init() {
	rootCmd.AddCommand(logsCmd)

	logsCmd.Flags().Bool("security", false, "Show security logs only")
	logsCmd.Flags().Bool("alerts", false, "Show alerts only")
	logsCmd.Flags().Bool("perf", false, "Show performance logs only")
	logsCmd.Flags().String("since", "", "Show logs since duration (e.g., 1h, 30m, 24h)")
	logsCmd.Flags().IntP("tail", "n", 100, "Number of recent entries to show")
	logsCmd.Flags().BoolP("follow", "f", false, "Follow logs in real-time")
	logsCmd.Flags().Bool("json", false, "Output raw JSON (no formatting)")
}

func runLogs(cmd *cobra.Command, args []string) error {
	// Determine log type
	logType := "all"
	if sec, _ := cmd.Flags().GetBool("security"); sec {
		logType = "security"
	} else if alerts, _ := cmd.Flags().GetBool("alerts"); alerts {
		logType = "alerts"
	} else if perf, _ := cmd.Flags().GetBool("perf"); perf {
		logType = "performance"
	}

	// Parse since duration
	var since time.Time
	if sinceStr, _ := cmd.Flags().GetString("since"); sinceStr != "" {
		duration, err := time.ParseDuration(sinceStr)
		if err != nil {
			return fmt.Errorf("invalid duration: %s (use format like 1h, 30m, 24h)", sinceStr)
		}
		since = time.Now().Add(-duration)
	}

	// Get limit
	limit, _ := cmd.Flags().GetInt("tail")

	// Get log directory
	homeDir, _ := os.UserHomeDir()
	logDir := filepath.Join(homeDir, ".devkit", "logs")

	// Check if log directory exists
	if _, err := os.Stat(logDir); os.IsNotExist(err) {
		fmt.Println("No logs found.")
		fmt.Println("\nLogs are created when monitoring daemon is enabled.")
		fmt.Println("Enable daemon logging in devkit.yaml:")
		fmt.Println("  monitoring:")
		fmt.Println("    outputs:")
		fmt.Println("      daemon: true")
		return nil
	}

	// Create daemon output to read logs
	daemon := output.NewDaemon(output.DaemonConfig{
		LogDir:  logDir,
		Enabled: true,
	})

	// Read logs
	events, err := daemon.ReadLogs(logType, since, limit)
	if err != nil {
		return fmt.Errorf("failed to read logs: %w", err)
	}

	if len(events) == 0 {
		fmt.Println("No logs found matching criteria.")
		return nil
	}

	// Output
	jsonOutput, _ := cmd.Flags().GetBool("json")
	cliOutput := output.NewCLI(output.CLIConfig{
		Writer:     os.Stdout,
		Enabled:    true,
		Verbose:    true,
		ShowPerf:   logType == "all" || logType == "performance",
		ShowSec:    logType == "all" || logType == "security",
		ShowAlerts: logType == "all" || logType == "alerts",
	})

	if jsonOutput {
		// Raw JSON output
		for _, event := range events {
			fmt.Printf(`{"timestamp":"%s","type":"%s","severity":"%s","message":"%s"}`,
				event.Timestamp.Format(time.RFC3339),
				event.Type,
				event.Severity,
				event.Message)
			fmt.Println()
		}
	} else {
		// Formatted table output
		cliOutput.PrintTable(events)
	}

	// Follow mode
	follow, _ := cmd.Flags().GetBool("follow")
	if follow {
		fmt.Println("\n--- Following logs (Ctrl+C to exit) ---")
		// TODO: Implement follow with file watching
		fmt.Println("Follow mode not yet implemented. Use 'tail -f ~/.devkit/logs/devkit.log'")
	}

	return nil
}
