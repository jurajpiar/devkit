package output

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/jurajpiar/devkit/internal/monitor"
)

const (
	// DefaultMaxFileSize is the maximum log file size before rotation (10MB)
	DefaultMaxFileSize = 10 * 1024 * 1024
	// DefaultMaxFiles is the maximum number of rotated log files to keep
	DefaultMaxFiles = 5
)

// DaemonOutput writes events to log files with rotation
type DaemonOutput struct {
	logDir      string
	enabled     bool
	mu          sync.Mutex
	file        *os.File
	currentSize int64
	maxFileSize int64
	maxFiles    int
	
	// Separate files for different event types
	perfFile     *os.File
	securityFile *os.File
	alertFile    *os.File
}

// DaemonConfig holds daemon output configuration
type DaemonConfig struct {
	LogDir      string
	Enabled     bool
	MaxFileSize int64
	MaxFiles    int
}

// DefaultDaemonConfig returns default daemon configuration
func DefaultDaemonConfig() DaemonConfig {
	homeDir, _ := os.UserHomeDir()
	return DaemonConfig{
		LogDir:      filepath.Join(homeDir, ".devkit", "logs"),
		Enabled:     false, // Disabled by default
		MaxFileSize: DefaultMaxFileSize,
		MaxFiles:    DefaultMaxFiles,
	}
}

// NewDaemon creates a new daemon output
func NewDaemon(cfg DaemonConfig) *DaemonOutput {
	if cfg.LogDir == "" {
		homeDir, _ := os.UserHomeDir()
		cfg.LogDir = filepath.Join(homeDir, ".devkit", "logs")
	}
	if cfg.MaxFileSize == 0 {
		cfg.MaxFileSize = DefaultMaxFileSize
	}
	if cfg.MaxFiles == 0 {
		cfg.MaxFiles = DefaultMaxFiles
	}

	return &DaemonOutput{
		logDir:      cfg.LogDir,
		enabled:     cfg.Enabled,
		maxFileSize: cfg.MaxFileSize,
		maxFiles:    cfg.MaxFiles,
	}
}

// Name returns the output's identifier
func (d *DaemonOutput) Name() string {
	return "daemon"
}

// Enabled returns whether this output is enabled
func (d *DaemonOutput) Enabled() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.enabled
}

// SetEnabled enables or disables the output
func (d *DaemonOutput) SetEnabled(enabled bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.enabled = enabled
}

// Start initializes the output and creates log files
func (d *DaemonOutput) Start(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.enabled {
		return nil
	}

	// Create log directory
	if err := os.MkdirAll(d.logDir, 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}

	// Open main log file
	var err error
	d.file, err = d.openLogFile("devkit.log")
	if err != nil {
		return err
	}

	// Open specialized log files
	d.perfFile, err = d.openLogFile("performance.log")
	if err != nil {
		return err
	}

	d.securityFile, err = d.openLogFile("security.log")
	if err != nil {
		return err
	}

	d.alertFile, err = d.openLogFile("alerts.log")
	if err != nil {
		return err
	}

	return nil
}

// Stop closes all log files
func (d *DaemonOutput) Stop() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	var errs []error
	
	if d.file != nil {
		if err := d.file.Close(); err != nil {
			errs = append(errs, err)
		}
		d.file = nil
	}
	
	if d.perfFile != nil {
		if err := d.perfFile.Close(); err != nil {
			errs = append(errs, err)
		}
		d.perfFile = nil
	}
	
	if d.securityFile != nil {
		if err := d.securityFile.Close(); err != nil {
			errs = append(errs, err)
		}
		d.securityFile = nil
	}
	
	if d.alertFile != nil {
		if err := d.alertFile.Close(); err != nil {
			errs = append(errs, err)
		}
		d.alertFile = nil
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors closing log files: %v", errs)
	}
	return nil
}

// Write sends an event to the appropriate log file(s)
func (d *DaemonOutput) Write(event monitor.Event) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.enabled {
		return nil
	}

	// Format as JSON line
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}
	line := append(data, '\n')

	// Write to main log
	if d.file != nil {
		if err := d.writeLine(d.file, "devkit.log", line); err != nil {
			return err
		}
	}

	// Write to specialized log based on event type
	switch event.Type {
	case monitor.EventTypePerformance, monitor.EventTypeResource:
		if d.perfFile != nil {
			d.writeLine(d.perfFile, "performance.log", line)
		}
	case monitor.EventTypeSecurity, monitor.EventTypeNetwork,
		monitor.EventTypeFileAccess, monitor.EventTypeProcess,
		monitor.EventTypeCapability, monitor.EventTypeBlocked,
		monitor.EventTypeCDP, monitor.EventTypeAudit:
		if d.securityFile != nil {
			d.writeLine(d.securityFile, "security.log", line)
		}
	case monitor.EventTypeAlert, monitor.EventTypeAnomaly:
		if d.alertFile != nil {
			d.writeLine(d.alertFile, "alerts.log", line)
		}
	}

	return nil
}

// writeLine writes a line to a file and handles rotation
func (d *DaemonOutput) writeLine(file *os.File, name string, line []byte) error {
	n, err := file.Write(line)
	if err != nil {
		return err
	}

	d.currentSize += int64(n)

	// Check if rotation is needed
	if d.currentSize >= d.maxFileSize {
		d.rotateFile(file, name)
	}

	return nil
}

// rotateFile rotates a log file
func (d *DaemonOutput) rotateFile(file *os.File, name string) error {
	file.Close()

	basePath := filepath.Join(d.logDir, name)

	// Remove oldest file if needed
	oldestPath := fmt.Sprintf("%s.%d", basePath, d.maxFiles)
	os.Remove(oldestPath)

	// Rotate existing files
	for i := d.maxFiles - 1; i >= 1; i-- {
		oldPath := fmt.Sprintf("%s.%d", basePath, i)
		newPath := fmt.Sprintf("%s.%d", basePath, i+1)
		os.Rename(oldPath, newPath)
	}

	// Rename current file
	os.Rename(basePath, fmt.Sprintf("%s.1", basePath))

	// Open new file
	newFile, err := d.openLogFile(name)
	if err != nil {
		return err
	}

	// Update the appropriate file pointer
	switch name {
	case "devkit.log":
		d.file = newFile
	case "performance.log":
		d.perfFile = newFile
	case "security.log":
		d.securityFile = newFile
	case "alerts.log":
		d.alertFile = newFile
	}

	d.currentSize = 0
	return nil
}

// openLogFile opens a log file for appending
func (d *DaemonOutput) openLogFile(name string) (*os.File, error) {
	path := filepath.Join(d.logDir, name)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file %s: %w", path, err)
	}
	return file, nil
}

// GetLogDir returns the log directory path
func (d *DaemonOutput) GetLogDir() string {
	return d.logDir
}

// ReadLogs reads events from a log file
func (d *DaemonOutput) ReadLogs(logType string, since time.Time, limit int) ([]monitor.Event, error) {
	var filename string
	switch logType {
	case "performance", "perf":
		filename = "performance.log"
	case "security", "sec":
		filename = "security.log"
	case "alerts", "alert":
		filename = "alerts.log"
	default:
		filename = "devkit.log"
	}

	path := filepath.Join(d.logDir, filename)
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []monitor.Event{}, nil
		}
		return nil, err
	}
	defer file.Close()

	var events []monitor.Event
	decoder := json.NewDecoder(file)

	for {
		var event monitor.Event
		if err := decoder.Decode(&event); err != nil {
			break // EOF or error
		}

		// Filter by time
		if !since.IsZero() && event.Timestamp.Before(since) {
			continue
		}

		events = append(events, event)

		// Apply limit
		if limit > 0 && len(events) >= limit {
			break
		}
	}

	return events, nil
}

// CleanOldLogs removes log files older than the specified duration
func (d *DaemonOutput) CleanOldLogs(maxAge time.Duration) error {
	entries, err := os.ReadDir(d.logDir)
	if err != nil {
		return err
	}

	cutoff := time.Now().Add(-maxAge)

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		if info.ModTime().Before(cutoff) {
			path := filepath.Join(d.logDir, entry.Name())
			os.Remove(path)
		}
	}

	return nil
}
