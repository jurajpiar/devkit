package cli

import (
	"fmt"
	"strings"
)

// Progress tracks and displays step-based progress
type Progress struct {
	total   int
	current int
	prefix  string
}

// NewProgress creates a new progress tracker
func NewProgress(total int) *Progress {
	return &Progress{
		total:   total,
		current: 0,
		prefix:  "",
	}
}

// SetPrefix sets a prefix for all progress messages (e.g., "[Phase 1/2] ")
func (p *Progress) SetPrefix(prefix string) {
	p.prefix = prefix
}

// Step advances to the next step and prints the message
func (p *Progress) Step(message string) {
	p.current++
	fmt.Printf("%s[%d/%d] %s\n", p.prefix, p.current, p.total, message)
}

// StepWithSpinner shows a step with a visual indicator (for longer operations)
func (p *Progress) StepWithSpinner(message string) {
	p.current++
	fmt.Printf("%s[%d/%d] %s...\n", p.prefix, p.current, p.total, message)
}

// SubStep prints a sub-step message (indented)
func (p *Progress) SubStep(message string) {
	fmt.Printf("       %s\n", message)
}

// Warn prints a warning message
func (p *Progress) Warn(message string) {
	fmt.Printf("       ⚠ %s\n", message)
}

// Success prints a success message for the current step
func (p *Progress) Success(message string) {
	fmt.Printf("       ✓ %s\n", message)
}

// Skip prints a skip message
func (p *Progress) Skip(message string) {
	fmt.Printf("       → Skipped: %s\n", message)
}

// Done prints a completion message with a summary
func (p *Progress) Done(message string) {
	fmt.Println()
	fmt.Println(strings.Repeat("─", 40))
	fmt.Printf("✓ %s\n", message)
	fmt.Println(strings.Repeat("─", 40))
}

// Error prints an error message
func (p *Progress) Error(message string) {
	fmt.Printf("       ✗ %s\n", message)
}
