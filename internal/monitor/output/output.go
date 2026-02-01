// Package output provides output backends for the monitoring system.
package output

import (
	"github.com/jurajpiar/devkit/internal/monitor"
)

// Registry holds registered output backends
type Registry struct {
	outputs map[string]monitor.Output
}

// NewRegistry creates a new output registry
func NewRegistry() *Registry {
	return &Registry{
		outputs: make(map[string]monitor.Output),
	}
}

// Register adds an output to the registry
func (r *Registry) Register(output monitor.Output) {
	r.outputs[output.Name()] = output
}

// Get returns an output by name
func (r *Registry) Get(name string) (monitor.Output, bool) {
	o, ok := r.outputs[name]
	return o, ok
}

// GetEnabled returns all enabled outputs
func (r *Registry) GetEnabled() []monitor.Output {
	enabled := make([]monitor.Output, 0)
	for _, o := range r.outputs {
		if o.Enabled() {
			enabled = append(enabled, o)
		}
	}
	return enabled
}

// All returns all registered outputs
func (r *Registry) All() []monitor.Output {
	all := make([]monitor.Output, 0, len(r.outputs))
	for _, o := range r.outputs {
		all = append(all, o)
	}
	return all
}
