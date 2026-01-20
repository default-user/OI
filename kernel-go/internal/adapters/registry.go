// WHY: Adapter registry enforces that all side-effects go through
// registered, capability-gated adapters. No side doors.
package adapters

import (
	"fmt"
	"sync"

	"github.com/user/oi/kernel-go/internal/capabilities"
)

// Adapter is the interface all model/tool adapters must implement.
// WHY: Uniform interface ensures capability verification at every boundary.
type Adapter interface {
	// Name returns the adapter identifier
	Name() string

	// Invoke executes the adapter's operation with a valid capability token
	// WHY: No tokenless calls - fail closed
	Invoke(token *capabilities.Token, params map[string]interface{}) (interface{}, error)

	// VerifyToken checks if the token is valid for this adapter
	VerifyToken(token *capabilities.Token, currentPosture int) error
}

// Registry manages all registered adapters.
type Registry struct {
	mu       sync.RWMutex
	adapters map[string]Adapter
}

// NewRegistry creates a new adapter registry
func NewRegistry() *Registry {
	return &Registry{
		adapters: make(map[string]Adapter),
	}
}

// Register adds an adapter to the registry.
// WHY: Explicit registration makes the attack surface enumerable.
func (r *Registry) Register(adapter Adapter) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	name := adapter.Name()
	if _, exists := r.adapters[name]; exists {
		return fmt.Errorf("adapter %s already registered", name)
	}

	r.adapters[name] = adapter
	return nil
}

// Get retrieves an adapter by name
func (r *Registry) Get(name string) (Adapter, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	adapter, exists := r.adapters[name]
	if !exists {
		return nil, fmt.Errorf("adapter %s not found", name)
	}

	return adapter, nil
}

// ListAdapters returns all registered adapter names
func (r *Registry) ListAdapters() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.adapters))
	for name := range r.adapters {
		names = append(names, name)
	}
	return names
}

// Invoke executes an adapter with capability verification.
// WHY: Central chokepoint - all adapter calls go through here.
func (r *Registry) Invoke(adapterName string, token *capabilities.Token, currentPosture int, params map[string]interface{}) (interface{}, error) {
	adapter, err := r.Get(adapterName)
	if err != nil {
		return nil, err
	}

	// Verify token before invocation
	if err := adapter.VerifyToken(token, currentPosture); err != nil {
		return nil, fmt.Errorf("token verification failed: %w", err)
	}

	// Invoke the adapter
	result, err := adapter.Invoke(token, params)
	return result, err
}
