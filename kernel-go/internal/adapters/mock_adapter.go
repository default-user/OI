// WHY: Mock adapter for testing corridor enforcement without
// requiring real model/tool dependencies.
package adapters

import (
	"fmt"

	"github.com/user/oi/kernel-go/internal/capabilities"
)

// MockAdapter is a test adapter that records invocations
type MockAdapter struct {
	name        string
	invocations []Invocation
}

// Invocation records a single adapter call
type Invocation struct {
	TokenDigest string
	Params      map[string]interface{}
	Result      interface{}
}

// NewMockAdapter creates a new mock adapter
func NewMockAdapter(name string) *MockAdapter {
	return &MockAdapter{
		name:        name,
		invocations: []Invocation{},
	}
}

// Name returns the adapter identifier
func (m *MockAdapter) Name() string {
	return m.name
}

// Invoke executes the mock operation and records the invocation
func (m *MockAdapter) Invoke(token *capabilities.Token, params map[string]interface{}) (interface{}, error) {
	// Check for nil token
	if token == nil {
		return nil, fmt.Errorf("nil token - invoke rejected")
	}

	// Record the invocation
	result := map[string]interface{}{
		"status":  "success",
		"message": fmt.Sprintf("mock adapter %s invoked", m.name),
	}

	m.invocations = append(m.invocations, Invocation{
		TokenDigest: token.Digest,
		Params:      params,
		Result:      result,
	})

	return result, nil
}

// VerifyToken checks token validity for this adapter
// WHY: Tokenless calls are rejected - fail closed
func (m *MockAdapter) VerifyToken(token *capabilities.Token, currentPosture int) error {
	if token == nil {
		return fmt.Errorf("nil token - tokenless invocation rejected")
	}

	// Verify token is valid
	valid, err := token.Verify(currentPosture)
	if !valid {
		return fmt.Errorf("token verification failed: %w", err)
	}

	// Check if token has required scope for this adapter
	if !token.HasScope(m.name) && !token.HasScope("*") {
		return fmt.Errorf("token does not have scope for adapter %s", m.name)
	}

	return nil
}

// GetInvocations returns recorded invocations (for testing)
func (m *MockAdapter) GetInvocations() []Invocation {
	return m.invocations
}

// ResetInvocations clears the invocation history (for testing)
func (m *MockAdapter) ResetInvocations() {
	m.invocations = []Invocation{}
}
