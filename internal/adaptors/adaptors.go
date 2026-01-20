package adapters

import (
	"errors"
	"kernel-go/internal/capabilities"
	"time"
)

// WHY: All external I/O must go through adapters, and adapters must be token-gated.

type Adapter interface {
	Name() string
	Verify(capability_token capabilities.CapabilityToken, posture_level string) error
	InvokeModel(capability_token capabilities.CapabilityToken, input []byte) ([]byte, error)
}

type NoopModelAdapter struct{}

func (n NoopModelAdapter) Name() string { return "noop-model" }

func (n NoopModelAdapter) Verify(capability_token capabilities.CapabilityToken, posture_level string) error {
	now := time.Now().UTC()
	if capability_token.IsRevoked() {
		return errors.New("TOKEN_REVOKED")
	}
	if capability_token.IsExpired(now) {
		return errors.New("TOKEN_EXPIRED")
	}
	// Stub does not implement posture comparisons; production code must enforce posture bounds.
	return nil
}

func (n NoopModelAdapter) InvokeModel(capability_token capabilities.CapabilityToken, input []byte) ([]byte, error) {
	if err := n.Verify(capability_token, ""); err != nil {
		return nil, err
	}
	// No-op: returns the input unchanged.
	return input, nil
}
