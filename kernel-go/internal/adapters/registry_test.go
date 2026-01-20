// WHY: These tests prove corridor integrity (CI-1, CI-2).
// No adapter invocation without token, no ghost calls.
package adapters

import (
	"testing"
	"time"

	"github.com/user/oi/kernel-go/internal/capabilities"
)

// TestAdapterRefusesTokenlessInvocation proves CI-1: no tokenless calls
func TestAdapterRefusesTokenlessInvocation(t *testing.T) {
	adapter := NewMockAdapter("test_adapter")

	// Attempt to invoke with nil token - should fail
	err := adapter.VerifyToken(nil, 1)
	if err == nil {
		t.Fatal("expected error for nil token, got nil")
	}

	if err.Error() != "nil token - tokenless invocation rejected" {
		t.Fatalf("unexpected error message: %v", err)
	}
}

// TestKernelRejectsDirectAdapterCallWithoutToken proves CI-1: registry enforces tokens
func TestKernelRejectsDirectAdapterCallWithoutToken(t *testing.T) {
	registry := NewRegistry()
	adapter := NewMockAdapter("test_adapter")
	registry.Register(adapter)

	// Attempt to invoke without a valid token - should fail
	_, err := registry.Invoke("test_adapter", nil, 1, map[string]interface{}{})
	if err == nil {
		t.Fatal("expected error for nil token invocation, got nil")
	}
}

// TestEveryAdapterInvocationHasTokenDigest proves CI-2: no ghost calls
func TestEveryAdapterInvocationHasTokenDigest(t *testing.T) {
	adapter := NewMockAdapter("test_adapter")

	// Create a valid token
	token, err := capabilities.Mint(
		"test_issuer",
		"test_subject",
		"test_audience",
		[]string{"test_adapter"},
		capabilities.Limits{MaxDepth: 10, MaxBudget: 100},
		5*time.Minute,
		capabilities.PostureBounds{MinPosture: 1, MaxPosture: 4},
		"test_namespace",
		"test_principal",
	)
	if err != nil {
		t.Fatalf("failed to mint token: %v", err)
	}

	// Invoke adapter
	_, err = adapter.Invoke(token, map[string]interface{}{"test": "data"})
	if err != nil {
		t.Fatalf("adapter invocation failed: %v", err)
	}

	// Verify invocation was recorded with token digest
	invocations := adapter.GetInvocations()
	if len(invocations) != 1 {
		t.Fatalf("expected 1 invocation, got %d", len(invocations))
	}

	if invocations[0].TokenDigest != token.Digest {
		t.Fatalf("token digest mismatch: expected %s, got %s", token.Digest, invocations[0].TokenDigest)
	}
}

// TestAdapterVerifiesTokenScope proves adapters enforce scope
func TestAdapterVerifiesTokenScope(t *testing.T) {
	adapter := NewMockAdapter("test_adapter")

	// Create a token without the required scope
	token, err := capabilities.Mint(
		"test_issuer",
		"test_subject",
		"test_audience",
		[]string{"other_adapter"}, // wrong scope
		capabilities.Limits{MaxDepth: 10, MaxBudget: 100},
		5*time.Minute,
		capabilities.PostureBounds{MinPosture: 1, MaxPosture: 4},
		"test_namespace",
		"test_principal",
	)
	if err != nil {
		t.Fatalf("failed to mint token: %v", err)
	}

	// Verify should fail due to scope mismatch
	err = adapter.VerifyToken(token, 1)
	if err == nil {
		t.Fatal("expected error for scope mismatch, got nil")
	}
}

// TestAdapterVerifiesPostureBounds proves posture gating
func TestAdapterVerifiesPostureBounds(t *testing.T) {
	adapter := NewMockAdapter("test_adapter")

	// Create a token with posture bounds [2, 4]
	token, err := capabilities.Mint(
		"test_issuer",
		"test_subject",
		"test_audience",
		[]string{"test_adapter"},
		capabilities.Limits{MaxDepth: 10, MaxBudget: 100},
		5*time.Minute,
		capabilities.PostureBounds{MinPosture: 2, MaxPosture: 4},
		"test_namespace",
		"test_principal",
	)
	if err != nil {
		t.Fatalf("failed to mint token: %v", err)
	}

	// Verify should fail with posture 1 (below minimum)
	err = adapter.VerifyToken(token, 1)
	if err == nil {
		t.Fatal("expected error for posture below minimum, got nil")
	}
}

// TestRevokedTokenRejected proves STOP dominance
func TestRevokedTokenRejected(t *testing.T) {
	adapter := NewMockAdapter("test_adapter")

	token, err := capabilities.Mint(
		"test_issuer",
		"test_subject",
		"test_audience",
		[]string{"test_adapter"},
		capabilities.Limits{MaxDepth: 10, MaxBudget: 100},
		5*time.Minute,
		capabilities.PostureBounds{MinPosture: 1, MaxPosture: 4},
		"test_namespace",
		"test_principal",
	)
	if err != nil {
		t.Fatalf("failed to mint token: %v", err)
	}

	// Revoke the token
	token.Revoke()

	// Verify should fail for revoked token
	err = adapter.VerifyToken(token, 1)
	if err == nil {
		t.Fatal("expected error for revoked token, got nil")
	}
}

// TestExpiredTokenRejected proves TTL enforcement
func TestExpiredTokenRejected(t *testing.T) {
	adapter := NewMockAdapter("test_adapter")

	// Create a token with 0 TTL (already expired)
	token, err := capabilities.Mint(
		"test_issuer",
		"test_subject",
		"test_audience",
		[]string{"test_adapter"},
		capabilities.Limits{MaxDepth: 10, MaxBudget: 100},
		0, // 0 TTL - immediately expired
		capabilities.PostureBounds{MinPosture: 1, MaxPosture: 4},
		"test_namespace",
		"test_principal",
	)
	if err != nil {
		t.Fatalf("failed to mint token: %v", err)
	}

	// Small delay to ensure expiration
	time.Sleep(10 * time.Millisecond)

	// Verify should fail for expired token
	err = adapter.VerifyToken(token, 1)
	if err == nil {
		t.Fatal("expected error for expired token, got nil")
	}
}
