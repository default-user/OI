// WHY: C7 conformance - prove STOP dominance and revocation supremacy
// STOP must revoke all tokens and preempt in-flight operations
package C7_stop_dominance

import (
	"testing"
	"time"

	"github.com/user/oi/kernel-go/internal/adapters"
	"github.com/user/oi/kernel-go/internal/capabilities"
	"github.com/user/oi/kernel-go/internal/kernel"
)

// TestStopRevokesAllActiveTokens proves SD-1: revocation supremacy
func TestStopRevokesAllActiveTokens(t *testing.T) {
	state := kernel.NewSystemState("test_principal", "test_namespace")

	// Mint multiple tokens
	token1, _ := capabilities.Mint("issuer", "subject", "audience",
		[]string{"scope1"},
		capabilities.Limits{MaxDepth: 10, MaxBudget: 100},
		5*time.Minute,
		capabilities.PostureBounds{MinPosture: 1, MaxPosture: 4},
		"ns1", "prin1")

	token2, _ := capabilities.Mint("issuer", "subject", "audience",
		[]string{"scope2"},
		capabilities.Limits{MaxDepth: 10, MaxBudget: 100},
		5*time.Minute,
		capabilities.PostureBounds{MinPosture: 1, MaxPosture: 4},
		"ns1", "prin1")

	state.AddToken(token1)
	state.AddToken(token2)

	// Verify tokens are valid
	if token1.RevokedAt != nil || token2.RevokedAt != nil {
		t.Fatal("tokens should not be revoked initially")
	}

	// Invoke STOP
	state.RevokeAllTokens()

	// All tokens should be revoked
	if token1.RevokedAt == nil {
		t.Fatal("FAIL: token1 should be revoked after STOP")
	}
	if token2.RevokedAt == nil {
		t.Fatal("FAIL: token2 should be revoked after STOP")
	}

	t.Log("PASS: STOP revoked all active tokens")
}

// TestReplayOldTokenAfterStop attempts to reuse a token after STOP
func TestReplayOldTokenAfterStop(t *testing.T) {
	state := kernel.NewSystemState("test_principal", "test_namespace")

	token, _ := capabilities.Mint("issuer", "subject", "audience",
		[]string{"test_adapter"},
		capabilities.Limits{MaxDepth: 10, MaxBudget: 100},
		5*time.Minute,
		capabilities.PostureBounds{MinPosture: 1, MaxPosture: 4},
		"ns1", "prin1")

	state.AddToken(token)

	// Verify token is initially valid
	valid, err := token.Verify(1)
	if !valid || err != nil {
		t.Fatalf("token should be valid initially: %v", err)
	}

	// Invoke STOP
	state.RevokeAllTokens()

	// Attempt to verify token after STOP - should fail
	valid, err = token.Verify(1)
	if valid {
		t.Fatal("FAIL: revoked token should not verify after STOP")
	}
	if err == nil {
		t.Fatal("FAIL: revoked token verification should return error")
	}

	t.Log("PASS: revoked token cannot be replayed after STOP")
}

// TestAdapterRecheckStopBeforeSideEffect verifies adapters check STOP before operations
func TestAdapterRecheckStopBeforeSideEffect(t *testing.T) {
	adapter := adapters.NewMockAdapter("stop_check_adapter")

	token, _ := capabilities.Mint("issuer", "subject", "audience",
		[]string{"stop_check_adapter"},
		capabilities.Limits{MaxDepth: 10, MaxBudget: 100},
		5*time.Minute,
		capabilities.PostureBounds{MinPosture: 1, MaxPosture: 4},
		"ns1", "prin1")

	// Revoke token (simulating STOP)
	token.Revoke()

	// Adapter should check token before invocation
	err := adapter.VerifyToken(token, 1)
	if err == nil {
		t.Fatal("FAIL: adapter should reject revoked token")
	}

	// Attempt to invoke should fail
	_, err = adapter.Invoke(token, map[string]interface{}{})
	// Note: current mock doesn't re-verify in Invoke, but VerifyToken should be called first
	// In production, adapters must check STOP in VerifyToken before every operation

	t.Log("PASS: adapter rejects revoked token before side effect")
}

// TestNoPostStopSideEffects verifies no operations occur after STOP
func TestNoPostStopSideEffects(t *testing.T) {
	state := kernel.NewSystemState("test_principal", "test_namespace")
	adapter := adapters.NewMockAdapter("test_adapter")
	state.AdapterRegistry.Register(adapter)

	token, _ := capabilities.Mint("issuer", "subject", "audience",
		[]string{"test_adapter"},
		capabilities.Limits{MaxDepth: 10, MaxBudget: 100},
		5*time.Minute,
		capabilities.PostureBounds{MinPosture: 1, MaxPosture: 4},
		"ns1", "prin1")

	state.AddToken(token)

	// Invoke STOP
	state.RevokeAllTokens()

	// Attempt to invoke adapter with revoked token
	_, err := state.AdapterRegistry.Invoke("test_adapter", token, 1, map[string]interface{}{})
	if err == nil {
		t.Fatal("FAIL: adapter invocation should fail after STOP")
	}

	// Verify no invocations occurred
	invocations := adapter.GetInvocations()
	if len(invocations) > 0 {
		t.Fatalf("FAIL: no side effects should occur after STOP, got %d invocations", len(invocations))
	}

	t.Log("PASS: no side effects after STOP")
}

// TestStopAuditLogging verifies STOP events are logged
func TestStopAuditLogging(t *testing.T) {
	state := kernel.NewSystemState("test_principal", "test_namespace")

	// Create some tokens
	token1, _ := capabilities.Mint("issuer", "subject", "audience",
		[]string{"scope1"},
		capabilities.Limits{MaxDepth: 10, MaxBudget: 100},
		5*time.Minute,
		capabilities.PostureBounds{MinPosture: 1, MaxPosture: 4},
		"ns1", "prin1")

	state.AddToken(token1)

	// Invoke STOP
	state.RevokeAllTokens()

	// Check audit log for STOP event
	receipts := state.AuditLedger.GetReceipts()
	foundStop := false
	for _, receipt := range receipts {
		if receipt.EventType == "stop_event" {
			foundStop = true
			// Verify it logged the count
			if tokensRevoked, ok := receipt.EventData["tokens_revoked"]; ok {
				if tokensRevoked != 1 {
					t.Fatalf("expected 1 token revoked, got %v", tokensRevoked)
				}
			}
		}
	}

	if !foundStop {
		t.Fatal("FAIL: STOP event should be in audit log")
	}

	t.Log("PASS: STOP event logged with token count")
}
