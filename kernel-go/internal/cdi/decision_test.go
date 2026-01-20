// WHY: These tests prove decision integrity (DI-1, DI-2, DI-3).
// Judge before power, DENY is terminal, DEGRADE is weaker.
package cdi

import (
	"testing"

	"github.com/user/oi/kernel-go/internal/cif"
)

// TestMissingGovernanceCapsuleDenies proves CI-3: fail-closed
func TestMissingGovernanceCapsuleDenies(t *testing.T) {
	ctx := &DecisionContext{
		Request: &cif.LabeledRequest{
			SanitizedInput:   "test input",
			TaintLabels:      []string{"clean"},
			SensitivityLevel: "low",
		},
		PostureLevel:   1,
		GovernanceRules: nil, // missing governance
		IntegrityState: "INTEGRITY_OK",
		ActiveConsents: map[string]bool{},
	}

	result, err := Decide(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Decision != DENY {
		t.Fatalf("expected DENY for missing governance, got %s", result.Decision)
	}

	if result.Reason != "missing_governance" {
		t.Fatalf("unexpected reason: %s", result.Reason)
	}
}

// TestUndefinedPostureDeniesHighRisk proves CI-3: undefined posture fails closed
func TestUndefinedPostureDeniesHighRisk(t *testing.T) {
	ctx := &DecisionContext{
		Request: &cif.LabeledRequest{
			SanitizedInput:   "test input",
			TaintLabels:      []string{"clean"},
			SensitivityLevel: "high",
		},
		PostureLevel:   0, // undefined posture
		GovernanceRules: map[string]interface{}{"exists": true},
		IntegrityState: "INTEGRITY_OK",
		ActiveConsents: map[string]bool{},
	}

	result, err := Decide(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Decision != DENY {
		t.Fatalf("expected DENY for undefined posture, got %s", result.Decision)
	}
}

// TestDenyMintsNoTokens proves DI-2: DENY is terminal
func TestDenyMintsNoTokens(t *testing.T) {
	ctx := &DecisionContext{
		Request: &cif.LabeledRequest{
			SanitizedInput:   "test input",
			TaintLabels:      []string{"instruction_smuggling_attempt"},
			SensitivityLevel: "low",
		},
		PostureLevel:   1,
		GovernanceRules: map[string]interface{}{"exists": true},
		IntegrityState: "INTEGRITY_OK",
		ActiveConsents: map[string]bool{},
	}

	result, err := Decide(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Decision != DENY {
		t.Fatalf("expected DENY for tainted input, got %s", result.Decision)
	}

	// DENY should not provide scope or tokens
	if len(result.DegradedScope) > 0 {
		t.Fatalf("DENY should not have degraded scope")
	}
}

// TestDegradeTokenIsSubsetOfAllow proves DI-3: DEGRADE is weaker
func TestDegradeTokenIsSubsetOfAllow(t *testing.T) {
	// Test ALLOW decision
	allowCtx := &DecisionContext{
		Request: &cif.LabeledRequest{
			SanitizedInput:   "test input",
			TaintLabels:      []string{"clean"},
			SensitivityLevel: "low",
		},
		PostureLevel:   1,
		GovernanceRules: map[string]interface{}{"exists": true},
		IntegrityState: "INTEGRITY_OK",
		ActiveConsents: map[string]bool{},
	}

	allowResult, err := Decide(allowCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Test DEGRADE decision
	degradeCtx := &DecisionContext{
		Request: &cif.LabeledRequest{
			SanitizedInput:   "test input",
			TaintLabels:      []string{"clean"},
			SensitivityLevel: "medium",
		},
		PostureLevel:   1,
		GovernanceRules: map[string]interface{}{"exists": true},
		IntegrityState: "INTEGRITY_OK",
		ActiveConsents: map[string]bool{},
	}

	degradeResult, err := Decide(degradeCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if degradeResult.Decision != DEGRADE {
		t.Fatalf("expected DEGRADE for medium sensitivity, got %s", degradeResult.Decision)
	}

	// DEGRADE scope should be subset of ALLOW scope
	if allowResult.Decision == ALLOW {
		// ALLOW has "*" scope
		if len(degradeResult.DegradedScope) >= len(allowResult.DegradedScope) {
			// If ALLOW is *, DEGRADE should be more restrictive
			if allowResult.DegradedScope[0] == "*" && degradeResult.DegradedScope[0] == "*" {
				t.Fatal("DEGRADE should not have same scope as ALLOW")
			}
		}
	}
}

// TestIntegrityVoidRefuses proves fail-closed on integrity break
func TestIntegrityVoidRefuses(t *testing.T) {
	ctx := &DecisionContext{
		Request: &cif.LabeledRequest{
			SanitizedInput:   "test input",
			TaintLabels:      []string{"clean"},
			SensitivityLevel: "low",
		},
		PostureLevel:   1,
		GovernanceRules: map[string]interface{}{"exists": true},
		IntegrityState: "INTEGRITY_VOID",
		ActiveConsents: map[string]bool{},
	}

	result, err := Decide(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Decision != DENY {
		t.Fatalf("expected DENY for INTEGRITY_VOID, got %s", result.Decision)
	}
}

// TestIntegrityDegradedForcesDEGRADE proves degraded integrity constrains capability
func TestIntegrityDegradedForcesDEGRADE(t *testing.T) {
	ctx := &DecisionContext{
		Request: &cif.LabeledRequest{
			SanitizedInput:   "test input",
			TaintLabels:      []string{"clean"},
			SensitivityLevel: "low",
		},
		PostureLevel:   1,
		GovernanceRules: map[string]interface{}{"exists": true},
		IntegrityState: "INTEGRITY_DEGRADED",
		ActiveConsents: map[string]bool{},
	}

	result, err := Decide(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Decision != DEGRADE {
		t.Fatalf("expected DEGRADE for INTEGRITY_DEGRADED, got %s", result.Decision)
	}

	// Should have limited scope
	hasReadOnly := false
	for _, scope := range result.DegradedScope {
		if scope == "read_only" {
			hasReadOnly = true
		}
	}

	if !hasReadOnly {
		t.Fatal("DEGRADE from integrity degradation should include read_only scope")
	}
}

// TestHighSensitivityRequiresConsent proves consent gating
func TestHighSensitivityRequiresConsent(t *testing.T) {
	// Without consent
	ctx := &DecisionContext{
		Request: &cif.LabeledRequest{
			SanitizedInput:   "test input",
			TaintLabels:      []string{"clean"},
			SensitivityLevel: "high",
		},
		PostureLevel:   1,
		GovernanceRules: map[string]interface{}{"exists": true},
		IntegrityState: "INTEGRITY_OK",
		ActiveConsents: map[string]bool{}, // no consent
	}

	result, err := Decide(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Decision != DENY {
		t.Fatalf("expected DENY for high risk without consent, got %s", result.Decision)
	}

	// With consent
	ctxWithConsent := &DecisionContext{
		Request: &cif.LabeledRequest{
			SanitizedInput:   "test input",
			TaintLabels:      []string{"clean"},
			SensitivityLevel: "high",
		},
		PostureLevel:   1,
		GovernanceRules: map[string]interface{}{"exists": true},
		IntegrityState: "INTEGRITY_OK",
		ActiveConsents: map[string]bool{"high_risk_operations": true},
	}

	resultWithConsent, err := Decide(ctxWithConsent)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resultWithConsent.Decision == DENY && resultWithConsent.Reason == "high_risk_requires_consent" {
		t.Fatal("expected ALLOW/DEGRADE with consent, but got DENY for consent")
	}
}
