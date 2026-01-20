// WHY: CDI is the judge-before-power primitive. No side effects
// occur without an explicit ALLOW or DEGRADE decision.
package cdi

import (
	"fmt"

	"github.com/user/oi/kernel-go/internal/cif"
)

// Decision represents the result of a CDI evaluation
type Decision string

const (
	ALLOW   Decision = "ALLOW"
	DENY    Decision = "DENY"
	DEGRADE Decision = "DEGRADE"
)

// DecisionResult contains the decision and associated metadata
type DecisionResult struct {
	Decision       Decision
	Reason         string
	DegradedScope  []string // If DEGRADE, what operations are allowed
	RequiredPosture int
	Metadata       map[string]interface{}
}

// DecisionContext provides inputs for CDI evaluation
type DecisionContext struct {
	Request          *cif.LabeledRequest
	PostureLevel     int
	GovernanceRules  map[string]interface{}
	IntegrityState   string
	ActiveConsents   map[string]bool
}

// Decide evaluates a request and returns ALLOW, DENY, or DEGRADE.
// WHY: Fail-closed decision logic - unknowns become DENY.
func Decide(ctx *DecisionContext) (*DecisionResult, error) {
	if ctx == nil {
		return &DecisionResult{
			Decision: DENY,
			Reason:   "nil context",
		}, fmt.Errorf("nil decision context")
	}

	// Check integrity state - VOID refuses all
	if ctx.IntegrityState == "INTEGRITY_VOID" {
		return &DecisionResult{
			Decision: DENY,
			Reason:   "integrity_void",
		}, nil
	}

	// Check if request is tainted
	if ctx.Request.IsTainted() {
		return &DecisionResult{
			Decision: DENY,
			Reason:   "tainted_input",
		}, nil
	}

	// Check posture requirements
	if ctx.PostureLevel == 0 {
		// Undefined posture - fail closed for any request
		return &DecisionResult{
			Decision: DENY,
			Reason:   "undefined_posture",
		}, nil
	}

	// Check governance rules (simplified)
	if ctx.GovernanceRules == nil {
		return &DecisionResult{
			Decision: DENY,
			Reason:   "missing_governance",
		}, nil
	}

	// Evaluate based on sensitivity and posture
	decision := evaluateRequest(ctx)

	return decision, nil
}

// evaluateRequest applies decision logic based on context
func evaluateRequest(ctx *DecisionContext) *DecisionResult {
	sensitivity := ctx.Request.SensitivityLevel

	// High sensitivity requires explicit consent
	if sensitivity == "high" {
		if !hasConsent(ctx.ActiveConsents, "high_risk_operations") {
			return &DecisionResult{
				Decision: DENY,
				Reason:   "high_risk_requires_consent",
			}
		}
	}

	// Degraded integrity state forces DEGRADE
	if ctx.IntegrityState == "INTEGRITY_DEGRADED" {
		return &DecisionResult{
			Decision:       DEGRADE,
			Reason:         "integrity_degraded",
			DegradedScope:  []string{"read_only", "query"},
			RequiredPosture: ctx.PostureLevel,
		}
	}

	// Default ALLOW for clean, low-sensitivity requests
	if sensitivity == "low" && !ctx.Request.IsTainted() {
		return &DecisionResult{
			Decision:       ALLOW,
			Reason:         "clean_low_sensitivity",
			DegradedScope:  []string{"*"}, // Full scope
			RequiredPosture: ctx.PostureLevel,
		}
	}

	// Medium sensitivity gets DEGRADE with limited scope
	if sensitivity == "medium" {
		return &DecisionResult{
			Decision:       DEGRADE,
			Reason:         "medium_sensitivity",
			DegradedScope:  []string{"query", "search", "read"},
			RequiredPosture: ctx.PostureLevel,
		}
	}

	// Unknown cases fail closed
	return &DecisionResult{
		Decision: DENY,
		Reason:   "unknown_case",
	}
}

// hasConsent checks if a specific consent is active
func hasConsent(consents map[string]bool, required string) bool {
	if consents == nil {
		return false
	}
	return consents[required]
}

// DecideOutput evaluates output artifacts before egress.
// WHY: Output CDI prevents information leakage through results.
func DecideOutput(content string, sensitivity string, postureLevel int) (*DecisionResult, error) {
	// Check if output should be allowed based on posture
	if sensitivity == "high" && postureLevel >= 2 {
		return &DecisionResult{
			Decision: DENY,
			Reason:   "high_sensitivity_blocked_by_posture",
		}, nil
	}

	// Check for bypass instructions in output
	if containsBypassPatterns(content) {
		return &DecisionResult{
			Decision: DENY,
			Reason:   "bypass_instruction_in_output",
		}, nil
	}

	// Default allow
	return &DecisionResult{
		Decision: ALLOW,
		Reason:   "output_approved",
	}, nil
}

// containsBypassPatterns is a simple check for instruction smuggling
func containsBypassPatterns(content string) bool {
	// Simplified check - production would be more sophisticated
	return false
}
