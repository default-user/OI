// WHY: The kernel pipeline is the canonical corridor implementation.
// ONE_PATH_LAW: all side-effects go through this pipeline.
package kernel

import (
	"fmt"
	"time"

	"github.com/user/oi/kernel-go/internal/capabilities"
	"github.com/user/oi/kernel-go/internal/cdi"
	"github.com/user/oi/kernel-go/internal/cif"
)

// Request represents a user request entering the system
type Request struct {
	RawInput string
	Metadata map[string]interface{}
}

// Response represents the final response to the user
type Response struct {
	Content      string
	Success      bool
	Error        string
	AuditTrail   []string
}

// Execute runs the complete corridor pipeline: CIF → CDI → kernel → CDI → CIF
// WHY: This is THE single path to capability. No bypass allowed.
func Execute(req *Request, state *SystemState) (*Response, error) {
	auditTrail := []string{}

	// STEP 1: CIF Ingress - sanitize and label input
	auditTrail = append(auditTrail, "cif_ingress_start")
	labeledRequest, err := cif.Ingress(req.RawInput, req.Metadata)
	if err != nil {
		return &Response{
			Success: false,
			Error:   fmt.Sprintf("cif_ingress_failed: %v", err),
			AuditTrail: auditTrail,
		}, err
	}
	auditTrail = append(auditTrail, "cif_ingress_complete")

	// STEP 2: CDI Decision - judge before power
	auditTrail = append(auditTrail, "cdi_decision_start")
	decisionCtx := &cdi.DecisionContext{
		Request:         labeledRequest,
		PostureLevel:    state.PostureLevel,
		GovernanceRules: state.GovernanceCapsule.Rules,
		IntegrityState:  string(state.IntegrityState),
		ActiveConsents:  state.AuthorityCapsule.ActiveConsents,
	}

	decision, err := cdi.Decide(decisionCtx)
	if err != nil {
		return &Response{
			Success: false,
			Error:   fmt.Sprintf("cdi_decision_failed: %v", err),
			AuditTrail: auditTrail,
		}, err
	}

	// Log CDI decision
	state.AuditLedger.AppendCDIDecision(string(decision.Decision), labeledRequest.InputHash, "")
	auditTrail = append(auditTrail, fmt.Sprintf("cdi_decision: %s", decision.Decision))

	// STEP 3: Handle DENY - no tokens, no calls
	if decision.Decision == cdi.DENY {
		auditTrail = append(auditTrail, "deny_terminal")
		return &Response{
			Success: false,
			Error:   fmt.Sprintf("request denied: %s", decision.Reason),
			AuditTrail: auditTrail,
		}, nil
	}

	// STEP 4: Mint capability tokens (ALLOW or DEGRADE)
	auditTrail = append(auditTrail, "token_mint_start")
	token, err := mintToken(decision, labeledRequest, state)
	if err != nil {
		return &Response{
			Success: false,
			Error:   fmt.Sprintf("token_mint_failed: %v", err),
			AuditTrail: auditTrail,
		}, err
	}
	state.AddToken(token)
	auditTrail = append(auditTrail, "token_mint_complete")

	// STEP 5: Kernel execute - invoke adapters with token
	auditTrail = append(auditTrail, "kernel_execute_start")
	outputContent, err := kernelExecute(token, labeledRequest, state)
	if err != nil {
		return &Response{
			Success: false,
			Error:   fmt.Sprintf("kernel_execute_failed: %v", err),
			AuditTrail: auditTrail,
		}, err
	}
	auditTrail = append(auditTrail, "kernel_execute_complete")

	// STEP 6: CDI output decision - check output before egress
	auditTrail = append(auditTrail, "cdi_output_decision_start")
	outputDecision, err := cdi.DecideOutput(outputContent, labeledRequest.SensitivityLevel, state.PostureLevel)
	if err != nil || outputDecision.Decision == cdi.DENY {
		return &Response{
			Success: false,
			Error:   "output blocked by CDI",
			AuditTrail: auditTrail,
		}, nil
	}
	auditTrail = append(auditTrail, "cdi_output_decision_complete")

	// STEP 7: CIF Egress - apply leak control and redaction
	auditTrail = append(auditTrail, "cif_egress_start")
	outputArtifact := &cif.OutputArtifact{
		Content:          outputContent,
		SensitivityLevel: labeledRequest.SensitivityLevel,
		LeakBudgetUsed:   len(outputContent), // simplified
		Metadata:         map[string]interface{}{},
	}

	finalResponse, err := cif.Egress(outputArtifact, state.PostureLevel, 10000) // 10KB leak budget
	if err != nil {
		return &Response{
			Success: false,
			Error:   fmt.Sprintf("cif_egress_failed: %v", err),
			AuditTrail: auditTrail,
		}, err
	}
	auditTrail = append(auditTrail, "cif_egress_complete")

	// STEP 8: Return user response
	return &Response{
		Content:    finalResponse.Content,
		Success:    true,
		Error:      "",
		AuditTrail: auditTrail,
	}, nil
}

// mintToken creates a capability token after CDI decision
func mintToken(decision *cdi.DecisionResult, request *cif.LabeledRequest, state *SystemState) (*capabilities.Token, error) {
	scope := decision.DegradedScope
	if len(scope) == 0 {
		scope = []string{"*"} // default full scope for ALLOW
	}

	limits := capabilities.Limits{
		MaxDepth:        10,
		MaxBudget:       1000,
		WorkspaceBounds: []string{},
	}

	postureBounds := capabilities.PostureBounds{
		MinPosture: decision.RequiredPosture,
		MaxPosture: 4, // P4 is maximum
	}

	token, err := capabilities.Mint(
		"kernel",
		state.IdentityCapsule.PrincipalID,
		"adapters",
		scope,
		limits,
		5*time.Minute, // 5 minute TTL
		postureBounds,
		state.IdentityCapsule.NamespaceID,
		state.IdentityCapsule.PrincipalID,
	)

	return token, err
}

// kernelExecute invokes adapters with the capability token.
// WHY: Single chokepoint - all adapter calls go through here.
func kernelExecute(token *capabilities.Token, request *cif.LabeledRequest, state *SystemState) (string, error) {
	// Check STOP before executing
	if token.RevokedAt != nil {
		return "", fmt.Errorf("token revoked - STOP dominance")
	}

	// For now, use a mock adapter
	// In production, this would route to real model/tool adapters
	adapterName := "mock_adapter"

	params := map[string]interface{}{
		"input": request.SanitizedInput,
	}

	result, err := state.AdapterRegistry.Invoke(adapterName, token, state.PostureLevel, params)
	if err != nil {
		// Log failed attempt
		state.AuditLedger.AppendAdapterAttempt(adapterName, false, token.Digest)
		return "", err
	}

	// Log successful attempt
	state.AuditLedger.AppendAdapterAttempt(adapterName, true, token.Digest)

	// Extract content from result
	if resultMap, ok := result.(map[string]interface{}); ok {
		if message, ok := resultMap["message"].(string); ok {
			return message, nil
		}
	}

	return fmt.Sprintf("result: %v", result), nil
}
