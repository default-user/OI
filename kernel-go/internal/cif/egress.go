// WHY: CIF egress prevents unauthorized information leakage through
// leak budgets and redaction.
package cif

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// OutputArtifact represents processed output ready for egress control
type OutputArtifact struct {
	Content          string
	ContentHash      string
	SensitivityLevel string
	LeakBudgetUsed   int
	Redacted         bool
	Metadata         map[string]interface{}
}

// UserResponse is the final sanitized output to the user
type UserResponse struct {
	Content      string
	Redacted     bool
	RedactionReason string
	OutputHash   string
}

// Egress processes output artifacts and applies leak control.
// WHY: Output shaping prevents disallowed emissions.
func Egress(artifact *OutputArtifact, postureLevel int, leakBudget int) (*UserResponse, error) {
	content := artifact.Content
	redacted := false
	redactionReason := ""

	// Compute hash of original content
	h := sha256.New()
	h.Write([]byte(content))
	outputHash := hex.EncodeToString(h.Sum(nil))

	// Apply leak budget constraints
	if artifact.LeakBudgetUsed > leakBudget {
		content = redactOverBudget(content, leakBudget)
		redacted = true
		redactionReason = "leak_budget_exceeded"
	}

	// Apply posture-based redaction
	if shouldRedactByPosture(artifact.SensitivityLevel, postureLevel) {
		content = redactSensitive(content)
		redacted = true
		redactionReason = "posture_constraint"
	}

	// Check for instruction smuggling in output
	if containsBypassInstructions(content) {
		content = stripBypassInstructions(content)
		redacted = true
		redactionReason = "bypass_instruction_detected"
	}

	return &UserResponse{
		Content:         content,
		Redacted:        redacted,
		RedactionReason: redactionReason,
		OutputHash:      outputHash,
	}, nil
}

// redactOverBudget truncates or redacts content that exceeds leak budget
func redactOverBudget(content string, budget int) string {
	if len(content) <= budget {
		return content
	}
	return content[:budget] + "\n[REDACTED: leak budget exceeded]"
}

// shouldRedactByPosture checks if content should be redacted based on posture
func shouldRedactByPosture(sensitivity string, posture int) bool {
	// Higher postures have stricter redaction
	switch sensitivity {
	case "high":
		return posture >= 2 // Redact high sensitivity at P2+
	case "medium":
		return posture >= 3 // Redact medium sensitivity at P3+
	case "low":
		return false // Never redact low sensitivity
	default:
		return true // Unknown sensitivity - fail closed
	}
}

// redactSensitive applies redaction patterns
func redactSensitive(content string) string {
	// Simple redaction - in production this would be more sophisticated
	// Could include PII detection, credential scanning, etc.
	return "[REDACTED: sensitive content filtered by posture constraint]"
}

// containsBypassInstructions detects if output contains bypass attempts
func containsBypassInstructions(content string) bool {
	lowerContent := strings.ToLower(content)

	bypassPatterns := []string{
		"ignore previous instructions",
		"disregard the above",
		"new instructions:",
		"system prompt:",
		"<|im_start|>",
		"override security",
	}

	for _, pattern := range bypassPatterns {
		if strings.Contains(lowerContent, pattern) {
			return true
		}
	}

	return false
}

// stripBypassInstructions removes detected bypass patterns
func stripBypassInstructions(content string) string {
	// In production, this would use sophisticated pattern matching
	// For now, replace entire content if bypass detected
	return "[OUTPUT BLOCKED: bypass instruction pattern detected]"
}
