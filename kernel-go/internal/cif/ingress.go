// WHY: CIF ingress is where content becomes labeled and sanitized.
// Boundary integrity prevents "content becomes authority" attacks.
package cif

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// LabeledRequest represents a sanitized and labeled user request.
type LabeledRequest struct {
	OriginalInput  string
	SanitizedInput string
	TaintLabels    []string
	SensitivityLevel string
	InputHash      string
	Metadata       map[string]interface{}
}

// Ingress processes raw user input into a labeled request.
// WHY: Sanitization and labeling happen before any authority checks.
func Ingress(rawInput string, metadata map[string]interface{}) (*LabeledRequest, error) {
	if len(rawInput) == 0 {
		return nil, fmt.Errorf("empty input rejected")
	}

	// Size limit enforcement (simple example: 100KB)
	if len(rawInput) > 100*1024 {
		return nil, fmt.Errorf("input exceeds size limit")
	}

	// Sanitize input
	sanitized := sanitizeInput(rawInput)

	// Detect taint
	taintLabels := detectTaint(rawInput)

	// Assess sensitivity
	sensitivity := assessSensitivity(rawInput, metadata)

	// Compute hash
	h := sha256.New()
	h.Write([]byte(sanitized))
	inputHash := hex.EncodeToString(h.Sum(nil))

	return &LabeledRequest{
		OriginalInput:    rawInput,
		SanitizedInput:   sanitized,
		TaintLabels:      taintLabels,
		SensitivityLevel: sensitivity,
		InputHash:        inputHash,
		Metadata:         metadata,
	}, nil
}

// sanitizeInput performs basic input sanitization
func sanitizeInput(input string) string {
	// Remove control characters
	sanitized := strings.Map(func(r rune) rune {
		if r < 32 && r != '\n' && r != '\t' {
			return -1
		}
		return r
	}, input)

	// Additional sanitization could include:
	// - Unicode normalization
	// - Script injection detection
	// - Null byte removal
	return sanitized
}

// detectTaint identifies instruction-smuggling patterns
// WHY: Tainted content cannot become authority
func detectTaint(input string) []string {
	labels := []string{}

	// Check for system prompt impersonation patterns
	patterns := []string{
		"system:",
		"assistant:",
		"<|im_start|>",
		"<|im_end|>",
		"[INST]",
		"[/INST]",
		"### Instruction:",
		"### System:",
	}

	lowerInput := strings.ToLower(input)
	for _, pattern := range patterns {
		if strings.Contains(lowerInput, strings.ToLower(pattern)) {
			labels = append(labels, "instruction_smuggling_attempt")
			break
		}
	}

	// Check for emotional escalation / pressure tactics
	pressurePatterns := []string{
		"urgent",
		"emergency",
		"immediately",
		"override",
		"ignore previous",
		"disregard",
	}

	for _, pattern := range pressurePatterns {
		if strings.Contains(lowerInput, pattern) {
			labels = append(labels, "pressure_tactic")
			break
		}
	}

	// If no taint detected, mark as clean
	if len(labels) == 0 {
		labels = append(labels, "clean")
	}

	return labels
}

// assessSensitivity determines the sensitivity level of the input
func assessSensitivity(input string, metadata map[string]interface{}) string {
	// Simple heuristic - in production this would be more sophisticated
	if metadata != nil {
		if level, ok := metadata["sensitivity"]; ok {
			return level.(string)
		}
	}

	// Default to low sensitivity
	return "low"
}

// IsTainted checks if a request has taint labels
func (lr *LabeledRequest) IsTainted() bool {
	for _, label := range lr.TaintLabels {
		if label != "clean" {
			return true
		}
	}
	return false
}
