// WHY: Capability tokens are the core authorization primitive.
// Every side-effect requires a valid, unexpired, unrevoked token
// with appropriate scope and posture bounds.
package capabilities

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// Token represents a scoped capability grant for a specific operation.
// Tokens are minted by the kernel after CDI ALLOW/DEGRADE decision
// and verified by adapters before any side-effect.
type Token struct {
	Issuer    string
	Subject   string
	Audience  string
	Scope     []string // allowed operations
	Limits    Limits
	TTL       time.Duration
	IssuedAt  time.Time
	ExpiresAt time.Time

	// Posture bounds: minimum and maximum posture levels this token is valid for
	PostureBounds PostureBounds

	NamespaceID string
	PrincipalID string

	// Digest is the cryptographic hash of this token's contents
	Digest string

	// RevokedAt is set when STOP is invoked
	RevokedAt *time.Time
}

// Limits constrain what a capability token can do
type Limits struct {
	MaxDepth         int      // call depth limit
	MaxBudget        int      // resource budget (e.g., tokens, API calls)
	WorkspaceBounds  []string // allowed file paths or workspace roots
}

// PostureBounds define the posture range this token is valid for
type PostureBounds struct {
	MinPosture int // minimum posture level required
	MaxPosture int // maximum posture level allowed
}

// Mint creates a new capability token with the given parameters.
// WHY: Centralized minting ensures all tokens have required fields
// and proper initialization.
func Mint(issuer, subject, audience string, scope []string, limits Limits, ttl time.Duration, postureBounds PostureBounds, namespaceID, principalID string) (*Token, error) {
	now := time.Now()

	token := &Token{
		Issuer:        issuer,
		Subject:       subject,
		Audience:      audience,
		Scope:         scope,
		Limits:        limits,
		TTL:           ttl,
		IssuedAt:      now,
		ExpiresAt:     now.Add(ttl),
		PostureBounds: postureBounds,
		NamespaceID:   namespaceID,
		PrincipalID:   principalID,
		RevokedAt:     nil,
	}

	// Compute digest
	token.Digest = token.computeDigest()

	return token, nil
}

// computeDigest generates a cryptographic hash of the token's contents
func (t *Token) computeDigest() string {
	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("%s|%s|%s|%v|%v|%v|%v|%s|%s",
		t.Issuer, t.Subject, t.Audience,
		t.Scope, t.Limits, t.IssuedAt.Unix(), t.ExpiresAt.Unix(),
		t.NamespaceID, t.PrincipalID)))
	return hex.EncodeToString(h.Sum(nil))
}

// Verify checks if a token is valid for use.
// WHY: Fail-closed verification - any problem returns false.
func (t *Token) Verify(currentPosture int) (bool, error) {
	now := time.Now()

	// Check revocation
	if t.RevokedAt != nil {
		return false, fmt.Errorf("token revoked at %v", t.RevokedAt)
	}

	// Check expiration
	if now.After(t.ExpiresAt) {
		return false, fmt.Errorf("token expired at %v", t.ExpiresAt)
	}

	// Check posture bounds
	if currentPosture < t.PostureBounds.MinPosture {
		return false, fmt.Errorf("current posture %d below minimum %d", currentPosture, t.PostureBounds.MinPosture)
	}
	if currentPosture > t.PostureBounds.MaxPosture {
		return false, fmt.Errorf("current posture %d above maximum %d", currentPosture, t.PostureBounds.MaxPosture)
	}

	return true, nil
}

// Revoke marks this token as revoked.
// WHY: STOP dominance - revocation is immediate and irreversible.
func (t *Token) Revoke() {
	now := time.Now()
	t.RevokedAt = &now
}

// HasScope checks if this token grants a specific operation scope.
func (t *Token) HasScope(operation string) bool {
	for _, s := range t.Scope {
		if s == operation {
			return true
		}
	}
	return false
}
