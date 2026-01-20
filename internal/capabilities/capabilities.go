package capabilities

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// WHY: Capability tokens are the mechanical permission artifact that makes
// MEDIATION_PATH enforceable. If nothing else exists, this must exist.

type CapabilityToken struct {
	Issuer      string
	Subject     string
	Audience    string
	Scope       []string
	TTL         time.Duration
	IssuedAt    time.Time
	ExpiresAt   time.Time
	PostureMin  string
	PostureMax  string
	NamespaceID string
	PrincipalID string
	Digest      string
	RevokedAt   *time.Time
}

func Mint(issuer, subject, audience string, scope []string, ttl time.Duration, postureMin, postureMax, namespaceID, principalID string) CapabilityToken {
	issuedAt := time.Now().UTC()
	expiresAt := issuedAt.Add(ttl)

	// Digest is content-addressed so receipts can reference it without leaking payload.
	h := sha256.Sum256([]byte(issuer + "|" + subject + "|" + audience + "|" + namespaceID + "|" + principalID + "|" + expiresAt.Format(time.RFC3339Nano)))
	digest := hex.EncodeToString(h[:])

	return CapabilityToken{
		Issuer:      issuer,
		Subject:     subject,
		Audience:    audience,
		Scope:       scope,
		TTL:         ttl,
		IssuedAt:    issuedAt,
		ExpiresAt:   expiresAt,
		PostureMin:  postureMin,
		PostureMax:  postureMax,
		NamespaceID: namespaceID,
		PrincipalID: principalID,
		Digest:      digest,
	}
}

func (c *CapabilityToken) Revoke(now time.Time) {
	c.RevokedAt = &now
}

func (c CapabilityToken) IsRevoked() bool {
	return c.RevokedAt != nil
}

func (c CapabilityToken) IsExpired(now time.Time) bool {
	return now.After(c.ExpiresAt)
}
