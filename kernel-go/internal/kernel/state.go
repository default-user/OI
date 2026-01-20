// WHY: Centralized system state provides a single source of truth
// for governance decisions and capability enforcement.
package kernel

import (
	"sync"

	"github.com/user/oi/kernel-go/internal/adapters"
	"github.com/user/oi/kernel-go/internal/audit"
	"github.com/user/oi/kernel-go/internal/capabilities"
	"github.com/user/oi/kernel-go/internal/memory"
	"github.com/user/oi/kernel-go/internal/posture"
)

// SystemState contains all governance-relevant state.
// WHY: Explicit state structure makes dependencies and
// invariants testable.
type SystemState struct {
	mu sync.RWMutex

	// Identity and authority
	IdentityCapsule   IdentityCapsule
	AuthorityCapsule  AuthorityCapsule
	GovernanceCapsule GovernanceCapsule

	// World model and semantic indexes
	WorldPack       WorldPack
	SemanticIndexes SemanticIndexes
	ProfileStore    ProfileStore

	// Audit and integrity
	AuditLedger    *audit.Ledger
	IntegrityState IntegrityState

	// Posture and capabilities
	PostureLevel          int
	ActiveCapabilityTokens map[string]*capabilities.Token

	// Adapters
	AdapterRegistry *adapters.Registry

	// Memory subsystem
	MemoryManager *memory.Manager

	// Declassification tracking
	DeclassificationLedger DeclassificationLedger
}

// IdentityCapsule holds user/principal identity information
type IdentityCapsule struct {
	PrincipalID string
	NamespaceID string
	Attributes  map[string]string
}

// AuthorityCapsule holds authorization and consent state
type AuthorityCapsule struct {
	ActiveConsents map[string]bool
	Revocations    []Revocation
}

// Revocation records when consent was withdrawn
type Revocation struct {
	Timestamp int64
	Scope     string
}

// GovernanceCapsule holds policy and governance rules
type GovernanceCapsule struct {
	PolicyVersion string
	Rules         map[string]interface{}
	Commitments   map[string]string // commitment_id -> hash
}

// WorldPack holds environmental context
type WorldPack struct {
	Timestamp int64
	Context   map[string]interface{}
}

// SemanticIndexes provide quick lookups
type SemanticIndexes struct {
	Indexes map[string]interface{}
}

// ProfileStore holds user preferences and history
type ProfileStore struct {
	Profiles map[string]interface{}
}

// IntegrityState tracks system integrity
type IntegrityState string

const (
	IntegrityOK       IntegrityState = "INTEGRITY_OK"
	IntegrityDegraded IntegrityState = "INTEGRITY_DEGRADED"
	IntegrityVoid     IntegrityState = "INTEGRITY_VOID"
)

// DeclassificationLedger tracks explicit information widening
type DeclassificationLedger struct {
	Entries []DeclassificationEntry
}

// DeclassificationEntry records when sensitive info was declassified
type DeclassificationEntry struct {
	Timestamp   int64
	ContentHash string
	Reason      string
	Approver    string
}

// NewSystemState creates a new system state with default values.
// WHY: Fail-closed initialization - start with minimal permissions.
func NewSystemState(principalID, namespaceID string) *SystemState {
	return &SystemState{
		IdentityCapsule: IdentityCapsule{
			PrincipalID: principalID,
			NamespaceID: namespaceID,
			Attributes:  make(map[string]string),
		},
		AuthorityCapsule: AuthorityCapsule{
			ActiveConsents: make(map[string]bool),
			Revocations:    []Revocation{},
		},
		GovernanceCapsule: GovernanceCapsule{
			PolicyVersion: "v1",
			Rules:         make(map[string]interface{}),
			Commitments:   make(map[string]string),
		},
		WorldPack: WorldPack{
			Context: make(map[string]interface{}),
		},
		SemanticIndexes: SemanticIndexes{
			Indexes: make(map[string]interface{}),
		},
		ProfileStore: ProfileStore{
			Profiles: make(map[string]interface{}),
		},
		AuditLedger:               audit.NewLedger(),
		IntegrityState:            IntegrityOK,
		PostureLevel:              posture.P1, // Default to most restrictive
		ActiveCapabilityTokens:    make(map[string]*capabilities.Token),
		AdapterRegistry:           adapters.NewRegistry(),
		MemoryManager:             memory.NewManager(),
		DeclassificationLedger:    DeclassificationLedger{Entries: []DeclassificationEntry{}},
	}
}

// SetIntegrityState updates the integrity state.
// WHY: State transitions must be explicit and auditable.
func (s *SystemState) SetIntegrityState(state IntegrityState) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.IntegrityState = state
	// Log to audit
	s.AuditLedger.AppendIntegrityStateChange(string(state))
}

// GetIntegrityState returns current integrity state (thread-safe)
func (s *SystemState) GetIntegrityState() IntegrityState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.IntegrityState
}

// RevokeAllTokens implements STOP dominance by revoking all active tokens.
// WHY: User STOP must immediately revoke all capability.
func (s *SystemState) RevokeAllTokens() {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, token := range s.ActiveCapabilityTokens {
		token.Revoke()
	}

	// Log to audit
	s.AuditLedger.AppendStopEvent(len(s.ActiveCapabilityTokens))
}

// AddToken registers a new active capability token
func (s *SystemState) AddToken(token *capabilities.Token) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.ActiveCapabilityTokens[token.Digest] = token
	s.AuditLedger.AppendTokenMint(token.Digest, token.Scope)
}
