// WHY: Memory partitioning prevents persistence-based attacks.
// Different partitions have different trust and custody properties.
package memory

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
)

// Partition types define trust boundaries
const (
	PartitionEphemeral    = "ephemeral"     // cleared each session
	PartitionDurable      = "durable"       // user-custodied persistent
	PartitionCommitments  = "commitments"   // system commitments
	PartitionProvenance   = "provenance"    // audit trail
	PartitionQuarantine   = "quarantine"    // untrusted content
	PartitionEvidence     = "evidence"      // encrypted evidence store
)

// Entry represents a memory entry in any partition
type Entry struct {
	ID          string
	Partition   string
	Content     string
	ContentHash string
	Metadata    map[string]interface{}
	Timestamp   int64
	Verified    bool // for quarantine promotion
}

// Manager manages all memory partitions
type Manager struct {
	mu         sync.RWMutex
	partitions map[string]*Partition
}

// Partition represents a single memory partition
type Partition struct {
	Name    string
	Entries map[string]*Entry
	Policy  PartitionPolicy
}

// PartitionPolicy defines access rules for a partition
type PartitionPolicy struct {
	AllowWrite      bool
	AllowRead       bool
	RequireCapability bool
	AppendOnly      bool
}

// NewManager creates a new memory manager with default partitions
func NewManager() *Manager {
	m := &Manager{
		partitions: make(map[string]*Partition),
	}

	// Initialize standard partitions
	m.partitions[PartitionEphemeral] = &Partition{
		Name:    PartitionEphemeral,
		Entries: make(map[string]*Entry),
		Policy: PartitionPolicy{
			AllowWrite:        true,
			AllowRead:         true,
			RequireCapability: false,
			AppendOnly:        false,
		},
	}

	m.partitions[PartitionDurable] = &Partition{
		Name:    PartitionDurable,
		Entries: make(map[string]*Entry),
		Policy: PartitionPolicy{
			AllowWrite:        true,
			AllowRead:         true,
			RequireCapability: true,
			AppendOnly:        false,
		},
	}

	m.partitions[PartitionCommitments] = &Partition{
		Name:    PartitionCommitments,
		Entries: make(map[string]*Entry),
		Policy: PartitionPolicy{
			AllowWrite:        true, // requires signed update
			AllowRead:         true,
			RequireCapability: true,
			AppendOnly:        false,
		},
	}

	m.partitions[PartitionProvenance] = &Partition{
		Name:    PartitionProvenance,
		Entries: make(map[string]*Entry),
		Policy: PartitionPolicy{
			AllowWrite:        true,
			AllowRead:         true,
			RequireCapability: false,
			AppendOnly:        true,
		},
	}

	m.partitions[PartitionQuarantine] = &Partition{
		Name:    PartitionQuarantine,
		Entries: make(map[string]*Entry),
		Policy: PartitionPolicy{
			AllowWrite:        true,
			AllowRead:         false, // quarantine is write-only until verified
			RequireCapability: false,
			AppendOnly:        true,
		},
	}

	m.partitions[PartitionEvidence] = &Partition{
		Name:    PartitionEvidence,
		Entries: make(map[string]*Entry),
		Policy: PartitionPolicy{
			AllowWrite:        true,
			AllowRead:         true,
			RequireCapability: true,
			AppendOnly:        true,
		},
	}

	return m
}

// Write adds an entry to a partition.
// WHY: Partition discipline - every write declares its partition.
func (m *Manager) Write(partition string, id string, content string, metadata map[string]interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	p, exists := m.partitions[partition]
	if !exists {
		return fmt.Errorf("partition %s does not exist", partition)
	}

	// Check policy
	if !p.Policy.AllowWrite {
		return fmt.Errorf("partition %s is read-only", partition)
	}

	// Check if append-only
	if p.Policy.AppendOnly && p.Entries[id] != nil {
		return fmt.Errorf("partition %s is append-only, cannot overwrite entry %s", partition, id)
	}

	// Compute content hash
	h := sha256.New()
	h.Write([]byte(content))
	contentHash := hex.EncodeToString(h.Sum(nil))

	// Initialize metadata if nil
	if metadata == nil {
		metadata = make(map[string]interface{})
	}

	entry := &Entry{
		ID:          id,
		Partition:   partition,
		Content:     content,
		ContentHash: contentHash,
		Metadata:    metadata,
		Timestamp:   currentTimestamp(),
		Verified:    false,
	}

	p.Entries[id] = entry
	return nil
}

// Read retrieves an entry from a partition
func (m *Manager) Read(partition string, id string) (*Entry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	p, exists := m.partitions[partition]
	if !exists {
		return nil, fmt.Errorf("partition %s does not exist", partition)
	}

	// Check policy
	if !p.Policy.AllowRead {
		return nil, fmt.Errorf("partition %s is write-only", partition)
	}

	entry, exists := p.Entries[id]
	if !exists {
		return nil, fmt.Errorf("entry %s not found in partition %s", id, partition)
	}

	return entry, nil
}

// PromoteFromQuarantine moves content from quarantine to durable after verification.
// WHY: Quarantined content is never promoted without explicit verification ritual.
func (m *Manager) PromoteFromQuarantine(id string, verificationRecord string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	quarantine := m.partitions[PartitionQuarantine]
	entry, exists := quarantine.Entries[id]
	if !exists {
		return fmt.Errorf("entry %s not found in quarantine", id)
	}

	// Require verification record
	if verificationRecord == "" {
		return fmt.Errorf("promotion requires verification record")
	}

	// Mark as verified
	entry.Verified = true
	entry.Metadata["verification_record"] = verificationRecord

	// Copy to durable partition
	durable := m.partitions[PartitionDurable]
	durable.Entries[id] = &Entry{
		ID:          entry.ID,
		Partition:   PartitionDurable,
		Content:     entry.Content,
		ContentHash: entry.ContentHash,
		Metadata:    entry.Metadata,
		Timestamp:   currentTimestamp(),
		Verified:    true,
	}

	return nil
}

// ListPartitions returns all partition names
func (m *Manager) ListPartitions() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	names := make([]string, 0, len(m.partitions))
	for name := range m.partitions {
		names = append(names, name)
	}
	return names
}

func currentTimestamp() int64 {
	// Simple timestamp - in production would use time.Now().Unix()
	return 0
}
