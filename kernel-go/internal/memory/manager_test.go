// WHY: These tests prove memory integrity (MI-1, MI-2, MI-3).
// Partition discipline, custody respect, quarantine enforcement.
package memory

import (
	"testing"
)

// TestMemoryWriteRequiresPartitionAndPolicy proves MI-1
func TestMemoryWriteRequiresPartitionAndPolicy(t *testing.T) {
	manager := NewManager()

	// Write to valid partition should succeed
	err := manager.Write(PartitionEphemeral, "test_id", "test content", nil)
	if err != nil {
		t.Fatalf("write to valid partition failed: %v", err)
	}

	// Write to non-existent partition should fail
	err = manager.Write("nonexistent", "test_id", "test content", nil)
	if err == nil {
		t.Fatal("expected error for non-existent partition")
	}
}

// TestQuarantinePromotionRequiresVerification proves MI-3
func TestQuarantinePromotionRequiresVerification(t *testing.T) {
	manager := NewManager()

	// Write to quarantine
	err := manager.Write(PartitionQuarantine, "untrusted_1", "untrusted content", nil)
	if err != nil {
		t.Fatalf("write to quarantine failed: %v", err)
	}

	// Attempt promotion without verification record - should fail
	err = manager.PromoteFromQuarantine("untrusted_1", "")
	if err == nil {
		t.Fatal("expected error for promotion without verification")
	}

	// Promotion with verification record should succeed
	err = manager.PromoteFromQuarantine("untrusted_1", "verification_signature_xyz")
	if err != nil {
		t.Fatalf("promotion with verification failed: %v", err)
	}

	// Verify content was promoted to durable
	entry, err := manager.Read(PartitionDurable, "untrusted_1")
	if err != nil {
		t.Fatalf("failed to read promoted content: %v", err)
	}

	if !entry.Verified {
		t.Fatal("promoted entry should be marked as verified")
	}
}

// TestAppendOnlyPartitions proves immutability constraints
func TestAppendOnlyPartitions(t *testing.T) {
	manager := NewManager()

	// Provenance is append-only
	err := manager.Write(PartitionProvenance, "event_1", "first write", nil)
	if err != nil {
		t.Fatalf("first write to provenance failed: %v", err)
	}

	// Attempt to overwrite should fail
	err = manager.Write(PartitionProvenance, "event_1", "overwrite attempt", nil)
	if err == nil {
		t.Fatal("expected error for overwrite in append-only partition")
	}
}

// TestPartitionIsolation proves different partitions are isolated
func TestPartitionIsolation(t *testing.T) {
	manager := NewManager()

	// Write to ephemeral
	err := manager.Write(PartitionEphemeral, "shared_id", "ephemeral content", nil)
	if err != nil {
		t.Fatalf("write to ephemeral failed: %v", err)
	}

	// Write to durable with same ID
	err = manager.Write(PartitionDurable, "shared_id", "durable content", nil)
	if err != nil {
		t.Fatalf("write to durable failed: %v", err)
	}

	// Read from ephemeral
	ephemeralEntry, err := manager.Read(PartitionEphemeral, "shared_id")
	if err != nil {
		t.Fatalf("read from ephemeral failed: %v", err)
	}

	// Read from durable
	durableEntry, err := manager.Read(PartitionDurable, "shared_id")
	if err != nil {
		t.Fatalf("read from durable failed: %v", err)
	}

	// Should be different content
	if ephemeralEntry.Content == durableEntry.Content {
		t.Fatal("partitions should be isolated, but contents match")
	}
}

// TestQuarantineWriteOnly proves quarantine cannot be read before promotion
func TestQuarantineWriteOnly(t *testing.T) {
	manager := NewManager()

	// Write to quarantine
	err := manager.Write(PartitionQuarantine, "suspicious_1", "suspicious content", nil)
	if err != nil {
		t.Fatalf("write to quarantine failed: %v", err)
	}

	// Attempt to read from quarantine should fail (write-only partition)
	_, err = manager.Read(PartitionQuarantine, "suspicious_1")
	if err == nil {
		t.Fatal("expected error reading from write-only quarantine partition")
	}
}

// TestContentHashComputed proves integrity tracking
func TestContentHashComputed(t *testing.T) {
	manager := NewManager()

	content := "test content for hashing"
	err := manager.Write(PartitionEphemeral, "hash_test", content, nil)
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}

	entry, err := manager.Read(PartitionEphemeral, "hash_test")
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}

	// Should have computed a hash
	if entry.ContentHash == "" {
		t.Fatal("content hash should be computed")
	}

	// Hash should be consistent
	err = manager.Write(PartitionDurable, "hash_test_2", content, nil)
	if err != nil {
		t.Fatalf("second write failed: %v", err)
	}

	entry2, err := manager.Read(PartitionDurable, "hash_test_2")
	if err != nil {
		t.Fatalf("second read failed: %v", err)
	}

	// Same content should produce same hash
	if entry.ContentHash != entry2.ContentHash {
		t.Fatal("same content should produce same hash")
	}
}

// TestListPartitions proves all standard partitions exist
func TestListPartitions(t *testing.T) {
	manager := NewManager()

	partitions := manager.ListPartitions()

	expectedPartitions := []string{
		PartitionEphemeral,
		PartitionDurable,
		PartitionCommitments,
		PartitionProvenance,
		PartitionQuarantine,
		PartitionEvidence,
	}

	if len(partitions) != len(expectedPartitions) {
		t.Fatalf("expected %d partitions, got %d", len(expectedPartitions), len(partitions))
	}

	// Check all expected partitions exist
	partitionMap := make(map[string]bool)
	for _, p := range partitions {
		partitionMap[p] = true
	}

	for _, expected := range expectedPartitions {
		if !partitionMap[expected] {
			t.Fatalf("expected partition %s not found", expected)
		}
	}
}
