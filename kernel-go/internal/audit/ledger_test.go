// WHY: These tests prove audit integrity (AU-1, AU-2).
// Tamper-evident chain, mechanics-only logging.
package audit

import (
	"testing"
)

// TestReceiptChainDetectsModification proves AU-2: tamper detection
func TestReceiptChainDetectsModification(t *testing.T) {
	ledger := NewLedger()

	// Add some receipts
	ledger.AppendCDIDecision("ALLOW", "input_hash_1", "output_hash_1")
	ledger.AppendTokenMint("token_digest_1", []string{"scope1", "scope2"})
	ledger.AppendAdapterAttempt("test_adapter", true, "token_digest_1")

	// Verify initial chain
	valid, err := ledger.Verify()
	if err != nil {
		t.Fatalf("initial chain verification failed: %v", err)
	}
	if !valid {
		t.Fatal("initial chain should be valid")
	}

	// Tamper with a receipt
	receipts := ledger.GetReceipts()
	if len(receipts) < 2 {
		t.Fatal("not enough receipts for tamper test")
	}

	// Modify the ledger internally (simulate tampering)
	ledger.mu.Lock()
	ledger.receipts[1].EventData["decision"] = "DENY" // tamper
	ledger.mu.Unlock()

	// Verification should now fail
	valid, err = ledger.Verify()
	if valid {
		t.Fatal("expected verification to fail after tampering")
	}
	if err == nil {
		t.Fatal("expected error after tampering")
	}
}

// TestAuditReceiptsContainNoRawUserContentByDefault proves AU-1
func TestAuditReceiptsContainNoRawUserContentByDefault(t *testing.T) {
	ledger := NewLedger()

	// Log a CDI decision with only hashes
	ledger.AppendCDIDecision("ALLOW", "hash_of_input", "hash_of_output")

	receipts := ledger.GetReceipts()
	if len(receipts) < 2 {
		t.Fatal("expected at least 2 receipts (genesis + decision)")
	}

	// Check the CDI decision receipt
	decisionReceipt := receipts[1]
	if decisionReceipt.EventType != "cdi_decision" {
		t.Fatalf("expected cdi_decision event, got %s", decisionReceipt.EventType)
	}

	// Verify only hashes are stored, not raw content
	eventData := decisionReceipt.EventData
	if _, hasRawInput := eventData["raw_input"]; hasRawInput {
		t.Fatal("receipt should not contain raw_input field")
	}
	if _, hasRawOutput := eventData["raw_output"]; hasRawOutput {
		t.Fatal("receipt should not contain raw_output field")
	}

	// Should have hashes
	if _, hasInputHash := eventData["input_hash"]; !hasInputHash {
		t.Fatal("receipt should contain input_hash")
	}
	if _, hasOutputHash := eventData["output_hash"]; !hasOutputHash {
		t.Fatal("receipt should contain output_hash")
	}
}

// TestReceiptChainLinkage proves hash chain integrity
func TestReceiptChainLinkage(t *testing.T) {
	ledger := NewLedger()

	// Add multiple receipts
	ledger.AppendCDIDecision("ALLOW", "hash1", "hash2")
	ledger.AppendTokenMint("token1", []string{"scope"})
	ledger.AppendAdapterAttempt("adapter1", true, "token1")

	receipts := ledger.GetReceipts()
	if len(receipts) < 4 {
		t.Fatalf("expected at least 4 receipts, got %d", len(receipts))
	}

	// Verify chain linkage
	for i := 1; i < len(receipts); i++ {
		current := receipts[i]
		previous := receipts[i-1]

		if current.PrevHash != previous.CurrentHash {
			t.Fatalf("chain break at receipt %d: prev_hash %s != previous current_hash %s",
				i, current.PrevHash, previous.CurrentHash)
		}
	}
}

// TestAppendOnlyLedger proves receipts cannot be removed
func TestAppendOnlyLedger(t *testing.T) {
	ledger := NewLedger()

	initialCount := len(ledger.GetReceipts())

	// Add receipts
	ledger.AppendCDIDecision("ALLOW", "hash1", "hash2")
	ledger.AppendTokenMint("token1", []string{"scope"})

	newCount := len(ledger.GetReceipts())
	if newCount != initialCount+2 {
		t.Fatalf("expected %d receipts, got %d", initialCount+2, newCount)
	}

	// GetReceipts returns a copy, so external modification shouldn't affect ledger
	externalCopy := ledger.GetReceipts()
	externalCopy = externalCopy[:len(externalCopy)-1] // remove last

	// Ledger should still have all receipts
	if len(ledger.GetReceipts()) != newCount {
		t.Fatal("ledger was modified through returned copy")
	}
}

// TestStopEventLogging proves STOP events are audited
func TestStopEventLogging(t *testing.T) {
	ledger := NewLedger()

	ledger.AppendStopEvent(5) // 5 tokens revoked

	receipts := ledger.GetReceipts()
	found := false
	for _, receipt := range receipts {
		if receipt.EventType == "stop_event" {
			found = true
			if receipt.EventData["tokens_revoked"] != 5 {
				t.Fatalf("expected tokens_revoked=5, got %v", receipt.EventData["tokens_revoked"])
			}
		}
	}

	if !found {
		t.Fatal("stop_event not found in receipts")
	}
}

// TestSequentialOrdering proves receipts are ordered
func TestSequentialOrdering(t *testing.T) {
	ledger := NewLedger()

	ledger.AppendCDIDecision("ALLOW", "hash1", "hash2")
	ledger.AppendTokenMint("token1", []string{"scope"})
	ledger.AppendAdapterAttempt("adapter1", true, "token1")

	receipts := ledger.GetReceipts()

	// Check sequences are monotonically increasing
	for i := 1; i < len(receipts); i++ {
		if receipts[i].Sequence != receipts[i-1].Sequence+1 {
			t.Fatalf("sequence break: receipt %d has sequence %d, previous was %d",
				i, receipts[i].Sequence, receipts[i-1].Sequence)
		}
	}
}
