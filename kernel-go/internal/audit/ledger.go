// WHY: Tamper-evident audit provides governance accountability.
// The hash chain ensures any modification breaks verification,
// forcing integrity degradation.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// Receipt represents a single audit log entry in the hash chain.
// WHY: Mechanics-only logging - no raw user content by default.
type Receipt struct {
	Sequence     int64
	Timestamp    int64
	EventType    string
	EventData    map[string]interface{} // structured data, not raw content
	PrevHash     string
	CurrentHash  string
}

// Ledger is an append-only, hash-chained audit log.
type Ledger struct {
	mu       sync.Mutex
	receipts []Receipt
	sequence int64
}

// NewLedger creates a new audit ledger with genesis receipt
func NewLedger() *Ledger {
	ledger := &Ledger{
		receipts: []Receipt{},
		sequence: 0,
	}

	// Genesis receipt
	genesis := Receipt{
		Sequence:    0,
		Timestamp:   time.Now().Unix(),
		EventType:   "genesis",
		EventData:   map[string]interface{}{"message": "audit ledger initialized"},
		PrevHash:    "0000000000000000",
		CurrentHash: "",
	}
	genesis.CurrentHash = computeHash(genesis)
	ledger.receipts = append(ledger.receipts, genesis)

	return ledger
}

// append adds a new receipt to the chain
func (l *Ledger) append(eventType string, eventData map[string]interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.sequence++

	var prevHash string
	if len(l.receipts) > 0 {
		prevHash = l.receipts[len(l.receipts)-1].CurrentHash
	} else {
		prevHash = "0000000000000000"
	}

	receipt := Receipt{
		Sequence:  l.sequence,
		Timestamp: time.Now().Unix(),
		EventType: eventType,
		EventData: eventData,
		PrevHash:  prevHash,
	}
	receipt.CurrentHash = computeHash(receipt)

	l.receipts = append(l.receipts, receipt)
}

// AppendCDIDecision logs a CDI decision (ALLOW/DENY/DEGRADE)
func (l *Ledger) AppendCDIDecision(decision string, inputHash string, outputHash string) {
	l.append("cdi_decision", map[string]interface{}{
		"decision":    decision,
		"input_hash":  inputHash,
		"output_hash": outputHash,
	})
}

// AppendTokenMint logs a capability token mint event
func (l *Ledger) AppendTokenMint(tokenDigest string, scope []string) {
	l.append("token_mint", map[string]interface{}{
		"token_digest": tokenDigest,
		"scope":        scope,
	})
}

// AppendAdapterAttempt logs an adapter invocation attempt
func (l *Ledger) AppendAdapterAttempt(adapterName string, accepted bool, tokenDigest string) {
	l.append("adapter_attempt", map[string]interface{}{
		"adapter":      adapterName,
		"accepted":     accepted,
		"token_digest": tokenDigest,
	})
}

// AppendMemoryWrite logs a memory partition write
func (l *Ledger) AppendMemoryWrite(partition string, scope string, contentHash string) {
	l.append("memory_write", map[string]interface{}{
		"partition":    partition,
		"scope":        scope,
		"content_hash": contentHash,
	})
}

// AppendIntegrityStateChange logs an integrity state transition
func (l *Ledger) AppendIntegrityStateChange(newState string) {
	l.append("integrity_state_change", map[string]interface{}{
		"new_state": newState,
	})
}

// AppendStopEvent logs a STOP/revocation event
func (l *Ledger) AppendStopEvent(tokensRevoked int) {
	l.append("stop_event", map[string]interface{}{
		"tokens_revoked": tokensRevoked,
	})
}

// AppendPostureChange logs a posture level change
func (l *Ledger) AppendPostureChange(fromLevel int, toLevel int, reason string) {
	l.append("posture_change", map[string]interface{}{
		"from_level": fromLevel,
		"to_level":   toLevel,
		"reason":     reason,
	})
}

// Verify checks the integrity of the entire receipt chain.
// WHY: Any tampering breaks the hash chain and forces integrity degradation.
func (l *Ledger) Verify() (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if len(l.receipts) == 0 {
		return false, fmt.Errorf("empty ledger")
	}

	for i, receipt := range l.receipts {
		// Verify hash
		expectedHash := computeHash(receipt)
		if receipt.CurrentHash != expectedHash {
			return false, fmt.Errorf("receipt %d hash mismatch: expected %s, got %s", i, expectedHash, receipt.CurrentHash)
		}

		// Verify chain linkage (except genesis)
		if i > 0 {
			prevReceipt := l.receipts[i-1]
			if receipt.PrevHash != prevReceipt.CurrentHash {
				return false, fmt.Errorf("receipt %d chain break: prev_hash %s != previous current_hash %s", i, receipt.PrevHash, prevReceipt.CurrentHash)
			}
		}
	}

	return true, nil
}

// GetReceipts returns a copy of all receipts (read-only)
func (l *Ledger) GetReceipts() []Receipt {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Return a copy to prevent external modification
	receipts := make([]Receipt, len(l.receipts))
	copy(receipts, l.receipts)
	return receipts
}

// computeHash generates a cryptographic hash for a receipt
func computeHash(r Receipt) string {
	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("%d|%d|%s|%v|%s",
		r.Sequence, r.Timestamp, r.EventType, r.EventData, r.PrevHash)))
	return hex.EncodeToString(h.Sum(nil))
}
