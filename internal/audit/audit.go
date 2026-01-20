package audit

import "time"

// WHY: Auditable governance requires a tamper-evident log.
// This stub keeps a minimal in-memory ledger to prove wiring.

type Receipt struct {
	TimeUTC       time.Time
	EventType     string
	TokenDigest   string
	PostureLevel  string
	Decision      string
	DetailsDigest string
}

type Ledger struct {
	receipts []Receipt
}

func NewLedger() *Ledger { return &Ledger{receipts: []Receipt{}} }

func (l *Ledger) Append(r Receipt) { l.receipts = append(l.receipts, r) }

func (l *Ledger) All() []Receipt {
	out := make([]Receipt, 0, len(l.receipts))
	out = append(out, l.receipts...)
	return out
}
