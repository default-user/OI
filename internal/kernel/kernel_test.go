package kernel_test

import (
	"kernel-go/internal/adapters"
	"kernel-go/internal/audit"
	"kernel-go/internal/kernel"
	"kernel-go/pkg/types"
	"testing"
)

func TestFailClosed_MissingGovernanceCapsuleDenies(t *testing.T) {
	ledger := audit.NewLedger()
	k := kernel.NewKernel(adapters.NoopModelAdapter{}, ledger)

	resp, _, err := k.ExecuteCorridor(types.OIRequest{
		UserIntent:  "echo",
		UserPayload: []byte("hi"),
		PrincipalID: "p",
		NamespaceID: "n",
	}, types.SystemState{
		PostureLevel:        "LOW",
		GovernanceCapsuleOK: false,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Denied {
		t.Fatalf("expected denied response")
	}
	if resp.ReasonCode != "MISSING_GOVERNANCE_CAPSULE" {
		t.Fatalf("unexpected reason: %s", resp.ReasonCode)
	}
}

func TestPipelineOrder_ProducesReceipts(t *testing.T) {
	ledger := audit.NewLedger()
	k := kernel.NewKernel(adapters.NoopModelAdapter{}, ledger)

	_, _, err := k.ExecuteCorridor(types.OIRequest{
		UserIntent:  "echo",
		UserPayload: []byte("hi"),
		PrincipalID: "p",
		NamespaceID: "n",
	}, types.SystemState{
		PostureLevel:        "LOW",
		GovernanceCapsuleOK: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	receipts := ledger.All()
	if len(receipts) < 4 {
		t.Fatalf("expected receipts, got %d", len(receipts))
	}
	// We expect at minimum: CDI_ACTION, TOKEN_MINT, ADAPTER_OK, CDI_OUTPUT
	// (The exact sequence can evolve, but the presence is required.)
	wantTypes := map[string]bool{"CDI_ACTION": false, "TOKEN_MINT": false, "ADAPTER_OK": false, "CDI_OUTPUT": false}
	for _, r := range receipts {
		if _, ok := wantTypes[r.EventType]; ok {
			wantTypes[r.EventType] = true
		}
	}
	for k, v := range wantTypes {
		if !v {
			t.Fatalf("missing receipt type: %s", k)
		}
	}
}
