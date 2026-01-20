package main

import (
	"fmt"
	"kernel-go/internal/adapters"
	"kernel-go/internal/audit"
	"kernel-go/internal/kernel"
	"kernel-go/pkg/types"
)

// WHY: This command is intentionally tiny. It exists so a reviewer can run the
// corridor end-to-end without wiring HTTP/gRPC yet.

func main() {
	ledger := audit.NewLedger()
	k := kernel.NewKernel(adapters.NoopModelAdapter{}, ledger)

	resp, _, err := k.ExecuteCorridor(types.OIRequest{
		UserIntent:  "echo",
		UserPayload: []byte("hello governed world"),
		PrincipalID: "principal-demo",
		NamespaceID: "namespace-demo",
	}, types.SystemState{
		PostureLevel:        "LOW",
		GovernanceCapsuleOK: true,
	})

	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println(resp.Body)
}
