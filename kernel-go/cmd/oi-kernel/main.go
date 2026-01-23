// WHY: Provide a runnable entrypoint for exercising the CIF → CDI → kernel corridor.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/user/oi/kernel-go/internal/adapters"
	"github.com/user/oi/kernel-go/internal/kernel"
)

type output struct {
	Content    string   `json:"content"`
	Success    bool     `json:"success"`
	Error      string   `json:"error,omitempty"`
	AuditTrail []string `json:"audit_trail"`
}

func main() {
	input := flag.String("input", "hello", "raw input for the corridor")
	principalID := flag.String("principal", "principal-1", "principal identifier")
	namespaceID := flag.String("namespace", "namespace-1", "namespace identifier")
	pretty := flag.Bool("pretty", true, "pretty-print JSON output")
	flag.Parse()

	state := kernel.NewSystemState(*principalID, *namespaceID)
	if err := state.AdapterRegistry.Register(adapters.NewMockAdapter("mock_adapter")); err != nil {
		fmt.Fprintf(os.Stderr, "failed to register adapter: %v\n", err)
		os.Exit(1)
	}

	req := &kernel.Request{
		RawInput: *input,
		Metadata: map[string]interface{}{
			"received_at": time.Now().UTC().Format(time.RFC3339),
		},
	}

	resp, err := kernel.Execute(req, state)
	if err != nil {
		fmt.Fprintf(os.Stderr, "execution failed: %v\n", err)
		os.Exit(1)
	}

	payload := output{
		Content:    resp.Content,
		Success:    resp.Success,
		Error:      resp.Error,
		AuditTrail: resp.AuditTrail,
	}

	var result []byte
	if *pretty {
		result, err = json.MarshalIndent(payload, "", "  ")
	} else {
		result, err = json.Marshal(payload)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to marshal output: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(result))
}
