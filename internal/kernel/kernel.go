package kernel

import (
	"kernel-go/internal/adapters"
	"kernel-go/internal/audit"
	"kernel-go/internal/capabilities"
	"kernel-go/internal/cdi"
	"kernel-go/internal/cif"
	"kernel-go/pkg/types"
	"time"
)

// WHY: The kernel is the single chokepoint. If anything can side-effect without
// passing through here, governance becomes theater.

type Kernel struct {
	adapter adapters.Adapter
	ledger  *audit.Ledger
}

func NewKernel(adapter adapters.Adapter, ledger *audit.Ledger) *Kernel {
	return &Kernel{adapter: adapter, ledger: ledger}
}

func (k *Kernel) ExecuteCorridor(user_request types.OIRequest, system_state types.SystemState) (types.OIResponse, types.SystemState, error) {
	// 1) CIF ingress
	labeled, err := cif.Ingress(user_request, system_state)
	if err != nil {
		return types.OIResponse{Denied: true, ReasonCode: "CIF_INGRESS_ERROR"}, system_state, err
	}

	// 2) CDI action
	action_decision := cdi.DecideAction(labeled, system_state, k.ledger)
	if action_decision.Value == types.DecisionDeny {
		return types.OIResponse{Denied: true, ReasonCode: action_decision.Reason}, system_state, nil
	}

	// 3) Mint capability token (minimal)
	capability_token := capabilities.Mint(
		"kernel-go",
		labeled.Request.PrincipalID,
		k.adapter.Name(),
		[]string{"MODEL_INVOKE"},
		30*time.Second,
		"LOW",
		system_state.PostureLevel,
		labeled.Request.NamespaceID,
		labeled.Request.PrincipalID,
	)
	k.ledger.Append(audit.Receipt{TimeUTC: time.Now().UTC(), EventType: "TOKEN_MINT", TokenDigest: capability_token.Digest, PostureLevel: system_state.PostureLevel})

	// 4) Adapter invocation (no-op model)
	model_out, err := k.adapter.InvokeModel(capability_token, labeled.Request.UserPayload)
	if err != nil {
		k.ledger.Append(audit.Receipt{TimeUTC: time.Now().UTC(), EventType: "ADAPTER_DENY", TokenDigest: capability_token.Digest, PostureLevel: system_state.PostureLevel})
		return types.OIResponse{Denied: true, ReasonCode: "ADAPTER_DENIED"}, system_state, err
	}
	k.ledger.Append(audit.Receipt{TimeUTC: time.Now().UTC(), EventType: "ADAPTER_OK", TokenDigest: capability_token.Digest, PostureLevel: system_state.PostureLevel})

	// 5) Produce output artifact (stub)
	output := types.OIResponse{Body: string(model_out)}

	// 6) CDI output
	output_decision := cdi.DecideOutput(output, system_state, k.ledger)
	if output_decision.Value == types.DecisionDeny {
		return types.OIResponse{Denied: true, ReasonCode: output_decision.Reason}, system_state, nil
	}

	// 7) CIF egress
	shaped, err := cif.Egress(output, system_state)
	if err != nil {
		return types.OIResponse{Denied: true, ReasonCode: "CIF_EGRESS_ERROR"}, system_state, err
	}

	return shaped, system_state, nil
}
