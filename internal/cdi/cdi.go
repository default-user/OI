package cdi

import (
	"kernel-go/internal/audit"
	"kernel-go/pkg/types"
	"time"
)

// WHY: CDI is the "judge before power". This stub is intentionally strict.

type Decision struct {
	Value  types.Decision
	Reason string
}

func DecideAction(labeled_user_request any, system_state types.SystemState, ledger *audit.Ledger) Decision {
	// FAIL_CLOSED: missing governance prerequisites => DENY.
	if !system_state.GovernanceCapsuleOK {
		d := Decision{Value: types.DecisionDeny, Reason: "MISSING_GOVERNANCE_CAPSULE"}
		ledger.Append(audit.Receipt{TimeUTC: time.Now().UTC(), EventType: "CDI_ACTION", Decision: string(d.Value), PostureLevel: system_state.PostureLevel})
		return d
	}

	if system_state.StopRequested {
		d := Decision{Value: types.DecisionDeny, Reason: "STOP_DOMINANCE"}
		ledger.Append(audit.Receipt{TimeUTC: time.Now().UTC(), EventType: "CDI_ACTION", Decision: string(d.Value), PostureLevel: system_state.PostureLevel})
		return d
	}

	// Default policy for the stub: allow low-risk processing.
	d := Decision{Value: types.DecisionAllow, Reason: "ALLOW_LOW_RISK_DEFAULT"}
	ledger.Append(audit.Receipt{TimeUTC: time.Now().UTC(), EventType: "CDI_ACTION", Decision: string(d.Value), PostureLevel: system_state.PostureLevel})
	return d
}

func DecideOutput(output types.OIResponse, system_state types.SystemState, ledger *audit.Ledger) Decision {
	// In a real implementation, output is checked for smuggling/leaks.
	d := Decision{Value: types.DecisionAllow, Reason: "ALLOW_OUTPUT_DEFAULT"}
	ledger.Append(audit.Receipt{TimeUTC: time.Now().UTC(), EventType: "CDI_OUTPUT", Decision: string(d.Value), PostureLevel: system_state.PostureLevel})
	return d
}
