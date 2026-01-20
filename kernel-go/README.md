# Governed OI Kernel - Go Reference Implementation

## WHY

This is the Phase 1 reference implementation of the Governed OI Stack in Go. It implements the canonical corridor: **CIF → CDI → kernel → CDI → CIF**, proving that governance can be topology, not tone.

## Status

✅ **Core corridor implemented and tested**
- All major invariants (CI, DI, AI, BI, MI, PI, AU, SD) have passing tests
- Conformance tests for C1 (corridor bypass) and C7 (STOP dominance) implemented
- 40+ unit and integration tests passing
- Race detector clean

## Architecture

```
CIF (Boundary)          CDI (Decision)         Kernel (Execution)
    ↓                        ↓                        ↓
Ingress                  ALLOW/                 Capability
Sanitize                DENY/                   Token Mint
Label                   DEGRADE                      ↓
    ↓                        ↓                   Adapter
    └────────────────────────┴───────────────→  Invocation
                                                     ↓
                                                  Audit
                                                  Receipt
```

## Quick Start

```bash
# Run all tests
go test ./...

# Run with race detector
go test -race ./...

# Run conformance tests
go test ./tools/conformance/... -v

# Run specific module tests
go test ./internal/kernel -v
go test ./internal/adapters -v
```

## Modules

### `/internal/kernel`
**WHY**: Single execution chokepoint - no side effects outside this path.

- `state.go`: System state management
- `pipeline.go`: Canonical corridor implementation (CIF→CDI→kernel→CDI→CIF)

### `/internal/capabilities`
**WHY**: Capability tokens are the authorization primitive.

- `token.go`: Token minting, verification, TTL, posture bounds, STOP revocation

### `/internal/adapters`
**WHY**: All model/tool calls go through adapters with token verification.

- `registry.go`: Adapter registration and invocation chokepoint
- `mock_adapter.go`: Test adapter for proving corridor enforcement

### `/internal/cdi`
**WHY**: Judge-before-power - decision happens before any side effect.

- `decision.go`: ALLOW/DENY/DEGRADE decision engine with fail-closed logic

### `/internal/cif`
**WHY**: Boundary integrity prevents content-becomes-authority attacks.

- `ingress.go`: Input sanitization, taint labeling, injection detection
- `egress.go`: Output control, leak budgets, redaction

### `/internal/audit`
**WHY**: Tamper-evident chain provides governance accountability.

- `ledger.go`: Append-only hash-chained audit receipts (mechanics-only, no raw content)

### `/internal/memory`
**WHY**: Memory partitioning prevents persistence-based attacks.

- `manager.go`: Partitioned memory (ephemeral, durable, commitments, quarantine, provenance, evidence)

### `/internal/posture`
**WHY**: Posture levels provide graduated constraint.

- `posture.go`: Posture state machine (P0-P4, higher = more restrictive)

## Invariants Proven

### Corridor Integrity (CI)
- ✅ CI-1: ONE_PATH_LAW - no side doors (tested in `adapters/registry_test.go`)
- ✅ CI-2: No ghost calls - every invocation has token + posture (tested in `adapters/registry_test.go`)
- ✅ CI-3: Fail-closed on corridor break (tested in `cdi/decision_test.go`, `kernel/pipeline_test.go`)

### Decision Integrity (DI)
- ✅ DI-1: Judge before power (tested in `kernel/pipeline_test.go`)
- ✅ DI-2: DENY is terminal (tested in `cdi/decision_test.go`, `kernel/pipeline_test.go`)
- ✅ DI-3: DEGRADE is weaker (tested in `cdi/decision_test.go`)

### Audit Integrity (AU)
- ✅ AU-1: Mechanics-only audit (tested in `audit/ledger_test.go`)
- ✅ AU-2: Tamper-evident chain (tested in `audit/ledger_test.go`)

### Memory Integrity (MI)
- ✅ MI-1: Partition discipline (tested in `memory/manager_test.go`)
- ✅ MI-2: Custody respect (tested in `memory/manager_test.go`)
- ✅ MI-3: Quarantine non-truth (tested in `memory/manager_test.go`)

### STOP Dominance (SD)
- ✅ SD-1: Revocation supremacy (tested in `kernel/pipeline_test.go`, conformance C7)

## Conformance Tests

### C1 - Corridor Bypass (`tools/conformance/C1_corridor_bypass`)
- ✅ Direct SDK call without token rejected
- ✅ Tokenless adapter invocation rejected
- ✅ Monkeypatch attempts fail
- ✅ No hidden fallback paths

### C7 - STOP Dominance (`tools/conformance/C7_stop_dominance`)
- ✅ STOP revokes all active tokens
- ✅ Revoked tokens cannot be replayed
- ✅ Adapters recheck STOP before operations
- ✅ No post-STOP side effects
- ✅ STOP events are audited

## Test Coverage

```
internal/adapters:     7/7 tests passing
internal/audit:        6/6 tests passing
internal/cdi:          7/7 tests passing
internal/kernel:       7/7 tests passing
internal/memory:       7/7 tests passing
conformance/C1:        4/4 tests passing
conformance/C7:        5/5 tests passing
```

## Key Design Decisions

1. **Fail-closed everywhere**: Missing governance → DENY, undefined posture → DENY for high-risk
2. **Token-gated adapters**: No invocation without valid, unexpired, unrevoked capability token
3. **Mechanics-only audit**: Hash-chained receipts contain digests, not raw content by default
4. **STOP dominance**: Revocation preempts in-flight operations and prevents future side-effects
5. **Posture inversion**: Higher posture = more constraint, not more freedom

## Running CI Locally

```bash
# Unit tests
go test ./...

# Race detector
go test -race ./...

# Conformance
go test ./tools/conformance/... -v

# Lint (requires golangci-lint)
golangci-lint run
```

## Next Steps (Phase 2)

- [ ] Implement remaining conformance categories (C2-C6, C8)
- [ ] Add property-based testing
- [ ] Bounded fuzz testing
- [ ] Rust hardening port
- [ ] Differential testing Go vs Rust
- [ ] Production-grade CIF instruction detection
- [ ] Real adapter implementations (model/tool)

## References

- Spec: `/docs/specs/SPEC.md`
- Conformance: `/docs/specs/CONFORMANCE.md`
- Invariants: `/docs/specs/INVARIANTS.md`
- Working Agreement: `/CLAUDE.md`
