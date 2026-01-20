# Formal Notation Appendix

This appendix ties the **formal proof sketch** (`artifacts/PROOF.md`) to:
- the **invariant set** (`docs/specs/INVARIANTS.md`)
- the **enforcement sites** in the reference corridor stub (`kernel-go/...`)

Its job is practical: for any proof statement, an auditor should be able to locate:
1) the corresponding **Invariant ID** (for conformance)
2) the **enforcement site(s)** (where code makes it true)
3) the **evidence hooks** (tests/probes that should exist)

---

## 1) Canonical names and mapping to proof terms

The proof sketch uses some legacy aliases. The canonical repo terms are:

| Canonical term (repo) | Proof-sketch alias in `PROOF.md` | Meaning |
|---|---|---|
| `CIF ingress` | `INPUT_VALIDATION_GATEWAY` | sanitize, size-limit, label/taint |
| `CDI action` | `GOVERNANCE_ACTION_GATEKEEPER` | judge-before-power (ALLOW/DENY/DEGRADE) |
| `kernel` | `SINGLE_EXECUTION_HANDLER` | single chokepoint for side effects |
| `CDI output` | `GOVERNANCE_OUTPUT_GATEKEEPER` | post-handler output decision |
| `CIF egress` | `OUTPUT_SHAPING_GATEWAY` | redaction, leak budget, smuggling suppression |

The canonical corridor is:

```
CIF → CDI → kernel → CDI → CIF
```

---

## 2) Minimal formal model (notation)

### 2.1 State

Let the runtime state be a tuple:

```
S := ⟨ posture_level, governance_capsule_ok, stop_requested, receipt_ledger, active_tokens ⟩
```

In the reference stub this is represented by:
- `pkg/types.SystemState`
- `internal/audit.Ledger`
- `internal/capabilities.CapabilityToken`

### 2.2 Requests and responses

```
R := ⟨ user_intent, user_payload, principal_id, namespace_id ⟩
O := ⟨ body, denied, degraded, reason_code ⟩
```

In the stub these are:
- `pkg/types.OIRequest`
- `pkg/types.OIResponse`

### 2.3 Corridor stages

Define stage functions:

- `CIF_in : (R, S) → (LR, S)` where `LR` is a labeled request
- `CDI_a  : (LR, S) → (D, S)` where `D ∈ {ALLOW, DENY, DEGRADE}`
- `K      : (LR, S, D) → (A, S)` where `A` is an output artifact; **all side effects are here**
- `CDI_o  : (A, S) → (D_out, S)`
- `CIF_out: (A, S, D_out) → (O, S)`

The corridor function is the composition:

```
P(R, S) = CIF_out( A, S4, D_out )
  where
    (LR, S1)     = CIF_in(R, S)
    (D, S2)      = CDI_a(LR, S1)
    if D = DENY then return ( ⟨denied=true⟩, S2 )
    (A, S3)      = K(LR, S2, D)
    (D_out, S4)  = CDI_o(A, S3)
```

### 2.4 Tokens and side effects

Let `E` be the set of external side effects, including model calls, tool calls, and I/O.

A **capability token** `T` is a signed/validated permission artifact with:

```
T := ⟨ issuer, subject, audience, scope, ttl, posture_bounds, digest, revoked_at ⟩
```

A side effect `e ∈ E` is **admissible** only if:

1) it occurs inside `K` (the kernel chokepoint), and
2) it is mediated by an adapter `A_d` that verifies `T`, and
3) a receipt entry is appended that references `T.digest`.

---

## 3) Proof axioms → Invariants → Enforcement

This section is the “bridge” auditors usually want.

### 3.1 Axiom ONE_PATH_LAW

**Proof claim:** All side effects occur only through the governed corridor.

**Mapped invariants:**
- `CI-1 (ONE_PATH_LAW / no side doors)`
- `DI-1 (Judge before power)`

**Enforcement (stub):**
- `kernel-go/internal/kernel/kernel.go` (`ExecuteCorridor` is the only place that calls an adapter)
- `kernel-go/internal/adapters/adapters.go` (adapter requires a token)

**Evidence hooks (stub):**
- `kernel-go/internal/kernel/kernel_test.go` checks that receipts include `CDI_ACTION` before `ADAPTER_OK`.

### 3.2 Axiom FAIL_CLOSED

**Proof claim:** Missing or invalid prerequisites yield DENY (or stricter DEGRADE).

**Mapped invariants:**
- `CI-3 (Fail-closed on corridor break)`
- `DI-2 (DENY is terminal)`

**Enforcement (stub):**
- `kernel-go/internal/cdi/cdi.go` denies when `governance_capsule_ok == false`

**Evidence hooks (stub):**
- `TestFailClosed_MissingGovernanceCapsuleDenies`

### 3.3 Axiom MEDIATION_PATH

**Proof claim:** All external I/O is mediated by registered adapters requiring valid capability tokens.

**Mapped invariants:**
- `CI-2 (No ghost calls)`
- `CI-1 (ONE_PATH_LAW)`

**Enforcement (stub):**
- `kernel-go/internal/capabilities/capabilities.go` token mint and digest
- `kernel-go/internal/adapters/adapters.go` rejects revoked/expired tokens
- `kernel-go/internal/audit/audit.go` receipts record token digests

**Evidence hooks (stub):**
- `TestPipelineOrder_ProducesReceipts` expects `TOKEN_MINT` and `ADAPTER_OK`

### 3.4 Axiom STOP_DOMINANCE

**Proof claim:** STOP or consent revocation preempts and prevents further side effects until re-authorized.

**Mapped invariants:**
- `CI-3 (Fail-closed on corridor break)`
- `DI-2 (DENY is terminal)`

**Enforcement (stub):**
- `kernel-go/internal/cdi/cdi.go` denies when `stop_requested == true`
- (Production: token revocation and in-flight preemption belong in `internal/kernel/*` and adapter re-checks)

**Evidence hooks (stub):**
- Extend with a STOP test once revocation bookkeeping is added to `SystemState`.

---

## 4) What is intentionally out of scope for the stub

The stub is an existence proof of the corridor shape. It does not yet implement:
- cryptographic signing and verification of capsules
- receipt chain hashing and anchoring
- posture lattice comparisons
- real CIF sanitization, redaction, leak budgets, or smuggling detection
- real adapter integrations (vendor model APIs, tools)

Those belong to the production phases, but this appendix stays stable: it is the mapping layer between formal claims and enforcement sites.
