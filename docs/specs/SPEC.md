# Governed OI Stack — Enterprise Technical Spec
**Target implementer:** Claude Code  
**Primary languages:** Go (Phase 1) → Rust (Phase 2 hardening)  
**Terminology:** Use **CIF / CDI / OI** in code and docs.  
**Naming rule:** All other identifiers should be semantic descriptors (e.g., `user_intent`, `system_state`, `posture_level`, `capability_token`, `audit_receipt`).

---

## 0) WHY (purpose of this spec)
Build a governed corridor for powerful systems: one path to capability, a judge before power, capability mediation, posture gating, and tamper‑evident audit—so governance is topology, not tone.

This spec is optimized to reduce agent thrashing: tight scope, explicit invariants, explicit file layout, explicit tests, explicit non‑goals.

---

## 1) Product shape
### 1.1 What we are shipping
An enterprise-grade governed runtime that implements the corridor:

**CIF → CDI → kernel → CDI → CIF**

Where:
- **CIF**: boundary discipline (sanitize, label, leak-control)
- **CDI**: decision point (ALLOW / DENY / DEGRADE) before any side effect
- **kernel**: single execution chokepoint that:
  - mints scoped capability tokens
  - invokes adapters (model/tool) only with valid tokens
  - logs audit receipts (mechanics, not content)
  - honors STOP dominance (revocation preempts)

### 1.2 Non-goals (explicit)
- Not “alignment” claims.
- Not info-theoretic confidentiality.
- Not protection against physical/firmware/TCB compromise.
- Not “free internet browsing” in oracle mode.
- Not hive behavior: cross‑agent memory smear is forbidden.

---

## 2) Repo layout (monorepo)
```
/docs
  /spec
    SPEC.md
    CONFORMANCE.md
  /adr
  /threat-model

/kernel-go            # Phase 1: Go reference kernel
  /cmd/kernel         # service entry (optional)
  /internal
    /cif
    /cdi
    /kernel
    /adapters
    /capabilities
    /audit
    /memory
    /posture
    /proof            # mechanical proof objects (hashes/receipts), not math proofs
  /pkg                # exported interfaces (stable)

/kernel-rs            # Phase 2: Rust hardening port (same interfaces)
/tools
  /conformance
  /fuzz
  /ci

/CLAUDE.md
```

---

## 3) Load-bearing invariants
### 3.1 Corridor integrity (ONE_PATH_LAW)
No model/tool invocation occurs unless routed through `kernel` and then through a registered adapter with a valid capability token.

### 3.2 Fail-closed (FAIL_CLOSED)
Absence of explicit permission is DENY (or DEGRADE to a strictly weaker lane). Unknowns never become “allowed by default.”

### 3.3 Mediation path (MEDIATION_PATH)
All external I/O is mediated by adapters that:
- verify capability tokens
- verify posture bounds
- append audit receipts for attempts (accept/reject)

### 3.4 STOP dominance (STOP_DOMINANCE)
User STOP or consent revocation:
- revokes all active capability tokens
- preempts in-flight operations
- blocks future side-effects until re-authorized

---

## 4) Core data model (shared between Go and Rust)
### 4.1 State skeleton
`system_state` contains:
- `identity_capsule`
- `authority_capsule`
- `governance_capsule`
- `world_pack`
- `semantic_indexes`
- `profile_store`
- `audit_receipt_ledger`
- `posture_level`
- `active_capability_tokens`
- `adapter_registry`
- `declassification_ledger`
- `integrity_state`

### 4.2 Capability tokens
Minimum fields:
- `issuer`, `subject`, `audience`
- `scope` (allowed operations)
- `limits` (budget / depth / workspace bounds)
- `ttl`, `issued_at`, `expires_at`
- `posture_bounds`
- `namespace_id`, `principal_id`
- `digest`
- `revoked_at`

### 4.3 Audit receipts (mechanics-only)
Record:
- posture declared/changed
- CDI decisions (input + output)
- token mint events (digest only)
- adapter attempts (accept/reject + digest)
- memory writes (partition + scope, not raw content)
- integrity state changes (OK / DEGRADED / VOID)

---

## 5) Canonical corridor pipeline
### 5.1 Mandatory order
1. `cif_ingress(user_intent, system_state) -> labeled_user_request`
2. `cdi_decide(labeled_user_request, system_state) -> decision`
3. If `DENY`: return refusal; **no tokens**, **no calls**
4. If `ALLOW/DEGRADE`:
   - `mint_capability_tokens(decision, labeled_user_request, system_state)`
   - `kernel_execute(labeled_user_request, system_state)`
5. `cdi_decide(output_artifact, system_state) -> output_decision` (ensemble allowed)
6. `cif_egress(output_decision, system_state) -> user_response`
7. `update_state(system_state, user_response) -> next_system_state`
8. return `user_response`

### 5.2 STOP dominance (runtime checks)
- STOP sets `revoked_at`
- every adapter re-checks STOP immediately before side effects

---

## 6) Modules to implement (with WHY protocol)
### 6.1 `/internal/cif`
**Responsibilities**
- input sanitization, taint labeling, size limits
- output leak controls + redaction by leak budget
- instruction-smuggling suppression

**WHY**
Boundary integrity is where “content becomes authority” attacks begin.

### 6.2 `/internal/cdi`
**Responsibilities**
- decide: `{ALLOW, DENY, DEGRADE}`
- fail-closed: unknown/missing prerequisites ⇒ `DENY`
- posture gate enforcement
- decision receipts

**WHY**
Judge-before-power is the central primitive.

### 6.3 `/internal/kernel`
**Responsibilities**
- single chokepoint for any side effect
- mint + verify capability tokens
- dispatch to adapters only
- produce receipts and integrity transitions

**WHY**
One path to power is the architecture.

### 6.4 `/internal/adapters`
**Responsibilities**
- `verify(capability_token, posture_level, workspace_bounds) -> ok/deny`
- `invoke_model(...)` and `invoke_tool(...)` behind the same interface
- deny tokenless calls; no hidden fallbacks

**WHY**
If adapters can be bypassed, governance becomes theater.

### 6.5 `/internal/memory`
Partitions:
- ephemeral
- user-custodied durable
- system commitments
- provenance ledger
- quarantine
- optional evidence store (encrypted + ACL)

**WHY**
Memory is the highest-leverage risk surface.

### 6.6 `/internal/posture`
- posture declaration and transitions
- undefined posture fails closed for high-risk

---

## 7) Go then Rust (rationale)
**Go (Phase 1):** fastest path to a working corridor + tests + conformance suite.  
**Rust (Phase 2):** harden the same interfaces and add differential tests vs the Go reference.

---

## 8) Required deliverables (definition of done)
1. `kernel-go` builds and passes all tests + conformance.
2. CI runs:
   - unit + integration tests
   - fuzz/property tests (bounded)
   - conformance suite (bypass attempts)
3. `kernel-rs` exists with shared interface and at least:
   - capability token verification
   - receipt chain verification
   - adapter exclusivity enforcement
4. Docs complete: `SPEC.md`, `CONFORMANCE.md`, ADRs for meaningful choices.
5. WHY protocol applied:
   - every module has a top-of-file WHY comment
   - every exported function has a brief WHY line if non-obvious

---

## 9) Naming conventions (strict)
- Use `CIF`, `CDI`, `OI` as-is.
- Everything else uses semantic descriptors:
  - `user_intent`, `validated_user_request`, `governance_capsule_status`,
    `requested_operation_risk_class`, `capability_token`, `audit_receipt_ledger`,
    `integrity_state`, `posture_level`, `declassification_ledger`, `quarantine_store`

---

## 10) Security defaults
- oracle mode: internet denied
- tool bus: allowlist only
- default posture: `P1`
- fail-closed everywhere
- no “best-effort invocation”
