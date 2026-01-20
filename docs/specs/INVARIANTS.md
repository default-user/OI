# Governed OI Stack — Invariants Map
This document is the *load-bearing bridge* between the spec and the test suite:
- **Invariant**: what must always hold
- **Enforcement**: where the code makes it true
- **Evidence**: which tests + conformance probes prove it

> Placement: save this as `docs/spec/INVARIANTS.md` alongside `SPEC.md` and `CONFORMANCE.md`.

---

## 0) Naming + scope
- **CIF / CDI / OI** are first-class terms and may appear as identifiers.
- Everything else uses semantic descriptor identifiers (`user_intent`, `system_state`, `posture_level`, `capability_token`, etc.).
- “Enforcement sites” below are *module paths*, not strict filenames—adapt to your repo layout, but keep the same module responsibilities.

---

## 1) Invariant families

### CI — Corridor Integrity
**CI-1 (ONE_PATH_LAW / no side doors)**  
**Claim:** No model/tool side-effect occurs unless the request traverses the canonical corridor:
**CIF → CDI → kernel → CDI → CIF**, and all side-effects occur only inside `kernel` via adapters.

**Enforcement**
- `internal/kernel/*` (single chokepoint; no side-effect utilities exported elsewhere)
- `internal/adapters/*` (token-required, refuse tokenless)
- `internal/cif/*` and `internal/cdi/*` (sealed pipeline tokens / stage gating)
- Build-time: forbid vendor SDK usage outside adapters (lint rule)

**Evidence**
- Unit: `TestKernelRejectsDirectAdapterCallWithoutToken`
- Unit: `TestAdapterRefusesTokenlessInvocation`
- Conformance: `C1_corridor_bypass/*` (direct SDK call attempts, tokenless adapter calls, monkeypatch attempts)
- Static: `forbid_vendor_clients_outside_adapters` linter

---

**CI-2 (No ghost calls)**  
**Claim:** Every invocation is attributable to a minted `capability_token` and a declared `posture_level`.

**Enforcement**
- `internal/cdi/*` (decision receipts include posture)
- `internal/capabilities/*` (mint binds posture + scope + ttl + workspace)
- `internal/audit/*` (receipt includes token digest + posture snapshot)
- `internal/adapters/*` (verify posture bounds and token digest pre-call)

**Evidence**
- Unit: `TestEveryAdapterInvocationHasReceiptAndTokenDigest`
- Property: `Prop_NoInvocationWithoutPosture`
- Conformance: `C1_corridor_bypass/ghost_calls`

---

**CI-3 (Fail-closed on corridor break)**  
**Claim:** Missing/invalid prerequisites => no side effects; system degrades or refuses.

**Enforcement**
- `internal/cdi/*` (unknown => DENY; missing governance => DENY)
- `internal/kernel/*` (refuse if audit sink missing for high-risk postures)
- `internal/posture/*` (undefined posture => fail-closed for high-risk)

**Evidence**
- Unit: `TestMissingGovernanceCapsuleDenies`
- Unit: `TestUndefinedPostureDeniesHighRisk`
- Conformance: `C8_misconfiguration/*` (missing audit sink, disabled registry, missing posture)

---

### DI — Decision Integrity
**DI-1 (Judge before power)**  
**Claim:** CDI decision happens *before* any side effect.

**Enforcement**
- `internal/kernel/pipeline.go` / `pipeline.rs` (pipeline order is fixed; no adapter calls pre-CDI)
- `internal/adapters/*` (require token minted only after CDI)

**Evidence**
- Unit: `TestNoAdapterCallBeforeCDIDecision`
- Trace test: `TestPipelineOrder_CIF_CDI_kernel_CDI_CIF`
- Conformance: `C3_judge_evasion/pre_call_attempts`

---

**DI-2 (DENY is terminal)**  
**Claim:** A DENY decision cannot be bypassed.

**Enforcement**
- `internal/kernel/*` (DENY returns refusal; no token mint; no call)
- `internal/adapters/*` (no token => deny)

**Evidence**
- Unit: `TestDenyMintsNoTokens`
- Conformance: `C3_judge_evasion/deny_bypass`

---

**DI-3 (DEGRADE is strictly weaker)**  
**Claim:** DEGRADE grants a strict subset of ALLOW (scope, ttl, posture bounds, ops).

**Enforcement**
- `internal/capabilities/*` (degrade token constructor enforces subset)
- `internal/cdi/*` (degrade mapping is monotonic)
- `internal/adapters/*` (refuse ops outside scope)

**Evidence**
- Unit: `TestDegradeTokenIsSubsetOfAllow`
- Property: `Prop_DegradeMonotonicity`
- Conformance: `C3_judge_evasion/degrade_inflation`

---

### AI — Authority Integrity
**AI-1 (Content ≠ authority)**  
**Claim:** Untrusted text cannot mutate authority model, governance rules, or commitments.

**Enforcement**
- `internal/cif/*` (taint labels; blocks “instruction-as-data” from becoming policy)
- `internal/memory/*` (system commitment partition write requires signed update ritual)
- `internal/kernel/*` (no path from user_text to policy mutation without explicit capability)

**Evidence**
- Unit: `TestUntrustedTextCannotWriteCommitmentsPartition`
- Conformance: `C2_authority_smuggling/*` (system prompt impersonation, escalation language)
- Fuzz: `Fuzz_AuthoritySmugglingPayloads`

---

**AI-2 (No authority escalation by persuasion)**  
**Claim:** Tone/urgency cannot grant privileges.

**Enforcement**
- `internal/cdi/*` (permission checks are structural; ignore rhetorical pressure)
- `internal/posture/*` (confirmation rituals and posture gates)

**Evidence**
- Conformance: `C2_authority_smuggling/pressure_loops`
- Golden: `Goldens_RefusalStability_UnderParaphrase`

---

**AI-3 (No silent policy mutation)**  
**Claim:** Commitments only change by explicit, logged, signed update ritual; mismatch => degrade/deny.

**Enforcement**
- `internal/proof/*` (commitment digest checks)
- `internal/audit/*` (integrity state transitions logged)
- `internal/cdi/*` (mismatch => DENY for high-risk)

**Evidence**
- Unit: `TestUnsignedCommitmentUpdateRejected`
- Conformance: `C8_misconfiguration/policy_mismatch`

---

### BI — Boundary Integrity
**BI-1 (Ingress sanitization & labeling)**  
**Claim:** Inputs are sanitized and taint-labeled; injection patterns cannot become authority.

**Enforcement**
- `internal/cif/ingress.*` (schema, size, injection/taint, sensitivity labels)

**Evidence**
- Unit: `TestCIFIngressLabelsTaintAndSensitivity`
- Fuzz: `Fuzz_CIFIngress_InjectionPayloads`
- Conformance: `C2_authority_smuggling/instruction_in_data`

---

**BI-2 (Egress hygiene & leak budgets)**  
**Claim:** Outputs respect redaction and leak budgets; sensitive egress requires explicit declassify mechanism.

**Enforcement**
- `internal/cif/egress.*` (redaction, leak budget enforcement)
- `internal/declassification/*` (explicit, logged widening)

**Evidence**
- Unit: `TestCIFEgressRedactsOverBudget`
- Conformance: `C4_leakage/*` (indirect leakage, tool-output leakage)
- Probe: `LeakBudget_Conformance_Probes`

---

**BI-3 (No instruction smuggling)**  
**Claim:** Output cannot contain bypass instructions or payloads intended to subvert downstream systems.

**Enforcement**
- `internal/cif/egress.*` (smuggling detectors; policy)
- `internal/cdi/*` (output CDI pass)

**Evidence**
- Golden: `Goldens_NoBypassInstructions`
- Conformance: `C4_leakage/instruction_smuggling`

---

### MI — Memory Integrity
**MI-1 (Partition discipline)**  
**Claim:** Every write declares a partition; partitions have allowed ops.

**Enforcement**
- `internal/memory/*` (typed partitions, access policy)
- `internal/kernel/*` (write operations require capability + CDI allow)

**Evidence**
- Unit: `TestMemoryWriteRequiresPartitionAndPolicy`
- Conformance: `C5_memory_poisoning/partition_violations`

---

**MI-2 (Custody respect)**  
**Claim:** Durable user-custodied memory can’t be exfiltrated or repurposed outside consented scopes.

**Enforcement**
- `internal/memory/*` (custody boundaries)
- `internal/cif/egress.*` (redaction by custody flags)

**Evidence**
- Conformance: `C4_leakage/memory_exfiltration`
- Unit: `TestCustodiedMemoryCannotBeReadWithoutCapability`

---

**MI-3 (Quarantine non-truth)**  
**Claim:** Quarantined content is never promoted without explicit verification ritual.

**Enforcement**
- `internal/memory/quarantine.*` (promotion requires verification record + capability)
- `internal/audit/*` (promotion logged)

**Evidence**
- Unit: `TestQuarantinePromotionRequiresVerification`
- Conformance: `C5_memory_poisoning/promotion_attempts`

---

### PI — Posture Integrity
**PI-1 (Declared posture required)**  
**Claim:** High-risk capability requires explicit posture; missing posture => fail closed.

**Enforcement**
- `internal/posture/*` (posture state machine)
- `internal/cdi/*` (posture gating)
- `internal/kernel/*` (refuse if posture undefined for high-risk route)

**Evidence**
- Unit: `TestHighRiskRequiresPosture`
- Conformance: `C6_posture_violations/undefined_posture`

---

**PI-2 (Posture narrows autonomy)**  
**Claim:** Higher posture means more constraint, not more freedom.

**Enforcement**
- `internal/posture/*` (capability policy maps posture to constraints)
- `internal/capabilities/*` (mint checks posture limits)

**Evidence**
- Property: `Prop_PostureMonotoneConstraints`
- Conformance: `C6_posture_violations/posture_spoofing`

---

### AU — Audit Integrity
**AU-1 (Mechanics-only audit)**  
**Claim:** Audit logs record governance mechanics without raw user content by default.

**Enforcement**
- `internal/audit/*` (receipt schema excludes raw payloads)
- `internal/kernel/*` (logs are append-only)

**Evidence**
- Unit: `TestAuditReceiptsContainNoRawUserContentByDefault`
- Conformance: `C8_misconfiguration/audit_schema_violation`

---

**AU-2 (Tamper-evident chain)**  
**Claim:** Receipts are hash-chained; any tamper breaks verification and forces integrity degradation/fail-closed.

**Enforcement**
- `internal/audit/receipt_chain.*` (prev_hash, sequence, signature/HMAC)
- `internal/kernel/heartbeat.*` (periodic verify; on fail => integrity change)

**Evidence**
- Unit: `TestReceiptChainDetectsModification`
- Property: `Prop_ReceiptChainUnforgeableWithoutKey`
- Conformance: `C8_misconfiguration/receipt_chain_tamper`

---

### SD — STOP Dominance
**SD-1 (Revocation supremacy)**  
**Claim:** STOP revokes all tokens and preempts in-flight operations; post-STOP side effects are impossible.

**Enforcement**
- `internal/authority/*` (STOP state, `revoked_at`)
- `internal/capabilities/*` (token verify checks `revoked_at`)
- `internal/adapters/*` (re-check STOP pre-call)

**Evidence**
- Unit: `TestStopRevokesAllTokens`
- Integration: `TestStopPreemptsInFlight`
- Conformance: `stop_preemption_tests/*`

---

## 2) Traceability checklist (how to use this file)
When adding a feature:
1. Identify which invariants it touches (above).
2. Add at least one unit/integration test under the invariant’s evidence list.
3. Add/extend a conformance probe if it expands the attack surface.
4. Add an enforcement note in the relevant module’s top-of-file **WHY** comment.

---

## 3) Minimum test naming conventions
- Unit tests: `Test<InvariantOrModule>_<Behavior>`
- Property tests: `Prop_<InvariantName>`
- Fuzz tests: `Fuzz_<Surface>_<Class>`
- Conformance folders: `C1_...` through `C8_...` matching `CONFORMANCE.md`

---

## 4) “Done” definition for invariants
A release is acceptable when:
- every invariant has at least one passing unit/integration test,
- every conformance category has at least one probe,
- corridor bypass probes are green,
- STOP dominance probes are green,
- receipt chain tamper probes are green.
