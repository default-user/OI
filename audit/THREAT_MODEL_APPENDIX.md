# Threat Model Appendix
**Purpose:** enumerate threats and residual risks in a procurement/audit-friendly way without diluting the CIF/CDI/OI semantics.

---

## A. System boundary and trust assumptions
### In-scope boundary (governed path)
- **CIF_IN**: ingestion + canonicalization + integrity checks for context
- **CDI**: compliance decision (ALLOW / DENY / DEGRADE)
- **Governed execution**: only permitted actions proceed
- **Audit hooks**: decision records, conformance evidence, optional tamper-evident logging

### Out-of-scope (explicit)
- Compromised OS / hypervisor / firmware / supply chain compromise of TCB
- Physical side channels, covert channels below chosen thresholds
- Coercion of operators/administrators outside governance process
- Arbitrary misbehavior of untrusted ML models beyond governed interface constraints

---

## B. Assets to protect
1. **Invariant integrity**: unreachable states remain unreachable
2. **Decision integrity**: CDI outcomes cannot be forged or bypassed
3. **Context integrity**: CIF prevents tainted/poisoned context from entering governed path
4. **Audit integrity**: evidence is complete, ordered, and attributable
5. **Authority model**: the designated authority can veto/stop within governance envelope

---

## C. Threat actors
- External attacker (network/tooling input)
- Malicious or compromised plugin/tool
- Insider with repo access (developer, operator, CI maintainer)
- Supply-chain adversary (dependencies, build system)
- Coercive actor (legal/physical pressure on staff)

---

## D. Attack surfaces
1. **Input channels**: user prompts, API inputs, file ingestion
2. **Tool / adapter layer**: any actuator / connector / extension mechanism
3. **Model boundary**: prompt injection, jailbreak attempts, model-spec exploitation
4. **Build/CI pipeline**: dependency poisoning, artifact substitution
5. **Logging / storage**: evidence deletion, tampering, selective omission
6. **Runtime configuration**: flags that loosen governance checks

---

## E. Threats (STRIDE-style) and required mitigations
### E1. Spoofing (identity / authority)
**Threat:** attacker impersonates authority, subsystem, or trusted tool.  
**Mitigations:**
- Capability tokens / signed requests for tool invocation
- Clear authority identifiers; reject ambiguous provenance
- Deny-by-default on missing provenance

### E2. Tampering (inputs / code / logs)
**Threat:** bypass CIF, alter CDI rules, or alter audit evidence.  
**Mitigations:**
- Single chokepoint enforcement: all paths must pass CIF→CDI
- Conformance tests include bypass attempts and negative cases
- Optional: hash-chained event log / Merkle anchoring for evidence

### E3. Repudiation (denying actions)
**Threat:** actor denies having performed/approved an action.  
**Mitigations:**
- Receipts tied to decision + inputs + policy version
- Immutable build metadata (commit hash, build ID)
- Separation of duties in CI approvals (where applicable)

### E4. Information disclosure (secrets / sensitive context)
**Threat:** context leaks via prompts, tools, logs, or model responses.  
**Mitigations:**
- CIF redaction rules + minimization
- Output filtering on sensitive classes
- Least-privilege tool capabilities; strict data egress policies

### E5. Denial of service (DoS)
**Threat:** adversary forces excessive governance checks or pathological inputs.  
**Mitigations:**
- Input size limits, timeouts, and early denial for malformed context
- Deterministic evaluation bounds for CDI
- Rate limiting at the gateway edge

### E6. Elevation of privilege (capability escalation)
**Threat:** tool execution beyond intended posture/permissions; “shadow path” that acts without CDI.  
**Mitigations:**
- One true execution path enforced at runtime and compile time
- Tool adapters require CDI-issued capability grants
- Conformance suite explicitly tests for unauthorized tool activation

---

## F. Key failure modes to test (minimum set)
1. Prompt injection attempting to override CIF rules
2. “Direct tool call” attempts that bypass CDI
3. Policy-version mismatch (stale CDI rules)
4. Unknown/undefined posture state (must degrade/deny)
5. Evidence deletion or partial logging (must be detectable or fail-closed)
6. Dependency substitution in CI (supply chain controls)

---

## G. Residual risks (must be acknowledged)
- **TCB compromise** can invalidate invariants in practice: mitigated only by hardened platforms, measured boot, secure enclaves, and operational controls.
- **Below-threshold covert channels**: mitigated by monitoring and strict output constraints; not fully eliminable.
- **Sophisticated insider coercion**: mitigated by governance process, separation of duties, and external anchoring of evidence.
- **Correlated dual implementation bugs**: mitigated by fuzzing, independent re-implementation, and conformance tests that are adversarial.

---

## H. Evidence expectations (what to produce)
To claim real compliance, produce:
- Conformance report outputs (CI artifacts)
- Policy versioning and changelog
- Bypass test results (negative tests)
- Optional: tamper-evident log anchors + verification instructions
