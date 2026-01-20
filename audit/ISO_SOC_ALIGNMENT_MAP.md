# ISO / SOC Alignment Map (without diluting semantics)
**Goal:** translate CIF/CDI/OI governance concepts into language auditors recognize, *without rewriting the system as generic compliance theater*.

---

## 1. ISO/IEC 27001:2022 (ISMS) mapping (selected, high-signal)
> Note: ISO 27001 is a management system standard. This repo is primarily a **technical governance specification**. The mapping shows where the spec can generate evidence for ISMS controls.

### A.5 Organizational controls
- **A.5.1 Policies for information security**  
  *Map:* `docs/specs/SPEC.md` and `INVARIANTS.md` define mandatory policies as enforceable obligations.
- **A.5.8 Information security in project management**  
  *Map:* Conformance suite + CI gating ensures security requirements are continuously enforced.

### A.6 People controls
- **A.6.3 Information security awareness, education and training**  
  *Map:* `artifacts/BOOK.md` provides decompression; `CONFORMANCE.md` provides operational checks.
- **A.6.4 Disciplinary process**  
  *Map:* Outside the technical spec; recommend organizational policy referencing conformance failure handling.

### A.8 Technological controls
- **A.8.2 Privileged access rights**  
  *Map:* CDI-issued capability grants; deny-by-default tooling.
- **A.8.5 Secure authentication**  
  *Map:* Capability token signing/verification (implementation requirement).
- **A.8.9 Configuration management**  
  *Map:* Policy versioning; conformance requires explicit versions and rejects unknown/undefined posture states.
- **A.8.12 Data leakage prevention**  
  *Map:* CIF redaction/minimization + output filters.
- **A.8.15 Logging** / **A.8.16 Monitoring activities**  
  *Map:* Audit hooks; optional tamper-evident log anchoring.
- **A.8.24 Use of cryptography**  
  *Map:* Evidence integrity (hash chains/Merkle anchors) and capability signatures (implementation-level).

**Where ISO evidence comes from:** conformance reports, policy version control, build artifacts, and operational runbooks that bind deployments to CIF/CDI invariants.

---

## 2. SOC 2 (AICPA Trust Services Criteria) mapping
SOC 2 focuses on controls for **Security, Availability, Confidentiality, Processing Integrity, Privacy**. The CIF/CDI/OI architecture supports strong evidence for several criteria.

### Security (Common Criteria)
- **CC6 (Logical and physical access controls)**  
  *Map:* CDI as logical control point; tooling via capability grants; deny-by-default access.
- **CC7 (System operations / change management / incident response)**  
  *Map:* Conformance suite + CI; logging hooks; threat model appendix informs incident response inputs.
- **CC8 (Change management)**  
  *Map:* Policy versioning + conformance gating; documented invariants reduce unauthorized drift.

### Availability
- **A1.2 (Capacity and performance monitoring)**  
  *Map:* DoS mitigations in threat model; rate limits/timeouts as implementation obligations.

### Confidentiality
- **C1.1 (Confidential information protection)**  
  *Map:* CIF minimization/redaction; least-privilege tool permissions; output constraints.

### Processing Integrity
- **PI1.1 / PI1.2 (Completeness, validity, accuracy)**  
  *Map:* Deterministic CIF canonicalization; CDI decisions are explainable and testable; conformance tests validate correct routing and halting behavior.

### Privacy (if applicable)
- *Map:* CIF’s data minimization + retention rules (organizational policy + implementation).

---

## 3. Recommended “audit packet” (what to hand an auditor)
1. `docs/specs/SPEC.md`
2. `docs/specs/INVARIANTS.md`
3. `docs/specs/CONFORMANCE.md`
4. `artifacts/PROOF.md` + `artifacts/FORMULA.md`
5. `docs/audit/THREAT_MODEL_APPENDIX.md`
6. `docs/audit/ISO_SOC_ALIGNMENT_MAP.md`
7. Conformance outputs from CI (build + test logs), plus policy version hashes

---

## 4. Key phrase translations (keep meaning, match auditor language)
- **CIF** → “Context integrity control” (input validation + canonicalization + minimization)
- **CDI** → “Policy decision point” (PDP) / “gating control” with explicit outcomes
- **ALLOW/DENY/DEGRADE** → “permit/deny/step-down to safe mode”
- **Invariants** → “non-overridable security/safety constraints”
- **Conformance suite** → “control effectiveness testing” / “continuous control verification”

---

## 5. What not to do (to avoid dilution)
- Don’t rename CIF/CDI into generic “safety layer” language in code.
- Don’t collapse invariants into “best practices.”
- Don’t treat ISO/SOC mapping as a substitute for conformance evidence.
- Don’t claim ISO/SOC compliance without an ISMS/control program and independent audit.

This map is intended to **accelerate** an audit by showing where the architecture already produces strong control evidence when implemented as specified.
