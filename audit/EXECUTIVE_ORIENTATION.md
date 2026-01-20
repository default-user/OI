# Executive Orientation (One Page)
**Audience:** buyers, auditors, institutional reviewers  
**Scope:** This repository is a *governance-grade specification artifact* for an **Ongoing Intelligence (OI)** system. It is not a product demo. It is the minimum coherent set of documents required to evaluate *integrity, enforceability, and auditability* of an OI governance stack.

---

## What this is
An **OI** (in this design) is a structured, governed, thread‑tending system that maintains partitioned state and commitments over time under an explicit authority model. The repo expresses that design via:
- **SPEC**: obligations and interfaces (what must exist)
- **INVARIANTS**: non‑negotiable safety/governance constraints (what must never be reachable)
- **CONFORMANCE**: how compliance is measured (how you know it’s real)
- **PROOF / FORMULA**: integrity argument and compact formal flow (why the claims hold in‑scope)
- **CRYSTAL / BOOK**: semantic nucleus and narrative decompression (how to understand and implement without drift)

---

## What integrity claim is being made (and what is not)
**Claim (in-scope):**  
If an implementation conforms to SPEC, enforces INVARIANTS, and passes CONFORMANCE tests, then within the modelled boundary the system fails closed: **non‑compliant states are not reachable via the governed interface.**

**Non-claims (out-of-scope by design):**
- “Perfect safety” or “alignment solved”
- elimination of physical/firmware side channels
- immunity to compromised trusted computing base (TCB)
- guarantees about an untrusted model’s internal reasoning

---

## Core governance flow (plain language)
1. **CIF (Context Integrity Firewall)** canonicalizes and constrains incoming context.
2. **CDI (Compliance Decision Interface)** evaluates obligations and returns **ALLOW / DENY / DEGRADE**.
3. If non‑ALLOW, execution **halts** with an auditable denial/degrade outcome.
4. If ALLOW, permitted computation proceeds under governed constraints and produces outputs plus audit material (receipts/log hooks).

This is a “governed choke point” design: there is exactly one approved path from input to action.

---

## What an auditor should look for
1. **Single path invariance:** no code path or tool path can bypass CIF→CDI.
2. **Fail-closed behavior:** undefined/uncertain states degrade or deny; never “best guess” into high risk.
3. **Traceability:** every decision is explainable by artifacts (SPEC/INVARIANTS) and test evidence (CONFORMANCE).
4. **Boundary honesty:** explicit handling of residual risk classes (TCB compromise, covert channels, coercion).

---

## What a buyer gets
- A high-signal **governance capsule** that can be implemented in Rust/Go (or other systems languages) and audited.
- A certification-ready separation of: **requirements**, **invariants**, **tests**, **integrity argument**.
- A structure designed for procurement: “show me the obligations, show me the invariants, show me the evidence.”

---

## What you would build to realize it
A minimal reference implementation typically includes:
- CIF module (context parsing/canonicalization + integrity checks)
- CDI module (rule engine / policy evaluator; deterministic outcomes)
- Event log + receipt hooks (tamper-evident logging optional but recommended)
- Conformance suite (must run in CI; includes bypass/negative tests)

---

## How to proceed as an evaluator
1. Read `docs/specs/SPEC.md` (obligations).
2. Read `docs/specs/INVARIANTS.md` (non-negotiables).
3. Read `docs/specs/CONFORMANCE.md` (how to test it).
4. Read `artifacts/PROOF.md` + `artifacts/FORMULA.md` (integrity argument).
5. Use the Threat Model Appendix and the ISO/SOC mapping (in this folder) to align with your compliance program.
