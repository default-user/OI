# Governed OI Stack (OI)

A **governance-first Ongoing Intelligence (OI) runtime** that makes powerful capability reachable only through a **single, testable corridor**:

**CIF → CDI → kernel → CDI → CIF**

- **CIF (Context Integrity Firewall):** boundary integrity (sanitize/label inputs; leak-control outputs)
- **CDI (Conscience Decision Interface):** *judge-before-power* decisions (ALLOW / DENY / DEGRADE)
- **kernel:** single execution chokepoint (capability tokens, adapter mediation, audit receipts)

This repo exists to show that governance can be **topology, not tone**: if the corridor holds, the system cannot “accidentally” side-step policy.

---

## Status

- ✅ **Go reference kernel implemented** in `kernel-go/` with unit + integration tests
- ✅ Initial **conformance tests** (e.g., corridor bypass resistance, STOP dominance)
- ✅ Spec, invariants, and formal notation appendix in `docs/specs/`
- ⏭️ Phase 2 (Rust hardening, fuzz/property testing, broader conformance) is described in the spec and `kernel-go/README.md`

---

## Quick start

> Requirements: Go (version per `kernel-go/go.mod`)

```bash
cd kernel-go

# Unit + integration tests
go test ./...

# Race detector
go test -race ./...

# Conformance tests
go test ./tools/conformance/... -v
