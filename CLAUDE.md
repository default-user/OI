# CLAUDE.md — Working Agreement for This Repository
This file guides Claude Code to work effectively in this repo with minimal thrash.

## 0) Ground rules
- **Plan first, then act.** Propose a concrete plan before edits; keep it small and verifiable.
- **One change-set at a time.** Avoid multi-module refactors unless explicitly required by failing tests.
- **Run tests early and often.** Prefer small diffs that keep CI green.
- **WHY protocol is mandatory.** Every module has a top-of-file WHY comment; exported functions get a brief WHY line when non-obvious.
- **Terminology rule:** use `CIF`, `CDI`, `OI` in code and docs. Do not replace those three with semantic-descriptor encodings.
- **Naming rule:** everything else uses semantic descriptors (`user_intent`, `system_state`, `posture_level`, `capability_token`, etc).

## 1) Quick start commands
### Go
- Unit tests: `go test ./...`
- Race: `go test -race ./...`
- Lint: `golangci-lint run`

### Rust (Phase 2)
- Tests: `cargo test`
- Lint: `cargo clippy`

### Conformance suite
- `go test ./tools/conformance/...` (or the repo’s conformance runner script if present)

## 2) What to build (core corridor)
Implement the canonical corridor:

**CIF → CDI → kernel → CDI → CIF**

- No side effects before `CDI` decision.
- No model/tool calls outside adapters inside `kernel`.
- No adapter accepts a tokenless call.
- STOP revokes capability tokens and preempts in-flight operations.

## 3) Where things live
- Spec: `/docs/spec/SPEC.md`
- Conformance: `/docs/spec/CONFORMANCE.md`
- Go reference kernel: `/kernel-go/internal/...`
- Rust hardening port: `/kernel-rs/...`
- Conformance tools: `/tools/conformance/...`

## 4) Implementation priorities (minimize thrash)
1. **Go corridor skeleton** that compiles.
2. **Capability token** mint/verify + TTL + posture bounds + STOP invalidation.
3. **Adapter registry** + adapter verify gate (reject tokenless).
4. **Audit receipt chain** (append-only hash chain) + verification tests.
5. **Conformance tests** (C1–C8) with at least one test per category.
6. Only then start Rust port + differential tests.

## 5) Definition of done for a PR
- Adds or changes a single coherent feature.
- Includes tests proving the behavior.
- Updates docs only when behavior changes.
- Keeps CI green.

## 6) Forbidden shortcuts
- Direct vendor/model/tool invocation outside adapters.
- “Temporary” debug bypass switches.
- Best-effort invocation when prerequisites missing (must fail closed).
- Storing raw content in audit logs by default.

## 7) When uncertain
Prefer to:
- add a failing test that captures the intended invariant
- implement the smallest code change to make it pass
- document the WHY succinctly
