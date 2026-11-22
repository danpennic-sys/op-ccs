# op-ccs

Operator Pages cognitive-collapse-survival module.

Deterministic. Evidence-producing. Forced reduction sequence once load threshold is crossed.

**PROOF NOT PROMISE.**

## Purpose

When observable metrics cross threshold, the module forces:

1. SEE — record current metrics and constraints
2. SET — strip to minimal next action inside locked sequences
3. ACT | DEFER | ABORT — one choice only, recorded
4. VERIFY — confirm constraints and no open generation
5. RECORD — emit evidence pack

Any further output without a new pack is invalid.

## Interface

See `module.go` for the locked contract.

## Status

Skeleton with test vectors.

- `impl.go`: minimal StubModule (threshold hard-coded for tests only)
- `module_test.go`: below-threshold pass-through, above-threshold ABORT, determinism check

Thresholds and metric definitions must become versioned configuration before any production use.

Aligned with Operator Desk sequence: SEE → SET → ACT → VERIFY → RECORD → REPEAT.

```bash
go test ./...
```
