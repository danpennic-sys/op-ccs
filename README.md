# op-ccs

Operator Pages cognitive-collapse-survival module.

Deterministic. Evidence-producing. Forced reduction sequence once load threshold is crossed.

**PROOF NOT PROMISE.**

**License:** MIT OR Apache-2.0 (dual). See [LICENSE](LICENSE).

## Purpose

When observable metrics cross threshold, the module forces the locked sequence:

SEE → SET → ACT → VERIFY → RECORD → REPEAT

Any further output without a new pack is invalid.

## Protocol source

SEE step definition and Field Manual / Field Card lock: [`docs/SEE-PROTOCOL.md`](docs/SEE-PROTOCOL.md)

## Interface

See `module.go` for the locked contract.

## Status

Skeleton with test vectors.

- `impl.go`: minimal StubModule (threshold hard-coded for tests only)
- `module_test.go`: below-threshold pass-through, above-threshold ABORT, determinism check

Thresholds and metric definitions must become versioned configuration before any production use.

```bash
go test ./...
```
