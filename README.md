# op-ccs

Operator Pages cognitive-collapse-survival module.

Deterministic. Evidence-producing. Forced reduction sequence once load threshold is crossed.

**PROOF NOT PROMISE.**

**License:** MIT OR Apache-2.0. See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).

## Purpose

When observable metrics cross threshold, the module forces the locked sequence:

SEE → SET → ACT → VERIFY → RECORD → REPEAT

Any further output without a new pack is invalid.

## Protocol source

SEE step definition and Field Manual / Field Card lock: [`docs/SEE-PROTOCOL.md`](docs/SEE-PROTOCOL.md)

## Interface

See `module.go` for the locked contract.

## Status

Skeleton with pinned test vectors.

- `impl.go`: minimal StubModule with defined errors for order, boundary, and tamper cases
- `testdata/vectors.json`: abstract vectors (no thresholds or metric definitions exposed)
- `module_test.go`: table-driven tests covering forced sequence, replay determinism, boundary fail-closed, and tamper

Thresholds and metric definitions must become versioned configuration before any production use.

```bash
go test ./...
```

License check (Go):

```bash
go-licenses check ./...
go-licenses report ./...
```
