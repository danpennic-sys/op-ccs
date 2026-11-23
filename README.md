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

- `impl.go`: minimal StubModule. Zero threshold means missing config (never legitimate). Hash is canonical (sorted keys, no wall-clock or map order in digest). ActionID fixed for determinism in vectors.
- `testdata/vectors.json`: abstract vectors covering forced sequence (including Assess twice and Replay after failed Record), replay determinism (double Replay), boundary fail-closed, and expanded tamper (hash, context, truncate, drop).
- `module_test.go`: table-driven tests from the JSON.
- `.github/workflows/ci.yml`: vet, race tests, go-licenses.

Thresholds and metric definitions must become versioned configuration before any production use.

```bash
go test ./...
go test -race -count=100 ./...
go vet ./...
```

License check (Go):

```bash
go-licenses check ./...
go-licenses report ./...
```

Tag `v0.1.0` to pin the contract for downstream modules.
