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

## Hash design (tamper-evident)

The outcome hash covers **step | context | input-payload | outcome** (canonical, sorted parts, no wall-clock, no map iteration order).

Input is included so that a mutation to the recorded input after Record is detected by Replay as `ErrTampered`. This is the stronger option for a tamper-evident contract.

Baseline metrics use `float64` (JSON number / IEEE 754). Other implementations must use the same encoding or the hash will differ. Fixed-point or string metrics are preferred for cross-language reuse in production.

## Status

Skeleton with pinned test vectors.

- `impl.go`: minimal StubModule. Zero threshold means missing config (never legitimate). ActionID fixed for determinism in vectors.
- `testdata/vectors.json`: abstract vectors covering forced sequence, replay determinism, boundary fail-closed, and expanded tamper.
- `module_test.go`: table-driven tests from the JSON. Uses `errors.Is` against sentinels. Fails loudly if the pinned hash placeholder remains.
- `.github/workflows/ci.yml`: vet, race tests (-count=100), go-licenses.

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
