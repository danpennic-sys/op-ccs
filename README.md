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

The outcome hash is SHA-256 (lowercase hex) over the **JCS-canonical** form (RFC 8785) of a single envelope:

```json
{
  "v": 1,
  "domain": "op-ccs/v1",
  "step": "...",
  "input": <payload bytes as JSON>,
  "context": {"ctx": "stub-context"},
  "outcome": <outcome bytes as JSON>
}
```

- `context` is a JSON **object** (not a string) so Go, Python, and other implementations agree on types.
- Pipeline: marshal envelope → `jcs.Transform` → SHA-256.
- Input is included, so `mutate_input` after Record produces `ErrTampered`.
- `v` and fixed `domain` allow future scheme changes without silent breakage.
- Non-I-JSON values are rejected as `ErrMalformedInput`: NaN, ±Inf, and integers outside ±(2^53 - 1).
- Library: `github.com/gowebpki/jcs` (Apache-2.0). CI `go-licenses` is the authority.

**Limit:** A plain hash provides integrity, not authenticity. Anyone who can edit a record can also recompute a matching hash. The current vectors cover accidental corruption and detectable edits, not an adversary with write access. For authenticity against a hostile party, sign the hash (Ed25519) or use an HMAC with a key held outside the record.

Baseline metrics use `float64`. JCS number serialization is deterministic across compliant implementations. Cross-check with a second language (e.g. Python `rfc8785`) is required before pinning.

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
