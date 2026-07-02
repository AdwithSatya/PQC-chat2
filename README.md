# PQChat

Post-quantum secure chat — see [pqchat-prd-unified.md](pqchat-prd-unified.md) for the
product/design spec (synthesized from three earlier drafts, also kept in this repo).

## Status

**Rollout Phase 0 (crypto core) — in progress.** Per the PRD's rollout plan, no
later phase (session establishment, relay, transparency log, UX) starts
before this phase's primitives are independently verified against NIST
test vectors.

## Layout

```
crypto/
  identity/    hybrid identity keypair + signatures: Ed25519 + ML-DSA-65 (PRD F1)
  kemhybrid/   hybrid key exchange: X25519 + ML-KEM-768, HKDF-SHA-256 combiner (PRD F2/F3)
  kat/         known-answer tests against official NIST ACVP vectors
```

Built on [Cloudflare CIRCL](https://github.com/cloudflare/circl) for
ML-KEM-768 / ML-DSA-65, and Go's stdlib `crypto/ecdh` + `crypto/hkdf`
(Go 1.24+) for the classical half and combiner.

Not yet implemented (later Phase 0 work / later phases): Double Ratchet,
periodic PQ ratchet injection, Merkle-batch prekey signing, the relay
server, and the transparency log.

## Running tests

```
go test ./...
```

This runs:
- Round-trip and tamper-detection tests for both hybrid primitives.
- KAT tests in `crypto/kat` that check our wrapper code against a subset
  of official NIST ACVP vectors (redistributed by CIRCL v1.6.4).

Note on ML-DSA-65 KAT coverage: NIST's ACVP sigGen/sigVer vectors
exercise FIPS204's internal signing primitive (no context-string
wrapping), which CIRCL only exposes internally to its own test suite.
Our `crypto/kat` package therefore verifies keygen byte-for-byte against
ACVP, and verifies sign/verify round-trip correctness using KAT-derived
keys through the same public API `crypto/identity` uses. For byte-exact
sigGen/sigVer conformance of the underlying primitive, run CIRCL's own
suite directly:

```
go test github.com/cloudflare/circl/sign/mldsa/mldsa65 -run TestACVP -v
```

(The equivalent for ML-KEM, `go test github.com/cloudflare/circl/kem/mlkem -run TestACVP`,
currently needs one extra indirect dependency, `golang.org/x/crypto/cryptobyte`,
pulled in only by an unrelated CIRCL subpackage — not added to this
repo's go.mod since our own code doesn't need it. Our `crypto/kat`
suite already verifies ML-KEM-768 keygen and encapsulation byte-for-byte
against the same official vectors.)

## Setup

Requires Go 1.24+ (for stdlib `crypto/hkdf` / `crypto/ecdh`); developed
against Go 1.26.4.
