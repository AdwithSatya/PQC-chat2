# PQChat

Post-quantum secure chat — see [pqchat-prd-unified.md](pqchat-prd-unified.md) for the
product/design spec (synthesized from three earlier drafts, also kept in this repo).

## Status

**Rollout Phases 0-3 (crypto core, local session, relay, transparency log)
implemented and tested.** Phases 4-5 (physical-device UX/latency
measurement and third-party cryptographic audit) are explicitly not
achievable by an autonomous coding session — see "What's not built" below.

76 tests pass across 9 packages (`go test ./...`).

## Layout

```
crypto/
  identity/    hybrid identity keypair + signatures: Ed25519 + ML-DSA-65 (F1)
  kemhybrid/   hybrid key exchange: X25519 + ML-KEM-768, HKDF-SHA-256 combiner (F2/F3)
  kat/         known-answer tests against official NIST ACVP vectors (Phase 0 exit gate)
  merkle/      shared domain-separated Merkle tree (used by prekey and translog)
  prekey/      Merkle-batch-signed one-time prekeys + signed last-resort prekey (F2/F9/F10)
  ratchet/     Double Ratchet + periodic ML-KEM-768 injection (F4/F5)
  session/     zero-additional-RTT session establishment + wire encoding (F3)

relay/         prekey directory + store-and-forward message queue (Phase 2)
translog/      identity transparency log: signed tree heads, inclusion proofs,
               witness/gossip equivocation detection (Phase 3, F5-F8)
```

Built on [Cloudflare CIRCL](https://github.com/cloudflare/circl) for
ML-KEM-768 / ML-DSA-65, `golang.org/x/crypto/chacha20poly1305` for the
ratchet's AEAD, and Go stdlib `crypto/ecdh` + `crypto/hkdf` (Go 1.24+)
for the classical half and combiners.

## What's built, by phase

- **Phase 0 (crypto core):** hybrid KEM/signature primitives, the HKDF
  combiner, the Double Ratchet with periodic ML-KEM-768 injection, and
  Merkle-batch prekey signing. Exit gate (NIST KAT pass) is `crypto/kat`.
- **Phase 1 (local session):** `crypto/session` ties identity + prekey +
  kemhybrid + ratchet into one-packet session establishment. Exit
  criteria (session-key equality, forward-secrecy key erasure) are
  explicit tests in `crypto/session`.
- **Phase 2 (relay integration):** `relay` is a content-blind
  store-and-forward queue and prekey directory. Exit criteria (offline
  delivery, prekey-depletion chaos test) are `relay/e2e_test.go` and
  `relay/relay_test.go`'s `TestPrekeyDepletionChaos`.
- **Phase 3 (transparency log):** `translog` implements signed tree
  heads, inclusion proofs, and a witness/gossip model for equivocation
  detection. Exit criterion (simulated equivocation detected in an
  adversarial testbed) is `translog/equivocation_test.go`.

## What's not built

- **Phase 4 (UX polish, physical-device latency).** N1/N2 latency
  targets need real mid-tier Android hardware and cellular network
  conditions — not measurable from this environment. No mobile client
  exists; everything above is a Go library plus in-memory/in-process
  servers.
- **Phase 5 (hardening + external audit).** A third-party cryptographic
  audit is, by definition, not something the same process that wrote
  the code can perform. Basic hardening that *is* code (prekey
  depletion defenses, malformed-key rejection) is covered above;
  "passes an external red-team pass" is not a box this repo can check
  itself.
- **Formal verification** (TLA+ model of the ratchet/PQ-injection state
  machine, Tamarin model of the negotiation logic) — named in the PRD
  (§9 risk 2, §12 P1/P3) as necessary before trusting this beyond a
  demo, and not done here.
- Group messaging, multi-device, sealed sender, wire padding, and
  witness governance are all explicitly out of scope per the PRD.

## Running tests

```
go test ./...
```

Notable test-design choices, in case they look surprising:

- **ML-DSA-65 KAT coverage** (`crypto/kat`): NIST's ACVP sigGen/sigVer
  vectors exercise FIPS204's internal signing primitive (no
  context-string wrapping), which CIRCL only exposes internally to its
  own test suite. `crypto/kat` verifies keygen byte-for-byte against
  ACVP, and verifies sign/verify round-trip correctness using
  KAT-derived keys through the same public API `crypto/identity` uses.
  For byte-exact sigGen/sigVer conformance of the underlying primitive:
  ```
  go test github.com/cloudflare/circl/sign/mldsa/mldsa65 -run TestACVP -v
  ```
  (The ML-KEM equivalent needs one extra indirect dependency not added
  to this repo's go.mod; `crypto/kat` already verifies ML-KEM-768
  keygen and encapsulation byte-for-byte against the same vectors.)
- **The ratchet's own doc comment is explicit that PQ-injection-boundary
  races under adversarial scheduling are not proven safe** — the PRD
  names this as the design's hardest open risk and calls for TLA+
  model-checking before trusting it beyond a demo. The tests here cover
  the common in-order and out-of-order-within-a-bounded-window cases,
  not adversarial concurrent scheduling.
- **`go test -race` could not be run** — this Windows environment has
  no C toolchain and `-race` requires cgo. The relay's concurrent
  prekey-depletion test (`TestPrekeyDepletionChaos`, 200 goroutines
  against a 50-key pool) passed without `-race`, but that is not the
  same as a clean race-detector run; treat the concurrency-safety claim
  as inspected-by-hand (single mutex, no unlocked paths), not verified.

## Setup

Requires Go 1.24+ (for stdlib `crypto/hkdf` / `crypto/ecdh`); developed
against Go 1.26.4.
