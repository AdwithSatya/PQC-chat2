# PRD: PQChat — Post-Quantum Messenger with Default-On Identity Verification

**Status:** v1.0 — all architectural decisions locked; no open design questions
**Owner/architect:** Claude (all decisions made per requester instruction)
**Date:** 2026-07-02
**Honest positioning:** state-of-the-art synthesis of deployed techniques plus one novel default. Not a claimed historical advancement — that label is earned post-deployment, post-audit, or not at all.

---

## 1. The thesis

Every deployed end-to-end messenger has the same two weakest links, and neither is an encryption algorithm:

1. **Harvest-now-decrypt-later:** classical key exchanges recorded today are readable by a future quantum adversary. Solved technology exists (hybrid PQC); it just has to be applied without wrecking latency.
2. **Identity verification theater:** safety numbers exist in Signal and WhatsApp, and effectively nobody compares them. In practice, billions of "verified encrypted" conversations rest on trust-on-first-use against the very server being trusted not to attack.

PQChat's design bet: fix (1) with the now-standard hybrid construction, and fix (2) by moving identity verification from an optional human ritual to a **default-on, automatic key-transparency check** — the client refuses to treat an identity as clean unless it appears consistently in a publicly auditable, append-only log. The user does nothing; the check happens anyway.

That second item is the differentiator. Everything else in this document is disciplined engineering of known techniques.

---

## 2. Threat model (drives every requirement; anything not traceable here was cut)

| # | Adversary capability | v1 stance |
|---|---|---|
| T1 | Passive network eavesdropping, now | Defeated (E2E encryption) |
| T2 | Record ciphertext now, decrypt with quantum computer later | Defeated (hybrid PQC key exchange; symmetric primitives at 256-bit) |
| T3 | Honest-but-curious server reads content | Defeated (server relays ciphertext only) |
| T4 | Malicious server substitutes identity keys (MITM at first contact) | **Defeated by default** via key transparency log + client auditing — the novel v1 property |
| T5 | Malicious server equivocates the transparency log itself | Mitigated: cross-client gossip of log heads + third-party witnesses; detection, not prevention |
| T6 | Server learns sender identity per message | Mitigated: sealed sender (sender identity inside the encrypted envelope) |
| T7 | Traffic analysis: timing, sizes, who-talks-when patterns | **Out of scope v1.** Stated plainly. Padding to size buckets is the only v1 gesture. |
| T8 | Compromised endpoint device | Out of scope — no messenger survives this |
| T9 | Denial of service: prekey pool draining, log spam | Mitigated: rate limits, signed last-resort prekeys, log admission control |

---

## 3. Locked cryptographic decisions

Every choice below is final for v1, with the deciding rationale. Alternatives were considered and rejected for the stated reason — not re-litigated per sprint.

| Decision | Choice | Rejected alternative & why |
|---|---|---|
| Key exchange | Hybrid X25519 + ML-KEM-768, secrets concatenated into HKDF-SHA-256 with full transcript hash as salt | Pure ML-KEM: too young to stand alone. ML-KEM-1024: +30% bytes for no threat-model-relevant gain (Cat 3 already exceeds the symmetric layer's margin) |
| KDF combining rule | key = HKDF(ikm = ecdh_ss ‖ kem_ss, salt = SHA-256(transcript), info = "pqchat-v1-session") | XOR combiner: destroys security if either input is attacker-influenced. Omitting transcript binding: enables unknown-key-share attacks |
| Signatures (identity) | Hybrid Ed25519 + ML-DSA-65; both must verify; either failure = hard abort | Classical-only: defensible today (no retroactive forgery risk) but migration across a pinned-key installed base later is an organizational disaster — pay 5 KB now |
| One-time prekey signing | One ML-DSA signature over a Merkle root of each 100-key batch; each served key carries its ~700 B inclusion path | Per-key signatures: 3.3 KB × 100 keys of storage and bandwidth for zero security gain |
| AEAD | ChaCha20-Poly1305 default; AES-256-GCM where hardware AES is detected. Choice is bound inside the signed handshake — never renegotiable mid-session | Runtime-negotiable cipher: negotiation surfaces are downgrade surfaces |
| Forward secrecy | Double Ratchet (symmetric per message) + fresh ML-KEM encapsulation injected every 50 messages or 24 h, whichever first | Per-message PQC: ~4.4 KB and ~2 ms tax per message for negligible marginal FS — this is the design that gave PQC its latency reputation |
| Session establishment | Async prekey bundles; KEM ciphertext + first AEAD payload in one packet; zero online handshake round trips | Interactive handshake: adds 1–2 RTT to first message; unnecessary given a prekey directory |
| Identity verification | Key transparency: all identity keys inserted into a server-operated append-only Merkle log (CONIKS/Parakeet lineage); clients verify inclusion proofs on every fetch and audit log-head consistency via gossip through independent witnesses. Safety numbers retained as an optional manual layer | TOFU-only: the deployed status quo this product exists to beat. Blockchain anchoring: latency, cost, and governance burden with no detection benefit over witnessed gossip |
| Key change UX | Pinned-key change without matching log entry = blocking warning (send disabled until acknowledged with friction) | Signal-style passive banner: proven ignorable; ignorable warnings select for exactly the attack they warn about |
| Metadata | Sealed sender: outer envelope authenticates to a delivery token only; sender identity revealed inside the AEAD | Full anonymity routing (mix/onion): different product, order-of-magnitude latency cost, out of scope |
| Local storage | Session state + prekey pool encrypted under an OS-keystore-held key (Secure Enclave / StrongBox); survives app kill without re-handshake | App-level password wrapping: users lose passwords; recovery flows become the attack surface |
| Wire padding | Message bodies padded to {256 B, 1 KB, 4 KB} buckets | Constant-size or cover traffic: T7 is out of scope; buckets are the cheap 80% |

---

## 4. System architecture

Four components. The first three were specified in the preceding architecture work (client = UI thread + crypto worker + key store; relay = prekey directory + store-and-forward queue + push; peer symmetric to client). v1 adds the fourth:

**Transparency log service.** Append-only Merkle tree over (user identifier → current identity key set). Server-operated but externally verifiable: signed tree heads published at fixed epochs (locked: 5 minutes), monitored by ≥3 independent witnesses (locked target for launch; academic/NGO operators), clients gossip observed heads opportunistically through message envelopes. A server that shows different trees to different users is detectable within one gossip exchange between any two honest clients.

Latency discipline carried over unchanged from the architecture phase, now with the log on the same critical-path budget:
- Inclusion-proof verification is pure hashing: sub-millisecond, done in the crypto worker during bundle fetch — no added round trip (proof rides in the bundle response).
- Log audits and witness cross-checks run on background timers, never on the send path.
- All prior latency mechanisms retained: idle-time keypair pregeneration (pool of 20), optimistic UI send states, connection pre-warming at app launch, PQC amortized per session.

---

## 5. Functional requirements

| ID | Requirement | P |
|---|---|---|
| F1 | Hybrid identity keygen (Ed25519 + ML-DSA-65) on install; identity auto-registered in transparency log before first bundle upload | P0 |
| F2 | Signed prekey bundles (X25519 + ML-KEM-768 OTPKs, Merkle-batch-signed; signed last-resort KEM key) published to directory | P0 |
| F3 | Zero-additional-RTT session establishment: KEM ciphertext + first message, one packet | P0 |
| F4 | Per-message symmetric AEAD only; PQ ratchet injection per §3 schedule | P0 |
| F5 | Inclusion proof verified on every identity/bundle fetch; unproven identity = no session, no silent fallback | P0 |
| F6 | Log-head gossip piggybacked on message envelopes; divergence detection alerts user and reports to witnesses | P0 |
| F7 | Pinned-key change without corresponding log entry → blocking send-disabled warning | P0 |
| F8 | Sealed-sender envelopes; relay sees delivery token, not sender identity | P1 |
| F9 | Store-and-forward with delete-on-delivery; 30-day undelivered TTL | P1 |
| F10 | Background prekey replenishment during device idle; depletion telemetry server-side | P1 |
| F11 | Optional manual safety-number/QR verification layered on top of automatic checks | P2 |

**Non-goals v1, locked:** group messaging (v2 via MLS with hybrid PQ ciphersuite), multi-device (v2 via per-device subkeys logged as a set under one identity), voice/video, federation, traffic-analysis resistance beyond padding buckets.

---

## 6. Non-functional requirements

| ID | Target |
|---|---|
| N1 | First-message p95 < 400 ms perceived (cold session, LTE, mid-tier Android) — includes inclusion-proof verify |
| N2 | Established-session send p95 < 100 ms; must be statistically indistinguishable from a classical-crypto control build in A/B measurement |
| N3 | Zero UI-thread crypto; 0 dropped frames during any key operation |
| N4 | Bundle + inclusion proof fetch ≤ 9 KB |
| N5 | Log divergence (equivocation) detection latency ≤ 24 h at 1% DAU gossip participation |
| N6 | Downgrade attempts (classical-only, unknown suite, unproven identity) rejected 100% in negotiation fuzzing |
| N7 | All primitives pass NIST KATs in CI on every build; release blocks on failure |
| N8 | Battery: background work (replenish, audit) ≤ 1% daily drain budget |

---

## 7. Rollout

| Phase | Scope | Exit gate (hard, non-negotiable) |
|---|---|---|
| 0 | Crypto core: hybrid KEM/sig, KDF combiner, ratchet | NIST KAT pass + independent implementation review of the combiner and transcript binding |
| 1 | Two-client local session, no server | Key agreement equality test; forward-secrecy verified by key-erasure test; PQ-injection state machine model-checked for desync |
| 2 | Relay + prekey directory + offline delivery | Offline-recipient delivery E2E test; prekey depletion chaos test |
| 3 | Transparency log + witness protocol | Simulated equivocation detected within N5 budget in adversarial testbed |
| 4 | UX: optimistic send, blocking key-change flow, onboarding | N1/N2 met on physical devices; key-change warning tested against user-study bypass attempts |
| 5 | Hardening + external audit | Third-party cryptographic audit of protocol + implementation; all criticals closed |

Phase order is dependency-true: no phase starts before its predecessor's gate. The Phase 0 gate is the one that gets pressure-tested by deadlines; it does not move.

---

## 8. Success metrics

1. ≥ 99.9% of sessions established against a log-proven identity (measures the default-on verification thesis directly — compare to effectively ~0% manual verification in incumbents).
2. Injected equivocation in staging detected within 24 h at 1% gossip participation.
3. N2 indistinguishability: users cannot detect PQC presence via latency (A/B, p > 0.05).
4. Zero downgrade acceptances across the fuzzing corpus, sustained release over release.

---

## 9. Risks, ranked by expected damage

1. **Log governance.** Witnesses must be genuinely independent or T5 mitigation is decorative. Locked mitigation: launch blocks on 3 signed witness commitments from organizationally unrelated operators; witness set and conduct rules published.
2. **Ratchet + PQ-injection state machine desync** — flagged from the start of this project as the hardest component. Mitigation: model-check the state machine (TLA+ or equivalent) in Phase 1, before any network code exists.
3. **Blocking key-change warning backlash.** Users losing a phone triggers legitimate key changes; blocking UX will generate support load. Mitigation: logged re-registration flow makes legitimate changes provable, warning distinguishes "logged rotation" (soft notice) from "unlogged substitution" (block).
4. **Merkle-batch prekey serving complexity** — inclusion-path bugs are subtle. Mitigation: property-based testing against a naive per-key-signature oracle implementation.
5. **ML-DSA/ML-KEM implementation immaturity.** Side-channel guidance still evolving. Mitigation: constant-time-audited libraries only; CVE tracking as standing operational duty, not integration checkbox.

---

## 10. What is genuinely new here, stated without inflation

Hybrid PQC: deployed (Signal PQXDH, TLS X25519MLKEM768). Key transparency: deployed in adjacent forms (WhatsApp, iMessage Contact Key Verification). Sealed sender, ratcheting, prekeys: deployed. The specific synthesis — **post-quantum session establishment where identity proofs are mandatory, automatic, and send-blocking by default, with equivocation detection via client gossip** — is, to the best of current knowledge, not shipped as a default-on combination anywhere. That is the defensible claim. "Advancement in the history of cybersecurity" is decided by auditors, attackers, and a decade of deployment — never by the PRD's author, and any document claiming it for itself should be read with suspicion.
