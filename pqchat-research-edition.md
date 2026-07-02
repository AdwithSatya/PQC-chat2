# PQChat — Research Edition
## A Post-Quantum Messenger with Default-On Identity Verification: Design, Falsifiable Claims, and Open Problems


**Audience:** security researchers, protocol analysts, formal-methods practitioners, usable-security researchers
**Date:** 2026-07-02
**Novelty stance:** calibrated, not inflated — see §2. Documents claiming to advance the history of cybersecurity do not; audited deployments that survive a decade of attack occasionally do.

---

## 1. System summary (one page, so this document stands alone)

PQChat is a 1:1 end-to-end encrypted messenger with two design commitments:

**Commitment A — quantum-resistant confidentiality without user-visible latency.**
Hybrid key establishment: X25519 + ML-KEM-768, both shared secrets combined via HKDF-SHA-256 with the full handshake transcript as salt. Async signed prekey bundles (Merkle-batch ML-DSA-65 + Ed25519 hybrid signatures) enable zero-round-trip session establishment: the first message carries the KEM ciphertext and AEAD payload in one packet. Per-message crypto is symmetric only (Double Ratchet, ChaCha20-Poly1305/AES-256-GCM); a fresh ML-KEM encapsulation is injected into the ratchet every 50 messages or 24 hours. Measured primitive costs (single core, pure-JS worst case): ML-KEM-768 keygen 0.67 ms / encaps 0.87 ms / decaps 0.75 ms; ML-DSA-65 sign ~13 ms / verify ~2.75 ms. The engineering thesis: PQC latency is a bytes-and-round-trips problem, not a compute problem, and is fully amortizable off the user-perceived path.

**Commitment B — identity verification as a default, not a ritual.**
All identity keys are inserted into a server-operated append-only Merkle transparency log (CONIKS/Parakeet lineage). Clients verify inclusion proofs on every key fetch (sub-millisecond, no extra round trip — the proof rides in the bundle response), gossip signed tree heads opportunistically through message envelopes, and cross-check against ≥3 organizationally independent witnesses publishing at 5-minute epochs. An unproven identity cannot receive a session — no silent fallback. A pinned-key change without a corresponding log entry produces a send-blocking warning, distinguished from a logged rotation (soft notice). Sealed-sender envelopes withhold sender identity from the relay.

Out of scope v1, stated without embarrassment: traffic analysis beyond size-bucket padding {256 B, 1 KB, 4 KB}, group messaging, multi-device, endpoint compromise.

---

## 2. Novelty statement, calibrated for a research audience

Prior art this design stands on, credited explicitly:

| Component | Prior deployment / literature |
|---|---|
| Hybrid PQ key establishment from prekeys | Signal PQXDH (2023); TLS 1.3 X25519MLKEM768 (Chrome/Cloudflare default, 2024) |
| Periodic post-quantum ratchet rekeying | Apple iMessage PQ3 (2024) — Level 3 in Apple's own taxonomy; Signal's sparse post-quantum ratchet / triple-ratchet line (2025) |
| Key transparency for messengers | CONIKS (2015); Parakeet; WhatsApp key transparency deployment; Apple Contact Key Verification |
| Sealed sender | Signal (2018) |

**The claim this design actually makes:** no shipped system, to the authors' knowledge as of early 2026, combines hybrid-PQ session establishment with *mandatory, send-blocking, gossip-audited* key transparency as the default for every session. Deployed key-transparency systems are advisory (WhatsApp) or opt-in (Apple CKV); deployed PQ messengers retain TOFU-plus-optional-safety-numbers as their identity layer. The composition — and specifically the security-economics bet that blocking UX plus logged-rotation escape hatches is deployable at consumer scale — is the research contribution candidate. It is a *systems and usable-security* claim more than a cryptographic one, and it is falsifiable (§3).

Researchers should treat any stronger novelty claim encountered elsewhere about this design as inflation.

---

## 3. Falsifiable claims — the attack surface, offered deliberately

Each claim is stated so that a single well-constructed experiment or proof can kill it. Killing one is a publishable result; that is the point.

**C1 (Latency indistinguishability).** Users in an A/B study cannot distinguish the hybrid-PQ build from a classical-only control by message-send experience (p > 0.05, n ≥ 1,000, mid-tier Android, LTE). *Falsified by:* a study showing perceptible degradation, or a network condition class (high-loss cellular, satellite) where handshake fragmentation makes first-message p95 exceed the 400 ms budget systematically.

**C2 (Equivocation detection bound).** With 1% of daily-active clients participating in tree-head gossip, a log server showing split views is detected within 24 hours with probability ≥ 0.99. *Falsified by:* a formal analysis or simulation showing the detection probability under realistic contact-graph topologies (clustered, not random) falls materially below the claim — contact graphs are assortative, and gossip on clustered graphs partitions more easily than the uniform-mixing assumption admits. The authors consider this the claim most likely to need revision.

**C3 (Downgrade impossibility).** No sequence of network-level message manipulations induces a client to complete a classical-only or unproven-identity session. *Falsified by:* a symbolic-model attack trace (Tamarin/ProVerif) against the negotiation and version-binding logic.

**C4 (Ratchet state-machine soundness).** The Double-Ratchet-plus-periodic-ML-KEM-injection state machine cannot deadlock or silently desync under message reordering, loss, and injection-boundary races. *Falsified by:* a model-checking counterexample. The injection boundary (message 50 crossing in flight in both directions simultaneously) is the suspected weak point.

**C5 (Blocking-warning viability).** A send-blocking key-change warning with a logged-rotation escape hatch produces < 5% conversation abandonment and does not train dismissal behavior within a 90-day cohort. *Falsified by:* a usable-security study showing warning fatigue converges to the Signal-banner outcome. If C5 falls, Commitment B degrades to advisory transparency — a materially weaker system — so this UX claim is load-bearing for the whole thesis.

**C6 (Combiner robustness).** The HKDF combiner with transcript-hash salt provides IND-CCA security if *either* X25519 or ML-KEM-768 is secure, and binds the session to the full negotiation transcript (no unknown-key-share). *Falsified by:* a proof gap or attack in the computational model; a machine-checked proof (CryptoVerif) closing this is invited and currently absent.

---

## 4. Open research problems, ranked by expected difficulty × impact

**P1 — Formal verification of the PQ-injected ratchet.** No public machine-checked proof covers a Double Ratchet with periodic KEM injection under adversarial scheduling. Deliverable sought: TLA+/Tamarin model + proof or counterexample. (Directly serves C4.)

**P2 — Gossip detection bounds on realistic contact graphs.** Replace the uniform-mixing assumption in C2 with measured messaging-graph topologies; derive participation-rate thresholds as a function of clustering coefficient. Epidemic-process literature applies; nobody has done it for key-transparency gossip specifically.

**P3 — Deniability under hybrid PQ establishment.** X3DH's deniability arguments do not transfer cleanly once KEM ciphertexts and mandatory signatures enter the handshake; the deniability status of PQXDH-style protocols is an acknowledged open question in the literature. Characterize what deniability property PQChat's handshake actually provides, and at what cost it could be strengthened.

**P4 — Security economics of blocking warnings.** C5 as a full research program: what escape-hatch friction level separates legitimate device-loss rotations from attacks without training dismissal? This is the least crypto-flavored problem here and plausibly the highest-impact one.

**P5 — Metadata protection under PQ bandwidth regimes.** Padding buckets and sealed sender are gestures. Real traffic-analysis resistance costs bandwidth precisely where PQ handshakes already spend it (~6–9 KB per session start). Characterize the joint overhead frontier.

**P6 — Post-quantum group messaging integration path.** MLS with hybrid PQ ciphersuites is specified in drafts but the tree-KEM cost profile at large group sizes, combined with per-epoch transparency checks for every member, has no published systems evaluation.

**P7 — Prekey-exhaustion economics.** Signed last-resort keys stop the availability attack but change the freshness/deniability profile of affected sessions. Quantify the attacker's cost to force last-resort usage at scale versus the defender's replenishment cost.

---

## 5. Evaluation methodology (reproducibility contract)

Any performance or detection claim made by this project is invalid unless produced under the following harness, which will be released with the artifacts:

- **Primitive benchmarks:** fixed library versions, NIST KAT verification as a precondition, single-core and worker-pool measurements, published raw distributions not just means.
- **Latency claims (C1):** physical mid-tier Android devices (device list pinned per release), network conditions emulated at the radio scheduler level (loss/latency profiles published), classical-control build differing *only* in crypto suite, p50/p95/p99 reported.
- **Detection claims (C2):** discrete-event simulator with pluggable contact-graph topologies (uniform, Watts–Strogatz, sampled real graphs where ethically obtainable), adversary model = fully adaptive log server, seeds published.
- **Negotiation robustness (C3, N6):** structure-aware fuzzing corpus released; symbolic model files released alongside.
- **UX claims (C5):** pre-registered study design, IRB-equivalent review, materials released for replication.

---

## 6. Artifact release plan

1. **Protocol specification** — standalone, implementation-independent, with test vectors for the combiner, ratchet transitions (including injection boundaries), bundle serialization, and inclusion proofs.
2. **Reference implementation** — permissively licensed; constant-time-audited primitive libraries only; the reference is a verification oracle, not a product.
3. **Formal models** — TLA+ state machine (P1) and Tamarin negotiation model (C3) published with the spec, including known incompleteness notes.
4. **Adversarial testbed** — the equivocating-log-server and gossip simulator from §5, so C2 attacks are runnable by anyone.
5. **Disclosure policy** — 90-day coordinated disclosure, no legal threats against good-faith research, safe-harbor language published before any deployment.

---

## 7. How to attack this design — a map for reviewers

Ranked by where the authors themselves expect blood:

1. **C5 / P4 (warning UX).** The whole default-on thesis rests on a human-factors bet. A negative usability result here is the cheapest total kill.
2. **C2 / P2 (gossip on clustered graphs).** The detection bound is stated under an assumption known to be optimistic.
3. **C4 / P1 (injection-boundary races).** Concurrency at the rekey boundary is where the authors have flagged desync risk since the project's first design pass.
4. **Witness independence (governance).** Three witnesses is a launch floor, not a security argument; capture or collusion analysis is invited.
5. **C6 (combiner proof gap).** Least likely to fall — the construction is conservative — but the machine-checked proof does not yet exist, and absence of proof is a standing invitation.
6. **Implementation side channels.** ML-KEM/ML-DSA constant-time engineering is younger than the algorithms; the reference implementation is offered as a target.

A design document that does not tell reviewers where to aim is asking them to waste time rediscovering its weak points. This one aims them.

---

## 8. Relationship to the engineering PRD

The companion document (`pqchat-prd-v1-locked.md`) locks every implementation decision — algorithms, parameters, rotation schedules, rollout gates, risk register — and remains the build contract. This research edition does not reopen those decisions; it exposes their assumptions as testable claims. If research results falsify a claim (most plausibly C2's participation threshold or C5's abandonment bound), the corresponding PRD decision gets revised through a logged design change, not silently.

The correct measure of whether this work "helps cybersecurity" is not this document's ambition. It is: how many of §3's claims survive contact with the community, how quickly the ones that fall are replaced, and whether anything in §4 produces results that outlive this particular system.
