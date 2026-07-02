# PRD: PQChat — Post-Quantum Messenger with Default-On Identity Verification

**Status:** v1.1 — unified synthesis of three prior drafts (`pqc-chat-prd.md`, `pqchat-prd-v1-locked.md`, `pqchat-research-edition.md`). Architectural decisions locked; open items are named, not hidden.
**Owner:** [you] — portfolio/learning project, not a production launch
**Date:** 2026-07-02
**Honest positioning:** a disciplined synthesis of deployed techniques (hybrid PQC, prekeys, ratcheting, sealed sender, key transparency) plus one combination — default-on, send-blocking, gossip-audited identity verification — that, to current knowledge, no shipped messenger ships as the default. That is a claim about *composition*, not cryptography, and it is earned by audit and years of survival, not by this document. See §10.

---

## 0. Why this version exists

Three drafts preceded this one, each strong in a different dimension:

- **The lean draft** was clearest on *why*: a plain-English threat table, an honest audience statement, and a glossary — the parts that keep a PRD legible to someone who isn't a cryptographer.
- **The locked draft** was strongest on *what*: every algorithm choice pinned with its rejected alternative, a fourth architectural component (the transparency log), and hard, non-negotiable phase gates.
- **The research edition** was strongest on *how you'd know if you're wrong*: falsifiable claims with explicit kill conditions, a prior-art table that credits what's actually novel, and a ranked list of where the design is expected to break first.

This document keeps all three properties. Nothing here is aspirational marketing — where a claim can't be traced to a threat, a test, or a named risk, it was cut.

---

## 1. The thesis

Every deployed end-to-end messenger has the same two weakest links, and neither is the encryption algorithm:

1. **Harvest-now-decrypt-later.** Classical key exchanges recorded today are readable by a future quantum adversary. The fix is solved technology (hybrid PQC); the engineering problem is applying it without wrecking latency.
2. **Identity verification theater.** Safety numbers exist in Signal and WhatsApp, and effectively nobody compares them. Billions of "verified encrypted" conversations rest on trust-on-first-use against the very server they're trusting not to attack.

PQChat fixes (1) with the now-standard hybrid construction, and fixes (2) by moving identity verification from an optional human ritual to a **default-on, automatic key-transparency check**: the client refuses to treat an identity as clean unless it appears consistently in a publicly auditable, append-only log. The user does nothing differently; the check happens anyway, and a substitution attack surfaces as a blocking warning instead of a banner nobody reads.

That second commitment is the differentiator. Everything else here is disciplined engineering of known techniques — see §10 for exactly how much credit that claim deserves.

---

## 2. Problem statement & audience

Messaging apps encrypted with classical algorithms (RSA, ECDH) are secure against today's computers but not against a sufficiently large quantum computer, which could retroactively break key exchanges recorded today. For any conversation with a confidentiality horizon beyond ~2035 (legal, medical, journalistic, long-term personal), that's a live risk now, not a future one.

**Who has this problem:** users and organizations whose message content needs to stay confidential for 10+ years — not the general SMS-replacement market; that's a positioning trap. The honest audience is narrow: privacy-conscious individuals, journalists, legal/medical correspondents, and — for this project specifically — you, as a portfolio piece demonstrating applied PQC and identity-transparency engineering.

**Non-goal, stated explicitly:** this is not an anonymity tool. Do not market it as one.

---

## 3. Threat model

Every requirement in this document traces to one of these rows. A feature that doesn't trace to one gets cut.

| # | Adversary capability | v1 stance |
|---|---|---|
| T1 | Passive network eavesdropper reads message content today | **Defeated** — end-to-end encryption is the core promise |
| T2 | Attacker records ciphertext today, decrypts with a quantum computer in ~2035+ ("harvest now, decrypt later") | **Defeated** — hybrid PQC key exchange; this is the entire reason PQC exists in this app |
| T3 | Honest-but-curious relay server reads message content | **Defeated** — server relays ciphertext only |
| T4 | Malicious server substitutes identity keys at first contact (MITM) | **Defeated by default** — key transparency log + mandatory client auditing; the novel v1 property |
| T5 | Malicious server equivocates the transparency log itself (shows different trees to different users) | **Mitigated, not prevented** — cross-client gossip of signed tree heads + ≥3 independent witnesses; this is detection, not prevention |
| T6 | Server learns sender identity per message | **Mitigated** — sealed sender (identity lives inside the encrypted envelope, not the outer packet) |
| T7 | Traffic analysis: timing, message sizes, who-talks-to-whom-when | **Out of scope v1, stated plainly.** Size-bucket padding is the only gesture. Call this out to stakeholders so nobody assumes it's covered. |
| T8 | Malicious or compromised client device (malware, unlocked phone) | **Out of scope** — no messenger survives endpoint compromise |
| T9 | Denial of service: prekey-pool draining, transparency-log spam | **Mitigated** — rate limits, signed last-resort prekeys, log admission control |

---

## 4. Goals / non-goals

**Goals (v1)**
- 1:1 encrypted messaging with hybrid post-quantum + classical key exchange
- Forward secrecy — leaking today's key doesn't expose yesterday's messages
- Offline message delivery — recipient doesn't need to be online at send time
- Default-on identity verification via transparency log — no user action required to get the protection
- Perceived latency indistinguishable from a non-PQC messenger

**Explicit non-goals (v1)**
- Group messaging — v2 at earliest, via MLS with a hybrid PQ ciphersuite (see §9 P6)
- Multi-device sync — v2, via per-device subkeys logged as a set under one identity
- Metadata / traffic-analysis protection beyond size-bucket padding
- Voice/video
- Federation with other messaging protocols

Cutting these isn't laziness. Group PQC key management combined with per-epoch transparency checks is a harder systems problem than everything else in this document combined (§9 P6); bolting it on later is safer than shipping v1 late trying to solve both at once.

---

## 5. Locked cryptographic decisions

Every choice below is final for v1, with the deciding rationale. Alternatives were considered and rejected for the stated reason — not re-litigated per sprint.

| Decision | Choice | Rejected alternative & why |
|---|---|---|
| Key exchange | Hybrid X25519 + ML-KEM-768, secrets concatenated into HKDF-SHA-256 with the full transcript hash as salt | Pure ML-KEM: too young to stand alone. ML-KEM-1024: +30% bytes for no threat-model-relevant gain — Category 3 already exceeds the symmetric layer's margin |
| KDF combining rule | `key = HKDF(ikm = ecdh_ss ‖ kem_ss, salt = SHA-256(transcript), info = "pqchat-v1-session")` | XOR combiner: destroys security if either input is attacker-influenced. Omitting transcript binding: enables unknown-key-share attacks |
| Identity signatures | Hybrid Ed25519 + ML-DSA-65; both must verify, either failure is a hard abort | Classical-only: defensible today, but migrating a pinned-key installed base later is an organizational disaster — pay ~5 KB now |
| One-time prekey signing | One ML-DSA-65 signature over a Merkle root of each 100-key batch; each served key carries its ~700 B inclusion path | Per-key signatures: 3.3 KB × 100 keys of storage and bandwidth for zero security gain |
| AEAD | ChaCha20-Poly1305 default; AES-256-GCM where hardware AES is detected. Bound inside the signed handshake — never renegotiable mid-session | Runtime-negotiable cipher: negotiation surfaces are downgrade surfaces |
| Forward secrecy | Double Ratchet (symmetric, per message) + fresh ML-KEM encapsulation injected every 50 messages or 24h, whichever first | Per-message PQC: ~4.4 KB and ~2 ms tax per message for negligible marginal FS gain — this is the design choice that gave PQC its (undeserved) latency reputation |
| Session establishment | Async prekey bundles; KEM ciphertext + first AEAD payload in one packet; zero online handshake round trips | Interactive handshake: adds 1–2 RTT to first message, unnecessary given a prekey directory |
| Identity verification | Key transparency: identity keys inserted into a server-operated append-only Merkle log (CONIKS/Parakeet lineage); clients verify inclusion proofs on every fetch and audit log-head consistency via gossip through independent witnesses. Safety numbers retained as an optional manual layer on top | TOFU-only: the deployed status quo this product exists to beat. Blockchain anchoring: latency, cost, and governance burden with no detection benefit over witnessed gossip |
| Key-change UX | Pinned-key change without a matching log entry → blocking warning (send disabled until acknowledged) | Signal-style passive banner: proven ignorable, and ignorable warnings select for exactly the attack they warn about |
| Metadata | Sealed sender: outer envelope authenticates to a delivery token only; sender identity revealed inside the AEAD | Full anonymity routing (mix/onion): different product, order-of-magnitude latency cost, out of scope |
| Local storage | Session state + prekey pool encrypted under an OS-keystore-held key (Secure Enclave / StrongBox); survives app kill without re-handshake | App-level password wrapping: users lose passwords; recovery flows become the attack surface |
| Wire padding | Message bodies padded to {256 B, 1 KB, 4 KB} buckets | Constant-size or cover traffic: T7 is explicitly out of scope; buckets are the cheap 80% |

---

## 6. System architecture (summary)

Four components:

- **Client** — UI thread, crypto worker, local key store (OS keystore-backed).
- **Relay server** — prekey directory, store-and-forward message queue, zero-knowledge of content.
- **Peer client** — symmetric to client.
- **Transparency log service** *(the v1 addition)* — append-only Merkle tree over (user identifier → current identity key set). Server-operated but externally verifiable: signed tree heads published at fixed 5-minute epochs, monitored by ≥3 independent witnesses (launch floor — academic/NGO operators), clients gossip observed heads opportunistically through message envelopes. A server showing different trees to different users is detectable within one gossip exchange between any two honest clients.

**Latency discipline** (carried through every component, not bolted on at the end):
- Inclusion-proof verification is pure hashing — sub-millisecond, done in the crypto worker during bundle fetch, no added round trip (the proof rides in the bundle response).
- Log audits and witness cross-checks run on background timers, never on the send path.
- Idle-time keypair pregeneration (pool of 20), optimistic UI send states, connection pre-warming at app launch, PQC cost amortized per session rather than per message.

Full byte-size breakdown and the zero-RTT first-message flow live in the companion architecture doc; this PRD assumes that design as baseline.

---

## 7. Functional requirements

| ID | Requirement | Priority |
|---|---|---|
| F1 | Client generates hybrid identity keypair (Ed25519 + ML-DSA-65) on install; identity is auto-registered in the transparency log before first bundle upload | P0 |
| F2 | Client generates and publishes signed prekey bundles (X25519 + ML-KEM-768 one-time keys, Merkle-batch-signed; plus a signed last-resort KEM key) to the directory | P0 |
| F3 | Session establishment adds zero round trips beyond message one: KEM ciphertext + first AEAD payload in one packet | P0 |
| F4 | Messages after session establishment use symmetric AEAD only; PQ ratchet injection follows the §5 schedule — no per-message PQC | P0 |
| F5 | Inclusion proof is verified on every identity/bundle fetch; an unproven identity gets no session and no silent fallback | P0 |
| F6 | Log-head gossip is piggybacked on message envelopes; divergence between observed heads alerts the user and reports to witnesses | P0 |
| F7 | User sees a safety-number / identity-verification flow for new contacts, and the client detects + alerts on identity-key changes for existing contacts | P0 |
| F8 | A pinned-key change without a corresponding log entry produces a blocking, send-disabled warning; a change *with* a logged rotation produces a soft notice | P0 |
| F9 | Sealed-sender envelopes: relay sees a delivery token, not sender identity | P1 |
| F10 | Server stores and forwards ciphertext for offline recipients; deletes on delivery; 30-day undelivered TTL | P1 |
| F11 | Client maintains a replenishing pool of one-time prekeys, tops up in background; depletion telemetry tracked server-side | P1 |
| F12 | Optional manual safety-number/QR verification layered on top of the automatic transparency check | P2 |

---

## 8. Non-functional requirements

*(This is where most PQC PRDs go soft — don't let this one.)*

| ID | Requirement | Target |
|---|---|---|
| N1 | First-message latency (cold session, cellular, mid-tier Android) — includes inclusion-proof verify | p95 < 400 ms perceived-send-to-sent-tick |
| N2 | Steady-state message send latency (established session) | p95 < 100 ms; statistically indistinguishable from a classical-crypto control build in A/B measurement |
| N3 | Keygen and all crypto ops never block the UI thread | 0 dropped frames during any key operation |
| N4 | Prekey bundle + inclusion proof fetch size | ≤ 9 KB (dominated by the ML-DSA signature) |
| N5 | Log divergence (equivocation) detection latency | ≤ 24h at 1% DAU gossip participation |
| N6 | Downgrade resistance | Any attempt to negotiate classical-only crypto, an unknown suite, or an unproven identity is rejected 100% of the time in negotiation fuzzing — never silently accepted |
| N7 | Crypto correctness gate | All primitives pass NIST KATs in CI on every build; release blocks on failure |
| N8 | Crash/relaunch key durability | Session state and prekey pool survive app kill without re-handshake |
| N9 | Battery/CPU: background work (prekey top-up, log audit) | ≤ 1% daily drain budget; runs only during device idle, capped duration per cycle |

---

## 9. Rollout plan

| Phase | Scope | Exit gate (hard, non-negotiable) |
|---|---|---|
| 0 — Crypto core | Hybrid KEM/signature primitives, HKDF combiner, ratchet | NIST KAT pass **+** independent implementation review of the combiner and transcript binding |
| 1 — Local session | Two local clients (no server) complete session establishment + message exchange | Session key equality on both sides; forward secrecy verified by key-erasure test; PQ-injection state machine model-checked for desync |
| 2 — Relay integration | Server relay, offline delivery, prekey directory | Offline-recipient delivery E2E test; prekey-depletion chaos test |
| 3 — Transparency log | Log service + witness protocol | Simulated equivocation detected within the N5 budget in an adversarial testbed |
| 4 — UX polish | Optimistic send, safety numbers, blocking key-change flow, onboarding | N1/N2 latency targets met on physical devices, not localhost; key-change warning tested against user-study bypass attempts |
| 5 — Hardening & audit | Rate limiting, prekey-depletion defenses, malformed-key rejection, external audit | Third-party cryptographic audit of protocol + implementation; all criticals closed |

Phase order is dependency-true: no phase starts before its predecessor's gate closes. **Do not start Phase 4 before Phase 0's crypto core has independent test-vector verification** — UX polish on top of unverified crypto primitives is how projects ship convincing-looking, broken security. The Phase 0 gate is the one that gets pressure-tested by deadlines; it does not move.

---

## 10. What is genuinely new here, stated without inflation

Prior art, credited explicitly — none of this is invented here:

| Component | Prior deployment / literature |
|---|---|
| Hybrid PQ key establishment from prekeys | Signal PQXDH (2023); TLS 1.3 X25519MLKEM768 (Chrome/Cloudflare default, 2024) |
| Periodic post-quantum ratchet rekeying | Apple iMessage PQ3 (2024); Signal's sparse post-quantum ratchet line (2025) |
| Key transparency for messengers | CONIKS (2015); Parakeet; WhatsApp key transparency (advisory); Apple Contact Key Verification (opt-in) |
| Sealed sender | Signal (2018) |

**The claim this design actually makes:** no shipped system, to current knowledge, combines hybrid-PQ session establishment with *mandatory, send-blocking, gossip-audited* key transparency as the default for every session. Deployed key-transparency systems are advisory or opt-in; deployed PQ messengers retain TOFU-plus-optional-safety-numbers as their identity layer. The composition — and specifically the security-economics bet that blocking UX with a logged-rotation escape hatch is deployable at consumer scale — is the contribution candidate. It is a *systems and usable-security* claim, not a cryptographic one, and §11 states exactly how it could be proven wrong.

"Advancement in the history of cybersecurity" is decided by auditors, attackers, and a decade of deployment — never by the PRD's author. Any document claiming that for itself should be read with suspicion.

---

## 11. Success metrics & falsifiable claims

Ordinary success metrics are easy to fudge ("latency feels fine"). Each metric below is written so a single well-constructed experiment can kill it — that's the point; a metric nobody could fail isn't measuring anything.

1. **Verification coverage.** ≥ 99.9% of sessions established against a log-proven identity — measures the default-on thesis directly (compare to ~0% manual safety-number verification in incumbents).
2. **Latency indistinguishability (C1).** Users in an A/B study cannot distinguish the hybrid-PQ build from a classical-only control by send experience (p > 0.05, n ≥ 1,000, mid-tier Android, LTE). *Falsified by:* a study showing perceptible degradation, or a network class (high-loss cellular, satellite) where handshake fragmentation pushes first-message p95 past 400 ms systematically.
3. **Equivocation detection bound (C2).** At 1% DAU gossip participation, a split-view log server is detected within 24h with probability ≥ 0.99. *Falsified by:* simulation under realistic (clustered, assortative) contact-graph topologies showing detection probability materially below this — the uniform-mixing assumption is known to be optimistic; this is the claim most likely to need revision.
4. **Downgrade impossibility (C3).** No sequence of network-level message manipulations induces a classical-only or unproven-identity session. *Falsified by:* a symbolic-model attack trace (Tamarin/ProVerif) against the negotiation and version-binding logic. Zero downgrade acceptances required across the fuzzing corpus, sustained release over release.
5. **Ratchet soundness (C4).** The Double-Ratchet-plus-periodic-ML-KEM-injection state machine cannot deadlock or silently desync under reordering, loss, or injection-boundary races. *Falsified by:* a model-checking counterexample. The injection boundary (message 50 crossing in flight in both directions simultaneously) is the suspected weak point.
6. **Blocking-warning viability (C5).** The send-blocking key-change warning produces < 5% conversation abandonment and doesn't train dismissal behavior within a 90-day cohort. *Falsified by:* a usable-security study showing warning fatigue converging to the Signal-banner outcome. **This one is load-bearing** — if C5 falls, Commitment B (§1) degrades to advisory transparency, a materially weaker system.
7. **Combiner robustness (C6).** The HKDF combiner with transcript-hash salt provides IND-CCA security if *either* X25519 or ML-KEM-768 is secure, and binds the session to the full negotiation transcript (no unknown-key-share). *Falsified by:* a proof gap or attack in the computational model. A machine-checked proof (CryptoVerif) closing this is invited and currently absent.

---

## 12. Risks, ranked by expected damage

1. **Blocking key-change warning backlash (C5 / P4 below).** Legitimate device loss triggers legitimate key changes; blocking UX generates support load and risks training users to dismiss warnings — the cheapest way to kill the whole default-on thesis. Mitigation: a logged re-registration flow makes legitimate changes provable; the warning distinguishes "logged rotation" (soft notice) from "unlogged substitution" (block).
2. **Log governance.** Witnesses must be genuinely independent or T5's mitigation is decorative. Mitigation: launch blocks on 3 signed witness commitments from organizationally unrelated operators; witness set and conduct rules published. Three witnesses is a launch floor, not a security argument — collusion/capture analysis is invited.
3. **Gossip detection on realistic (clustered) contact graphs (C2 / P2).** The 24h/1% bound is stated under an assumption known to be optimistic — real messaging graphs are assortative, and gossip partitions more easily on clustered graphs than uniform mixing admits.
4. **Ratchet + PQ-injection state-machine desync (C4 / P1).** Flagged as the hardest component since the first design pass. Mitigation: model-check the state machine (TLA+ or equivalent) in Phase 1, before any network code exists.
5. **Merkle-batch prekey serving complexity.** Inclusion-path bugs are subtle. Mitigation: property-based testing against a naive per-key-signature oracle implementation.
6. **One-time prekey exhaustion under burst load.** Needs the last-resort key plus a depletion-rate alert; unresolved — what's the actual replenishment SLA.
7. **ML-DSA/ML-KEM implementation immaturity.** Algorithms are finalized standards, but side-channel guidance is still maturing. Mitigation: constant-time-audited libraries only; CVE tracking as a standing operational duty, not a one-time integration checkbox.
8. **Combiner proof gap (C6).** Least likely to fall — the construction is conservative — but no machine-checked proof exists yet, and absence of proof is a standing invitation to reviewers.

---

## 13. Open research problems (for anyone extending this beyond a portfolio project)

Ranked by expected difficulty × impact. Not on the v1 critical path, but each maps to a risk in §12 or a claim in §11.

- **P1 — Formal verification of the PQ-injected ratchet.** No public machine-checked proof covers a Double Ratchet with periodic KEM injection under adversarial scheduling. Serves C4.
- **P2 — Gossip detection bounds on realistic contact graphs.** Replace the uniform-mixing assumption in C2 with measured messaging-graph topologies; derive participation-rate thresholds as a function of clustering coefficient.
- **P3 — Deniability under hybrid PQ establishment.** X3DH's deniability arguments don't transfer cleanly once KEM ciphertexts and mandatory signatures enter the handshake. Characterize what PQChat's handshake actually provides.
- **P4 — Security economics of blocking warnings.** C5 as a full research program: what escape-hatch friction level separates legitimate device-loss rotations from attacks without training dismissal? Least crypto-flavored, plausibly highest-impact.
- **P5 — Metadata protection under PQ bandwidth regimes.** Padding buckets and sealed sender are gestures; real traffic-analysis resistance costs bandwidth precisely where PQ handshakes already spend it (~6–9 KB/session start).
- **P6 — Post-quantum group messaging integration path.** MLS with hybrid PQ ciphersuites is drafted, but tree-KEM cost at large group sizes combined with per-epoch transparency checks per member has no published systems evaluation.
- **P7 — Prekey-exhaustion economics.** Signed last-resort keys stop the availability attack but change the freshness/deniability profile of affected sessions. Quantify attacker cost to force last-resort usage versus defender replenishment cost.

---

## 14. Glossary

- **KEM (Key Encapsulation Mechanism):** a way for two parties to agree on a shared secret using public keys, without either side sending the secret itself. ML-KEM is the PQC replacement for classical Diffie-Hellman.
- **Hybrid crypto:** running a classical algorithm and a post-quantum algorithm together and combining both outputs, so breaking either one alone isn't enough.
- **AEAD:** Authenticated Encryption with Associated Data — the fast symmetric cipher (e.g. ChaCha20-Poly1305, AES-256-GCM) that does the actual message encryption once the session key exists.
- **Forward secrecy:** leaking today's key doesn't let an attacker decrypt yesterday's messages.
- **Prekey:** a public key uploaded in advance so someone can message you without you being online.
- **Transparency log:** a server-operated, append-only, cryptographically verifiable record (Merkle tree) of every identity key ever registered — designed so the server cannot show different, inconsistent views to different users without getting caught.
- **Inclusion proof:** a short cryptographic proof that a specific entry (e.g., your contact's identity key) is really present in the transparency log, verifiable without downloading the whole log.
- **Sealed sender:** a technique where the outer message envelope doesn't reveal who sent it — the relay sees only enough to route the message, not who's talking to whom.
- **Equivocation:** when a server shows different, inconsistent versions of the log to different clients, so it can lie to one party about another's identity key without the lie being globally visible.

---

## 15. Relationship between this document and prior drafts

`pqc-chat-prd.md` (lean draft), `pqchat-prd-v1-locked.md` (locked decisions), and `pqchat-research-edition.md` (falsifiable claims + open problems) are superseded by this document for planning purposes but are not deleted — the research edition in particular has value as a standalone document if this project is ever shared with a security-research audience rather than used as an engineering build contract. If future results falsify a claim in §11 (most plausibly C2's participation threshold or C5's abandonment bound), the corresponding decision in §5 gets revised through a logged design change here, not silently.
