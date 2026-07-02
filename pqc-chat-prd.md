# PRD: Post-Quantum Secure Chat App (working name: PQChat)

**Status:** Draft v0.1 — for a learning/portfolio project, not production launch
**Owner:** [you]
**Last updated:** 2026-07-02

---

## 0. Read this before anything else: the threat model

A PRD without a threat model is a feature list wearing a PRD's clothes. Every requirement below exists to answer one of these four questions. If a proposed feature doesn't trace back to one of them, cut it.

| # | Threat | Are we defending against it? |
|---|---|---|
| 1 | A passive network eavesdropper reads message content today | Yes — this is the core promise |
| 2 | An attacker records ciphertext today and decrypts it in ~2035+ with a quantum computer ("harvest now, decrypt later") | Yes — this is the *entire reason PQC exists in this app* |
| 3 | The relay server operator reads message content | Yes — server sees ciphertext + metadata only |
| 4 | The relay server operator sees *who talks to whom, when* (metadata/traffic analysis) | **No — explicitly out of scope for v1.** Call this out to stakeholders so nobody assumes it's covered. |
| 5 | A malicious or compromised client device (malware, unlocked phone) | No — end-device compromise defeats any messenger |
| 6 | Active MITM impersonating a contact's identity | Partially — mitigated by identity pinning + safety-number verification, not eliminated |

**Non-goal, stated explicitly:** this is not an anonymity tool. Do not market it as one.

---

## 1. Problem statement

Messaging apps encrypted with classical algorithms (RSA, ECDH) are secure against today's computers but not against a sufficiently large quantum computer, which could retroactively break key exchanges recorded today. For any conversation with a confidentiality horizon beyond ~2035 (legal, medical, journalistic, long-term personal), that's a live risk right now, not a future one.

**Who has this problem:** users and organizations whose message content needs to stay confidential for 10+ years. Not the general SMS-replacement market — that's a positioning trap. This product's honest audience is narrow: privacy-conscious individuals, journalists, legal/medical correspondents, and — for this project specifically — you, as a portfolio piece demonstrating applied PQC engineering.

---

## 2. Goals / non-goals

**Goals (v1)**
- 1:1 encrypted messaging with hybrid post-quantum + classical key exchange
- Forward secrecy (past messages stay safe if today's key leaks)
- Offline message delivery (recipient doesn't need to be online)
- Perceived latency indistinguishable from a non-PQC messenger

**Explicit non-goals (v1)**
- Group messaging (materially harder key management — v2 at earliest)
- Metadata/traffic-analysis protection
- Multi-device sync
- Voice/video
- Federation with other messaging protocols

Cutting these isn't laziness — group PQC key management alone is a harder problem than everything in this document combined, and bolting it on later is safer than getting v1 late trying to solve both at once.

---

## 3. Functional requirements

| ID | Requirement | Priority |
|---|---|---|
| F1 | Client generates hybrid identity keypair (Ed25519 + ML-DSA-65) on first launch | P0 |
| F2 | Client generates and publishes signed prekey bundles (X25519 + ML-KEM-768) to server | P0 |
| F3 | Client establishes a session with zero additional round trips beyond message one | P0 |
| F4 | Messages after session establishment use symmetric AEAD only — no per-message PQC | P0 |
| F5 | Session key rotates on a schedule (message count or time-based, whichever first) | P0 |
| F6 | User sees a safety-number / identity-verification flow for new contacts | P0 |
| F7 | Client detects and alerts on identity key changes for existing contacts | P0 |
| F8 | Server stores and forwards ciphertext for offline recipients; deletes on delivery | P1 |
| F9 | Client maintains a replenishing pool of one-time prekeys, tops up in background | P1 |
| F10 | Client has a signed last-resort prekey as fallback when the one-time pool is exhausted | P1 |

---

## 4. Non-functional requirements (this is where most PQC PRDs go soft — don't let this one)

| ID | Requirement | Target |
|---|---|---|
| N1 | First-message latency (cold session, cellular network) | p95 < 400ms perceived-send-to-sent-tick |
| N2 | Steady-state message send latency (established session) | p95 < 100ms, indistinguishable from non-PQC baseline |
| N3 | Keygen never blocks the UI thread | 0 dropped frames during any keygen op |
| N4 | Prekey bundle fetch size | < 8KB (see architecture doc — dominated by ML-DSA signature) |
| N5 | Battery/CPU: background prekey pool top-up | Runs only during device idle, capped duration per cycle |
| N6 | Downgrade resistance | Any attempt to negotiate classical-only crypto is rejected, not silently accepted |
| N7 | Crash/relaunch key durability | Session state and prekey pool survive app kill without re-handshake |

---

## 5. System architecture (summary — see companion diagram)

Three components: **client** (UI thread, crypto worker, local key store), **relay server** (prekey directory, message queue, zero-knowledge of content), **peer client**. Full breakdown, byte sizes, and the zero-RTT first-message flow were covered in the architecture discussion — this PRD assumes that design as the baseline and doesn't re-derive it.

---

## 6. Rollout plan

| Phase | Scope | Exit criteria |
|---|---|---|
| 0 — Crypto core | Hybrid KEM/signature primitives, HKDF combiner, unit tests against known test vectors | All primitives pass NIST test vectors |
| 1 — Local session | Two local clients (no server) complete session establishment + message exchange | Session key matches on both sides, forward secrecy verified by key-erasure test |
| 2 — Relay integration | Server relay, offline delivery, prekey directory | Message delivered to an offline recipient who comes online later |
| 3 — UX polish | Optimistic send, safety numbers, key-change alerts | N1/N2 latency targets met on real devices, not localhost |
| 4 — Hardening | Rate limiting, prekey depletion defenses, malformed-key rejection | Passes an internal red-team pass against F6/F7/N6 |

Do not start Phase 3 before Phase 0's crypto core has independent test-vector verification. UX polish on top of unverified crypto primitives is how projects ship convincing-looking, broken security.

---

## 7. Success metrics

- p95 first-message latency under target on real mid-tier Android hardware, not a dev machine
- Zero silent downgrades in fuzz testing of the negotiation path
- 100% of session establishments verified against NIST KAT (known-answer test) vectors in CI

---

## 8. Open risks

1. **One-time prekey exhaustion under burst load** — needs a last-resort key and a depletion-rate alert; unresolved: what's the actual replenishment SLA.
2. **Identity verification UX** — safety-number comparison has historically low real-world adoption in every messenger that's shipped it. Decide now whether to accept that or invest in a stronger default (e.g., QR-based verification at first contact).
3. **ML-DSA-65 signature size (3.3KB)** — dominates bundle size; batch-signing one-time prekeys (Merkle root over the pool) is the mitigation, not yet designed in detail.
4. **NIST algorithm stability** — ML-KEM/ML-DSA are finalized standards, but implementations and side-channel guidance are still maturing. Track library CVEs as an ongoing operational cost, not a one-time integration task.

---

## 9. Glossary (since you're new to this)

- **KEM (Key Encapsulation Mechanism):** a way for two parties to agree on a shared secret using public keys, without either side sending the secret itself. ML-KEM is the PQC replacement for classical Diffie-Hellman.
- **Hybrid crypto:** running a classical algorithm and a post-quantum algorithm together, combining both outputs, so breaking either one alone isn't enough.
- **AEAD:** Authenticated Encryption with Associated Data — the fast symmetric cipher (e.g. AES-256-GCM) that does the actual message encryption after the session key exists.
- **Forward secrecy:** a property where leaking today's key doesn't let an attacker decrypt yesterday's messages.
- **Prekey:** a public key uploaded in advance so someone can message you without you being online.
