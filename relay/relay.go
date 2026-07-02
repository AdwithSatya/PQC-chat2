// Package relay implements PQChat's Phase 2 relay server: a prekey
// directory plus a store-and-forward message queue (PRD §6
// architecture, F9-F11).
//
// Deliberately, this package never imports crypto/session,
// crypto/ratchet, or crypto/kemhybrid. Message content is routed as
// opaque []byte envelopes (see crypto/session's wire encoding) — the
// relay operator sees ciphertext and coarse metadata (who's queued for
// whom, when) only, never plaintext or session key material (PRD
// threat model T3: "server relays ciphertext only"). It does
// understand the prekey directory's structure (identities, batches,
// consumption), because that's directory/availability metadata the
// server necessarily manages, not conversation content — and,
// critically, it only ever holds *public* prekey material: private
// keys never leave the owning client (see crypto/prekey.Batch, whose
// private keys are unexported and never serialized here).
package relay

import (
	"errors"
	"sync"
	"time"

	"pqchat/crypto/identity"
	"pqchat/crypto/prekey"
)

var (
	ErrUnknownUser        = errors.New("relay: unknown user")
	ErrNoPrekeysPublished = errors.New("relay: user has published no prekeys")
	ErrNoPrekeysAvailable = errors.New("relay: one-time prekey pool exhausted and no last-resort key on file")
)

// DefaultMessageTTL matches PRD F9/F10's 30-day undelivered-message
// retention window.
const DefaultMessageTTL = 30 * 24 * time.Hour

// QueuedMessage is one store-and-forward entry. Envelope is opaque to
// this package.
type QueuedMessage struct {
	From     string
	Envelope []byte
	QueuedAt time.Time
}

type userPrekeys struct {
	bundles       []*prekey.Bundle
	consumed      []bool
	nextCursor    int
	lastResort    *prekey.LastResort
	lastResortUse int // telemetry: how many times we've fallen back
}

func (u *userPrekeys) remaining() int {
	n := 0
	for _, c := range u.consumed {
		if !c {
			n++
		}
	}
	return n
}

// Server is an in-memory relay. It is safe for concurrent use.
type Server struct {
	mu         sync.Mutex
	identities map[string]identity.PublicKey
	prekeys    map[string]*userPrekeys
	queues     map[string][]QueuedMessage
}

// NewServer creates an empty relay.
func NewServer() *Server {
	return &Server{
		identities: make(map[string]identity.PublicKey),
		prekeys:    make(map[string]*userPrekeys),
		queues:     make(map[string][]QueuedMessage),
	}
}

// PublishIdentity registers (or replaces) a user's identity public
// key. In this Phase 2 scaffold, trust in this binding is
// trust-on-first-use — closing that gap with mandatory transparency-log
// verification is Phase 3 (PRD F5), not this package's job.
func (s *Server) PublishIdentity(userID string, pub identity.PublicKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.identities[userID] = pub
}

// FetchIdentity returns a previously published identity public key.
func (s *Server) FetchIdentity(userID string) (identity.PublicKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pub, ok := s.identities[userID]
	if !ok {
		return identity.PublicKey{}, ErrUnknownUser
	}
	return pub, nil
}

// PublishPrekeys registers a fresh batch of one-time prekey bundles
// plus a signed last-resort prekey for userID, replacing whatever was
// published before. Only public Bundle/LastResort data is accepted —
// this package never sees or stores private key material (PRD F9).
func (s *Server) PublishPrekeys(userID string, bundles []*prekey.Bundle, lastResort *prekey.LastResort) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prekeys[userID] = &userPrekeys{
		bundles:    bundles,
		consumed:   make([]bool, len(bundles)),
		lastResort: lastResort,
	}
}

// FetchPrekeyBundle issues one not-yet-consumed one-time prekey bundle
// for userID, marking it consumed so it is never handed out again
// (PRD: one-time prekeys are exactly that). If the pool is exhausted,
// it falls back to the signed last-resort prekey (PRD F10) and
// reports isLastResort=true so the caller can track depletion.
func (s *Server) FetchPrekeyBundle(userID string) (bundle *prekey.Bundle, isLastResort bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	up, ok := s.prekeys[userID]
	if !ok {
		return nil, false, ErrNoPrekeysPublished
	}

	for i := 0; i < len(up.bundles); i++ {
		idx := (up.nextCursor + i) % len(up.bundles)
		if !up.consumed[idx] {
			up.consumed[idx] = true
			up.nextCursor = (idx + 1) % len(up.bundles)
			return up.bundles[idx], false, nil
		}
	}

	if up.lastResort == nil {
		return nil, false, ErrNoPrekeysAvailable
	}
	up.lastResortUse++
	return nil, true, nil
}

// LastResortPrekey returns userID's signed last-resort prekey
// directly, for the (isLastResort==true) case FetchPrekeyBundle
// signals.
func (s *Server) LastResortPrekey(userID string) (*prekey.LastResort, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	up, ok := s.prekeys[userID]
	if !ok {
		return nil, ErrNoPrekeysPublished
	}
	if up.lastResort == nil {
		return nil, ErrNoPrekeysAvailable
	}
	return up.lastResort, nil
}

// PrekeyTelemetry reports pool depletion state for userID, per PRD
// F9's "depletion telemetry" requirement and open risk #1 ("what's the
// actual replenishment SLA" — this is the raw signal that SLA would be
// defined against).
type PrekeyTelemetry struct {
	Remaining      int
	BatchSize      int
	LastResortUses int
}

func (s *Server) PrekeyTelemetry(userID string) (PrekeyTelemetry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	up, ok := s.prekeys[userID]
	if !ok {
		return PrekeyTelemetry{}, ErrNoPrekeysPublished
	}
	return PrekeyTelemetry{
		Remaining:      up.remaining(),
		BatchSize:      len(up.bundles),
		LastResortUses: up.lastResortUse,
	}, nil
}

// SendMessage enqueues an opaque envelope for recipientID. The relay
// does not require the recipient to be online — that's the whole
// point of store-and-forward (PRD F9).
func (s *Server) SendMessage(recipientID, senderID string, envelope []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.identities[recipientID]; !ok {
		return ErrUnknownUser
	}
	s.queues[recipientID] = append(s.queues[recipientID], QueuedMessage{
		From:     senderID,
		Envelope: envelope,
		QueuedAt: time.Now(),
	})
	return nil
}

// PollMessages returns and deletes every message queued for userID
// (delete-on-delivery, PRD F9).
func (s *Server) PollMessages(userID string) []QueuedMessage {
	s.mu.Lock()
	defer s.mu.Unlock()
	msgs := s.queues[userID]
	delete(s.queues, userID)
	return msgs
}

// PurgeExpired removes queued messages older than ttl as of now,
// returning how many were purged (PRD F9's 30-day undelivered TTL).
func (s *Server) PurgeExpired(now time.Time, ttl time.Duration) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	purged := 0
	for userID, msgs := range s.queues {
		kept := msgs[:0:0]
		for _, m := range msgs {
			if now.Sub(m.QueuedAt) > ttl {
				purged++
				continue
			}
			kept = append(kept, m)
		}
		if len(kept) == 0 {
			delete(s.queues, userID)
		} else {
			s.queues[userID] = kept
		}
	}
	return purged
}
