package relay

import (
	"sync"
	"testing"
	"time"

	"pqchat/crypto/identity"
	"pqchat/crypto/prekey"
)

func newTestIdentity(t *testing.T) *identity.KeyPair {
	t.Helper()
	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}
	return id
}

func TestPublishAndFetchIdentity(t *testing.T) {
	s := NewServer()
	id := newTestIdentity(t)

	s.PublishIdentity("bob", id.Public())

	got, err := s.FetchIdentity("bob")
	if err != nil {
		t.Fatalf("FetchIdentity: %v", err)
	}
	if !got.Ed25519.Equal(id.Public().Ed25519) {
		t.Fatal("fetched identity does not match published identity")
	}
}

func TestFetchIdentityUnknownUser(t *testing.T) {
	s := NewServer()
	if _, err := s.FetchIdentity("nobody"); err != ErrUnknownUser {
		t.Fatalf("error = %v, want ErrUnknownUser", err)
	}
}

func bundlesFor(t *testing.T, batch *prekey.Batch) []*prekey.Bundle {
	t.Helper()
	bundles := make([]*prekey.Bundle, batch.Size())
	for i := 0; i < batch.Size(); i++ {
		b, err := batch.Bundle(i)
		if err != nil {
			t.Fatalf("Bundle(%d): %v", i, err)
		}
		bundles[i] = b
	}
	return bundles
}

func TestFetchPrekeyBundleConsumesEachOnce(t *testing.T) {
	s := NewServer()
	id := newTestIdentity(t)
	s.PublishIdentity("bob", id.Public())

	batch, err := prekey.GenerateBatch(id, 5)
	if err != nil {
		t.Fatalf("GenerateBatch: %v", err)
	}
	_, lastResort, err := prekey.GenerateLastResort(id)
	if err != nil {
		t.Fatalf("GenerateLastResort: %v", err)
	}
	s.PublishPrekeys("bob", bundlesFor(t, batch), lastResort)

	seen := make(map[int]bool)
	for i := 0; i < 5; i++ {
		bundle, isLastResort, err := s.FetchPrekeyBundle("bob")
		if err != nil {
			t.Fatalf("FetchPrekeyBundle: %v", err)
		}
		if isLastResort {
			t.Fatalf("got last-resort key on issuance %d, expected a one-time key", i)
		}
		if seen[bundle.Index] {
			t.Fatalf("index %d issued more than once", bundle.Index)
		}
		seen[bundle.Index] = true
	}

	if len(seen) != 5 {
		t.Fatalf("issued %d distinct indices, want 5", len(seen))
	}
}

// TestPrekeyDepletionChaos is Phase 2's "prekey depletion chaos test"
// exit criterion: many concurrent fetchers racing against a small
// pool must never double-issue a one-time key, and must fall back to
// the last-resort key exactly once the pool is exhausted, however the
// requests happen to interleave.
func TestPrekeyDepletionChaos(t *testing.T) {
	const batchSize = 50
	const fetchers = 200 // far more than batchSize, forcing depletion

	s := NewServer()
	id := newTestIdentity(t)
	s.PublishIdentity("bob", id.Public())

	batch, err := prekey.GenerateBatch(id, batchSize)
	if err != nil {
		t.Fatalf("GenerateBatch: %v", err)
	}
	_, lastResort, err := prekey.GenerateLastResort(id)
	if err != nil {
		t.Fatalf("GenerateLastResort: %v", err)
	}
	s.PublishPrekeys("bob", bundlesFor(t, batch), lastResort)

	var mu sync.Mutex
	seenIndices := make(map[int]int) // index -> issuance count
	lastResortCount := 0

	var wg sync.WaitGroup
	for i := 0; i < fetchers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			bundle, isLastResort, err := s.FetchPrekeyBundle("bob")
			if err != nil {
				t.Errorf("FetchPrekeyBundle: %v", err)
				return
			}
			mu.Lock()
			defer mu.Unlock()
			if isLastResort {
				lastResortCount++
			} else {
				seenIndices[bundle.Index]++
			}
		}()
	}
	wg.Wait()

	if len(seenIndices) != batchSize {
		t.Errorf("distinct one-time indices issued = %d, want %d", len(seenIndices), batchSize)
	}
	for idx, count := range seenIndices {
		if count != 1 {
			t.Errorf("index %d issued %d times, want exactly 1", idx, count)
		}
	}
	if want := fetchers - batchSize; lastResortCount != want {
		t.Errorf("last-resort issuances = %d, want %d", lastResortCount, want)
	}

	telemetry, err := s.PrekeyTelemetry("bob")
	if err != nil {
		t.Fatalf("PrekeyTelemetry: %v", err)
	}
	if telemetry.Remaining != 0 {
		t.Errorf("Remaining = %d, want 0 after full depletion", telemetry.Remaining)
	}
	if telemetry.LastResortUses != fetchers-batchSize {
		t.Errorf("LastResortUses = %d, want %d", telemetry.LastResortUses, fetchers-batchSize)
	}
}

func TestFetchPrekeyBundleNoLastResortErrorsWhenExhausted(t *testing.T) {
	s := NewServer()
	id := newTestIdentity(t)
	s.PublishIdentity("bob", id.Public())

	batch, err := prekey.GenerateBatch(id, 1)
	if err != nil {
		t.Fatalf("GenerateBatch: %v", err)
	}
	s.PublishPrekeys("bob", bundlesFor(t, batch), nil)

	if _, _, err := s.FetchPrekeyBundle("bob"); err != nil {
		t.Fatalf("first FetchPrekeyBundle: %v", err)
	}
	if _, _, err := s.FetchPrekeyBundle("bob"); err != ErrNoPrekeysAvailable {
		t.Fatalf("error = %v, want ErrNoPrekeysAvailable", err)
	}
}

func TestSendAndPollMessages(t *testing.T) {
	s := NewServer()
	id := newTestIdentity(t)
	s.PublishIdentity("bob", id.Public())

	if err := s.SendMessage("bob", "alice", []byte("envelope-1")); err != nil {
		t.Fatalf("SendMessage: %v", err)
	}
	if err := s.SendMessage("bob", "alice", []byte("envelope-2")); err != nil {
		t.Fatalf("SendMessage: %v", err)
	}

	msgs := s.PollMessages("bob")
	if len(msgs) != 2 {
		t.Fatalf("got %d messages, want 2", len(msgs))
	}
	if string(msgs[0].Envelope) != "envelope-1" || string(msgs[1].Envelope) != "envelope-2" {
		t.Fatalf("messages out of order or corrupted: %+v", msgs)
	}
}

func TestPollDeletesOnDelivery(t *testing.T) {
	s := NewServer()
	id := newTestIdentity(t)
	s.PublishIdentity("bob", id.Public())

	if err := s.SendMessage("bob", "alice", []byte("hi")); err != nil {
		t.Fatalf("SendMessage: %v", err)
	}
	if msgs := s.PollMessages("bob"); len(msgs) != 1 {
		t.Fatalf("first poll got %d messages, want 1", len(msgs))
	}
	if msgs := s.PollMessages("bob"); len(msgs) != 0 {
		t.Fatalf("second poll got %d messages, want 0 (delete-on-delivery)", len(msgs))
	}
}

func TestSendMessageRejectsUnknownRecipient(t *testing.T) {
	s := NewServer()
	if err := s.SendMessage("nobody", "alice", []byte("hi")); err != ErrUnknownUser {
		t.Fatalf("error = %v, want ErrUnknownUser", err)
	}
}

func TestPurgeExpiredMessages(t *testing.T) {
	s := NewServer()
	id := newTestIdentity(t)
	s.PublishIdentity("bob", id.Public())

	if err := s.SendMessage("bob", "alice", []byte("old")); err != nil {
		t.Fatalf("SendMessage: %v", err)
	}
	// Backdate the queued message past the TTL.
	s.mu.Lock()
	s.queues["bob"][0].QueuedAt = time.Now().Add(-31 * 24 * time.Hour)
	s.mu.Unlock()

	if err := s.SendMessage("bob", "alice", []byte("fresh")); err != nil {
		t.Fatalf("SendMessage: %v", err)
	}

	purged := s.PurgeExpired(time.Now(), DefaultMessageTTL)
	if purged != 1 {
		t.Fatalf("purged = %d, want 1", purged)
	}

	msgs := s.PollMessages("bob")
	if len(msgs) != 1 || string(msgs[0].Envelope) != "fresh" {
		t.Fatalf("expected only the fresh message to survive purge, got %+v", msgs)
	}
}
