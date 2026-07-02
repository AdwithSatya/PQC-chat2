package relay

import (
	"testing"

	"pqchat/crypto/identity"
	"pqchat/crypto/prekey"
	"pqchat/crypto/session"
)

// TestOfflineRecipientDelivery is Phase 2's headline exit criterion:
// "Message delivered to an offline recipient who comes online later."
// Bob never touches the server while Alice sends; the message sits in
// the relay's queue until Bob polls, at which point he completes
// session establishment and reads it — proving the store-and-forward
// path and the zero-additional-RTT handshake compose correctly.
func TestOfflineRecipientDelivery(t *testing.T) {
	relay := NewServer()

	aliceID, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}
	bobID, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}
	relay.PublishIdentity("alice", aliceID.Public())
	relay.PublishIdentity("bob", bobID.Public())

	bobBatch, err := prekey.GenerateBatch(bobID, 10)
	if err != nil {
		t.Fatalf("GenerateBatch: %v", err)
	}
	_, bobLastResort, err := prekey.GenerateLastResort(bobID)
	if err != nil {
		t.Fatalf("GenerateLastResort: %v", err)
	}
	relay.PublishPrekeys("bob", bundlesFor(t, bobBatch), bobLastResort)

	// --- Alice sends while Bob is offline. ---
	bobIdentityPub, err := relay.FetchIdentity("bob")
	if err != nil {
		t.Fatalf("FetchIdentity: %v", err)
	}
	bundle, isLastResort, err := relay.FetchPrekeyBundle("bob")
	if err != nil {
		t.Fatalf("FetchPrekeyBundle: %v", err)
	}
	if isLastResort {
		t.Fatal("expected a one-time prekey, got the last-resort key")
	}

	aliceState, initMsg, err := session.EstablishAsInitiator(aliceID, bobIdentityPub, bundle, []byte("are you there?"))
	if err != nil {
		t.Fatalf("EstablishAsInitiator: %v", err)
	}
	envelope, err := initMsg.MarshalEnvelope()
	if err != nil {
		t.Fatalf("MarshalEnvelope: %v", err)
	}
	if err := relay.SendMessage("bob", "alice", envelope); err != nil {
		t.Fatalf("SendMessage: %v", err)
	}

	// Bob is still offline: nothing has been delivered to him, but the
	// message is durably queued.
	telemetry, err := relay.PrekeyTelemetry("bob")
	if err != nil {
		t.Fatalf("PrekeyTelemetry: %v", err)
	}
	if telemetry.Remaining != bobBatch.Size()-1 {
		t.Fatalf("Remaining = %d, want %d", telemetry.Remaining, bobBatch.Size()-1)
	}

	// --- Time passes. Bob comes online and polls. ---
	queued := relay.PollMessages("bob")
	if len(queued) != 1 {
		t.Fatalf("got %d queued messages for Bob, want 1", len(queued))
	}
	if queued[0].From != "alice" {
		t.Fatalf("From = %q, want %q", queued[0].From, "alice")
	}

	gotInit, gotSub, err := session.UnmarshalEnvelope(queued[0].Envelope)
	if err != nil {
		t.Fatalf("UnmarshalEnvelope: %v", err)
	}
	if gotSub != nil || gotInit == nil {
		t.Fatal("expected the queued envelope to be an InitialMessage")
	}

	bobPrekeyPriv, err := bobBatch.PrivateKey(gotInit.PrekeyIndex)
	if err != nil {
		t.Fatalf("PrivateKey: %v", err)
	}
	bobState, plaintext, err := session.EstablishAsResponder(bobID, bundle, bobPrekeyPriv, gotInit)
	if err != nil {
		t.Fatalf("EstablishAsResponder: %v", err)
	}
	if string(plaintext) != "are you there?" {
		t.Fatalf("got %q, want %q", plaintext, "are you there?")
	}

	// A second poll must come back empty (delete-on-delivery).
	if msgs := relay.PollMessages("bob"); len(msgs) != 0 {
		t.Fatalf("second poll got %d messages, want 0", len(msgs))
	}

	// --- Bob replies, also relayed, also verified end to end. ---
	hdr, ct, err := bobState.EncryptMessage([]byte("yes, I'm here now"), nil)
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}
	sub := &session.SubsequentMessage{Header: hdr, Ciphertext: ct}
	if err := relay.SendMessage("alice", "bob", sub.MarshalEnvelope()); err != nil {
		t.Fatalf("SendMessage: %v", err)
	}

	aliceQueue := relay.PollMessages("alice")
	if len(aliceQueue) != 1 {
		t.Fatalf("got %d queued messages for Alice, want 1", len(aliceQueue))
	}
	_, gotSub2, err := session.UnmarshalEnvelope(aliceQueue[0].Envelope)
	if err != nil {
		t.Fatalf("UnmarshalEnvelope: %v", err)
	}
	reply, err := aliceState.DecryptMessage(gotSub2.Header, gotSub2.Ciphertext, nil)
	if err != nil {
		t.Fatalf("DecryptMessage: %v", err)
	}
	if string(reply) != "yes, I'm here now" {
		t.Fatalf("got %q, want %q", reply, "yes, I'm here now")
	}
}

// TestOfflineDeliveryFallsBackToLastResortWhenPoolExhausted exercises
// F10 end to end: once Bob's one-time pool is drained, new sessions
// still establish correctly against his last-resort key while he's
// offline.
func TestOfflineDeliveryFallsBackToLastResortWhenPoolExhausted(t *testing.T) {
	relay := NewServer()

	aliceID, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}
	bobID, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}
	relay.PublishIdentity("alice", aliceID.Public())
	relay.PublishIdentity("bob", bobID.Public())

	bobBatch, err := prekey.GenerateBatch(bobID, 1)
	if err != nil {
		t.Fatalf("GenerateBatch: %v", err)
	}
	bobLastResortPriv, bobLastResort, err := prekey.GenerateLastResort(bobID)
	if err != nil {
		t.Fatalf("GenerateLastResort: %v", err)
	}
	relay.PublishPrekeys("bob", bundlesFor(t, bobBatch), bobLastResort)

	// Drain the single one-time prekey.
	if _, isLastResort, err := relay.FetchPrekeyBundle("bob"); err != nil || isLastResort {
		t.Fatalf("expected to drain the one one-time prekey first, isLastResort=%v err=%v", isLastResort, err)
	}

	bobIdentityPub, err := relay.FetchIdentity("bob")
	if err != nil {
		t.Fatalf("FetchIdentity: %v", err)
	}
	_, isLastResort, err := relay.FetchPrekeyBundle("bob")
	if err != nil {
		t.Fatalf("FetchPrekeyBundle: %v", err)
	}
	if !isLastResort {
		t.Fatal("expected the pool to be exhausted, forcing last-resort issuance")
	}
	lastResort, err := relay.LastResortPrekey("bob")
	if err != nil {
		t.Fatalf("LastResortPrekey: %v", err)
	}
	if err := prekey.VerifyLastResort(bobIdentityPub, lastResort); err != nil {
		t.Fatalf("VerifyLastResort: %v", err)
	}

	// Alice establishes against Bob's last-resort key while he's
	// offline, via the last-resort-specific path (the key carries a
	// direct signature, not a Merkle inclusion proof, so it can't go
	// through the batch-bundle establishment functions).
	_, initMsg, err := session.EstablishAsInitiatorLastResort(aliceID, bobIdentityPub, lastResort, []byte("pool's dry, using last resort"))
	if err != nil {
		t.Fatalf("EstablishAsInitiatorLastResort: %v", err)
	}
	if !initMsg.IsLastResort {
		t.Fatal("expected InitialMessage.IsLastResort to be true")
	}
	envelope, err := initMsg.MarshalEnvelope()
	if err != nil {
		t.Fatalf("MarshalEnvelope: %v", err)
	}
	if err := relay.SendMessage("bob", "alice", envelope); err != nil {
		t.Fatalf("SendMessage: %v", err)
	}

	// Bob comes online, polls, and establishes his side against the
	// same last-resort private key.
	queued := relay.PollMessages("bob")
	if len(queued) != 1 {
		t.Fatalf("got %d queued messages for Bob, want 1", len(queued))
	}
	gotInit, gotSub, err := session.UnmarshalEnvelope(queued[0].Envelope)
	if err != nil {
		t.Fatalf("UnmarshalEnvelope: %v", err)
	}
	if gotSub != nil || gotInit == nil || !gotInit.IsLastResort {
		t.Fatal("expected a last-resort InitialMessage")
	}

	_, plaintext, err := session.EstablishAsResponderLastResort(bobID, lastResort, bobLastResortPriv, gotInit)
	if err != nil {
		t.Fatalf("EstablishAsResponderLastResort: %v", err)
	}
	if string(plaintext) != "pool's dry, using last resort" {
		t.Fatalf("got %q, want %q", plaintext, "pool's dry, using last resort")
	}
}
