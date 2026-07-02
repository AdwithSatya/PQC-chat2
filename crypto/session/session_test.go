package session

import (
	"bytes"
	"testing"

	"pqchat/crypto/identity"
	"pqchat/crypto/kemhybrid"
	"pqchat/crypto/prekey"
)

type party struct {
	id    *identity.KeyPair
	batch *prekey.Batch
}

func newParty(t *testing.T, prekeyCount int) *party {
	t.Helper()
	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}
	batch, err := prekey.GenerateBatch(id, prekeyCount)
	if err != nil {
		t.Fatalf("prekey.GenerateBatch: %v", err)
	}
	return &party{id: id, batch: batch}
}

// TestEstablishRoundTrip is Phase 1's core scenario: two local
// clients, no relay server, completing session establishment and a
// first message exchange in a single packet (PRD F3).
func TestEstablishRoundTrip(t *testing.T) {
	alice := newParty(t, 10)
	bob := newParty(t, 10)

	bundle, err := bob.batch.Bundle(0)
	if err != nil {
		t.Fatalf("Bundle: %v", err)
	}

	aliceState, initMsg, err := EstablishAsInitiator(alice.id, bob.id.Public(), bundle, []byte("hello bob"))
	if err != nil {
		t.Fatalf("EstablishAsInitiator: %v", err)
	}

	bobPrekeyPriv, err := bob.batch.PrivateKey(initMsg.PrekeyIndex)
	if err != nil {
		t.Fatalf("PrivateKey: %v", err)
	}

	bobState, plaintext, err := EstablishAsResponder(bob.id, bundle, bobPrekeyPriv, initMsg)
	if err != nil {
		t.Fatalf("EstablishAsResponder: %v", err)
	}

	if string(plaintext) != "hello bob" {
		t.Fatalf("got %q, want %q", plaintext, "hello bob")
	}

	// Continue the conversation past the handshake to prove the
	// established ratchet states are actually usable, not just
	// the initial message.
	hdr, ct, err := bobState.EncryptMessage([]byte("hi alice"), nil)
	if err != nil {
		t.Fatalf("bob EncryptMessage: %v", err)
	}
	reply, err := aliceState.DecryptMessage(hdr, ct, nil)
	if err != nil {
		t.Fatalf("alice DecryptMessage: %v", err)
	}
	if string(reply) != "hi alice" {
		t.Fatalf("got %q, want %q", reply, "hi alice")
	}
}

// TestSessionKeyMatchesOnBothSides is Phase 1's exit criterion
// "Session key matches on both sides", checked directly against the
// raw hybrid-KEM session key both parties derive (before either side's
// ratchet has mixed it further), rather than inferring it only from a
// successful decrypt.
func TestSessionKeyMatchesOnBothSides(t *testing.T) {
	alice := newParty(t, 5)
	bob := newParty(t, 5)

	bundle, err := bob.batch.Bundle(0)
	if err != nil {
		t.Fatalf("Bundle: %v", err)
	}
	if err := prekey.VerifyBundle(bob.id.Public(), bundle); err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}

	responderKEMPub, err := kemhybrid.UnmarshalPublicKey(bundle.PublicKey)
	if err != nil {
		t.Fatalf("UnmarshalPublicKey: %v", err)
	}

	transcript, err := buildTranscript(alice.id.Public(), bob.id.Public(), bundle)
	if err != nil {
		t.Fatalf("buildTranscript: %v", err)
	}

	ct, aliceSessionKey, err := kemhybrid.Encapsulate(responderKEMPub, transcript, nil)
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}

	bobPrekeyPriv, err := bob.batch.PrivateKey(0)
	if err != nil {
		t.Fatalf("PrivateKey: %v", err)
	}
	bobSessionKey, err := kemhybrid.Decapsulate(bobPrekeyPriv, ct, transcript)
	if err != nil {
		t.Fatalf("Decapsulate: %v", err)
	}

	if !bytes.Equal(aliceSessionKey, bobSessionKey) {
		t.Fatal("initiator and responder derived different session keys")
	}
}

// TestForwardSecrecyAfterEstablishment is Phase 1's other exit
// criterion: forward secrecy verified by a key-erasure test, run
// against ratchet state produced by full session establishment (not
// just the ratchet package's own unit-level init helpers).
func TestForwardSecrecyAfterEstablishment(t *testing.T) {
	alice := newParty(t, 5)
	bob := newParty(t, 5)

	bundle, err := bob.batch.Bundle(0)
	if err != nil {
		t.Fatalf("Bundle: %v", err)
	}
	aliceState, initMsg, err := EstablishAsInitiator(alice.id, bob.id.Public(), bundle, []byte("m0"))
	if err != nil {
		t.Fatalf("EstablishAsInitiator: %v", err)
	}
	bobPrekeyPriv, err := bob.batch.PrivateKey(initMsg.PrekeyIndex)
	if err != nil {
		t.Fatalf("PrivateKey: %v", err)
	}
	bobState, _, err := EstablishAsResponder(bob.id, bundle, bobPrekeyPriv, initMsg)
	if err != nil {
		t.Fatalf("EstablishAsResponder: %v", err)
	}

	// A second message, Alice -> Bob, so Bob has a receiving chain to
	// erase.
	hdr1, ct1, err := aliceState.EncryptMessage([]byte("m1"), nil)
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}
	if _, err := bobState.DecryptMessage(hdr1, ct1, nil); err != nil {
		t.Fatalf("DecryptMessage: %v", err)
	}

	hdr2, ct2, err := aliceState.EncryptMessage([]byte("m2"), nil)
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}

	// An attacker who compromises Bob right now (after m1 was
	// consumed, before m2 arrives) gets whatever chain state Bob
	// currently holds. That state must not be able to decrypt m1,
	// whose key was already erased by the chain step performed
	// during its own decryption.
	compromisedState := *bobState
	if _, err := compromisedState.DecryptMessage(hdr1, ct1, nil); err == nil {
		t.Fatal("a post-compromise state could still decrypt an already-consumed message")
	}

	if _, err := bobState.DecryptMessage(hdr2, ct2, nil); err != nil {
		t.Fatalf("legitimate decryption of m2 failed: %v", err)
	}
}

func TestEstablishRejectsWrongResponderIdentity(t *testing.T) {
	alice := newParty(t, 5)
	bob := newParty(t, 5)
	impostor := newParty(t, 5)

	bundle, err := bob.batch.Bundle(0)
	if err != nil {
		t.Fatalf("Bundle: %v", err)
	}

	if _, _, err := EstablishAsInitiator(alice.id, impostor.id.Public(), bundle, []byte("hi")); err == nil {
		t.Fatal("EstablishAsInitiator accepted a bundle that does not belong to the claimed responder")
	}
}

func TestEstablishRejectsTamperedFirstMessageCiphertext(t *testing.T) {
	alice := newParty(t, 5)
	bob := newParty(t, 5)

	bundle, err := bob.batch.Bundle(0)
	if err != nil {
		t.Fatalf("Bundle: %v", err)
	}
	_, initMsg, err := EstablishAsInitiator(alice.id, bob.id.Public(), bundle, []byte("hi"))
	if err != nil {
		t.Fatalf("EstablishAsInitiator: %v", err)
	}

	tampered := *initMsg
	tampered.Ciphertext = bytes.Clone(initMsg.Ciphertext)
	tampered.Ciphertext[0] ^= 0xFF

	bobPrekeyPriv, err := bob.batch.PrivateKey(initMsg.PrekeyIndex)
	if err != nil {
		t.Fatalf("PrivateKey: %v", err)
	}
	if _, _, err := EstablishAsResponder(bob.id, bundle, bobPrekeyPriv, &tampered); err == nil {
		t.Fatal("EstablishAsResponder accepted a tampered first-message ciphertext")
	}
}

func TestEstablishRejectsMismatchedTranscript(t *testing.T) {
	alice := newParty(t, 5)
	bob := newParty(t, 5)

	bundle, err := bob.batch.Bundle(0)
	if err != nil {
		t.Fatalf("Bundle: %v", err)
	}
	_, initMsg, err := EstablishAsInitiator(alice.id, bob.id.Public(), bundle, []byte("hi"))
	if err != nil {
		t.Fatalf("EstablishAsInitiator: %v", err)
	}

	// Simulate the message being delivered as if it were addressed to
	// a *different* claimed sender identity -- the transcript Bob
	// reconstructs won't match the one Alice used, so decapsulation
	// must not silently succeed with the wrong key.
	impostor := newParty(t, 1)
	tampered := *initMsg
	tampered.SenderIdentity = impostor.id.Public()

	bobPrekeyPriv, err := bob.batch.PrivateKey(initMsg.PrekeyIndex)
	if err != nil {
		t.Fatalf("PrivateKey: %v", err)
	}
	state, _, err := EstablishAsResponder(bob.id, bundle, bobPrekeyPriv, &tampered)
	if err == nil {
		// kemhybrid's implicit rejection means Decapsulate itself
		// won't error -- it derives *some* key. The real check is
		// that this key cannot possibly match Alice's, which the
		// AEAD decryption of the piggybacked first message enforces.
		t.Fatalf("expected first-message decryption to fail under a mismatched transcript, got state %v", state)
	}
}
