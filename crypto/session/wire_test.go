package session

import (
	"testing"
)

func TestInitialMessageWireRoundTrip(t *testing.T) {
	alice := newParty(t, 5)
	bob := newParty(t, 5)

	bundle, err := bob.batch.Bundle(0)
	if err != nil {
		t.Fatalf("Bundle: %v", err)
	}
	_, initMsg, err := EstablishAsInitiator(alice.id, bob.id.Public(), bundle, []byte("wire test"))
	if err != nil {
		t.Fatalf("EstablishAsInitiator: %v", err)
	}

	envelope, err := initMsg.MarshalEnvelope()
	if err != nil {
		t.Fatalf("MarshalEnvelope: %v", err)
	}

	gotInit, gotSub, err := UnmarshalEnvelope(envelope)
	if err != nil {
		t.Fatalf("UnmarshalEnvelope: %v", err)
	}
	if gotSub != nil {
		t.Fatal("expected a nil SubsequentMessage for an initial-message envelope")
	}
	if gotInit == nil {
		t.Fatal("expected a non-nil InitialMessage")
	}

	bobPrekeyPriv, err := bob.batch.PrivateKey(gotInit.PrekeyIndex)
	if err != nil {
		t.Fatalf("PrivateKey: %v", err)
	}
	_, plaintext, err := EstablishAsResponder(bob.id, bundle, bobPrekeyPriv, gotInit)
	if err != nil {
		t.Fatalf("EstablishAsResponder after wire round-trip: %v", err)
	}
	if string(plaintext) != "wire test" {
		t.Fatalf("got %q, want %q", plaintext, "wire test")
	}
}

func TestSubsequentMessageWireRoundTrip(t *testing.T) {
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

	hdr, ct, err := bobState.EncryptMessage([]byte("wire subsequent"), nil)
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}
	sub := &SubsequentMessage{Header: hdr, Ciphertext: ct}
	envelope := sub.MarshalEnvelope()

	gotInit, gotSub, err := UnmarshalEnvelope(envelope)
	if err != nil {
		t.Fatalf("UnmarshalEnvelope: %v", err)
	}
	if gotInit != nil {
		t.Fatal("expected a nil InitialMessage for a subsequent-message envelope")
	}
	if gotSub == nil {
		t.Fatal("expected a non-nil SubsequentMessage")
	}

	plaintext, err := aliceState.DecryptMessage(gotSub.Header, gotSub.Ciphertext, nil)
	if err != nil {
		t.Fatalf("DecryptMessage after wire round-trip: %v", err)
	}
	if string(plaintext) != "wire subsequent" {
		t.Fatalf("got %q, want %q", plaintext, "wire subsequent")
	}
}

func TestUnmarshalEnvelopeRejectsUnknownType(t *testing.T) {
	if _, _, err := UnmarshalEnvelope([]byte{0xFF, 0x01, 0x02}); err != ErrUnknownEnvelopeType {
		t.Fatalf("error = %v, want ErrUnknownEnvelopeType", err)
	}
}

func TestUnmarshalEnvelopeRejectsEmpty(t *testing.T) {
	if _, _, err := UnmarshalEnvelope(nil); err == nil {
		t.Fatal("expected an error for an empty envelope")
	}
}

func TestUnmarshalInitialMessageRejectsTruncatedBuffer(t *testing.T) {
	alice := newParty(t, 5)
	bob := newParty(t, 5)
	bundle, err := bob.batch.Bundle(0)
	if err != nil {
		t.Fatalf("Bundle: %v", err)
	}
	_, initMsg, err := EstablishAsInitiator(alice.id, bob.id.Public(), bundle, []byte("m"))
	if err != nil {
		t.Fatalf("EstablishAsInitiator: %v", err)
	}
	envelope, err := initMsg.MarshalEnvelope()
	if err != nil {
		t.Fatalf("MarshalEnvelope: %v", err)
	}

	truncated := envelope[:len(envelope)-10]
	if _, _, err := UnmarshalEnvelope(truncated); err == nil {
		t.Fatal("expected an error unmarshaling a truncated envelope")
	}
}
