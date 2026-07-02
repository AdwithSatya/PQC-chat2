package kemhybrid

import (
	"bytes"
	"testing"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
)

func TestEncapsulateDecapsulateRoundTrip(t *testing.T) {
	responderPriv, err := GenerateKeyPair(nil)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	transcript := []byte("initiator-identity || responder-identity || prekey-bundle")

	ct, initiatorKey, err := Encapsulate(responderPriv.Public(), transcript, nil)
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}

	responderKey, err := Decapsulate(responderPriv, ct, transcript)
	if err != nil {
		t.Fatalf("Decapsulate: %v", err)
	}

	if !bytes.Equal(initiatorKey, responderKey) {
		t.Fatal("session keys do not match between initiator and responder")
	}
	if len(initiatorKey) != SessionKeySize {
		t.Fatalf("session key size = %d, want %d", len(initiatorKey), SessionKeySize)
	}
}

func TestDifferentTranscriptsProduceDifferentKeys(t *testing.T) {
	responderPriv, err := GenerateKeyPair(nil)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	ct, key1, err := Encapsulate(responderPriv.Public(), []byte("transcript-a"), nil)
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}

	// Decapsulate against a transcript that doesn't match what the
	// initiator used — this must NOT reproduce the initiator's key,
	// since transcript binding exists precisely to prevent unknown-
	// key-share attacks (PRD §5).
	key2, err := Decapsulate(responderPriv, ct, []byte("transcript-b"))
	if err != nil {
		t.Fatalf("Decapsulate: %v", err)
	}

	if bytes.Equal(key1, key2) {
		t.Fatal("session keys matched despite different transcripts")
	}
}

func TestTamperedMLKEMCiphertextChangesKey(t *testing.T) {
	responderPriv, err := GenerateKeyPair(nil)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	transcript := []byte("transcript")

	ct, initiatorKey, err := Encapsulate(responderPriv.Public(), transcript, nil)
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}

	tampered := *ct
	tampered.MLKEMCiphertext = bytes.Clone(ct.MLKEMCiphertext)
	tampered.MLKEMCiphertext[0] ^= 0xFF

	responderKey, err := Decapsulate(responderPriv, &tampered, transcript)
	if err != nil {
		t.Fatalf("Decapsulate: %v", err)
	}

	if bytes.Equal(initiatorKey, responderKey) {
		t.Fatal("tampering with the ML-KEM ciphertext did not change the derived key")
	}
}

func TestWrongMLKEMCiphertextSizeRejected(t *testing.T) {
	responderPriv, err := GenerateKeyPair(nil)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ct := &Ciphertext{
		X25519Ephemeral: responderPriv.Public().X25519,
		MLKEMCiphertext: make([]byte, mlkem768.CiphertextSize-1),
	}

	if _, err := Decapsulate(responderPriv, ct, []byte("t")); err != ErrDecapsulation {
		t.Fatalf("Decapsulate error = %v, want ErrDecapsulation", err)
	}
}
