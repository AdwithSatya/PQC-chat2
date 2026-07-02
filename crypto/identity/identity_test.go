package identity

import (
	"bytes"
	"testing"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	kp, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	msg := []byte("pqchat prekey bundle v1")
	sig, err := kp.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if err := Verify(kp.Public(), msg, sig); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerifyRejectsTamperedMessage(t *testing.T) {
	kp, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	msg := []byte("original message")
	sig, err := kp.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	tampered := []byte("tampered message")
	if err := Verify(kp.Public(), tampered, sig); err == nil {
		t.Fatal("Verify accepted a signature over a different message")
	}
}

func TestVerifyRejectsTamperedEd25519Component(t *testing.T) {
	kp, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	msg := []byte("message")
	sig, err := kp.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	corrupted := *sig
	corrupted.Ed25519 = bytes.Clone(sig.Ed25519)
	corrupted.Ed25519[0] ^= 0xFF

	if err := Verify(kp.Public(), msg, &corrupted); err == nil {
		t.Fatal("Verify accepted a corrupted Ed25519 component")
	}
}

func TestVerifyRejectsTamperedMLDSAComponent(t *testing.T) {
	kp, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	msg := []byte("message")
	sig, err := kp.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	corrupted := *sig
	corrupted.MLDSA = bytes.Clone(sig.MLDSA)
	corrupted.MLDSA[0] ^= 0xFF

	if err := Verify(kp.Public(), msg, &corrupted); err == nil {
		t.Fatal("Verify accepted a corrupted ML-DSA-65 component")
	}
}

func TestVerifyRejectsWrongIdentity(t *testing.T) {
	kp1, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	kp2, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	msg := []byte("message")
	sig, err := kp1.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if err := Verify(kp2.Public(), msg, sig); err == nil {
		t.Fatal("Verify accepted a signature under the wrong identity's public key")
	}
}
