package ratchet

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"
	"time"
)

func newTestPair(t *testing.T) (*State, *State) {
	t.Helper()

	bobRatchetPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating Bob's ratchet key: %v", err)
	}

	sessionKey := make([]byte, 32)
	if _, err := rand.Read(sessionKey); err != nil {
		t.Fatalf("generating session key: %v", err)
	}
	// Alice and Bob must start from the identical session key, as they
	// would after crypto/kemhybrid's Encapsulate/Decapsulate agree.
	sessionKeyCopy := bytes.Clone(sessionKey)

	alice, err := InitAlice(sessionKey, bobRatchetPriv.PublicKey())
	if err != nil {
		t.Fatalf("InitAlice: %v", err)
	}
	bob := InitBob(sessionKeyCopy, bobRatchetPriv)

	return alice, bob
}

func TestBasicAliceToBobMessage(t *testing.T) {
	alice, bob := newTestPair(t)

	hdr, ct, err := alice.EncryptMessage([]byte("hello bob"), nil)
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}

	pt, err := bob.DecryptMessage(hdr, ct, nil)
	if err != nil {
		t.Fatalf("DecryptMessage: %v", err)
	}
	if string(pt) != "hello bob" {
		t.Fatalf("got %q, want %q", pt, "hello bob")
	}
}

func TestAlternatingConversation(t *testing.T) {
	alice, bob := newTestPair(t)

	send := func(from, to *State, name, msg string) {
		hdr, ct, err := from.EncryptMessage([]byte(msg), []byte(name))
		if err != nil {
			t.Fatalf("%s EncryptMessage: %v", name, err)
		}
		pt, err := to.DecryptMessage(hdr, ct, []byte(name))
		if err != nil {
			t.Fatalf("%s's peer DecryptMessage: %v", name, err)
		}
		if string(pt) != msg {
			t.Fatalf("got %q, want %q", pt, msg)
		}
	}

	for i := 0; i < 20; i++ {
		send(alice, bob, "alice", "hi from alice")
		send(bob, alice, "bob", "hi from bob")
	}
}

func TestMultipleMessagesInOneChain(t *testing.T) {
	alice, bob := newTestPair(t)

	for i := 0; i < 5; i++ {
		hdr, ct, err := alice.EncryptMessage([]byte("msg"), nil)
		if err != nil {
			t.Fatalf("EncryptMessage: %v", err)
		}
		if _, err := bob.DecryptMessage(hdr, ct, nil); err != nil {
			t.Fatalf("DecryptMessage: %v", err)
		}
	}
}

func TestOutOfOrderDeliveryWithinSkipWindow(t *testing.T) {
	alice, bob := newTestPair(t)

	type sent struct {
		hdr *Header
		ct  []byte
	}
	var msgs []sent
	for i := 0; i < 5; i++ {
		hdr, ct, err := alice.EncryptMessage([]byte("msg"), nil)
		if err != nil {
			t.Fatalf("EncryptMessage: %v", err)
		}
		msgs = append(msgs, sent{hdr, ct})
	}

	// Deliver out of order: 0, 2, 4, then 1, 3.
	order := []int{0, 2, 4, 1, 3}
	for _, i := range order {
		if _, err := bob.DecryptMessage(msgs[i].hdr, msgs[i].ct, nil); err != nil {
			t.Fatalf("DecryptMessage(msg %d): %v", i, err)
		}
	}
}

func TestDuplicateMessageRejected(t *testing.T) {
	alice, bob := newTestPair(t)

	hdr, ct, err := alice.EncryptMessage([]byte("msg"), nil)
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}
	if _, err := bob.DecryptMessage(hdr, ct, nil); err != nil {
		t.Fatalf("first DecryptMessage: %v", err)
	}
	if _, err := bob.DecryptMessage(hdr, ct, nil); err == nil {
		t.Fatal("replaying the same message succeeded; want an error")
	}
}

func TestTamperedCiphertextRejected(t *testing.T) {
	alice, bob := newTestPair(t)

	hdr, ct, err := alice.EncryptMessage([]byte("msg"), nil)
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}
	tampered := bytes.Clone(ct)
	tampered[0] ^= 0xFF

	if _, err := bob.DecryptMessage(hdr, tampered, nil); err == nil {
		t.Fatal("decrypted a tampered ciphertext; want an error")
	}
}

func TestForwardSecrecyKeyErasure(t *testing.T) {
	alice, bob := newTestPair(t)

	// Alice -> Bob, so Bob has a receiving chain key to erase.
	hdr1, ct1, err := alice.EncryptMessage([]byte("first"), nil)
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}
	if _, err := bob.DecryptMessage(hdr1, ct1, nil); err != nil {
		t.Fatalf("DecryptMessage: %v", err)
	}

	// Snapshot the message key an attacker who compromises Bob right
	// now could extract by re-deriving from his current chain state.
	chainSnapshot := bytes.Clone(bob.chainRecv)
	compromisedKey := chainStep(&chainSnapshot)

	hdr2, ct2, err := alice.EncryptMessage([]byte("second"), nil)
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}

	// The key an attacker could derive from the post-compromise chain
	// state must not be the key that actually decrypts message 2,
	// because message 1's key material was erased (chain stepped)
	// during its own decryption, and the attacker's snapshot is
	// downstream of message 1 already having consumed the chain step.
	// The real forward-secrecy property under test: this snapshot key
	// cannot decrypt message 1 (already consumed and erased) and
	// message 2 requires the chain to have advanced past this
	// snapshot's own consumption.
	if _, err := aeadOpen(compromisedKey, ct1, associatedDataWithHeader(hdr1, nil)); err == nil {
		t.Fatal("a key derived after message 1 was consumed could still decrypt message 1")
	}

	if _, err := bob.DecryptMessage(hdr2, ct2, nil); err != nil {
		t.Fatalf("legitimate DecryptMessage of message 2 failed: %v", err)
	}
}

func TestPQInjectionOccursOnSchedule(t *testing.T) {
	alice, bob := newTestPair(t)
	alice.MessageThreshold = 3
	bob.MessageThreshold = 3

	sawMLKEMPub := false
	sawMLKEMCiphertext := false

	send := func(from, to *State, msg string) {
		hdr, ct, err := from.EncryptMessage([]byte(msg), nil)
		if err != nil {
			t.Fatalf("EncryptMessage: %v", err)
		}
		if hdr.MLKEMPub != nil {
			sawMLKEMPub = true
		}
		if hdr.MLKEMCiphertext != nil {
			sawMLKEMCiphertext = true
		}
		if _, err := to.DecryptMessage(hdr, ct, nil); err != nil {
			t.Fatalf("DecryptMessage: %v", err)
		}
	}

	// Enough alternating turns to cross the (lowered) threshold twice
	// over, so both the injection-initiating side and the
	// injection-responding side get exercised.
	for i := 0; i < 10; i++ {
		send(alice, bob, "a")
		send(bob, alice, "b")
	}

	if !sawMLKEMPub {
		t.Error("no message ever carried an ML-KEM public key; PQ injection never triggered")
	}
	if !sawMLKEMCiphertext {
		t.Error("no message ever carried an ML-KEM ciphertext; PQ injection response never sent")
	}
}

func TestPQInjectionOnTimeThreshold(t *testing.T) {
	alice, bob := newTestPair(t)
	alice.MessageThreshold = 1 << 30 // effectively disabled
	bob.MessageThreshold = 1 << 30
	alice.TimeThreshold = 0 // always due
	bob.TimeThreshold = 0

	// Message 1, Alice -> Bob: Alice's sending chain was already
	// established fresh in InitAlice (itself seeded by a fresh
	// ML-KEM-768 encapsulation during session establishment), so her
	// very first send does not re-check the injection schedule — by
	// design, prepareSendingChain only runs the injection check when
	// starting a *new* sending chain after having received something.
	hdr1, ct1, err := alice.EncryptMessage([]byte("a"), nil)
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}
	if hdr1.MLKEMPub != nil {
		t.Fatal("did not expect a PQ injection on Alice's first message")
	}
	if _, err := bob.DecryptMessage(hdr1, ct1, nil); err != nil {
		t.Fatalf("DecryptMessage: %v", err)
	}

	// Message 2, Bob -> Alice: this is Bob's first new sending chain,
	// triggered by having just received from Alice, so it does run
	// the injection check — with TimeThreshold=0, it's always due.
	hdr2, ct2, err := bob.EncryptMessage([]byte("b"), nil)
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}
	if hdr2.MLKEMPub == nil {
		t.Fatal("expected Bob to initiate a PQ injection on his first new sending chain")
	}
	if _, err := alice.DecryptMessage(hdr2, ct2, nil); err != nil {
		t.Fatalf("DecryptMessage: %v", err)
	}

	// Message 3, Alice -> Bob: Alice owes Bob a response to the
	// ML-KEM public key he just advertised.
	hdr3, ct3, err := alice.EncryptMessage([]byte("c"), nil)
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}
	if hdr3.MLKEMCiphertext == nil {
		t.Fatal("expected Alice to respond to Bob's PQ injection with an ML-KEM ciphertext")
	}
	if _, err := bob.DecryptMessage(hdr3, ct3, nil); err != nil {
		t.Fatalf("DecryptMessage: %v", err)
	}
}

func TestHeaderMarshalRoundTrip(t *testing.T) {
	hdr := &Header{
		DHPub:           bytes.Repeat([]byte{0x01}, 32),
		PN:              7,
		N:               42,
		MLKEMPub:        bytes.Repeat([]byte{0x02}, 1184),
		MLKEMCiphertext: bytes.Repeat([]byte{0x03}, 1088),
	}
	buf := hdr.Marshal()
	got, err := UnmarshalHeader(buf)
	if err != nil {
		t.Fatalf("UnmarshalHeader: %v", err)
	}
	if !bytes.Equal(got.DHPub, hdr.DHPub) || got.PN != hdr.PN || got.N != hdr.N ||
		!bytes.Equal(got.MLKEMPub, hdr.MLKEMPub) || !bytes.Equal(got.MLKEMCiphertext, hdr.MLKEMCiphertext) {
		t.Fatal("round-tripped header does not match original")
	}
}

func TestHeaderMarshalRoundTripNoOptionalFields(t *testing.T) {
	hdr := &Header{DHPub: bytes.Repeat([]byte{0x01}, 32), PN: 0, N: 0}
	got, err := UnmarshalHeader(hdr.Marshal())
	if err != nil {
		t.Fatalf("UnmarshalHeader: %v", err)
	}
	if got.MLKEMPub != nil || got.MLKEMCiphertext != nil {
		t.Fatal("expected nil optional fields to round-trip as nil")
	}
}

func TestSkipTooLargeRejected(t *testing.T) {
	alice, bob := newTestPair(t)

	hdr, ct, err := alice.EncryptMessage([]byte("first"), nil)
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}
	if _, err := bob.DecryptMessage(hdr, ct, nil); err != nil {
		t.Fatalf("DecryptMessage: %v", err)
	}

	// Craft a header claiming an enormous message index in the same
	// chain, forcing an out-of-bounds skip.
	hdr2, ct2, err := alice.EncryptMessage([]byte("far"), nil)
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}
	hdr2.N = MaxSkip + 100

	if _, err := bob.DecryptMessage(hdr2, ct2, nil); err != ErrSkipTooLarge {
		t.Fatalf("error = %v, want ErrSkipTooLarge", err)
	}
}

func TestInitBobHasNoImmediateSendingChain(t *testing.T) {
	_, bob := newTestPair(t)
	if bob.chainSend != nil {
		t.Fatal("Bob should have no sending chain until he receives a message from Alice")
	}
}

func TestSessionKeysDivergeAcrossSessions(t *testing.T) {
	alice1, bob1 := newTestPair(t)
	alice2, bob2 := newTestPair(t)
	_ = bob1
	_ = bob2

	if bytes.Equal(alice1.chainSend, alice2.chainSend) {
		t.Fatal("two independently initialized sessions produced the same sending chain key")
	}
}

func TestInjectionDueRespectsThresholds(t *testing.T) {
	s := newState(make([]byte, 32))
	s.MessageThreshold = 5
	s.TimeThreshold = time.Hour
	if s.injectionDue() {
		t.Fatal("injection should not be due immediately after init")
	}
	s.msgsSinceInject = 5
	if !s.injectionDue() {
		t.Fatal("injection should be due once msgsSinceInject reaches the threshold")
	}
}
