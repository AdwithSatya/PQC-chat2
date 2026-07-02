package translog

import (
	"testing"

	"pqchat/crypto/identity"
)

func newOperator(t *testing.T) *identity.KeyPair {
	t.Helper()
	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}
	return id
}

func TestAppendAndInclusionProofVerifies(t *testing.T) {
	op := newOperator(t)
	server := NewServer(op)

	users := make([]*identity.KeyPair, 5)
	for i := range users {
		users[i] = newOperator(t)
		server.Append(userIDFor(i), users[i].Public())
	}

	sth, err := server.PublishSTH()
	if err != nil {
		t.Fatalf("PublishSTH: %v", err)
	}
	if err := VerifySTH(sth); err != nil {
		t.Fatalf("VerifySTH: %v", err)
	}
	if sth.TreeSize != len(users) {
		t.Fatalf("TreeSize = %d, want %d", sth.TreeSize, len(users))
	}

	for i := range users {
		entry, proof, gotSTH, err := server.InclusionProof(i)
		if err != nil {
			t.Fatalf("InclusionProof(%d): %v", i, err)
		}
		if gotSTH.RootHash != sth.RootHash {
			t.Fatalf("InclusionProof(%d) returned a different STH than PublishSTH", i)
		}
		if err := VerifyInclusion(sth, entry, proof); err != nil {
			t.Fatalf("VerifyInclusion(%d): %v", i, err)
		}
	}
}

func userIDFor(i int) string {
	return string([]byte{'u', 's', 'e', 'r', byte('0' + i)})
}

func TestVerifyInclusionRejectsWrongEntry(t *testing.T) {
	op := newOperator(t)
	server := NewServer(op)
	alice := newOperator(t)
	bob := newOperator(t)
	server.Append("alice", alice.Public())
	server.Append("bob", bob.Public())

	sth, err := server.PublishSTH()
	if err != nil {
		t.Fatalf("PublishSTH: %v", err)
	}

	entry0, proof0, _, err := server.InclusionProof(0)
	if err != nil {
		t.Fatalf("InclusionProof(0): %v", err)
	}
	entry1, _, _, err := server.InclusionProof(1)
	if err != nil {
		t.Fatalf("InclusionProof(1): %v", err)
	}

	// Try to pass off entry1's content under entry0's proof.
	swapped := entry0
	swapped.PublicKey = entry1.PublicKey
	if err := VerifyInclusion(sth, swapped, proof0); err == nil {
		t.Fatal("VerifyInclusion accepted a substituted public key")
	}
}

func TestInclusionProofRejectsIndexNotYetPublished(t *testing.T) {
	op := newOperator(t)
	server := NewServer(op)
	alice := newOperator(t)
	server.Append("alice", alice.Public())
	if _, err := server.PublishSTH(); err != nil {
		t.Fatalf("PublishSTH: %v", err)
	}

	bob := newOperator(t)
	server.Append("bob", bob.Public()) // not yet covered by any STH

	if _, _, _, err := server.InclusionProof(1); err != ErrUnknownIndex {
		t.Fatalf("error = %v, want ErrUnknownIndex", err)
	}
}

func TestLatestEntryForUserReflectsRotation(t *testing.T) {
	op := newOperator(t)
	server := NewServer(op)
	firstKey := newOperator(t)
	secondKey := newOperator(t)

	server.Append("alice", firstKey.Public())
	server.Append("alice", secondKey.Public())

	entry, ok := server.LatestEntryForUser("alice")
	if !ok {
		t.Fatal("LatestEntryForUser: not found")
	}
	if !entry.PublicKey.Equal(secondKey.Public()) {
		t.Fatal("LatestEntryForUser did not return the most recent rotation")
	}
}

func TestVerifySTHRejectsTamperedRoot(t *testing.T) {
	op := newOperator(t)
	server := NewServer(op)
	server.Append("alice", newOperator(t).Public())
	sth, err := server.PublishSTH()
	if err != nil {
		t.Fatalf("PublishSTH: %v", err)
	}

	sth.RootHash[0] ^= 0xFF
	if err := VerifySTH(sth); err == nil {
		t.Fatal("VerifySTH accepted a tampered root hash")
	}
}

func TestCurrentSTHBeforePublishErrors(t *testing.T) {
	server := NewServer(newOperator(t))
	if _, err := server.CurrentSTH(); err != ErrNoSTHPublished {
		t.Fatalf("error = %v, want ErrNoSTHPublished", err)
	}
}

func TestCheckKeyChange(t *testing.T) {
	keyA := newOperator(t).Public()
	keyB := newOperator(t).Public()

	if lvl := CheckKeyChange(keyA, keyA, false); lvl != AlertNone {
		t.Errorf("unchanged key: got %v, want AlertNone", lvl)
	}
	if lvl := CheckKeyChange(keyA, keyB, true); lvl != AlertSoftNotice {
		t.Errorf("logged rotation: got %v, want AlertSoftNotice", lvl)
	}
	if lvl := CheckKeyChange(keyA, keyB, false); lvl != AlertBlocking {
		t.Errorf("unlogged substitution: got %v, want AlertBlocking", lvl)
	}
}
