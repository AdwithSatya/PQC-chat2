package translog

import (
	"pqchat/crypto/identity"
	"pqchat/crypto/merkle"
)

// VerifyInclusion checks that entry is genuinely included in the tree
// committed to by sth (PRD F5: "Inclusion proof verified on every
// identity/bundle fetch; unproven identity = no session, no silent
// fallback"). Callers must independently verify sth itself (VerifySTH)
// and that sth.OperatorIdentity is the log operator they trust —
// this function only checks the proof, not the head's authenticity.
func VerifyInclusion(sth *SignedTreeHead, entry Entry, proof []merkle.Hash) error {
	leaf, err := leafData(entry)
	if err != nil {
		return err
	}
	if !merkle.VerifyInclusionProof(leaf, entry.Index, sth.TreeSize, proof, sth.RootHash) {
		return ErrInvalidInclusionProof
	}
	return nil
}

// AlertLevel is what a client shows the user when a contact's pinned
// identity key doesn't match what it just observed (PRD F7/F8).
type AlertLevel int

const (
	// AlertNone: the observed key matches what's pinned. Nothing to
	// show the user.
	AlertNone AlertLevel = iota
	// AlertSoftNotice: the key changed, but the new key has a
	// corresponding log entry — a legitimate, provable rotation
	// (e.g. the contact reinstalled or rotated their identity key).
	AlertSoftNotice
	// AlertBlocking: the key changed with no corresponding log entry.
	// Per PRD §5 ("Key-change UX"), sending is disabled until the
	// user acknowledges — this is the case that actually defeats a
	// substitution attack, as opposed to a passive banner nobody
	// reads.
	AlertBlocking
)

// CheckKeyChange compares a previously pinned identity against a
// newly observed one for the same contact. observedIsLogged should be
// the result of successfully verifying observed's inclusion in the
// log (VerifyInclusion + VerifySTH) — a caller must not pass true
// here without having actually checked that.
func CheckKeyChange(pinned, observed identity.PublicKey, observedIsLogged bool) AlertLevel {
	if pinned.Equal(observed) {
		return AlertNone
	}
	if observedIsLogged {
		return AlertSoftNotice
	}
	return AlertBlocking
}
