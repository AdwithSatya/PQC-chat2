// Package session ties together identity, prekey, kemhybrid, and
// ratchet into PQChat's zero-additional-RTT session establishment
// (PRD F3): the initiator's hybrid KEM ciphertext and the first
// application message travel in a single packet, with no interactive
// handshake round trip.
//
// This is Phase 1 of the rollout plan: two local parties, no relay
// server, no transparency log. Identity-key trust here is whatever the
// caller passes in directly — verifying that a given identity key is
// the *correct* one for a contact is the transparency log's job
// (PRD F5), not this package's, and is out of scope until Phase 3.
package session

import (
	"pqchat/crypto/identity"
	"pqchat/crypto/kemhybrid"
	"pqchat/crypto/prekey"
	"pqchat/crypto/ratchet"
)

// InitialMessage is everything the initiator sends to establish a
// session and deliver the first application message in one packet.
type InitialMessage struct {
	SenderIdentity identity.PublicKey
	KEMCiphertext  *kemhybrid.Ciphertext
	PrekeyIndex    int
	// IsLastResort indicates the responder's last-resort prekey (PRD
	// F10) was used instead of a Merkle-batch one-time prekey; when
	// true, PrekeyIndex is meaningless and should be ignored.
	IsLastResort bool
	Header       *ratchet.Header
	Ciphertext   []byte
}

// buildTranscript binds both parties' identities and the specific
// prekey (batch root + slot index) into the handshake transcript, so
// the derived session key can't be replayed against a different
// identity pairing or a different prekey slot (PRD §5, "Omitting
// transcript binding: enables unknown-key-share attacks").
func buildTranscript(initiator, responder identity.PublicKey, bundle *prekey.Bundle) ([]byte, error) {
	initBytes, err := initiator.Marshal()
	if err != nil {
		return nil, err
	}
	respBytes, err := responder.Marshal()
	if err != nil {
		return nil, err
	}
	t := make([]byte, 0, len(initBytes)+len(respBytes)+len(bundle.Root)+4)
	t = append(t, initBytes...)
	t = append(t, respBytes...)
	t = append(t, bundle.Root[:]...)
	t = append(t, byte(bundle.Index>>24), byte(bundle.Index>>16), byte(bundle.Index>>8), byte(bundle.Index))
	return t, nil
}

// EstablishAsInitiator runs the initiator's side of session
// establishment against a prekey bundle already verified to belong to
// responderID (see prekey.VerifyBundle), producing both the local
// ratchet state and the wire message to send.
func EstablishAsInitiator(
	initiatorID *identity.KeyPair,
	responderID identity.PublicKey,
	bundle *prekey.Bundle,
	firstMessage []byte,
) (*ratchet.State, *InitialMessage, error) {
	if err := prekey.VerifyBundle(responderID, bundle); err != nil {
		return nil, nil, err
	}

	responderKEMPub, err := kemhybrid.UnmarshalPublicKey(bundle.PublicKey)
	if err != nil {
		return nil, nil, err
	}

	transcript, err := buildTranscript(initiatorID.Public(), responderID, bundle)
	if err != nil {
		return nil, nil, err
	}

	ct, sessionKey, err := kemhybrid.Encapsulate(responderKEMPub, transcript, nil)
	if err != nil {
		return nil, nil, err
	}

	state, err := ratchet.InitAlice(sessionKey, responderKEMPub.X25519)
	if err != nil {
		return nil, nil, err
	}

	hdr, aeadCiphertext, err := state.EncryptMessage(firstMessage, nil)
	if err != nil {
		return nil, nil, err
	}

	return state, &InitialMessage{
		SenderIdentity: initiatorID.Public(),
		KEMCiphertext:  ct,
		PrekeyIndex:    bundle.Index,
		Header:         hdr,
		Ciphertext:     aeadCiphertext,
	}, nil
}

// EstablishAsResponder runs the responder's side: given the private
// key for the one-time prekey the initiator used (identified by
// msg.PrekeyIndex) and the same bundle metadata used to build the
// transcript on the initiator's side, it derives the same ratchet
// state and decrypts the first application message.
func EstablishAsResponder(
	responderID *identity.KeyPair,
	bundle *prekey.Bundle,
	prekeyPriv *kemhybrid.PrivateKey,
	msg *InitialMessage,
) (*ratchet.State, []byte, error) {
	transcript, err := buildTranscript(msg.SenderIdentity, responderID.Public(), bundle)
	if err != nil {
		return nil, nil, err
	}

	sessionKey, err := kemhybrid.Decapsulate(prekeyPriv, msg.KEMCiphertext, transcript)
	if err != nil {
		return nil, nil, err
	}

	state := ratchet.InitBob(sessionKey, prekeyPriv.X25519)

	plaintext, err := state.DecryptMessage(msg.Header, msg.Ciphertext, nil)
	if err != nil {
		return nil, nil, err
	}

	return state, plaintext, nil
}

func buildLastResortTranscript(initiator, responder identity.PublicKey, lr *prekey.LastResort) ([]byte, error) {
	initBytes, err := initiator.Marshal()
	if err != nil {
		return nil, err
	}
	respBytes, err := responder.Marshal()
	if err != nil {
		return nil, err
	}
	t := make([]byte, 0, len(initBytes)+len(respBytes)+len(lr.PublicKey))
	t = append(t, initBytes...)
	t = append(t, respBytes...)
	t = append(t, lr.PublicKey...)
	return t, nil
}

// EstablishAsInitiatorLastResort is EstablishAsInitiator's counterpart
// for a responder's signed last-resort prekey (PRD F10), used once
// the responder's one-time pool is exhausted. A last-resort key is
// reused across sessions rather than consumed, so sessions
// established this way don't carry the one-time-prekey freshness
// guarantee — that trade-off is exactly what makes it a fallback
// rather than the default path.
func EstablishAsInitiatorLastResort(
	initiatorID *identity.KeyPair,
	responderID identity.PublicKey,
	lastResort *prekey.LastResort,
	firstMessage []byte,
) (*ratchet.State, *InitialMessage, error) {
	if err := prekey.VerifyLastResort(responderID, lastResort); err != nil {
		return nil, nil, err
	}

	responderKEMPub, err := kemhybrid.UnmarshalPublicKey(lastResort.PublicKey)
	if err != nil {
		return nil, nil, err
	}

	transcript, err := buildLastResortTranscript(initiatorID.Public(), responderID, lastResort)
	if err != nil {
		return nil, nil, err
	}

	ct, sessionKey, err := kemhybrid.Encapsulate(responderKEMPub, transcript, nil)
	if err != nil {
		return nil, nil, err
	}

	state, err := ratchet.InitAlice(sessionKey, responderKEMPub.X25519)
	if err != nil {
		return nil, nil, err
	}

	hdr, aeadCiphertext, err := state.EncryptMessage(firstMessage, nil)
	if err != nil {
		return nil, nil, err
	}

	return state, &InitialMessage{
		SenderIdentity: initiatorID.Public(),
		KEMCiphertext:  ct,
		IsLastResort:   true,
		Header:         hdr,
		Ciphertext:     aeadCiphertext,
	}, nil
}

// EstablishAsResponderLastResort is EstablishAsResponder's counterpart
// for the signed last-resort prekey path.
func EstablishAsResponderLastResort(
	responderID *identity.KeyPair,
	lastResort *prekey.LastResort,
	lastResortPriv *kemhybrid.PrivateKey,
	msg *InitialMessage,
) (*ratchet.State, []byte, error) {
	transcript, err := buildLastResortTranscript(msg.SenderIdentity, responderID.Public(), lastResort)
	if err != nil {
		return nil, nil, err
	}

	sessionKey, err := kemhybrid.Decapsulate(lastResortPriv, msg.KEMCiphertext, transcript)
	if err != nil {
		return nil, nil, err
	}

	state := ratchet.InitBob(sessionKey, lastResortPriv.X25519)

	plaintext, err := state.DecryptMessage(msg.Header, msg.Ciphertext, nil)
	if err != nil {
		return nil, nil, err
	}

	return state, plaintext, nil
}
