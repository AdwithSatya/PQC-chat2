// Wire encoding for session messages. This is what actually crosses
// the boundary to a content-blind relay (Phase 2): everything below
// serializes to an opaque []byte blob that the relay stores and
// forwards without needing to understand — it never imports this
// package (see relay/relay.go).
package session

import (
	"encoding/binary"
	"errors"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"

	"pqchat/crypto/identity"
	"pqchat/crypto/kemhybrid"
	"pqchat/crypto/ratchet"
)

const (
	envelopeTypeInitial    byte = 1
	envelopeTypeSubsequent byte = 2
)

var ErrUnknownEnvelopeType = errors.New("session: unknown envelope type")

func appendLenPrefixed(buf, data []byte) []byte {
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(data)))
	return append(buf, data...)
}

func readLenPrefixed(buf []byte) ([]byte, []byte, error) {
	if len(buf) < 4 {
		return nil, nil, errors.New("session: truncated field")
	}
	n := binary.BigEndian.Uint32(buf)
	buf = buf[4:]
	if uint64(len(buf)) < uint64(n) {
		return nil, nil, errors.New("session: truncated field body")
	}
	return buf[:n], buf[n:], nil
}

// Marshal serializes an InitialMessage's body (without the envelope
// type tag).
func (m *InitialMessage) Marshal() ([]byte, error) {
	idBytes, err := m.SenderIdentity.Marshal()
	if err != nil {
		return nil, err
	}
	ctBytes, err := m.KEMCiphertext.Marshal()
	if err != nil {
		return nil, err
	}

	var buf []byte
	buf = appendLenPrefixed(buf, idBytes)
	buf = appendLenPrefixed(buf, ctBytes)
	buf = binary.BigEndian.AppendUint32(buf, uint32(m.PrekeyIndex))
	if m.IsLastResort {
		buf = append(buf, 1)
	} else {
		buf = append(buf, 0)
	}
	buf = appendLenPrefixed(buf, m.Header.Marshal())
	buf = appendLenPrefixed(buf, m.Ciphertext)
	return buf, nil
}

// UnmarshalInitialMessage parses an InitialMessage body previously
// produced by Marshal.
func UnmarshalInitialMessage(buf []byte) (*InitialMessage, error) {
	idBytes, buf, err := readLenPrefixed(buf)
	if err != nil {
		return nil, err
	}
	senderID, err := unmarshalIdentityPublicKey(idBytes)
	if err != nil {
		return nil, err
	}

	ctBytes, buf, err := readLenPrefixed(buf)
	if err != nil {
		return nil, err
	}
	ct, err := kemhybrid.UnmarshalCiphertext(ctBytes)
	if err != nil {
		return nil, err
	}

	if len(buf) < 4 {
		return nil, errors.New("session: truncated prekey index")
	}
	prekeyIndex := binary.BigEndian.Uint32(buf)
	buf = buf[4:]

	if len(buf) < 1 {
		return nil, errors.New("session: truncated last-resort flag")
	}
	isLastResort := buf[0] != 0
	buf = buf[1:]

	hdrBytes, buf, err := readLenPrefixed(buf)
	if err != nil {
		return nil, err
	}
	hdr, err := ratchet.UnmarshalHeader(hdrBytes)
	if err != nil {
		return nil, err
	}

	ciphertext, buf, err := readLenPrefixed(buf)
	if err != nil {
		return nil, err
	}
	if len(buf) != 0 {
		return nil, errors.New("session: trailing bytes after InitialMessage")
	}

	return &InitialMessage{
		SenderIdentity: *senderID,
		KEMCiphertext:  ct,
		PrekeyIndex:    int(prekeyIndex),
		IsLastResort:   isLastResort,
		Header:         hdr,
		Ciphertext:     ciphertext,
	}, nil
}

// SubsequentMessage is a post-handshake ratchet message: just a header
// and an AEAD ciphertext, with no per-message KEM material (PRD F4:
// "Messages after session establishment use symmetric AEAD only").
type SubsequentMessage struct {
	Header     *ratchet.Header
	Ciphertext []byte
}

// Marshal serializes a SubsequentMessage's body.
func (m *SubsequentMessage) Marshal() []byte {
	var buf []byte
	buf = appendLenPrefixed(buf, m.Header.Marshal())
	buf = appendLenPrefixed(buf, m.Ciphertext)
	return buf
}

// UnmarshalSubsequentMessage parses a SubsequentMessage body
// previously produced by Marshal.
func UnmarshalSubsequentMessage(buf []byte) (*SubsequentMessage, error) {
	hdrBytes, buf, err := readLenPrefixed(buf)
	if err != nil {
		return nil, err
	}
	hdr, err := ratchet.UnmarshalHeader(hdrBytes)
	if err != nil {
		return nil, err
	}
	ciphertext, buf, err := readLenPrefixed(buf)
	if err != nil {
		return nil, err
	}
	if len(buf) != 0 {
		return nil, errors.New("session: trailing bytes after SubsequentMessage")
	}
	return &SubsequentMessage{Header: hdr, Ciphertext: ciphertext}, nil
}

// MarshalEnvelope wraps an InitialMessage with the type tag a relay
// (or the receiving client, before it knows which kind of message
// this is) uses to dispatch it.
func (m *InitialMessage) MarshalEnvelope() ([]byte, error) {
	body, err := m.Marshal()
	if err != nil {
		return nil, err
	}
	return append([]byte{envelopeTypeInitial}, body...), nil
}

// MarshalEnvelope wraps a SubsequentMessage with its type tag.
func (m *SubsequentMessage) MarshalEnvelope() []byte {
	return append([]byte{envelopeTypeSubsequent}, m.Marshal()...)
}

// UnmarshalEnvelope inspects an opaque envelope's type tag and parses
// the appropriate message type. Exactly one of the returned messages
// is non-nil on success.
func UnmarshalEnvelope(buf []byte) (initMsg *InitialMessage, subMsg *SubsequentMessage, err error) {
	if len(buf) == 0 {
		return nil, nil, errors.New("session: empty envelope")
	}
	switch buf[0] {
	case envelopeTypeInitial:
		m, err := UnmarshalInitialMessage(buf[1:])
		return m, nil, err
	case envelopeTypeSubsequent:
		m, err := UnmarshalSubsequentMessage(buf[1:])
		return nil, m, err
	default:
		return nil, nil, ErrUnknownEnvelopeType
	}
}

func unmarshalIdentityPublicKey(buf []byte) (*identity.PublicKey, error) {
	const ed25519Size = 32
	if len(buf) != ed25519Size+mldsa65.PublicKeySize {
		return nil, errors.New("session: invalid identity public key length")
	}
	edPub := buf[:ed25519Size]
	mldsaBytes := buf[ed25519Size:]

	var mldsaPub mldsa65.PublicKey
	if err := mldsaPub.UnmarshalBinary(mldsaBytes); err != nil {
		return nil, err
	}

	return &identity.PublicKey{Ed25519: append([]byte{}, edPub...), MLDSA: &mldsaPub}, nil
}
