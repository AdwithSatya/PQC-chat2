// Package kemhybrid implements PQChat's hybrid key exchange: X25519 +
// ML-KEM-768, combined with an HKDF-SHA-256 combiner over the full
// handshake transcript (PRD F2/F3, §5 "Key exchange" and "KDF combining
// rule"). Breaking either X25519 or ML-KEM-768 alone is not enough to
// recover the session key.
package kemhybrid

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
)

const (
	// SessionKeySize is the size in bytes of the derived session key.
	SessionKeySize = 32

	hkdfInfo = "pqchat-v1-session"
)

// ErrDecapsulation is returned when a ciphertext cannot be decapsulated
// (malformed X25519 point or ML-KEM ciphertext of the wrong size).
var ErrDecapsulation = errors.New("kemhybrid: decapsulation failed")

// PublicKey is a hybrid KEM public key, as published in a signed
// prekey bundle (PRD F2).
type PublicKey struct {
	X25519 *ecdh.PublicKey
	MLKEM  *mlkem768.PublicKey
}

// PrivateKey is a hybrid KEM private key.
type PrivateKey struct {
	X25519 *ecdh.PrivateKey
	MLKEM  *mlkem768.PrivateKey
}

// Public returns the public half of the keypair.
func (priv *PrivateKey) Public() *PublicKey {
	return &PublicKey{
		X25519: priv.X25519.PublicKey(),
		MLKEM:  priv.MLKEM.Public().(*mlkem768.PublicKey),
	}
}

// PublicKeySize is the size in bytes of a marshaled hybrid public key:
// a 32-byte X25519 point followed by a packed ML-KEM-768 encapsulation
// key.
const PublicKeySize = 32 + mlkem768.PublicKeySize

// Marshal serializes the public key as it's published in prekey
// bundles and used as Merkle leaf data (crypto/prekey).
func (pub *PublicKey) Marshal() ([]byte, error) {
	mlkemBytes, err := pub.MLKEM.MarshalBinary()
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, PublicKeySize)
	out = append(out, pub.X25519.Bytes()...)
	out = append(out, mlkemBytes...)
	return out, nil
}

// UnmarshalPublicKey parses a public key previously produced by Marshal.
func UnmarshalPublicKey(buf []byte) (*PublicKey, error) {
	if len(buf) != PublicKeySize {
		return nil, errors.New("kemhybrid: invalid public key length")
	}
	x25519Pub, err := ecdh.X25519().NewPublicKey(buf[:32])
	if err != nil {
		return nil, err
	}
	var mlkemPub mlkem768.PublicKey
	if err := mlkemPub.Unpack(buf[32:]); err != nil {
		return nil, err
	}
	return &PublicKey{X25519: x25519Pub, MLKEM: &mlkemPub}, nil
}

// GenerateKeyPair generates a fresh hybrid KEM keypair using entropy
// from rnd. If rnd is nil, crypto/rand.Reader is used.
func GenerateKeyPair(rnd io.Reader) (*PrivateKey, error) {
	if rnd == nil {
		rnd = rand.Reader
	}
	x25519Priv, err := ecdh.X25519().GenerateKey(rnd)
	if err != nil {
		return nil, err
	}
	_, mlkemPriv, err := mlkem768.GenerateKeyPair(rnd)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{X25519: x25519Priv, MLKEM: mlkemPriv}, nil
}

// Ciphertext is what an initiator sends to a responder to establish a
// hybrid session: an ephemeral X25519 public key plus an ML-KEM-768
// encapsulation.
type Ciphertext struct {
	X25519Ephemeral *ecdh.PublicKey
	MLKEMCiphertext []byte
}

// Marshal serializes a Ciphertext for wire transport (e.g. as part of
// crypto/session's InitialMessage envelope).
func (ct *Ciphertext) Marshal() ([]byte, error) {
	out := make([]byte, 0, 32+len(ct.MLKEMCiphertext))
	out = append(out, ct.X25519Ephemeral.Bytes()...)
	out = append(out, ct.MLKEMCiphertext...)
	return out, nil
}

// UnmarshalCiphertext parses a Ciphertext previously produced by Marshal.
func UnmarshalCiphertext(buf []byte) (*Ciphertext, error) {
	if len(buf) != 32+mlkem768.CiphertextSize {
		return nil, errors.New("kemhybrid: invalid ciphertext length")
	}
	x25519Pub, err := ecdh.X25519().NewPublicKey(buf[:32])
	if err != nil {
		return nil, err
	}
	return &Ciphertext{
		X25519Ephemeral: x25519Pub,
		MLKEMCiphertext: bytes.Clone(buf[32:]),
	}, nil
}

// Encapsulate establishes a session against the responder's hybrid
// public key. transcript is the full handshake transcript (identity
// keys, prekey bundle, any application framing) and is bound into the
// derived key via the HKDF salt, preventing unknown-key-share attacks
// (PRD §5, rejected-alternative note on the combiner).
func Encapsulate(pub *PublicKey, transcript []byte, rnd io.Reader) (*Ciphertext, []byte, error) {
	if rnd == nil {
		rnd = rand.Reader
	}

	ephemeralPriv, err := ecdh.X25519().GenerateKey(rnd)
	if err != nil {
		return nil, nil, err
	}
	ecdhSS, err := ephemeralPriv.ECDH(pub.X25519)
	if err != nil {
		return nil, nil, err
	}

	ct := make([]byte, mlkem768.CiphertextSize)
	kemSS := make([]byte, mlkem768.SharedKeySize)
	pub.MLKEM.EncapsulateTo(ct, kemSS, nil)

	sessionKey, err := combine(ecdhSS, kemSS, transcript)
	if err != nil {
		return nil, nil, err
	}

	return &Ciphertext{
		X25519Ephemeral: ephemeralPriv.PublicKey(),
		MLKEMCiphertext: ct,
	}, sessionKey, nil
}

// Decapsulate completes the session on the responder's side.
func Decapsulate(priv *PrivateKey, ct *Ciphertext, transcript []byte) ([]byte, error) {
	if len(ct.MLKEMCiphertext) != mlkem768.CiphertextSize {
		return nil, ErrDecapsulation
	}

	ecdhSS, err := priv.X25519.ECDH(ct.X25519Ephemeral)
	if err != nil {
		return nil, ErrDecapsulation
	}

	kemSS := make([]byte, mlkem768.SharedKeySize)
	priv.MLKEM.DecapsulateTo(kemSS, ct.MLKEMCiphertext)

	return combine(ecdhSS, kemSS, transcript)
}

// combine implements the locked KDF combining rule:
//
//	key = HKDF-SHA256(ikm = ecdh_ss || kem_ss, salt = SHA256(transcript), info = "pqchat-v1-session")
//
// Concatenation (not XOR) is used so that security holds if *either*
// input secret is uncompromised; the transcript-derived salt binds the
// key to the full negotiation, not just the two shared secrets.
func combine(ecdhSS, kemSS, transcript []byte) ([]byte, error) {
	ikm := make([]byte, 0, len(ecdhSS)+len(kemSS))
	ikm = append(ikm, ecdhSS...)
	ikm = append(ikm, kemSS...)

	salt := sha256.Sum256(transcript)

	return hkdf.Key(sha256.New, ikm, salt[:], hkdfInfo, SessionKeySize)
}
