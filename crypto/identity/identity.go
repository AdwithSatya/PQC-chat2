// Package identity implements PQChat's hybrid identity keypair and
// dual-signature scheme: Ed25519 + ML-DSA-65 (PRD F1, §5 "Identity
// signatures"). Both signatures must verify; either failure is a hard abort.
package identity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// ErrVerification is returned when either the classical or the
// post-quantum signature fails to verify.
var ErrVerification = errors.New("identity: signature verification failed")

// KeyPair is a hybrid identity keypair: classical Ed25519 plus
// post-quantum ML-DSA-65. Neither algorithm alone is trusted to carry
// the identity guarantee — see PRD §5 for the rejected alternatives.
type KeyPair struct {
	Ed25519Public  ed25519.PublicKey
	Ed25519Private ed25519.PrivateKey
	MLDSAPublic    *mldsa65.PublicKey
	MLDSAPrivate   *mldsa65.PrivateKey
}

// PublicKey is the public half of a hybrid identity, as published to
// the transparency log and distributed in prekey bundles.
type PublicKey struct {
	Ed25519 ed25519.PublicKey
	MLDSA   *mldsa65.PublicKey
}

// Equal reports whether two public keys are the same identity (both
// the classical and post-quantum components match).
func (pub PublicKey) Equal(other PublicKey) bool {
	if !pub.Ed25519.Equal(other.Ed25519) {
		return false
	}
	a, err1 := pub.MLDSA.MarshalBinary()
	b, err2 := other.MLDSA.MarshalBinary()
	if err1 != nil || err2 != nil {
		return false
	}
	return bytes.Equal(a, b)
}

// Marshal serializes the public key for transcript binding (e.g.
// crypto/session's handshake transcript) and transparency-log
// publication.
func (pub PublicKey) Marshal() ([]byte, error) {
	mldsaBytes, err := pub.MLDSA.MarshalBinary()
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(pub.Ed25519)+len(mldsaBytes))
	out = append(out, pub.Ed25519...)
	out = append(out, mldsaBytes...)
	return out, nil
}

// Signature is a hybrid signature: both components must be present and
// must both verify.
type Signature struct {
	Ed25519 []byte
	MLDSA   []byte
}

// Generate creates a new hybrid identity keypair using crypto/rand.
func Generate() (*KeyPair, error) {
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	mldsaPub, mldsaPriv, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &KeyPair{
		Ed25519Public:  edPub,
		Ed25519Private: edPriv,
		MLDSAPublic:    mldsaPub,
		MLDSAPrivate:   mldsaPriv,
	}, nil
}

// Public returns the public half of the keypair.
func (kp *KeyPair) Public() PublicKey {
	return PublicKey{Ed25519: kp.Ed25519Public, MLDSA: kp.MLDSAPublic}
}

// Sign produces a hybrid signature over msg. ML-DSA-65 signing uses
// randomized signing (the FIPS204 default for deployed use, as opposed
// to the deterministic mode used only for KAT verification in the
// crypto/kat package).
func (kp *KeyPair) Sign(msg []byte) (*Signature, error) {
	edSig := ed25519.Sign(kp.Ed25519Private, msg)

	mldsaSig := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(kp.MLDSAPrivate, msg, nil, true, mldsaSig); err != nil {
		return nil, err
	}
	return &Signature{Ed25519: edSig, MLDSA: mldsaSig}, nil
}

// Verify checks a hybrid signature. Both the Ed25519 and ML-DSA-65
// components must verify; a single-component failure is a hard abort
// (returns ErrVerification), never a silent downgrade to one algorithm.
func Verify(pub PublicKey, msg []byte, sig *Signature) error {
	if !ed25519.Verify(pub.Ed25519, msg, sig.Ed25519) {
		return ErrVerification
	}
	if !mldsa65.Verify(pub.MLDSA, msg, nil, sig.MLDSA) {
		return ErrVerification
	}
	return nil
}
