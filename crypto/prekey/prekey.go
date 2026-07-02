// Package prekey implements PQChat's signed prekey bundles (PRD F2,
// F9, F10): one-time hybrid KEM prekeys published in Merkle-batch-signed
// groups so the identity signs the batch root once rather than every
// key individually, plus a single always-available signed last-resort
// prekey for when the one-time pool is exhausted.
package prekey

import (
	"encoding/binary"
	"errors"

	"pqchat/crypto/identity"
	"pqchat/crypto/kemhybrid"
	"pqchat/crypto/merkle"
)

const merkleDomain = "prekey-batch"

var (
	ErrInvalidInclusionProof = errors.New("prekey: inclusion proof does not match the signed batch root")
	ErrIndexOutOfRange       = errors.New("prekey: index out of range for this bundle's batch size")
)

const lastResortDomainTag = "pqchat-v1-last-resort-prekey"

func leafData(pubBytes []byte, index int) []byte {
	out := make([]byte, len(pubBytes)+4)
	copy(out, pubBytes)
	binary.BigEndian.PutUint32(out[len(pubBytes):], uint32(index))
	return out
}

// Batch is a signed batch of one-time hybrid KEM prekeys. The
// identity's signature covers only the Merkle root, not each key.
type Batch struct {
	privates []*kemhybrid.PrivateKey
	pubBytes [][]byte
	tree     *merkle.Tree
	root     merkle.Hash
	rootSig  *identity.Signature
}

// GenerateBatch creates size fresh one-time hybrid KEM prekeys and
// signs their Merkle root with id.
func GenerateBatch(id *identity.KeyPair, size int) (*Batch, error) {
	if size <= 0 {
		return nil, errors.New("prekey: batch size must be positive")
	}

	privates := make([]*kemhybrid.PrivateKey, size)
	pubBytes := make([][]byte, size)
	leaves := make([][]byte, size)

	for i := 0; i < size; i++ {
		priv, err := kemhybrid.GenerateKeyPair(nil)
		if err != nil {
			return nil, err
		}
		pb, err := priv.Public().Marshal()
		if err != nil {
			return nil, err
		}
		privates[i] = priv
		pubBytes[i] = pb
		leaves[i] = leafData(pb, i)
	}

	tree := merkle.BuildTree(merkleDomain, leaves)
	root := tree.Root()
	sig, err := id.Sign(root[:])
	if err != nil {
		return nil, err
	}

	return &Batch{privates: privates, pubBytes: pubBytes, tree: tree, root: root, rootSig: sig}, nil
}

// Size returns the number of one-time prekeys in the batch.
func (b *Batch) Size() int { return len(b.privates) }

// PrivateKey returns the private key at index, so the server (or, in
// this local-only Phase 0/1 scaffold, the owning client) can decapsulate
// a session established against it. Once used, callers are responsible
// for not reusing it — one-time prekeys are exactly that.
func (b *Batch) PrivateKey(index int) (*kemhybrid.PrivateKey, error) {
	if index < 0 || index >= len(b.privates) {
		return nil, ErrIndexOutOfRange
	}
	return b.privates[index], nil
}

// Bundle packages the one-time prekey at index together with its
// inclusion proof against the signed batch root, ready to publish to
// a directory or hand to a client establishing a session.
type Bundle struct {
	PublicKey     []byte
	Index         int
	BatchSize     int
	Proof         []merkle.Hash
	Root          merkle.Hash
	RootSignature *identity.Signature
}

// Bundle produces a Bundle for the one-time prekey at index.
func (b *Batch) Bundle(index int) (*Bundle, error) {
	if index < 0 || index >= len(b.privates) {
		return nil, ErrIndexOutOfRange
	}
	proof, err := b.tree.InclusionProof(index)
	if err != nil {
		return nil, err
	}
	return &Bundle{
		PublicKey:     b.pubBytes[index],
		Index:         index,
		BatchSize:     len(b.privates),
		Proof:         proof,
		Root:          b.root,
		RootSignature: b.rootSig,
	}, nil
}

// VerifyBundle checks that bundle's public key is genuinely included
// under a batch root that issuerPub actually signed. A caller must
// still independently confirm issuerPub is the identity they intend to
// talk to (PRD F5: that's the transparency log's job, not this
// function's).
func VerifyBundle(issuerPub identity.PublicKey, bundle *Bundle) error {
	if err := identity.Verify(issuerPub, bundle.Root[:], bundle.RootSignature); err != nil {
		return err
	}
	leaf := leafData(bundle.PublicKey, bundle.Index)
	if !merkle.VerifyInclusionProof(leaf, bundle.Index, bundle.BatchSize, bundle.Proof, bundle.Root) {
		return ErrInvalidInclusionProof
	}
	return nil
}

// LastResort is a single, always-available signed prekey used when a
// peer's one-time prekey pool has been exhausted (PRD F10). Unlike
// batch members, it is signed directly rather than through a Merkle
// root, and reused across sessions until replaced — so it does not
// carry the one-time prekeys' fresh-per-session guarantee.
type LastResort struct {
	PublicKey []byte
	Signature *identity.Signature
}

// GenerateLastResort creates a fresh last-resort hybrid KEM keypair
// and signs it with id.
func GenerateLastResort(id *identity.KeyPair) (*kemhybrid.PrivateKey, *LastResort, error) {
	priv, err := kemhybrid.GenerateKeyPair(nil)
	if err != nil {
		return nil, nil, err
	}
	pubBytes, err := priv.Public().Marshal()
	if err != nil {
		return nil, nil, err
	}
	msg := append([]byte(lastResortDomainTag), pubBytes...)
	sig, err := id.Sign(msg)
	if err != nil {
		return nil, nil, err
	}
	return priv, &LastResort{PublicKey: pubBytes, Signature: sig}, nil
}

// VerifyLastResort checks a last-resort prekey's signature.
func VerifyLastResort(issuerPub identity.PublicKey, lr *LastResort) error {
	msg := append([]byte(lastResortDomainTag), lr.PublicKey...)
	return identity.Verify(issuerPub, msg, lr.Signature)
}
