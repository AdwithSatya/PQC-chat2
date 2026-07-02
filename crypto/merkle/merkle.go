// Package merkle implements a domain-separated, padded binary Merkle
// tree shared by crypto/prekey (batch-signed one-time prekeys) and
// translog (the identity transparency log) — both need the same
// "commit to a set of leaves once, prove membership of any one of them
// cheaply" primitive.
//
// Leaf and internal nodes are domain-separated (0x00 / 0x01 prefixes)
// to prevent the classic second-preimage attack where an internal
// node's hash is replayed as if it were a leaf.
//
// The tree pads the leaf count up to the next power of two with
// deterministic, domain-tagged padding leaves, giving a perfectly
// balanced tree and a simple fixed-depth inclusion proof. This is a
// simplification versus the unbalanced-tree construction RFC 6962
// (Certificate Transparency) uses to avoid padding — acceptable here
// because both callers build trees with code in this same repo, so
// there's no cross-implementation wire format to match.
package merkle

import (
	"crypto/sha256"
	"errors"
	"fmt"
)

var ErrIndexOutOfRange = errors.New("merkle: index out of range")

type Hash [32]byte

func leafHash(data []byte) Hash {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	var out Hash
	copy(out[:], h.Sum(nil))
	return out
}

func nodeHash(left, right Hash) Hash {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left[:])
	h.Write(right[:])
	var out Hash
	copy(out[:], h.Sum(nil))
	return out
}

func nextPowerOfTwo(n int) int {
	p := 1
	for p < n {
		p <<= 1
	}
	return p
}

func paddingLeaf(domain string, index int) []byte {
	return []byte(fmt.Sprintf("pqchat-merkle-padding-leaf-%s-%d", domain, index))
}

// Tree is a Merkle tree built over a fixed set of leaves.
type Tree struct {
	n      int // number of real (unpadded) leaves
	levels [][]Hash
}

// BuildTree constructs a Merkle tree over leafData, padding to the
// next power of two. domain distinguishes padding leaves across
// different callers (e.g. "prekey-batch" vs "translog") so their
// padding leaves can never collide even if leaf content otherwise
// coincided.
func BuildTree(domain string, leafData [][]byte) *Tree {
	n := len(leafData)
	size := nextPowerOfTwo(max(n, 1))

	leaves := make([]Hash, size)
	for i := 0; i < size; i++ {
		if i < n {
			leaves[i] = leafHash(leafData[i])
		} else {
			leaves[i] = leafHash(paddingLeaf(domain, i))
		}
	}

	levels := [][]Hash{leaves}
	cur := leaves
	for len(cur) > 1 {
		next := make([]Hash, len(cur)/2)
		for i := range next {
			next[i] = nodeHash(cur[2*i], cur[2*i+1])
		}
		levels = append(levels, next)
		cur = next
	}

	return &Tree{n: n, levels: levels}
}

// Root returns the tree's Merkle root.
func (t *Tree) Root() Hash {
	return t.levels[len(t.levels)-1][0]
}

// InclusionProof returns the audit path (sibling hashes, leaf to
// root) proving that the leaf at index is present in the tree.
func (t *Tree) InclusionProof(index int) ([]Hash, error) {
	if index < 0 || index >= t.n {
		return nil, ErrIndexOutOfRange
	}
	var path []Hash
	idx := index
	for lvl := 0; lvl < len(t.levels)-1; lvl++ {
		level := t.levels[lvl]
		path = append(path, level[idx^1])
		idx >>= 1
	}
	return path, nil
}

// VerifyInclusionProof recomputes the root from leafData and an audit
// path and checks it against root. size is the real (unpadded) leaf
// count as of the tree being proved against.
func VerifyInclusionProof(leafData []byte, index, size int, path []Hash, root Hash) bool {
	if index < 0 || index >= size {
		return false
	}
	depth := 0
	for p := nextPowerOfTwo(size); p > 1; p >>= 1 {
		depth++
	}
	if len(path) != depth {
		return false
	}

	h := leafHash(leafData)
	idx := index
	for _, sibling := range path {
		if idx&1 == 0 {
			h = nodeHash(h, sibling)
		} else {
			h = nodeHash(sibling, h)
		}
		idx >>= 1
	}
	return h == root
}
