package merkle

import (
	"fmt"
	"testing"
)

func testLeaves(n int) [][]byte {
	leaves := make([][]byte, n)
	for i := range leaves {
		leaves[i] = []byte(fmt.Sprintf("leaf-%d", i))
	}
	return leaves
}

func TestInclusionProofVerifiesForEveryLeaf(t *testing.T) {
	for _, n := range []int{1, 2, 3, 5, 7, 8, 16, 100} {
		leaves := testLeaves(n)
		tree := BuildTree("test", leaves)
		root := tree.Root()

		for i := 0; i < n; i++ {
			proof, err := tree.InclusionProof(i)
			if err != nil {
				t.Fatalf("n=%d i=%d: InclusionProof: %v", n, i, err)
			}
			if !VerifyInclusionProof(leaves[i], i, n, proof, root) {
				t.Fatalf("n=%d i=%d: valid inclusion proof rejected", n, i)
			}
		}
	}
}

func TestInclusionProofRejectsWrongLeaf(t *testing.T) {
	leaves := testLeaves(10)
	tree := BuildTree("test", leaves)
	root := tree.Root()

	proof, err := tree.InclusionProof(3)
	if err != nil {
		t.Fatalf("InclusionProof: %v", err)
	}
	if VerifyInclusionProof([]byte("not-the-real-leaf"), 3, 10, proof, root) {
		t.Fatal("proof verified against the wrong leaf data")
	}
}

func TestInclusionProofRejectsWrongIndex(t *testing.T) {
	leaves := testLeaves(10)
	tree := BuildTree("test", leaves)
	root := tree.Root()

	proof, err := tree.InclusionProof(3)
	if err != nil {
		t.Fatalf("InclusionProof: %v", err)
	}
	if VerifyInclusionProof(leaves[3], 4, 10, proof, root) {
		t.Fatal("proof verified against the wrong index")
	}
}

func TestInclusionProofRejectsTamperedRoot(t *testing.T) {
	leaves := testLeaves(10)
	tree := BuildTree("test", leaves)
	root := tree.Root()
	root[0] ^= 0xFF

	proof, err := tree.InclusionProof(3)
	if err != nil {
		t.Fatalf("InclusionProof: %v", err)
	}
	if VerifyInclusionProof(leaves[3], 3, 10, proof, root) {
		t.Fatal("proof verified against a tampered root")
	}
}

func TestInclusionProofRejectsTamperedPathElement(t *testing.T) {
	leaves := testLeaves(10)
	tree := BuildTree("test", leaves)
	root := tree.Root()

	proof, err := tree.InclusionProof(3)
	if err != nil {
		t.Fatalf("InclusionProof: %v", err)
	}
	if len(proof) == 0 {
		t.Fatal("expected a non-empty proof for a 10-leaf tree")
	}
	proof[0][0] ^= 0xFF

	if VerifyInclusionProof(leaves[3], 3, 10, proof, root) {
		t.Fatal("proof verified with a tampered path element")
	}
}

func TestDifferentLeafSetsHaveDifferentRoots(t *testing.T) {
	root1 := BuildTree("test", testLeaves(10)).Root()
	root2 := BuildTree("test", testLeaves(10)).Root()
	if root1 != root2 {
		t.Fatal("identical leaf sets produced different roots; tree construction is not deterministic")
	}

	root3 := BuildTree("test", testLeaves(11)).Root()
	if root1 == root3 {
		t.Fatal("different leaf sets produced the same root")
	}
}

func TestDifferentDomainsProduceDifferentPadding(t *testing.T) {
	// A tree with a non-power-of-two leaf count needs padding; two
	// different domains over the *same* real leaves must still
	// produce different roots, since the padding leaves differ.
	leaves := testLeaves(3)
	rootA := BuildTree("domain-a", leaves).Root()
	rootB := BuildTree("domain-b", leaves).Root()
	if rootA == rootB {
		t.Fatal("different domains produced the same root despite different padding leaves")
	}
}
