package prekey

import (
	"testing"

	"pqchat/crypto/identity"
)

func TestBundleRoundTripVerifies(t *testing.T) {
	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}

	batch, err := GenerateBatch(id, 20)
	if err != nil {
		t.Fatalf("GenerateBatch: %v", err)
	}

	for i := 0; i < batch.Size(); i++ {
		bundle, err := batch.Bundle(i)
		if err != nil {
			t.Fatalf("Bundle(%d): %v", i, err)
		}
		if err := VerifyBundle(id.Public(), bundle); err != nil {
			t.Fatalf("VerifyBundle(%d): %v", i, err)
		}
	}
}

func TestVerifyBundleRejectsWrongIssuer(t *testing.T) {
	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}
	otherID, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}

	batch, err := GenerateBatch(id, 5)
	if err != nil {
		t.Fatalf("GenerateBatch: %v", err)
	}
	bundle, err := batch.Bundle(0)
	if err != nil {
		t.Fatalf("Bundle: %v", err)
	}

	if err := VerifyBundle(otherID.Public(), bundle); err == nil {
		t.Fatal("VerifyBundle accepted a batch signed by a different identity")
	}
}

func TestVerifyBundleRejectsSubstitutedPublicKey(t *testing.T) {
	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}

	batch, err := GenerateBatch(id, 5)
	if err != nil {
		t.Fatalf("GenerateBatch: %v", err)
	}
	bundle0, err := batch.Bundle(0)
	if err != nil {
		t.Fatalf("Bundle(0): %v", err)
	}
	bundle1, err := batch.Bundle(1)
	if err != nil {
		t.Fatalf("Bundle(1): %v", err)
	}

	// A malicious server swaps in a different slot's key while keeping
	// index 0's proof and the (still-valid) signed root.
	swapped := *bundle0
	swapped.PublicKey = bundle1.PublicKey

	if err := VerifyBundle(id.Public(), &swapped); err == nil {
		t.Fatal("VerifyBundle accepted a public key substituted from a different slot")
	}
}

func TestVerifyBundleRejectsIndexRelabeling(t *testing.T) {
	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}

	batch, err := GenerateBatch(id, 5)
	if err != nil {
		t.Fatalf("GenerateBatch: %v", err)
	}
	bundle, err := batch.Bundle(0)
	if err != nil {
		t.Fatalf("Bundle: %v", err)
	}

	// A malicious server relabels which slot this key claims to be at,
	// hoping the proof still checks out against some other leaf.
	relabeled := *bundle
	relabeled.Index = 1

	if err := VerifyBundle(id.Public(), &relabeled); err == nil {
		t.Fatal("VerifyBundle accepted a bundle whose index was relabeled")
	}
}

func TestLastResortRoundTripVerifies(t *testing.T) {
	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}

	_, lr, err := GenerateLastResort(id)
	if err != nil {
		t.Fatalf("GenerateLastResort: %v", err)
	}

	if err := VerifyLastResort(id.Public(), lr); err != nil {
		t.Fatalf("VerifyLastResort: %v", err)
	}
}

func TestVerifyLastResortRejectsWrongIssuer(t *testing.T) {
	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}
	otherID, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}

	_, lr, err := GenerateLastResort(id)
	if err != nil {
		t.Fatalf("GenerateLastResort: %v", err)
	}

	if err := VerifyLastResort(otherID.Public(), lr); err == nil {
		t.Fatal("VerifyLastResort accepted a last-resort key signed by a different identity")
	}
}

func TestPrivateKeyMatchesBundlePublicKey(t *testing.T) {
	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}
	batch, err := GenerateBatch(id, 3)
	if err != nil {
		t.Fatalf("GenerateBatch: %v", err)
	}

	priv, err := batch.PrivateKey(1)
	if err != nil {
		t.Fatalf("PrivateKey: %v", err)
	}
	bundle, err := batch.Bundle(1)
	if err != nil {
		t.Fatalf("Bundle: %v", err)
	}

	pubFromPriv, err := priv.Public().Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(pubFromPriv) != string(bundle.PublicKey) {
		t.Fatal("private key at index 1 does not correspond to bundle(1)'s public key")
	}
}
