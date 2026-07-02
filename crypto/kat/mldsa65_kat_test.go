package kat

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

type mldsaKeygenVector struct {
	TcID int    `json:"tcId"`
	Seed string `json:"seed"`
	PK   string `json:"pk"`
	SK   string `json:"sk"`
}

type mldsaSigGenVector struct {
	TcID      int    `json:"tcId"`
	SK        string `json:"sk"`
	Message   string `json:"message"`
	Signature string `json:"signature"`
}

func TestMLDSA65KeyGenKAT(t *testing.T) {
	var vectors []mldsaKeygenVector
	loadVectors(t, "testdata/mldsa65_keygen.json", &vectors)
	if len(vectors) == 0 {
		t.Fatal("no test vectors loaded")
	}

	for _, v := range vectors {
		v := v
		t.Run(hex.EncodeToString([]byte{byte(v.TcID)}), func(t *testing.T) {
			seedBytes := hexBytes(t, v.Seed)
			if len(seedBytes) != mldsa65.SeedSize {
				t.Fatalf("tcId %d: seed length = %d, want %d", v.TcID, len(seedBytes), mldsa65.SeedSize)
			}
			var seed [mldsa65.SeedSize]byte
			copy(seed[:], seedBytes)

			pk, sk := mldsa65.NewKeyFromSeed(&seed)

			gotPK := pk.Bytes()
			wantPK := hexBytes(t, v.PK)
			if !bytes.Equal(gotPK, wantPK) {
				t.Errorf("tcId %d: public key mismatch\ngot  %x\nwant %x", v.TcID, gotPK, wantPK)
			}

			gotSK := sk.Bytes()
			wantSK := hexBytes(t, v.SK)
			if !bytes.Equal(gotSK, wantSK) {
				t.Errorf("tcId %d: private key mismatch\ngot  %x\nwant %x", v.TcID, gotSK, wantSK)
			}
		})
	}
}

// TestMLDSA65KATDerivedKeySignVerify does NOT compare against the ACVP
// sigGen "signature" field byte-for-byte. NIST's ACVP ML-DSA vectors
// exercise FIPS204's internal Sign_internal/Verify_internal primitives,
// which sign the message directly with no domain separation. CIRCL only
// exposes those through unexported functions (unsafeSignInternal /
// unsafeVerifyInternal) used by its own internal ACVP test — Go's
// "internal/" import restriction means this repo cannot reach them from
// outside the CIRCL module, and the public SignTo/Verify API always
// applies FIPS204's external wrapping (M' = 0x00 || len(ctx) || ctx ||
// M) before signing, so it will never reproduce the ACVP signature
// bytes even with an empty context.
//
// What this test verifies instead: a NIST-KAT-derived keypair (loaded
// from the same official vectors, not from crypto/rand) round-trips
// correctly through the exact public API this repo's crypto/identity
// package calls — sign, then verify, then confirm tampering is
// rejected. Byte-exact conformance of the underlying signing primitive
// is covered by running CIRCL's own test suite (see the "make kat" /
// README instructions), which does have access to the internal
// primitives and validates them against the same ACVP vectors.
func TestMLDSA65KATDerivedKeySignVerify(t *testing.T) {
	var vectors []mldsaSigGenVector
	loadVectors(t, "testdata/mldsa65_siggen.json", &vectors)
	if len(vectors) == 0 {
		t.Fatal("no test vectors loaded")
	}

	for _, v := range vectors {
		v := v
		t.Run(hex.EncodeToString([]byte{byte(v.TcID)}), func(t *testing.T) {
			skBytes := hexBytes(t, v.SK)
			var sk mldsa65.PrivateKey
			if err := sk.UnmarshalBinary(skBytes); err != nil {
				t.Fatalf("tcId %d: UnmarshalBinary: %v", v.TcID, err)
			}
			pk := sk.Public().(*mldsa65.PublicKey)

			msg := hexBytes(t, v.Message)
			sig := make([]byte, mldsa65.SignatureSize)
			if err := mldsa65.SignTo(&sk, msg, nil, false, sig); err != nil {
				t.Fatalf("tcId %d: SignTo: %v", v.TcID, err)
			}

			if !mldsa65.Verify(pk, msg, nil, sig) {
				t.Fatalf("tcId %d: Verify rejected a signature produced by SignTo over a KAT-derived key", v.TcID)
			}

			tampered := bytes.Clone(sig)
			tampered[0] ^= 0xFF
			if mldsa65.Verify(pk, msg, nil, tampered) {
				t.Fatalf("tcId %d: Verify accepted a tampered signature", v.TcID)
			}
		})
	}
}
