// Package kat verifies PQChat's crypto primitives against official NIST
// ACVP known-answer test vectors (PRD Phase 0 exit criteria: "All
// primitives pass NIST test vectors"; N7: "All primitives pass NIST
// KATs in CI on every build; release blocks on failure").
//
// Test vectors in testdata/ are a small subset (3 cases per algorithm)
// extracted from NIST's official ACVP test vectors, as redistributed
// by github.com/cloudflare/circl v1.6.4 (kem/mlkem/testdata,
// sign/mldsa/testdata). Extraction script: see comment at the bottom
// of this file. These tests exercise the exact CIRCL entry points
// (NewKeyFromSeed, EncapsulateTo, SignTo) that the identity and
// kemhybrid packages call — a bug in how this repo drives those APIs
// would show up here even if CIRCL's own internals are correct.
package kat

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
)

type mlkemKeygenVector struct {
	TcID int    `json:"tcId"`
	Z    string `json:"z"`
	D    string `json:"d"`
	EK   string `json:"ek"`
	DK   string `json:"dk"`
}

type mlkemEncapVector struct {
	TcID int    `json:"tcId"`
	EK   string `json:"ek"`
	M    string `json:"m"`
	C    string `json:"c"`
	K    string `json:"k"`
}

func loadVectors(t *testing.T, path string, dst interface{}) {
	t.Helper()
	buf, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var wrapper struct {
		Source string          `json:"source"`
		Tests  json.RawMessage `json:"tests"`
	}
	if err := json.Unmarshal(buf, &wrapper); err != nil {
		t.Fatalf("unmarshalling %s: %v", path, err)
	}
	if err := json.Unmarshal(wrapper.Tests, dst); err != nil {
		t.Fatalf("unmarshalling tests in %s: %v", path, err)
	}
}

func hexBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("invalid hex %q: %v", s, err)
	}
	return b
}

func TestMLKEM768KeyGenKAT(t *testing.T) {
	var vectors []mlkemKeygenVector
	loadVectors(t, "testdata/mlkem768_keygen.json", &vectors)
	if len(vectors) == 0 {
		t.Fatal("no test vectors loaded")
	}

	for _, v := range vectors {
		v := v
		t.Run(hex.EncodeToString([]byte{byte(v.TcID)}), func(t *testing.T) {
			d := hexBytes(t, v.D)
			z := hexBytes(t, v.Z)

			seed := make([]byte, 0, mlkem768.KeySeedSize)
			seed = append(seed, d...)
			seed = append(seed, z...)

			pk, sk := mlkem768.NewKeyFromSeed(seed)

			gotEK := make([]byte, mlkem768.PublicKeySize)
			pk.Pack(gotEK)
			wantEK := hexBytes(t, v.EK)
			if !bytes.Equal(gotEK, wantEK) {
				t.Errorf("tcId %d: encapsulation key mismatch\ngot  %x\nwant %x", v.TcID, gotEK, wantEK)
			}

			gotDK := make([]byte, mlkem768.PrivateKeySize)
			sk.Pack(gotDK)
			wantDK := hexBytes(t, v.DK)
			if !bytes.Equal(gotDK, wantDK) {
				t.Errorf("tcId %d: decapsulation key mismatch\ngot  %x\nwant %x", v.TcID, gotDK, wantDK)
			}
		})
	}
}

func TestMLKEM768EncapsulationKAT(t *testing.T) {
	var vectors []mlkemEncapVector
	loadVectors(t, "testdata/mlkem768_encap.json", &vectors)
	if len(vectors) == 0 {
		t.Fatal("no test vectors loaded")
	}

	for _, v := range vectors {
		v := v
		t.Run(hex.EncodeToString([]byte{byte(v.TcID)}), func(t *testing.T) {
			ekBytes := hexBytes(t, v.EK)
			var pk mlkem768.PublicKey
			if err := pk.Unpack(ekBytes); err != nil {
				t.Fatalf("tcId %d: Unpack: %v", v.TcID, err)
			}

			m := hexBytes(t, v.M)
			ct := make([]byte, mlkem768.CiphertextSize)
			ss := make([]byte, mlkem768.SharedKeySize)
			pk.EncapsulateTo(ct, ss, m)

			wantC := hexBytes(t, v.C)
			if !bytes.Equal(ct, wantC) {
				t.Errorf("tcId %d: ciphertext mismatch\ngot  %x\nwant %x", v.TcID, ct, wantC)
			}
			wantK := hexBytes(t, v.K)
			if !bytes.Equal(ss, wantK) {
				t.Errorf("tcId %d: shared secret mismatch\ngot  %x\nwant %x", v.TcID, ss, wantK)
			}
		})
	}
}

// Extraction script (Python, run once against CIRCL's bundled ACVP
// vectors under $(go env GOPATH)/pkg/mod/github.com/cloudflare/circl@v1.6.4):
//
//   for ML-KEM-keyGen-FIPS203: select parameterSet == "ML-KEM-768",
//   take the first 3 {tcId, z, d} from prompt.json.gz and the matching
//   {tcId, ek, dk} from expectedResults.json.gz.
//
//   for ML-KEM-encapDecap-FIPS203: select the AFT/encapsulation group
//   with parameterSet == "ML-KEM-768", take the first 3
//   {tcId, ek, m} from prompt.json.gz and matching {tcId, c, k} from
//   expectedResults.json.gz.
