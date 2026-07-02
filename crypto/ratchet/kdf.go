package ratchet

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
)

const rootKDFInfo = "pqchat-v1-ratchet"

// chainStep advances a KDF chain key in place and returns the message
// key derived from its prior value. This is the symmetric-key ratchet:
// CK_new = HMAC(CK, 0x02), MK = HMAC(CK, 0x01) (Signal Double Ratchet
// convention).
func chainStep(ck *[]byte) []byte {
	mk := hmacSum(*ck, []byte{0x01})
	*ck = hmacSum(*ck, []byte{0x02})
	return mk
}

func hmacSum(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// rootKDF is the DH-ratchet KDF step: it mixes a fresh DH (and,
// periodically, ML-KEM) shared secret into the root key, producing a
// new root key and a new chain key. kemSS may be nil when this step
// carries no PQ injection.
//
// Same combining discipline as crypto/kemhybrid: concatenate secrets
// into the HKDF input keying material rather than XOR, and use the
// existing root key as salt so each step is bound to the ratchet's
// history.
func rootKDF(rootKey, dhOut, kemSS []byte) (newRoot, newChainKey []byte, err error) {
	ikm := make([]byte, 0, len(dhOut)+len(kemSS))
	ikm = append(ikm, dhOut...)
	ikm = append(ikm, kemSS...)

	out, err := hkdf.Key(sha256.New, ikm, rootKey, rootKDFInfo, 64)
	if err != nil {
		return nil, nil, err
	}
	return out[:32], out[32:], nil
}
