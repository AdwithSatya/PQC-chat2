package ratchet

import (
	"golang.org/x/crypto/chacha20poly1305"
)

// Each message key is used exactly once (it's derived fresh per
// message by chainStep and then discarded), so a fixed all-zero nonce
// is safe here — there is no key/nonce pair reuse.
var zeroNonce = make([]byte, chacha20poly1305.NonceSize)

func aeadSeal(messageKey, plaintext, associatedData []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(messageKey)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, zeroNonce, plaintext, associatedData), nil
}

func aeadOpen(messageKey, ciphertext, associatedData []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(messageKey)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, zeroNonce, ciphertext, associatedData)
}
