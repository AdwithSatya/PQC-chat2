// Package ratchet implements PQChat's per-message forward secrecy:
// a Double Ratchet (X25519 DH ratchet + symmetric KDF chains) with a
// periodic ML-KEM-768 injection layered on top (PRD F4/F5, §5 "Forward
// secrecy": "Double Ratchet (symmetric per message) + fresh ML-KEM
// encapsulation injected every 50 messages or 24h, whichever first").
//
// This implementation handles the common in-order-and-alternating-turns
// case, plus out-of-order delivery within a bounded skipped-key window.
// It does not claim to be race-free under adversarial scheduling at the
// PQ-injection boundary — the PRD names that exact scenario (§8 risk 2:
// "Ratchet + PQ-injection state machine desync") as the hardest open
// problem in this design and calls for formal model-checking (TLA+)
// before this code is trusted beyond a demo. That model-checking has
// not been done here; treat concurrent in-flight injections as an
// explicitly open risk, not a solved one.
package ratchet

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"time"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
)

// DefaultMessageThreshold and DefaultTimeThreshold implement the
// locked PQ-injection schedule from PRD §5.
const (
	DefaultMessageThreshold = 50
	DefaultTimeThreshold    = 24 * time.Hour

	// MaxSkip bounds how many message keys we'll derive-and-store to
	// cover out-of-order/dropped messages, so a malicious or buggy
	// peer can't force unbounded memory growth via a huge N or PN.
	MaxSkip = 1000
)

var (
	ErrDuplicateOrTooOld = errors.New("ratchet: message key not found (duplicate, too old, or out of skip window)")
	ErrSkipTooLarge      = errors.New("ratchet: header requests skipping more than MaxSkip messages")
	ErrUnexpectedKEMCT   = errors.New("ratchet: received an ML-KEM ciphertext with no pending encapsulation to decapsulate")
)

type skippedKey struct {
	dhPub string
	n     uint32
}

// State is one party's view of a ratcheting session. It is not
// safe for concurrent use.
type State struct {
	RootKey []byte

	dhSelf   *ecdh.PrivateKey
	dhRemote *ecdh.PublicKey

	chainSend []byte
	chainRecv []byte

	nSend, nRecv, pn uint32

	// needsNewSendingChain is set whenever we've just processed a
	// received message and haven't yet started our own new sending
	// chain — mirroring the classic Double Ratchet rule that a new DH
	// ratchet step happens only when it becomes "our turn" to send.
	needsNewSendingChain bool

	skipped map[skippedKey][]byte

	// PQ injection bookkeeping (PRD §5 schedule).
	MessageThreshold int
	TimeThreshold    time.Duration
	msgsSinceInject  int
	lastInject       time.Time

	// selfPendingKEMPriv is set when we've advertised our own
	// ML-KEM-768 public key (initiating an injection) and are waiting
	// for the peer's encapsulation.
	selfPendingKEMPriv *mlkem768.PrivateKey

	// peerAdvertisedKEMPub is set when the peer has advertised a
	// ML-KEM-768 public key we have not yet responded to.
	peerAdvertisedKEMPub *mlkem768.PublicKey
}

func newState(rootKey []byte) *State {
	return &State{
		RootKey:          rootKey,
		MessageThreshold: DefaultMessageThreshold,
		TimeThreshold:    DefaultTimeThreshold,
		lastInject:       time.Now(),
		skipped:          make(map[skippedKey][]byte),
	}
}

// InitAlice initializes the ratchet for the session initiator, given
// the hybrid-handshake session key (crypto/kemhybrid's Encapsulate
// output) and the responder's initial X25519 ratchet public key (their
// signed prekey). This performs Alice's first DH ratchet step
// immediately, matching classic Double Ratchet / X3DH initialization.
func InitAlice(sessionKey []byte, bobRatchetPub *ecdh.PublicKey) (*State, error) {
	dhSelf, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	s := newState(sessionKey)
	s.dhSelf = dhSelf
	s.dhRemote = bobRatchetPub

	dhOut, err := dhSelf.ECDH(bobRatchetPub)
	if err != nil {
		return nil, err
	}
	s.RootKey, s.chainSend, err = rootKDF(s.RootKey, dhOut, nil)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// InitBob initializes the ratchet for the session responder, given the
// hybrid-handshake session key and Bob's own ratchet keypair (the same
// keypair backing the prekey Alice used to reach him).
func InitBob(sessionKey []byte, bobRatchetPriv *ecdh.PrivateKey) *State {
	s := newState(sessionKey)
	s.dhSelf = bobRatchetPriv
	s.needsNewSendingChain = false
	return s
}

func (s *State) injectionDue() bool {
	return s.msgsSinceInject >= s.MessageThreshold || time.Since(s.lastInject) >= s.TimeThreshold
}

// prepareSendingChain performs the DH-ratchet (and, if due, PQ
// injection) step needed before this party can send its next message,
// if it hasn't already been done since the last received message.
func (s *State) prepareSendingChain() (*Header, error) {
	hdr := &Header{PN: s.pn}

	if s.needsNewSendingChain {
		newSelf, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		s.dhSelf = newSelf

		dhOut, err := s.dhSelf.ECDH(s.dhRemote)
		if err != nil {
			return nil, err
		}

		var kemSS []byte
		if s.peerAdvertisedKEMPub != nil {
			ct := make([]byte, mlkem768.CiphertextSize)
			ss := make([]byte, mlkem768.SharedKeySize)
			s.peerAdvertisedKEMPub.EncapsulateTo(ct, ss, nil)
			hdr.MLKEMCiphertext = ct
			kemSS = ss
			s.peerAdvertisedKEMPub = nil
		}

		s.pn = s.nSend
		s.nSend = 0
		hdr.PN = s.pn

		s.RootKey, s.chainSend, err = rootKDF(s.RootKey, dhOut, kemSS)
		if err != nil {
			return nil, err
		}
		s.needsNewSendingChain = false

		if s.injectionDue() {
			pub, priv, err := mlkem768.GenerateKeyPair(rand.Reader)
			if err != nil {
				return nil, err
			}
			pubBytes, err := pub.MarshalBinary()
			if err != nil {
				return nil, err
			}
			hdr.MLKEMPub = pubBytes
			s.selfPendingKEMPriv = priv
			s.msgsSinceInject = 0
			s.lastInject = time.Now()
		}
	}

	hdr.DHPub = s.dhSelf.PublicKey().Bytes()
	return hdr, nil
}

// EncryptMessage encrypts plaintext for the current position in the
// ratchet, returning the header that must accompany the ciphertext.
// associatedData is additionally authenticated (but not encrypted) —
// e.g. sender/recipient routing metadata.
func (s *State) EncryptMessage(plaintext, associatedData []byte) (*Header, []byte, error) {
	hdr, err := s.prepareSendingChain()
	if err != nil {
		return nil, nil, err
	}
	hdr.N = s.nSend

	mk := chainStep(&s.chainSend)
	s.nSend++
	s.msgsSinceInject++

	ct, err := aeadSeal(mk, plaintext, associatedDataWithHeader(hdr, associatedData))
	if err != nil {
		return nil, nil, err
	}
	return hdr, ct, nil
}

// DecryptMessage decrypts a message given its header, performing a DH
// ratchet step (and consuming any PQ injection material) if the header
// carries a new remote ratchet key.
func (s *State) DecryptMessage(hdr *Header, ciphertext, associatedData []byte) ([]byte, error) {
	if mk, ok := s.takeSkippedKey(hdr); ok {
		return aeadOpen(mk, ciphertext, associatedDataWithHeader(hdr, associatedData))
	}

	isNewRatchetKey := s.dhRemote == nil || string(hdr.DHPub) != string(s.dhRemote.Bytes())

	if isNewRatchetKey {
		if s.dhRemote != nil {
			if err := s.skipMessageKeys(hdr.PN); err != nil {
				return nil, err
			}
		}
		if err := s.dhRatchetStep(hdr); err != nil {
			return nil, err
		}
	}

	if err := s.skipMessageKeys(hdr.N); err != nil {
		return nil, err
	}

	mk := chainStep(&s.chainRecv)
	s.nRecv++

	return aeadOpen(mk, ciphertext, associatedDataWithHeader(hdr, associatedData))
}

// dhRatchetStep processes a newly observed remote ratchet public key:
// derives a fresh receiving chain (consuming a pending PQ injection
// response if present), records any PQ injection the peer is
// initiating for us to respond to on our next send, and marks that we
// owe the peer a new sending chain.
func (s *State) dhRatchetStep(hdr *Header) error {
	remotePub, err := ecdh.X25519().NewPublicKey(hdr.DHPub)
	if err != nil {
		return err
	}

	var kemSS []byte
	if hdr.MLKEMCiphertext != nil {
		if s.selfPendingKEMPriv == nil {
			return ErrUnexpectedKEMCT
		}
		ss := make([]byte, mlkem768.SharedKeySize)
		s.selfPendingKEMPriv.DecapsulateTo(ss, hdr.MLKEMCiphertext)
		kemSS = ss
		s.selfPendingKEMPriv = nil
	}

	s.dhRemote = remotePub

	dhOut, err := s.dhSelf.ECDH(s.dhRemote)
	if err != nil {
		return err
	}

	s.nRecv = 0
	s.RootKey, s.chainRecv, err = rootKDF(s.RootKey, dhOut, kemSS)
	if err != nil {
		return err
	}

	if hdr.MLKEMPub != nil {
		var pub mlkem768.PublicKey
		if err := pub.Unpack(hdr.MLKEMPub); err != nil {
			return err
		}
		s.peerAdvertisedKEMPub = &pub
	}

	s.needsNewSendingChain = true
	return nil
}

// skipMessageKeys advances the current receiving chain up to (but not
// including) message number until, storing each derived message key
// for later out-of-order delivery.
func (s *State) skipMessageKeys(until uint32) error {
	if s.chainRecv == nil {
		return nil
	}
	if until < s.nRecv {
		return nil
	}
	if until-s.nRecv > MaxSkip {
		return ErrSkipTooLarge
	}
	dhKey := string(s.dhRemote.Bytes())
	for s.nRecv < until {
		mk := chainStep(&s.chainRecv)
		s.skipped[skippedKey{dhPub: dhKey, n: s.nRecv}] = mk
		s.nRecv++
	}
	return nil
}

func (s *State) takeSkippedKey(hdr *Header) ([]byte, bool) {
	key := skippedKey{dhPub: string(hdr.DHPub), n: hdr.N}
	mk, ok := s.skipped[key]
	if ok {
		delete(s.skipped, key)
	}
	return mk, ok
}

func associatedDataWithHeader(hdr *Header, ad []byte) []byte {
	return append(append([]byte{}, ad...), hdr.Marshal()...)
}
