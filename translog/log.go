// Package translog implements PQChat's identity transparency log
// (PRD F5-F8, §5 "Identity verification"): an append-only, Merkle-
// tree-committed record of every identity key ever registered, so a
// client can refuse to establish a session against an identity key
// that isn't provably in the log, and can tell a legitimate key
// rotation (a new log entry) apart from an unlogged substitution (a
// MITM'd key with no log entry).
//
// This is Phase 3 of the rollout plan and, per the PRD's own honesty
// framing (§10), the actual novelty claim in this design: hybrid PQC
// and prekeys are deployed elsewhere; mandatory, send-blocking,
// gossip-audited key transparency as the *default* is the composition
// this project is testing.
package translog

import (
	"encoding/binary"
	"errors"
	"sync"
	"time"

	"pqchat/crypto/identity"
	"pqchat/crypto/merkle"
)

var (
	ErrUnknownIndex          = errors.New("translog: no entry at that index")
	ErrNoSTHPublished        = errors.New("translog: no tree head has been published yet")
	ErrInvalidInclusionProof = errors.New("translog: inclusion proof does not match the given tree head")
)

const merkleDomain = "translog"

// Entry is one append-only log record: userID registered or rotated
// to PublicKey at Index.
type Entry struct {
	Index     int
	UserID    string
	PublicKey identity.PublicKey
	Timestamp time.Time
}

func leafData(e Entry) ([]byte, error) {
	pubBytes, err := e.PublicKey.Marshal()
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 0, len(e.UserID)+4+4+len(pubBytes))
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(e.UserID)))
	buf = append(buf, []byte(e.UserID)...)
	buf = binary.BigEndian.AppendUint32(buf, uint32(e.Index))
	buf = append(buf, pubBytes...)
	return buf, nil
}

// Server is the log operator's append-only store. It is not itself
// the thing clients are asked to trust unconditionally — the whole
// point of §5/§6 is that clients, gossip, and witnesses can catch it
// lying (PRD T5).
type Server struct {
	mu           sync.Mutex
	operatorID   *identity.KeyPair
	entries      []Entry
	latestByUser map[string]int
	currentSTH   *SignedTreeHead
}

// NewServer creates an empty log operated under operatorID.
func NewServer(operatorID *identity.KeyPair) *Server {
	return &Server{
		operatorID:   operatorID,
		latestByUser: make(map[string]int),
	}
}

// OperatorIdentity returns the log operator's public identity, which
// callers must already trust out-of-band (e.g. pinned at install
// time) — the log proves consistency of what this operator publishes,
// not that this operator is trustworthy in the first place.
func (s *Server) OperatorIdentity() identity.PublicKey {
	return s.operatorID.Public()
}

// Append adds a new entry binding userID to pub. This does not
// immediately change what clients see — that happens at the next
// PublishSTH, mirroring real transparency logs where writes land
// between epochs (PRD: "signed tree heads published at fixed
// epochs").
func (s *Server) Append(userID string, pub identity.PublicKey) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := len(s.entries)
	s.entries = append(s.entries, Entry{
		Index:     idx,
		UserID:    userID,
		PublicKey: pub,
		Timestamp: time.Now(),
	})
	s.latestByUser[userID] = idx
	return idx
}

// PublishSTH rebuilds the Merkle tree over every entry appended so
// far and signs a fresh tree head. In a real deployment this runs on
// a timer (the PRD locks a 5-minute epoch); here it's invoked
// explicitly so tests and simulations control epoch boundaries
// precisely.
func (s *Server) PublishSTH() (*SignedTreeHead, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.publishSTHLocked()
}

func (s *Server) publishSTHLocked() (*SignedTreeHead, error) {
	leaves := make([][]byte, len(s.entries))
	for i, e := range s.entries {
		l, err := leafData(e)
		if err != nil {
			return nil, err
		}
		leaves[i] = l
	}
	root := merkle.BuildTree(merkleDomain, leaves).Root()
	sth, err := signTreeHead(s.operatorID, len(s.entries), root, time.Now())
	if err != nil {
		return nil, err
	}
	s.currentSTH = sth
	return sth, nil
}

// CurrentSTH returns the most recently published tree head.
func (s *Server) CurrentSTH() (*SignedTreeHead, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.currentSTH == nil {
		return nil, ErrNoSTHPublished
	}
	return s.currentSTH, nil
}

// Entry returns the entry at index, as of the current tree.
func (s *Server) Entry(index int) (Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if index < 0 || index >= len(s.entries) {
		return Entry{}, ErrUnknownIndex
	}
	return s.entries[index], nil
}

// LatestEntryForUser returns the most recent entry for userID —
// i.e. the identity key currently on file for them.
func (s *Server) LatestEntryForUser(userID string) (Entry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx, ok := s.latestByUser[userID]
	if !ok {
		return Entry{}, false
	}
	return s.entries[idx], true
}

// InclusionProof returns the audit path proving that the entry at
// index is included under the tree as of the most recently published
// STH. It errors if index was appended after that STH was published
// (the entry exists, but isn't covered by any proof yet — it will be
// once the next STH is published).
func (s *Server) InclusionProof(index int) (Entry, []merkle.Hash, *SignedTreeHead, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.currentSTH == nil {
		return Entry{}, nil, nil, ErrNoSTHPublished
	}
	if index < 0 || index >= s.currentSTH.TreeSize {
		return Entry{}, nil, nil, ErrUnknownIndex
	}

	leaves := make([][]byte, s.currentSTH.TreeSize)
	for i := 0; i < s.currentSTH.TreeSize; i++ {
		l, err := leafData(s.entries[i])
		if err != nil {
			return Entry{}, nil, nil, err
		}
		leaves[i] = l
	}
	tree := merkle.BuildTree(merkleDomain, leaves)
	proof, err := tree.InclusionProof(index)
	if err != nil {
		return Entry{}, nil, nil, err
	}
	return s.entries[index], proof, s.currentSTH, nil
}
