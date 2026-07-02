package translog

import (
	"errors"

	"pqchat/crypto/identity"
)

var (
	ErrEvidenceTreeSizeMismatch  = errors.New("translog: evidence tree sizes differ, not equivocation")
	ErrEvidenceSameRoot          = errors.New("translog: evidence root hashes are identical, not equivocation")
	ErrEvidenceOperatorMismatch  = errors.New("translog: evidence STHs claim different operator identities")
	ErrEvidenceWrongOperator     = errors.New("translog: evidence does not implicate the given operator identity")
	ErrSTHFromUnexpectedOperator = errors.New("translog: STH signed by an unexpected operator identity")
)

// Evidence is cryptographic proof that a log operator equivocated:
// two validly signed tree heads, same tree size, different roots.
// Anyone can verify it independently (VerifyEvidence) without trusting
// whoever surfaced it — this is what makes detection via gossip
// meaningful rather than just a rumor (PRD T5 mitigation: "detection,
// not prevention").
type Evidence struct {
	A, B *SignedTreeHead
}

// VerifyEvidence independently confirms that Evidence proves
// operatorPub equivocated.
func VerifyEvidence(ev *Evidence, operatorPub identity.PublicKey) error {
	if ev.A.TreeSize != ev.B.TreeSize {
		return ErrEvidenceTreeSizeMismatch
	}
	if ev.A.RootHash == ev.B.RootHash {
		return ErrEvidenceSameRoot
	}
	if err := VerifySTH(ev.A); err != nil {
		return err
	}
	if err := VerifySTH(ev.B); err != nil {
		return err
	}
	if !ev.A.OperatorIdentity.Equal(ev.B.OperatorIdentity) {
		return ErrEvidenceOperatorMismatch
	}
	if !ev.A.OperatorIdentity.Equal(operatorPub) {
		return ErrEvidenceWrongOperator
	}
	return nil
}

// ClientView is what a single client (or witness) remembers about a
// log: every distinct tree-head-at-a-given-size it has observed,
// whether from a direct fetch or via gossip from a peer (PRD F6:
// "Log-head gossip piggybacked on message envelopes; divergence
// detection alerts user and reports to witnesses").
type ClientView struct {
	OperatorIdentity identity.PublicKey
	seen             map[int]*SignedTreeHead
}

// NewClientView creates a view that only accepts STHs claiming to be
// from operatorIdentity — a client shouldn't silently merge gossip
// about a different log into its own.
func NewClientView(operatorIdentity identity.PublicKey) *ClientView {
	return &ClientView{
		OperatorIdentity: operatorIdentity,
		seen:             make(map[int]*SignedTreeHead),
	}
}

// Observe records sth (from a direct fetch or from a peer), returning
// non-nil Evidence if it conflicts with an STH already known for the
// same tree size.
func (c *ClientView) Observe(sth *SignedTreeHead) (*Evidence, error) {
	if !sth.OperatorIdentity.Equal(c.OperatorIdentity) {
		return nil, ErrSTHFromUnexpectedOperator
	}
	if err := VerifySTH(sth); err != nil {
		return nil, err
	}

	prior, ok := c.seen[sth.TreeSize]
	if ok && prior.RootHash != sth.RootHash {
		return &Evidence{A: prior, B: sth}, nil
	}
	if !ok {
		c.seen[sth.TreeSize] = sth
	}
	return nil, nil
}

// GossipWith exchanges every STH each side has observed so far,
// modeling PRD F6's "gossip opportunistically through message
// envelopes." Either side's own direct observations can reveal
// equivocation to the *other* side, not just to itself — that's the
// entire mechanism by which a client who never talked to a victim
// directly still ends up able to prove the log lied.
func (c *ClientView) GossipWith(other *ClientView) (evidenceForC, evidenceForOther []*Evidence) {
	otherSTHs := make([]*SignedTreeHead, 0, len(other.seen))
	for _, sth := range other.seen {
		otherSTHs = append(otherSTHs, sth)
	}
	cSTHs := make([]*SignedTreeHead, 0, len(c.seen))
	for _, sth := range c.seen {
		cSTHs = append(cSTHs, sth)
	}

	for _, sth := range otherSTHs {
		if ev, err := c.Observe(sth); err == nil && ev != nil {
			evidenceForC = append(evidenceForC, ev)
		}
	}
	for _, sth := range cSTHs {
		if ev, err := other.Observe(sth); err == nil && ev != nil {
			evidenceForOther = append(evidenceForOther, ev)
		}
	}
	return
}
