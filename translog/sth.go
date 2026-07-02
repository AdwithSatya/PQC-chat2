package translog

import (
	"encoding/binary"
	"time"

	"pqchat/crypto/identity"
	"pqchat/crypto/merkle"
)

// SignedTreeHead (STH) is the log operator's signed commitment to a
// specific tree state, published at fixed epochs (PRD §5/§6: "signed
// tree heads published at fixed epochs"). Clients gossip these
// opportunistically and cross-check them via witnesses to detect a
// log that shows different trees to different users (PRD T5).
type SignedTreeHead struct {
	TreeSize         int
	RootHash         merkle.Hash
	Timestamp        time.Time
	OperatorIdentity identity.PublicKey
	Signature        *identity.Signature
}

func sthSigningBytes(treeSize int, root merkle.Hash, ts time.Time) []byte {
	buf := make([]byte, 0, 4+len(root)+8)
	buf = binary.BigEndian.AppendUint32(buf, uint32(treeSize))
	buf = append(buf, root[:]...)
	buf = binary.BigEndian.AppendUint64(buf, uint64(ts.UnixNano()))
	return buf
}

func signTreeHead(operatorID *identity.KeyPair, treeSize int, root merkle.Hash, ts time.Time) (*SignedTreeHead, error) {
	sig, err := operatorID.Sign(sthSigningBytes(treeSize, root, ts))
	if err != nil {
		return nil, err
	}
	return &SignedTreeHead{
		TreeSize:         treeSize,
		RootHash:         root,
		Timestamp:        ts,
		OperatorIdentity: operatorID.Public(),
		Signature:        sig,
	}, nil
}

// VerifySTH checks a signed tree head's signature against the
// operator identity it claims. It does not check who that operator
// identity actually belongs to — that binding has to come from
// somewhere the caller already trusts (out of scope for this
// scaffold; see the PRD's own note that a real deployment would pin
// the log operator's identity out-of-band).
func VerifySTH(sth *SignedTreeHead) error {
	return identity.Verify(sth.OperatorIdentity, sthSigningBytes(sth.TreeSize, sth.RootHash, sth.Timestamp), sth.Signature)
}
