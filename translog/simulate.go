package translog

import (
	"time"

	"pqchat/crypto/identity"
	"pqchat/crypto/merkle"
)

// SignTreeHeadForSimulation signs an arbitrary (treeSize, root) pair
// as operatorID. A malicious or compromised log operator can already
// do this with its own key — that's the threat this package defends
// against (PRD T5), not a capability this function grants. It exists
// so tests and adversarial-testbed simulations can construct an
// equivocating operator without production client/server code
// needing to expose "sign any root you like" as a general API.
func SignTreeHeadForSimulation(operatorID *identity.KeyPair, treeSize int, root merkle.Hash, ts time.Time) (*SignedTreeHead, error) {
	return signTreeHead(operatorID, treeSize, root, ts)
}
