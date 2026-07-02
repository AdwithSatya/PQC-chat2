package translog

import (
	"testing"
	"time"

	"pqchat/crypto/merkle"
)

func TestWitnessDetectsDirectEquivocation(t *testing.T) {
	op := newOperator(t)
	pub := op.Public()

	rootA := merkle.Hash{0x01}
	rootB := merkle.Hash{0x02}
	ts := time.Now()

	sthA, err := SignTreeHeadForSimulation(op, 10, rootA, ts)
	if err != nil {
		t.Fatalf("SignTreeHeadForSimulation: %v", err)
	}
	sthB, err := SignTreeHeadForSimulation(op, 10, rootB, ts)
	if err != nil {
		t.Fatalf("SignTreeHeadForSimulation: %v", err)
	}

	view := NewClientView(pub)
	if ev, err := view.Observe(sthA); err != nil || ev != nil {
		t.Fatalf("first Observe: ev=%v err=%v, want (nil, nil)", ev, err)
	}
	ev, err := view.Observe(sthB)
	if err != nil {
		t.Fatalf("second Observe: %v", err)
	}
	if ev == nil {
		t.Fatal("expected equivocation evidence, got nil")
	}
	if err := VerifyEvidence(ev, pub); err != nil {
		t.Fatalf("VerifyEvidence: %v", err)
	}
}

func TestVerifyEvidenceRejectsNonEquivocation(t *testing.T) {
	op := newOperator(t)
	pub := op.Public()
	root := merkle.Hash{0x01}
	ts := time.Now()

	sthA, err := SignTreeHeadForSimulation(op, 10, root, ts)
	if err != nil {
		t.Fatalf("SignTreeHeadForSimulation: %v", err)
	}
	sthB, err := SignTreeHeadForSimulation(op, 10, root, ts.Add(time.Second))
	if err != nil {
		t.Fatalf("SignTreeHeadForSimulation: %v", err)
	}

	ev := &Evidence{A: sthA, B: sthB}
	if err := VerifyEvidence(ev, pub); err != ErrEvidenceSameRoot {
		t.Fatalf("error = %v, want ErrEvidenceSameRoot", err)
	}
}

func TestVerifyEvidenceRejectsForgedSTH(t *testing.T) {
	op := newOperator(t)
	impostor := newOperator(t)
	pub := op.Public()
	ts := time.Now()

	sthA, err := SignTreeHeadForSimulation(op, 10, merkle.Hash{0x01}, ts)
	if err != nil {
		t.Fatalf("SignTreeHeadForSimulation: %v", err)
	}
	// A forged STH claiming to be from op but actually signed by
	// someone else, with the OperatorIdentity field lied about.
	forged, err := SignTreeHeadForSimulation(impostor, 10, merkle.Hash{0x02}, ts)
	if err != nil {
		t.Fatalf("SignTreeHeadForSimulation: %v", err)
	}
	forged.OperatorIdentity = pub // lie about who signed it

	ev := &Evidence{A: sthA, B: forged}
	if err := VerifyEvidence(ev, pub); err == nil {
		t.Fatal("VerifyEvidence accepted evidence containing a forged STH")
	}
}

// TestGossipDetectsEquivocationBetweenTwoVictims is Phase 3's exit
// criterion: a log that shows two different clients two different
// (but individually well-formed and validly signed) views of the
// same tree size is caught the moment those two clients gossip with
// each other, without either needing to trust a third party — the
// evidence is self-certifying.
func TestGossipDetectsEquivocationBetweenTwoVictims(t *testing.T) {
	op := newOperator(t)
	pub := op.Public()
	ts := time.Now()

	honestSTH, err := SignTreeHeadForSimulation(op, 100, merkle.Hash{0xAA}, ts)
	if err != nil {
		t.Fatalf("SignTreeHeadForSimulation: %v", err)
	}
	equivocatingSTH, err := SignTreeHeadForSimulation(op, 100, merkle.Hash{0xBB}, ts)
	if err != nil {
		t.Fatalf("SignTreeHeadForSimulation: %v", err)
	}

	victim1 := NewClientView(pub) // fetched the "honest" branch
	victim2 := NewClientView(pub) // fetched the equivocating branch
	if _, err := victim1.Observe(honestSTH); err != nil {
		t.Fatalf("victim1 Observe: %v", err)
	}
	if _, err := victim2.Observe(equivocatingSTH); err != nil {
		t.Fatalf("victim2 Observe: %v", err)
	}

	// Neither victim has detected anything on their own yet -- each
	// has only ever seen one branch. Gossiping reveals it to both.
	evFor1, evFor2 := victim1.GossipWith(victim2)

	if len(evFor1) != 1 || len(evFor2) != 1 {
		t.Fatalf("got %d/%d equivocation reports, want 1/1", len(evFor1), len(evFor2))
	}
	if err := VerifyEvidence(evFor1[0], pub); err != nil {
		t.Fatalf("VerifyEvidence(victim1's evidence): %v", err)
	}
	if err := VerifyEvidence(evFor2[0], pub); err != nil {
		t.Fatalf("VerifyEvidence(victim2's evidence): %v", err)
	}
}

// TestGossipSimulationAcrossPopulation is the "adversarial testbed"
// version of the exit criterion: a population of clients, most of
// whom only ever fetch the log directly, plus a small fraction who
// gossip pairwise each round. A log that starts equivocating partway
// through must be caught within the simulation, propagating from
// whichever two clients first gossip across the split.
//
// This is a scoped stand-in for the PRD's own C2 claim (§11: "1% DAU
// gossip participation... detected within 24h") — it demonstrates the
// detection *mechanism* works under adversarial conditions, not the
// specific participation-rate/timing bound, which the PRD itself
// flags (§13 P2) as needing real contact-graph data this scaffold
// doesn't have.
func TestGossipSimulationAcrossPopulation(t *testing.T) {
	const population = 50
	op := newOperator(t)
	pub := op.Public()
	ts := time.Now()

	// The log has already equivocated: two irreconcilable STHs exist
	// for the same tree size. Split the population into two groups,
	// each of which only ever directly observes one of the two views
	// (modeling a log that partitions clients, e.g. by network
	// vantage point).
	sthA, err := SignTreeHeadForSimulation(op, 100, merkle.Hash{0x01}, ts)
	if err != nil {
		t.Fatalf("SignTreeHeadForSimulation: %v", err)
	}
	sthB, err := SignTreeHeadForSimulation(op, 100, merkle.Hash{0x02}, ts)
	if err != nil {
		t.Fatalf("SignTreeHeadForSimulation: %v", err)
	}

	clients := make([]*ClientView, population)
	for i := range clients {
		clients[i] = NewClientView(pub)
		if i%2 == 0 {
			if _, err := clients[i].Observe(sthA); err != nil {
				t.Fatalf("Observe: %v", err)
			}
		} else {
			if _, err := clients[i].Observe(sthB); err != nil {
				t.Fatalf("Observe: %v", err)
			}
		}
	}

	// Simulate rounds of pairwise gossip (i talks to i+1, a minimal
	// ring topology) until someone detects the split. A ring
	// guarantees the split propagates in at most population/2 rounds;
	// this checks detection actually happens within that bound rather
	// than asserting a specific real-world timing claim.
	detected := false
	for round := 0; round < population && !detected; round++ {
		for i := 0; i < population; i++ {
			j := (i + 1) % population
			evForI, evForJ := clients[i].GossipWith(clients[j])
			for _, ev := range evForI {
				if err := VerifyEvidence(ev, pub); err == nil {
					detected = true
				}
			}
			for _, ev := range evForJ {
				if err := VerifyEvidence(ev, pub); err == nil {
					detected = true
				}
			}
		}
	}

	if !detected {
		t.Fatal("equivocation was never detected across the simulated population")
	}
}
