package main

import (
	"math/rand"
	"testing"

	"go.dedis.ch/kyber/v3"
)

func TestSingleSpend(t *testing.T) {
	//	Initialization. Will define the base and generate a initial set of shielded coins.
	base := Base{
		g: suite.Point().Base(),
		j: MulP(suite.Point().Base(), newScalar(base2)),
		h: MulP(suite.Point().Base(), newScalar(base3)),
	}

	cmList := [N]kyber.Point{}
	minSize := 32
	wg.Add(N / minSize)
	for j := 0; j < N/minSize; j++ {
		go func(j, minSize int) {
			offset := minSize * j
			for i := 0; i < minSize; i++ {
				cmList[i+offset] = commit(base, randomScalar(), randomScalar(), randomScalar())
			}
			wg.Done()
		}(j, minSize)
	}
	wg.Wait()

	// Testing the minting proofs!
	// TODO: We are currently just evaluating the General Schnorr Proofs, we still need to remove and add from the sets.

	//	Given a MimbleWimble coin witness, generate a proof for minting a shielded coin.
	w := newMintWitness(5, 25)                       // The MimbleWimble coin witness
	cC := AddP(MulP(base.h, w.v), MulP(base.j, w.r)) // The MimbleWimble coin
	mintProof, err := w.generateProof(base, cC)      // Generating the mintproof from witness and coin.
	if err != nil {
		t.Error(err)
	}
	// Validate the minting proof.
	if !mintProof.Verify() {
		t.Errorf("Minting proof validation was unsuccessful")
	}

	// The shielded coin is then extracted from the proof
	shieldedIndex := rand.Intn(N) // In practice it is appended to the list, not randomly assigned
	shieldedCoin := mintProof.cD

	// Spending the coin
	oOOMwitness := newOOOMWitness(base, w.q, w.v, w.ro, shieldedIndex)
	//shieldedCoin := commit(base, oOOMwitness.s, oOOMwitness.v, oOOMwitness.r) // We can also generate it given the ooom witness
	cmList[oOOMwitness.l] = shieldedCoin

	oooms := make([]OOOMWitness, 0, 1)
	outputs := make([]MWCoinWitness, 0, 1)

	oooms = append(oooms, oOOMwitness)
	outputs = append(outputs, MWCoinWitness{
		v: oOOMwitness.v,
		r: randomScalar(), // Randomly picking the blinding factor for the output coin
	})
	spendWitness := SpendWitness{
		oooms:   oooms,
		outputs: outputs,
	}

	spendProof := spendWitness.Prove(base, cmList)

	r := spendProof.Verify(base, cmList)

	if !r {
		t.Errorf("Proof not valid")
	}

}
