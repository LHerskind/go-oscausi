package main

import (
	"fmt"

	"go.dedis.ch/kyber/v3"
)

// Currently not implementing the range proofs

type SpendWitness struct {
	oooms   []OOOMWitness
	outputs []MWCoinWitness
}

type SpendProof struct {
	oooms []OneOutOfManyProof // proofs
	pS    []kyber.Point       // coefficients in polynomial - no! I believe this is the public key for the inputs.
	cS    []kyber.Point       // outputs
	sigE  SchnorrSignature    // excess signature
	sigQS []SchnorrSignature  // input signatures
}

func (witness SpendWitness) Prove(base Base, cmList [N]kyber.Point) SpendProof {
	ooomProofs := make([]OneOutOfManyProof, 0, len(witness.oooms))
	pS := make([]kyber.Point, 0, len(witness.oooms))
	sigQS := make([]SchnorrSignature, 0, len(witness.oooms))
	cS := make([]kyber.Point, 0, len(witness.outputs))

	// Initiate ooom proofs
	for i := range witness.oooms {
		ooomW := &witness.oooms[i]
		ooomProof := ooomW.InitProof(base)
		ooomProofs = append(ooomProofs, ooomProof)
	}

	// Calculate challenge
	h := suite.Hash()
	_, _ = h.Write([]byte("Spending"))
	for i := range ooomProofs {
		ooomProof := &ooomProofs[i]
		_, _ = ooomProof.cA.MarshalTo(h)
		_, _ = ooomProof.cB.MarshalTo(h)
		_, _ = ooomProof.cC.MarshalTo(h)
		_, _ = ooomProof.cD.MarshalTo(h)
	}
	res := h.Sum(nil)
	challenge := suite.Scalar().SetBytes(res)

	// Finish proofs
	for i := range witness.oooms {
		ooomW := &witness.oooms[i]
		ooomW.FinishProof(base, cmList, challenge, &ooomProofs[i])

		p := MulP(base.g, ooomW.q)
		pS = append(pS, p)

		sigQ := sign(base.g, ooomW.q, challenge)
		sigQS = append(sigQS, sigQ)
	}

	e := newScalar(0)
	challengeToM := Pow(challenge, m)
	for _, output := range witness.outputs {
		cS = append(cS, output.commit(base))
		e = AddS(e, MulS(output.r, challengeToM))
	}

	for i, _ := range witness.oooms {
		ooom := &witness.oooms[i]
		temp := MulS(ooom.r, challengeToM)
		challengeToK := newScalar(1)
		for _, gamma := range ooom.gamma {
			temp = AddS(temp, MulS(gamma, challengeToK))
			challengeToK = MulS(challengeToK, challenge)
		}
		e = SubS(e, temp)
	}

	msg := challenge
	sigE := sign(base.j, e, msg)

	return SpendProof{
		oooms: ooomProofs,
		pS:    pS,
		cS:    cS,
		sigE:  sigE,
		sigQS: sigQS,
	}
}

func (proof SpendProof) Verify(base Base, cmList [N]kyber.Point) bool {
	// TODO: implement verification of rangeproofs.

	h := suite.Hash()
	_, _ = h.Write([]byte("Spending"))
	for i := range proof.oooms {
		ooomProof := &proof.oooms[i]
		_, _ = ooomProof.cA.MarshalTo(h)
		_, _ = ooomProof.cB.MarshalTo(h)
		_, _ = ooomProof.cC.MarshalTo(h)
		_, _ = ooomProof.cD.MarshalTo(h)
	}
	res := h.Sum(nil)
	challenge := suite.Scalar().SetBytes(res)

	// For all inputs calculate
	sS := make([]kyber.Point, 0, len(proof.oooms))

	for i := 0; i < len(proof.oooms); i++ {
		// TODO: Verify if s_i is not in the set

		// Evaluate that the individual signatures match
		if !proof.sigQS[i].verify(base.g, proof.pS[i], challenge) {
			fmt.Println("The signatures with q does not validate")
			return false
		}

		ooom := proof.oooms[i]

		qS := ooom.cQk
		zV := ooom.zV
		zR := ooom.zR

		cS_i := AddP(MulP(base.h, zV), MulP(base.j, zR))
		challengeToK := newScalar(1)
		for _, qK := range qS { // k= 0..m
			cS_i = AddP(cS_i, MulP(qK, challengeToK))
			challengeToK = MulS(challengeToK, challenge)
		}
		sS = append(sS, cS_i)

		_, err := ooom.Verify(base, cmList, challenge)
		if err != nil {
			fmt.Println(err)
			return false
		}
	}
	challengeToM := Pow(challenge, m)
	outSum := MulP(proof.cS[0], challengeToM)
	for _, output := range proof.cS[1:] {
		outSum = AddP(outSum, MulP(output, challengeToM))
	}

	sourceSum := sS[0]
	for _, sS_i := range sS[1:] {
		sourceSum = AddP(sourceSum, sS_i)
	}

	excess := SubP(outSum, sourceSum)

	if !proof.sigE.verify(base.j, excess, challenge) {
		fmt.Println("There is an issue with the excess value")
		return false
	}

	return true
}
