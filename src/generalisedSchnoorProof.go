package main

import (
	"fmt"

	"go.dedis.ch/kyber/v3"
)

type GSPWitness struct {
	s kyber.Scalar
	r kyber.Scalar
}

type GSP struct {
	cT kyber.Point
	cS kyber.Point
}

func (proof GSP) Verify(cA kyber.Point) (bool, error) {
	h := suite.Hash()
	_, _ = h.Write([]byte("GeneralisedSchnorrProof"))
	_, _ = cA.MarshalTo(h)
	_, _ = proof.cT.MarshalTo(h)

	res := h.Sum(nil)
	x := suite.Scalar().SetBytes(res)
	eval := AddP(MulP(cA, x), proof.cT)

	if !proof.cS.Equal(eval) {
		return false, fmt.Errorf("The proof does not validate")
	}

	return true, nil
}

func (witness GSPWitness) Generate(g1, g2, cA kyber.Point) (GSP, error) {
	cA2 := AddP(MulP(g1, witness.s), MulP(g2, witness.r))

	if !cA.Equal(cA2) {
		return GSP{}, fmt.Errorf("The A does not match g1^s*g2^r")
	}

	s0, t0 := randomScalar(), randomScalar()

	cT := AddP(MulP(g1, s0), MulP(g2, t0))

	h := suite.Hash()
	_, _ = h.Write([]byte("GeneralisedSchnorrProof"))
	_, _ = cA.MarshalTo(h)
	_, _ = cT.MarshalTo(h)

	res := h.Sum(nil)
	x := suite.Scalar().SetBytes(res)

	s1 := AddS(s0, MulS(witness.s, x))
	t1 := AddS(t0, MulS(witness.r, x))

	cS := AddP(MulP(g1, s1), MulP(g2, t1))

	return GSP{
		cT: cT,
		cS: cS,
	}, nil
}
