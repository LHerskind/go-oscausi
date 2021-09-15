package main

import (
	"fmt"

	"go.dedis.ch/kyber/v3"
)

type MintWitness struct {
	v  kyber.Scalar
	r  kyber.Scalar
	q  kyber.Scalar
	s  kyber.Scalar
	ro kyber.Scalar
}

func newMintWitness(v, r int) MintWitness {
	return MintWitness{
		v: newScalar(v),
		r: newScalar(r),
	}
}

type MintProof struct {
	cC    kyber.Point
	cD    kyber.Point
	gspHJ GSP
	gspGJ GSP
}

func (witness *MintWitness) generateProof(base Base, cC kyber.Point) (MintProof, error) {
	cC2 := AddP(MulP(base.h, witness.v), MulP(base.j, witness.r))

	if !cC2.Equal(cC) {
		return MintProof{}, fmt.Errorf("C is not matching")
	}

	gspWitnessHJ := GSPWitness{
		s: witness.v,
		r: witness.r,
	}

	gspProof1, err := gspWitnessHJ.Generate(base.h, base.j, cC)
	if err != nil {
		return MintProof{}, fmt.Errorf("cC not matching")
	}

	q, ro := randomScalar(), randomScalar()
	cP := MulP(base.g, q)

	h := suite.Hash()
	_, _ = h.Write([]byte("SerialHash"))
	_, _ = cP.MarshalTo(h)
	res := h.Sum(nil)
	s := suite.Scalar().SetBytes(res)

	cD := AddP(MulP(base.g, s), AddP(MulP(base.h, witness.v), MulP(base.j, ro)))
	r := SubS(ro, witness.r)

	gspWitnessGJ := GSPWitness{
		s: s,
		r: r,
	}

	excess := SubP(cD, cC)
	gspProof2, err := gspWitnessGJ.Generate(base.g, base.j, excess)

	if err != nil {
		return MintProof{}, fmt.Errorf("cD / cC not matching")
	}

	witness.s = s
	witness.ro = ro
	witness.q = q

	return MintProof{
		gspHJ: gspProof1,
		gspGJ: gspProof2,
		cC:    cC,
		cD:    cD,
	}, nil
}

func (proof MintProof) Verify() bool {
	_, err1 := proof.gspHJ.Verify(proof.cC)
	if err1 != nil {
		return false
	}

	excess := SubP(proof.cD, proof.cC)

	_, err2 := proof.gspGJ.Verify(excess)
	if err2 != nil {
		return false
	}

	// TODO: remove cC from list of unspent coins, i.e., CList.
	// TODO: Add cD to list of notes, i.e., CMList.

	return true
}
