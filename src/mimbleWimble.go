package main

import (
	"fmt"

	"go.dedis.ch/kyber/v3"
)

// TODO: Remember that we are using the generators h and j!

type MWCoinWitness struct {
	v kyber.Scalar
	r kyber.Scalar
}

type MWWitness struct {
	inputs  []MWCoinWitness
	change  []MWCoinWitness
	outputs []MWCoinWitness
	vO      kyber.Scalar
	a       kyber.Scalar
	rA      kyber.Point
	x       kyber.Scalar
	cX      kyber.Point
}

type MWReceiveWitness struct {
	output MWCoinWitness
	b      kyber.Scalar
}

type MWTransferInit struct {
	inputs  []kyber.Point
	outputs []kyber.Point
	cX      kyber.Point
	v       kyber.Scalar
	rA      kyber.Point
}

type MWTransferResponse struct {
	output kyber.Point
	rB     kyber.Point
	sB     kyber.Scalar
	pB     kyber.Point
}

type MWTransfer struct {
	excess  kyber.Point
	s       kyber.Scalar
	R       kyber.Point
	inputs  []kyber.Point
	outputs []kyber.Point
}

func (witness MWCoinWitness) commit(base Base) kyber.Point {
	return AddP(MulP(base.h, witness.v), MulP(base.j, witness.r))
}

func (witness *MWWitness) InitTransfer(base Base) MWTransferInit {
	witness.a = randomScalar()
	witness.rA = MulP(base.j, witness.a)

	// Calculate x as the difference between outputSum and inputSum

	outputs := make([]kyber.Point, 0, len(witness.change))
	inputs := make([]kyber.Point, 0, len(witness.inputs))

	outputSum := newScalar(0)
	inputSum := newScalar(0)
	for _, change := range witness.change { // This is just a practicality, in reality, this is an output.
		outputSum = AddS(outputSum, change.r)
		outputs = append(outputs, change.commit(base))
	}
	for _, input := range witness.inputs {
		inputSum = AddS(inputSum, input.r)
		inputs = append(inputs, input.commit(base))
	}

	witness.x = SubS(outputSum, inputSum)
	witness.cX = MulP(base.j, witness.x)

	return MWTransferInit{
		inputs:  inputs,
		outputs: outputs,
		cX:      witness.cX,
		v:       witness.vO,
		rA:      witness.rA,
	}

}

func (witness *MWReceiveWitness) AcceptTransfer(base Base, transfer MWTransferInit) MWTransferResponse {
	witness.b = randomScalar()
	rB := MulP(base.j, witness.b)
	pB := MulP(base.j, witness.output.r)

	h := suite.Hash()
	_, _ = h.Write([]byte("MWChallenge"))
	_, _ = AddP(transfer.rA, rB).MarshalTo(h)
	_, _ = AddP(transfer.cX, pB).MarshalTo(h)

	res := h.Sum(nil)
	e := suite.Scalar().SetBytes(res)

	sB := AddS(witness.b, MulS(e, witness.output.r))

	return MWTransferResponse{
		output: witness.output.commit(base),
		rB:     rB,
		sB:     sB,
		pB:     pB,
	}

}

func (witness *MWWitness) FinishTransfer(base Base, transfer MWTransferInit, response MWTransferResponse) MWTransfer {
	h := suite.Hash()
	_, _ = h.Write([]byte("MWChallenge"))
	_, _ = AddP(transfer.rA, response.rB).MarshalTo(h)
	_, _ = AddP(transfer.cX, response.pB).MarshalTo(h)

	res := h.Sum(nil)
	e := suite.Scalar().SetBytes(res)

	sa := AddS(witness.a, MulS(e, witness.x))
	s := AddS(sa, response.sB)

	R := AddP(transfer.rA, response.rB)

	excess := AddP(transfer.cX, response.pB)

	inputs := make([]kyber.Point, 0, len(witness.inputs))
	outputs := make([]kyber.Point, 0, len(witness.change)+1)

	for _, input := range witness.inputs {
		inputs = append(inputs, input.commit(base))
	}
	for _, change := range witness.change {
		outputs = append(outputs, change.commit(base))
	}
	outputs = append(outputs, response.output)

	return MWTransfer{
		excess:  excess,
		s:       s,
		R:       R,
		inputs:  inputs,
		outputs: outputs,
	}

}

func (transfer MWTransfer) Verify(base Base) bool {
	// TODO, needs to look into sets of existing coins

	outputSum := transfer.outputs[0]
	for _, output := range transfer.outputs[1:] {
		outputSum = AddP(outputSum, output)
	}

	inputSum := transfer.inputs[0]
	for _, input := range transfer.inputs[1:] {
		inputSum = AddP(inputSum, input)
	}

	evalExcess := SubP(outputSum, inputSum)

	if !evalExcess.Equal(transfer.excess) {
		fmt.Println("There is a mismatch in the excess")
		return false
	}

	h := suite.Hash()
	_, _ = h.Write([]byte("MWChallenge"))
	_, _ = transfer.R.MarshalTo(h)
	_, _ = transfer.excess.MarshalTo(h)

	res := h.Sum(nil)
	e := suite.Scalar().SetBytes(res)

	evalS := AddP(transfer.R, MulP(evalExcess, e))

	if !MulP(base.j, transfer.s).Equal(evalS) {
		fmt.Println("The signatures do not match!")
		return false
	}

	// TODO: Evaluate rangeproofs on the outputs, and update sets.

	return true
}
