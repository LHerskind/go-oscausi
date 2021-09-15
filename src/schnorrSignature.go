package main

import (
	"go.dedis.ch/kyber/v3"
)

type SchnorrSignature struct {
	s kyber.Scalar
	e kyber.Scalar
}

func sign(generator kyber.Point, x, m kyber.Scalar) SchnorrSignature {
	k := randomScalar()
	r := MulP(generator, k)

	h := suite.Hash()
	_, _ = h.Write([]byte("SchnorrSignature"))
	_, _ = r.MarshalTo(h)
	_, _ = m.MarshalTo(h)
	res := h.Sum(nil)
	e := suite.Scalar().SetBytes(res)

	s := SubS(k, MulS(x, e))

	return SchnorrSignature{
		s: s,
		e: e,
	}
}

func (sig SchnorrSignature) verify(generator, y kyber.Point, m kyber.Scalar) bool {
	rv := AddP(MulP(generator, sig.s), MulP(y, sig.e)) // g^s*y^e = g^{k-xe}*g^{xe} = g^k

	h := suite.Hash()
	_, _ = h.Write([]byte("SchnorrSignature"))
	_, _ = rv.MarshalTo(h)
	_, _ = m.MarshalTo(h)
	res := h.Sum(nil)
	ev := suite.Scalar().SetBytes(res)

	return ev.Equal(sig.e)
}
