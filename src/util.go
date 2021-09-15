package main

import (
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/suites"
)

type Base struct {
	g, h, j kyber.Point
}

func commit(base Base, s, v, r kyber.Scalar) kyber.Point {
	return AddP(MulP(base.g, s), AddP(MulP(base.h, v), MulP(base.j, r)))
}

func Pow(a kyber.Scalar, b int) kyber.Scalar {
	return expBySquaring(a, b)
}

func expBySquaring(x kyber.Scalar, n int) kyber.Scalar {
	if n == 0 {
		return newScalar(1)
	} else if n == 1 {
		return x
	} else if (n & 1) == 0 { // n is even
		return expBySquaring(MulS(x, x), n/2)
	} else { // Odd
		return MulS(x, expBySquaring(MulS(x, x), (n-1)/2))
	}
}

var suite = suites.MustFind("p256")

func newScalar(a int) kyber.Scalar {
	return suite.Scalar().SetInt64(int64(a))
}

func AddP(a, b kyber.Point) kyber.Point {
	return suite.Point().Add(a, b)
}

func MulP(a kyber.Point, b kyber.Scalar) kyber.Point {
	return suite.Point().Mul(b, a)
}

func SubP(a, b kyber.Point) kyber.Point {
	return suite.Point().Sub(a, b)
}

func NegP(a kyber.Point) kyber.Point {
	return suite.Point().Neg(a)
}

func AddS(a, b kyber.Scalar) kyber.Scalar {
	return suite.Scalar().Add(a, b)
}

func SubS(a, b kyber.Scalar) kyber.Scalar {
	return suite.Scalar().Sub(a, b)
}

func MulS(a, b kyber.Scalar) kyber.Scalar {
	return suite.Scalar().Mul(a, b)
}

func NegS(a kyber.Scalar) kyber.Scalar {
	return suite.Scalar().Neg(a)
}

func randomScalar() kyber.Scalar {
	return suite.Scalar().Pick(suite.RandomStream())
}

func vectorCommit(base Base, values []kyber.Scalar, blinding kyber.Scalar) kyber.Point {
	// TODO: THis should be fixed. Should utilise "real" generators, i.e., unknown coefficient, instead of this manner. But it does the job for now.
	res := suite.Point().Mul(values[0], suite.Point().Base())
	for i := 1; i < len(values); i++ {
		nBase := suite.Point().Mul(newScalar(i*5+1), suite.Point().Base())
		res = AddP(res, MulP(nBase, values[i]))
	}
	res = AddP(res, MulP(base.h, blinding))
	return res
}

func getNAry(val int) (returnVal [m]int) {
	i := m - 1
	for i >= 0 {
		q := val / n
		r := val - q*n
		returnVal[i] = r
		val = q
		i--
	}
	return
}
