package main

import (
	"fmt"
	"sync"

	"go.dedis.ch/kyber/v3"
)

var wg = sync.WaitGroup{}

type OOOMWitness struct {
	q     kyber.Scalar
	s     kyber.Scalar
	v     kyber.Scalar
	r     kyber.Scalar
	l     int
	gamma [m]kyber.Scalar
	part1 OOOMWitnessP1
}

type OOOMWitnessP1 struct {
	a  [m][n]kyber.Scalar
	rA kyber.Scalar
	rB kyber.Scalar
	rC kyber.Scalar
	rD kyber.Scalar
}

func newOOOMWitness(base Base, q, v, r kyber.Scalar, l int) OOOMWitness {
	cP := MulP(base.g, q)

	h := suite.Hash()
	_, _ = h.Write([]byte("SerialHash"))
	_, _ = cP.MarshalTo(h)
	res := h.Sum(nil)
	s := suite.Scalar().SetBytes(res)

	return OOOMWitness{
		q: q,
		s: s,
		v: v,
		r: r,
		l: l,
	}
}

type OneOutOfManyProof struct {
	cA  kyber.Point
	cB  kyber.Point
	cC  kyber.Point
	cD  kyber.Point
	cGk [m]kyber.Point
	cQk [m]kyber.Point
	fs  [m][n]kyber.Scalar
	zA  kyber.Scalar
	zC  kyber.Scalar
	zV  kyber.Scalar
	zR  kyber.Scalar
	s   kyber.Scalar
}

func (witness *OOOMWitness) InitProof(base Base) OneOutOfManyProof {
	rA, rB, rC, rD := randomScalar(), randomScalar(), randomScalar(), randomScalar()
	lBins := getNAry(witness.l)
	a := generateA()

	vA := make([]kyber.Scalar, 0, N)
	vB := make([]kyber.Scalar, 0, N)
	vC := make([]kyber.Scalar, 0, N)
	vD := make([]kyber.Scalar, 0, N)

	for i := 0; i < n; i++ {
		for j := 0; j < m; j++ {
			vA = append(vA, a[j][i])
			vB = append(vB, delta(lBins[j], i))
			vC = append(vC, MulS(a[j][i], SubS(newScalar(1), MulS(newScalar(2), delta(lBins[j], i)))))
			vD = append(vD, NegS(MulS(a[j][i], a[j][i])))
		}
	}

	cA := vectorCommit(base, vA, rA)
	cB := vectorCommit(base, vB, rB)
	cC := vectorCommit(base, vC, rC)
	cD := vectorCommit(base, vD, rD)

	witness.part1 = OOOMWitnessP1{
		a:  a,
		rA: rA,
		rB: rB,
		rC: rC,
		rD: rD,
	}

	return OneOutOfManyProof{
		cA: cA,
		cB: cB,
		cC: cC,
		cD: cD,
	}
}

func (witness *OOOMWitness) FinishProof(base Base, cmList [N]kyber.Point, challenge kyber.Scalar, ooom *OneOutOfManyProof) {
	lBins := getNAry(witness.l)
	serial := commit(base, witness.s, newScalar(0), newScalar(0))

	minSize := 32
	wg.Add(N / minSize)
	for j := 0; j < N/minSize; j++ {
		go func(j, minSize int) {
			offset := minSize * j
			for i := 0; i < minSize; i++ {
				cmList[i+offset] = SubP(cmList[i+offset], serial)
			}
			wg.Done()
		}(j, minSize)
	}
	wg.Wait()

	pIK := [N][m]kyber.Scalar{}
	calculatePiks(&lBins, &witness.part1.a, &pIK)

	x := challenge

	rho := [m]kyber.Scalar{}
	tau := [m]kyber.Scalar{}
	gamma := [m]kyber.Scalar{}
	gKs := [m]kyber.Point{}
	qKs := [m]kyber.Point{}

	wg.Add(m)
	for k := 0; k < m; k++ {
		go func(k int, rho, tau, gamma *[m]kyber.Scalar, gKs, qKs *[m]kyber.Point) {
			(*rho)[k], (*tau)[k], (*gamma)[k] = randomScalar(), randomScalar(), randomScalar()

			gK := MulP(cmList[0], pIK[0][k])
			for i := 1; i < N; i++ {
				gK = AddP(gK, MulP(cmList[i], pIK[i][k]))
			}
			gK = AddP(gK, MulP(base.j, NegS((*gamma)[k])))
			(*gKs)[k] = gK

			qK := AddP(MulP(base.j, (*gamma)[k]), commit(base, newScalar(0), (*rho)[k], (*tau)[k]))
			(*qKs)[k] = qK
			wg.Done()
		}(k, &rho, &tau, &gamma, &gKs, &qKs)
	}
	wg.Wait()

	witness.gamma = gamma

	zA := AddS(MulS(witness.part1.rB, x), witness.part1.rA)
	zC := AddS(MulS(witness.part1.rC, x), witness.part1.rD)

	xToM := Pow(x, m)
	zV := MulS(witness.v, xToM)
	zR := MulS(witness.r, xToM)

	for k := 0; k < m; k++ {
		xtokIt := Pow(x, k)
		zV = SubS(zV, MulS(rho[k], xtokIt))
		zR = SubS(zR, MulS(tau[k], xtokIt))
	}

	fMatrix := [m][n]kyber.Scalar{}
	for i := 0; i < n; i++ {
		for j := 0; j < m; j++ {
			fMatrix[j][i] = f(lBins, witness.part1.a, j, i, x)
		}
	}

	ooom.zA = zA
	ooom.zC = zC
	ooom.zV = zV
	ooom.zR = zR
	ooom.fs = fMatrix
	ooom.cGk = gKs
	ooom.cQk = qKs
	ooom.s = witness.s

}

func (proof OneOutOfManyProof) Verify(base Base, cmList [N]kyber.Point, challenge kyber.Scalar) (bool, error) {
	serial := commit(base, proof.s, newScalar(0), newScalar(0))

	minSize := 32
	wg.Add(N / minSize)
	for j := 0; j < N/minSize; j++ {
		go func(j, minSize int) {
			offset := minSize * j
			for i := 0; i < minSize; i++ {
				cmList[i+offset] = SubP(cmList[i+offset], serial)
			}
			wg.Done()
		}(j, minSize)
	}
	wg.Wait()

	x := challenge

	fVals := make([]kyber.Scalar, 0, N)
	f2Vals := make([]kyber.Scalar, 0, N)

	for i := 0; i < n; i++ {
		for j := 0; j < m; j++ {
			fVals = append(fVals, proof.fs[j][i])
			f2Vals = append(f2Vals, MulS(proof.fs[j][i], SubS(x, proof.fs[j][i])))
		}
	}

	eval1 := AddP(MulP(proof.cB, x), proof.cA)
	eval2 := AddP(MulP(proof.cC, x), proof.cD)

	fVec := vectorCommit(base, fVals, proof.zA)
	f2Vec := vectorCommit(base, f2Vals, proof.zC)

	if !eval1.Equal(fVec) {
		return false, fmt.Errorf("First evaluation failed")
	}
	if !eval2.Equal(f2Vec) {
		return false, fmt.Errorf("Second evaluation failed")
	}

	eval3 := commit(base, newScalar(0), proof.zV, proof.zR)

	iBin := getNAry(0)
	exponent := newScalar(1)
	for j := 0; j < m; j++ {
		exponent = MulS(exponent, proof.fs[j][iBin[j]])
	}
	init := MulP(cmList[0], exponent)

	var mutex = sync.RWMutex{}

	wg.Add(N / minSize)
	for j := 0; j < N/minSize; j++ {
		go func(j, minSize int) {
			offset := minSize * j
			for k := 0; k < minSize; k++ {
				i := k + offset
				if i == 0 {
					continue
				}
				iBin := getNAry(i)
				exponent := newScalar(1)
				for j := 0; j < m; j++ {
					exponent = MulS(exponent, proof.fs[j][iBin[j]])
				}
				cI := MulP(cmList[i], exponent)
				mutex.Lock()
				init = AddP(init, cI)
				mutex.Unlock()
				// cmList[i + offset] = SubP(cmList[i + offset], serial)
			}
			wg.Done()
		}(j, minSize)
	}
	wg.Wait()

	secondPart := MulP(AddP(proof.cGk[0], proof.cQk[0]), NegS(newScalar(1)))
	for k := 1; k < m; k++ {
		temp := MulP(AddP(proof.cGk[k], proof.cQk[k]), NegS(Pow(x, k)))
		secondPart = AddP(secondPart, temp)
	}
	tot := AddP(init, secondPart)

	if !eval3.Equal(tot) {
		return false, fmt.Errorf("Third evaluation failed")
	}
	return true, nil
}

func calculatePiks(lBin *[m]int, a *[m][n]kyber.Scalar, pIk *[N][m]kyber.Scalar) {
	minSize := 32
	wg.Add(N / minSize)
	for g := 0; g < N/minSize; g++ {
		go func(g, minSize int, lBin *[m]int, a *[m][n]kyber.Scalar, pIk *[N][m]kyber.Scalar) {
			offset := minSize * g
			for i_ := 0; i_ < minSize; i_++ {
				i := i_ + offset
				ps := make([]kyber.Scalar, m+1, m+1)
				iBin := getNAry(i)

				// Init `ps[0] = a_{0,i_0}` and `ps[1] = delta_{l_j, i_j}`
				ps[0] = (*a)[0][iBin[0]]
				ps[1] = delta((*lBin)[0], iBin[0])

				for j := 1; j < m; j++ {
					// `d = \delta_{l_j, i_j}`
					d := delta((*lBin)[j], iBin[j])
					// `aTemp = a_{j, i_j}`
					aTemp := (*a)[j][iBin[j]]
					// Init next coefficient, `ps[j+1] = \delta_{l_j, i_j} * ps[j]`
					ps[j+1] = MulS(d, ps[j])

					for k := j; k >= 1; k-- {
						// Update all existing coefficients with the new `a_{j, i_j}` and `\delta_{l_j, i_j}` values
						// `a_{j, i_j}` as it directly applies, and `\delta_{l_j, i_j}` for the coefficient - 1.
						// `ps[k] = a_{j, i_j} * ps[k] + \delta_{l_i, i_j} * ps[k-1]
						ps[k] = AddS(MulS(aTemp, ps[k]), MulS(d, ps[k-1]))
					}
					// coefficient 0 is a special case, only influenced by `a_{j, i_j}`
					ps[0] = MulS(aTemp, ps[0])
				}
				for k := 0; k < m; k++ {
					pIk[i][k] = ps[k]
				}
			}
			wg.Done()
		}(g, minSize, lBin, a, pIk)
	}
	wg.Wait()
}

func generateA() (a [m][n]kyber.Scalar) {
	for i := 1; i < n; i++ {
		for j := 0; j < m; j++ {
			a[j][i] = randomScalar()
		}
	}
	for j := 0; j < m; j++ {
		a[j][0] = newScalar(0)
		for i := 1; i < n; i++ {
			a[j][0] = SubS(a[j][0], a[j][i])
		}
	}
	return
}

func delta(j, i int) kyber.Scalar {
	if j == i {
		return suite.Scalar().One()
	}
	return suite.Scalar().Zero()
}

func f(lBin [m]int, a [m][n]kyber.Scalar, j, i int, x kyber.Scalar) kyber.Scalar {
	return AddS(MulS(delta(lBin[j], i), x), a[j][i])
}
