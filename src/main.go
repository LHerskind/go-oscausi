package main

import (
	"fmt"
	"math/rand"
	"runtime"
	"time"

	"go.dedis.ch/kyber/v3"
)

const (
	n     = 4
	m     = 6
	N     = 4096
	base2 = 8234530354789
	base3 = 23463423412
)

var threads = runtime.GOMAXPROCS(4)

func main() {
	rand.Seed(time.Now().UnixNano())

	testSingleSpend()

	//testMultiSpend()

	//testBlockContent()

	//testMimbleWimble()
}

func testMimbleWimble() {
	fmt.Println("Testing MimbleWimble transaction..")
	base := Base{
		g: suite.Point().Base(),
		j: MulP(suite.Point().Base(), newScalar(base2)),
		h: MulP(suite.Point().Base(), newScalar(base3)),
	}

	cA := MWCoinWitness{
		v: newScalar(25),
		r: randomScalar(),
	}
	cB := MWCoinWitness{
		v: newScalar(15),
		r: randomScalar(),
	}
	cC := MWCoinWitness{
		v: newScalar(10),
		r: randomScalar(),
	}

	inputs := make([]MWCoinWitness, 0, 1)
	inputs = append(inputs, cA)

	changes := make([]MWCoinWitness, 0, 1)
	changes = append(changes, cC)

	mwwitness := MWWitness{
		inputs: inputs,
		change: changes,
		vO:     SubS(cA.v, cC.v),
	}

	initTransfer := mwwitness.InitTransfer(base)
	mwReceive := MWReceiveWitness{output: cB}
	response := mwReceive.AcceptTransfer(base, initTransfer)
	transfer := mwwitness.FinishTransfer(base, initTransfer, response)

	if !transfer.Verify(base) {
		fmt.Println("We got issues with the MimbleWimble")
	}

}

func testBlockContent() {

	fmt.Println("Creating the contents of a 'block'..")

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

	toEmulate := 10

	fmt.Println("Initiating a block with ", toEmulate, " spends")

	tx := BlockContent{
		mints:  make([]MintProof, 0, 0),
		spends: make([]SpendProof, 0, 0),
	}

	for i := 0; i < toEmulate; i++ {
		w := MintWitness{ // The MimbleWimble coin witness
			v: newScalar(rand.Intn(1000)),
			r: randomScalar(),
		}
		cC := AddP(MulP(base.h, w.v), MulP(base.j, w.r)) // The MimbleWimble coin
		mintProof, err := w.generateProof(base, cC)      // Generating the mintproof from witness and coin.
		if err != nil {
			fmt.Println(err)
		}
		tx = tx.Join(CreateBlockContentMint(mintProof))
	}

	oOOMWitnesses := make([]OOOMWitness, 0, toEmulate)
	for i := 0; i < toEmulate; i++ {
		// Defining a shielded coin, with a witness and generating the proofs
		oOOMwitness := newOOOMWitness(base, randomScalar(), newScalar(rand.Intn(1000)), randomScalar(), rand.Intn(N))
		shieldedCoin := commit(base, oOOMwitness.s, oOOMwitness.v, oOOMwitness.r)
		cmList[oOOMwitness.l] = shieldedCoin // This should happen outside, elseway we fuck up the other proofs!
		oOOMWitnesses = append(oOOMWitnesses, oOOMwitness)
		fmt.Print(oOOMwitness.l, " ")
	}
	fmt.Println("")

	for i := 0; i < toEmulate; i++ {
		oooms := make([]OOOMWitness, 0, 1)
		outputs := make([]MWCoinWitness, 0, 2)

		oOOMwitness := oOOMWitnesses[i]
		oooms = append(oooms, oOOMwitness)
		outputs = append(outputs, MWCoinWitness{
			v: oOOMwitness.v,
			r: randomScalar(),
		})
		if rand.Intn(2) > 0 {
			outputs = append(outputs, MWCoinWitness{
				v: newScalar(0),
				r: randomScalar(),
			})
		}

		spendWitness := SpendWitness{
			oooms:   oooms,
			outputs: outputs,
		}

		spendProof := spendWitness.Prove(base, cmList)

		tx = tx.Join(CreateBlockContentSpend(spendProof))
	}

	totOutputs := 0
	for _, spend := range tx.spends {
		totOutputs = totOutputs + len(spend.cS)
	}

	start := time.Now()
	fmt.Println("Initiating verification of block content. Mints: ", len(tx.mints), ", Spends: ", len(tx.spends), " with ", totOutputs, " outputs")
	if !tx.Verify(base, cmList) {
		fmt.Println("We have big issues, the transactions does not validate!")
	}
	fmt.Println("Block content verified in ", time.Now().Sub(start))
}

func testMultiSpend() {
	base := Base{
		g: suite.Point().Base(),
		j: MulP(suite.Point().Base(), newScalar(base2)),
		h: MulP(suite.Point().Base(), newScalar(base3)),
	}

	cmList := [N]kyber.Point{}
	start := time.Now()
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

	fmt.Println("Minting and spending a single coin finished")

	// Testing with multiple spends
	fmt.Println("Testing with two inputs")
	oOOMwitness := newOOOMWitness(base, newScalar(22), newScalar(25), newScalar(23), rand.Intn(N))
	oOOMwitness2 := newOOOMWitness(base, newScalar(12322), newScalar(123), newScalar(2543), rand.Intn(N))
	shieldedCoin := commit(base, oOOMwitness.s, oOOMwitness.v, oOOMwitness.r)
	shieldedCoin2 := commit(base, oOOMwitness2.s, oOOMwitness2.v, oOOMwitness2.r)

	if oOOMwitness.l == oOOMwitness2.l {
		fmt.Println("The randomly picked indexes are identical!")
	}

	cmList[oOOMwitness.l] = shieldedCoin
	cmList[oOOMwitness2.l] = shieldedCoin2

	start = time.Now()

	oooms := make([]OOOMWitness, 0, 2)
	outputs := make([]MWCoinWitness, 0, 2)

	oooms = append(oooms, oOOMwitness)
	oooms = append(oooms, oOOMwitness2)
	outputs = append(outputs, MWCoinWitness{
		v: oOOMwitness.v,
		r: randomScalar(),
	})
	outputs = append(outputs, MWCoinWitness{
		v: oOOMwitness2.v,
		r: randomScalar(),
	})

	spendWitness := SpendWitness{
		oooms:   oooms,
		outputs: outputs,
	}

	spendProof := spendWitness.Prove(base, cmList)
	fmt.Println("Proving spend in: ", time.Now().Sub(start))
	tx := CreateBlockContentSpend(spendProof)
	//tx = tx.Join(CreateBlockContentMint(mintProof))

	start = time.Now()
	//r = spendProof.Verify(base, cmList)
	//fmt.Println("Verifying spend to: ", r, "in ", time.Now().Sub(start))

	r := tx.Verify(base, cmList)
	fmt.Println("Verifying spend to: ", r, "in ", time.Now().Sub(start))
}

func testSingleSpend() {
	//	Initialization. Will define the base and generate a initial set of shielded coins.
	base := Base{
		g: suite.Point().Base(),
		j: MulP(suite.Point().Base(), newScalar(base2)),
		h: MulP(suite.Point().Base(), newScalar(base3)),
	}

	cmList := [N]kyber.Point{}
	start := time.Now()
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

	init := time.Now().Sub(start)
	fmt.Println("Init finished in: ", init)

	// Testing the minting proofs!

	//	Given a MimbleWimble coin witness, generate a proof for minting a shielded coin.
	start = time.Now()
	w := newMintWitness(5, 25)                       // The MimbleWimble coin witness
	cC := AddP(MulP(base.h, w.v), MulP(base.j, w.r)) // The MimbleWimble coin
	mintProof, err := w.generateProof(base, cC)      // Generating the mintproof from witness and coin.
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("Generated mint proof in: ", time.Now().Sub(start))
	start = time.Now()
	// Validate the minting proof.
	if !mintProof.Verify() {
		fmt.Println("Minting proof validation was unsuccessful")
	}
	fmt.Println("Mint proof validated in: ", time.Now().Sub(start))

	// The shielded coin is then extracted from the proof
	shieldedIndex := rand.Intn(N) // In practice it is appended to the list, not randomly assigned
	shieldedCoin := mintProof.cD

	// Spending the coin
	start = time.Now()
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
	fmt.Println("Proving spend in: ", time.Now().Sub(start))

	start = time.Now()
	r := spendProof.Verify(base, cmList)
	fmt.Println("Verifying spend to: ", r, "in ", time.Now().Sub(start))
}
