package main

import "go.dedis.ch/kyber/v3"

type BlockContent struct {
	mints  []MintProof
	spends []SpendProof
}

func CreateBlockContentSpend(proof SpendProof) BlockContent {
	totMints := make([]MintProof, 0, 1)
	totSpends := make([]SpendProof, 0, 1)

	totSpends = append(totSpends, proof)

	return BlockContent{
		mints:  totMints,
		spends: totSpends,
	}
}

func CreateBlockContentMint(proof MintProof) BlockContent {
	totMints := make([]MintProof, 0, 1)
	totSpends := make([]SpendProof, 0, 1)

	totMints = append(totMints, proof)

	return BlockContent{
		mints:  totMints,
		spends: totSpends,
	}
}

func (tx BlockContent) Join(other BlockContent) BlockContent {
	totMints := make([]MintProof, 0, len(tx.mints)+len(other.mints))
	totSpends := make([]SpendProof, 0, len(tx.spends)+len(other.spends))

	for _, mint := range tx.mints {
		totMints = append(totMints, mint)
	}
	for _, mint := range other.mints {
		totMints = append(totMints, mint)
	}

	for _, spend := range tx.spends {
		totSpends = append(totSpends, spend)
	}

	for _, spend := range other.spends {
		totSpends = append(totSpends, spend)
	}

	return BlockContent{
		mints:  totMints,
		spends: totSpends,
	}
}

func (tx BlockContent) Verify(base Base, cmList [N]kyber.Point) bool {
	// TODO, this should also update lists, and take non-shielded into account, for now, just simple.
	// Should remove elements from the mw sets, and add to the shielded. For now, just run the validations.
	for _, mint := range tx.mints {
		if !mint.Verify() {
			return false
		}
	}

	for _, spend := range tx.spends {
		if !spend.Verify(base, cmList) {
			return false
		}
	}

	return true
}
