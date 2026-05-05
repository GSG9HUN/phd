package main

import (
	"fmt"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// SetRandom can fail and can generate zero, which we exclude.
func generateSecretKey() (*fr.Element, error) {
	var x fr.Element
	for {
		if _, err := x.SetRandom(); err != nil {
			return nil, fmt.Errorf("crypto/rand reading error: %w", err)
		}
		if !x.IsZero() {
			return &x, nil
		}
	}
}

func computePublicKey(x *fr.Element) *bls12381.G2Affine {
	_, _, _, G2 := bls12381.Generators()
	var xBig big.Int
	x.BigInt(&xBig)
	var X bls12381.G2Affine
	X.ScalarMultiplication(&G2, &xBig)
	return &X
}
