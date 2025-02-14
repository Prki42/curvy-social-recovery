package keyrecovery

import (
	"errors"

	BN254_fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	SECP256K1_fr "github.com/consensys/gnark-crypto/ecc/secp256k1/fr"
)

func Split(threashold_t, numberOfShares_n uint64, spendingKey_sk, viewingKey_vk string) ([]Share, error) {
	
	if threashold_t > numberOfShares_n {
		return nil, errors.New("threashold t should be less than or equal to number of shares n")
	}

	// Generate the polynomials for the spending key and viewing key
	var skPolynomial []SECP256K1_fr.Element = make([]SECP256K1_fr.Element, threashold_t)
	var vkPolynomial []BN254_fr.Element = make([]BN254_fr.Element, threashold_t)

	// Generate random coefficients for the polynomials
	for i := uint64(1); i < threashold_t; i++ {
		_, errs := skPolynomial[i].SetRandom()
		_, errv := vkPolynomial[i].SetRandom()

		if errs != nil {
			return nil, errs
		}
		if errv != nil {
			return nil, errv
		}
	}
	
	// Set the free coefficients of the polynomials to the spending key and viewing key
	_, errs := skPolynomial[0].SetString(spendingKey_sk)
	_, errv := vkPolynomial[0].SetString(viewingKey_vk)

	if errs != nil {
		return nil, errs
	}
	if errv != nil {
		return nil, errv
	}

	// Generate the shares
	var shares []Share = make([]Share, numberOfShares_n)
	for i := uint64(0); i < numberOfShares_n; i++ {
		// Define x coordinate for the share as field element
		var xsk SECP256K1_fr.Element
		var xvk BN254_fr.Element
		xsk.SetUint64(i+1)
		xvk.SetUint64(i+1)

		// Evaluate the polynomials at the x coordinate
		var y1 SECP256K1_fr.Element = evalSpending(skPolynomial, xsk)
		var y2 BN254_fr.Element = evalViewing(vkPolynomial, xvk)

		// Set the share
		shares[i].SetX(xsk.String())
		shares[i].SetSpending(y1.String())
		shares[i].SetViewing(y2.String())
	}

	return shares, nil
}

// https://github.com/Consensys/gnark-crypto/blob/master/ecc/bn254/fr/polynomial/polynomial.go line 25

func evalSpending(polynomial []SECP256K1_fr.Element, x SECP256K1_fr.Element) SECP256K1_fr.Element {
	var result SECP256K1_fr.Element = polynomial[len(polynomial) - 1]
	for i := len(polynomial) - 2; i >= 0; i-- {
		result.Mul(&result, &x)
		result.Add(&result, &polynomial[i])
	}
	return result
}

func evalViewing(polynomial []BN254_fr.Element, x BN254_fr.Element) BN254_fr.Element {
	var result BN254_fr.Element = polynomial[len(polynomial) - 1]
	for i := len(polynomial) - 2; i >= 0; i-- {
		result.Mul(&result, &x)
		result.Add(&result, &polynomial[i])
	}
	return result
}