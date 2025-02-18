package keyrecovery

import (
	"errors"
	BN254_fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	SECP256K1_fr "github.com/consensys/gnark-crypto/ecc/secp256k1/fr"
)

func Recover(threshold int, shares []Share) (string, string, error) {

	// Check if the number of shares is less than the threshold
	if len(shares) < threshold {
		return "", "", errors.New("number of shares is less than the threshold")
	}

	points, err := choosePointsFromShares(threshold, shares)
	if err != nil {
		return "", "", err
	}

	return recoverFromPoints(points)

}

func recoverFromPoints(points []point) (string, string, error) {

	// Define the spending key and viewing key as field elements for calculations
	var sk SECP256K1_fr.Element
	var vk BN254_fr.Element

	// Initialize the spending key and viewing key as zero
	sk.SetZero()
	vk.SetZero()

	// Recover the spending key and viewing key from the shares
	//  		n             n
	// Result = Σ  y_i   *    Π ( x_j / (x_j - x_i) )
	// 		   i=1           j=1
	// 						j ≠ i

	for i := range points {
		// Current term = y_i
		var lsk SECP256K1_fr.Element
		var lvk BN254_fr.Element
		lsk.Set(&points[i].yS)
		lvk.Set(&points[i].yV)

		// Denominators for the Lagrange basis Li
		denominatorS := SECP256K1_fr.One()
		denominatorV := BN254_fr.One()

		// Apply Li to the current term
		for j := range points {
			if i == j {
				continue
			}

			// current term * xj
			lsk.Mul(&lsk, &points[j].xS)
			lvk.Mul(&lvk, &points[j].xV)

			// xj - xi
			var diffS SECP256K1_fr.Element
			var diffV BN254_fr.Element
			diffS.Sub(&points[j].xS, &points[i].xS)
			diffV.Sub(&points[j].xV, &points[i].xV)

			// denominator *= (xj - xi)
			denominatorS.Mul(&denominatorS, &diffS)
			denominatorV.Mul(&denominatorV, &diffV)
		}

		// Divide by the denominator
		lsk.Div(&lsk, &denominatorS)
		lvk.Div(&lvk, &denominatorV)

		// Add the current term to the spending key and viewing key
		sk.Add(&sk, &lsk)
		vk.Add(&vk, &lvk)
	}

	return sk.Text(16), vk.Text(16), nil
}

func choosePointsFromShares(threshold int, shares []Share) ([]point, error) {

	shareMap := make(map[string]int)
	for i, share := range shares {
		shareMap[share.Point] = i
	}

	// We should have at least threshold of distinct x points
	if len(shareMap) < threshold {
		return nil, errors.New("number of shares with distinct points is less than the threshold")
	}

	var points = make([]point, 0, threshold)

	// Transform the shares from string to field element before interpolating
	for xStr, shareIdx := range shareMap {
		var p point
		_, errX1 := p.xS.SetString("0x" + xStr)
		_, errX2 := p.xV.SetString("0x" + xStr)
		_, errY1 := p.yS.SetString("0x" + shares[shareIdx].SpendingEval)
		_, errY2 := p.yV.SetString("0x" + shares[shareIdx].ViewingEval)

		if errX1 != nil {
			return nil, errX1
		}
		if errX2 != nil {
			return nil, errX2
		}
		if errY1 != nil {
			return nil, errY1
		}
		if errY2 != nil {
			return nil, errY2
		}

		points = append(points, p)
	}
	return points, nil
}

type point struct {
	xS SECP256K1_fr.Element
	xV BN254_fr.Element
	yS SECP256K1_fr.Element
	yV BN254_fr.Element
}
