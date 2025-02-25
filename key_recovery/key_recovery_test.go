package keyrecovery

import (
	"fmt"
	"testing"

	BN254_fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	SECP256K1_fr "github.com/consensys/gnark-crypto/ecc/secp256k1/fr"
)

func TestSplitAndRecover(t *testing.T) {
	n := 20
	threshold := 14

	shares, spendingKeyStr, viewingKeyStr, err := setupRandomShares(n, threshold)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Spending key: %s\n", spendingKeyStr)
	t.Logf("Viewing key: %s\n", viewingKeyStr)
	t.Logf("Shares: %v\n", shares)

	t.Run("Split: xi != 0 for all i", func(t *testing.T) {
		for _, share := range shares {
			if share.Point == "0" {
				t.Fatal("One share evaluation point is zero")
			}
		}
	})

	t.Run("Split: xi != xj for i != j", func(t *testing.T) {
		for i, share := range shares {
			for j := i + 1; j < len(shares); j++ {
				if share.Point == shares[j].Point {
					t.Fatal("Two shares have the same evaluation point")
				}
			}
		}
	})

	t.Run("Recover with given shares = t", func(t *testing.T) {
		newSpendingKeyStr, newViewingKeyStr, err := Recover(threshold, shares[0:threshold])
		t.Logf("Recovered spending key: %s\n", newSpendingKeyStr)
		t.Logf("Recovered viewing key: %s\n", newViewingKeyStr)
		if err != nil {
			t.Fatalf("Failed to recover the shares: %s", err)
		}
		if newSpendingKeyStr != spendingKeyStr {
			t.Error("Spending keys do not match")
		}
		if newViewingKeyStr != viewingKeyStr {
			t.Error("Viewing keys do not match")
		}
	})

	t.Run("Recover with given shares = t + 1 > t", func(t *testing.T) {
		newSpendingKeyStr, newViewingKeyStr, err := Recover(threshold, shares[0:threshold+1])
		t.Logf("Recovered spending key: %s\n", newSpendingKeyStr)
		t.Logf("Recovered viewing key: %s\n", newViewingKeyStr)
		if err != nil {
			t.Fatalf("Failed to recover the shares: %s\n", err)
		}
		if newSpendingKeyStr != spendingKeyStr {
			t.Error("Spending keys do not match")
		}
		if newViewingKeyStr != viewingKeyStr {
			t.Error("Viewing keys do not match")
		}
	})

	t.Run("Recover with given shares = t - 1 < t", func(t *testing.T) {
		_, _, err := Recover(threshold, shares[0:threshold-1])
		if err == nil {
			t.Error("Keys should not have been reconstructed")
		}
	})

	t.Run("Recover with shares containing duplicate points", func(t *testing.T) {
		sharesCopy := make([]Share, threshold)
		copy(sharesCopy, shares[0:threshold])
		sharesCopy[0].Point = sharesCopy[1].Point

		t.Logf("Shares given: %v\n", sharesCopy)

		_, _, err := Recover(threshold, sharesCopy[0:threshold])
		if err == nil {
			t.Error("Keys should not have been reconstructed")
		}
	})

	t.Run("Recover with given shares = t + 1 and one is modified", func(t *testing.T) {
		sharesCopy := make([]Share, threshold+1)
		copy(sharesCopy, shares[0:threshold+1])

		var skEval SECP256K1_fr.Element
		_, err := skEval.SetString("0x" + sharesCopy[0].SpendingEval)
		if err != nil {
			t.Fatal(err)
		}
		var vkEval BN254_fr.Element
		_, err = vkEval.SetString("0x" + sharesCopy[0].ViewingEval)
		if err != nil {
			t.Fatal(err)
		}

		skEval.Double(&skEval)
		vkEval.Double(&vkEval)

		sharesCopy[0].SpendingEval = skEval.Text(16)
		sharesCopy[0].ViewingEval = vkEval.Text(16)

		t.Logf("Shares given: %v\n", sharesCopy)

		_, _, err = Recover(threshold, sharesCopy)

		if err == nil {
			t.Error("Keys should not have been reconstructed")
		}
	})

}

func TestExtractPointsFromShares(t *testing.T) {
	n := 20
	threshold := 14

	shares, _, _, err := setupRandomShares(n, threshold)
	if err != nil {
		t.Fatal(err)
	}

	points, err := extractPointsFromShares(shares, threshold)
	if err != nil {
		t.Fatal(err)
	}

	if len(points) > threshold {
		t.Fatal("extractPointsFromShare returned more points than expected")
	}
}

func TestPointsUnique(t *testing.T) {
	shares, _, _, err := setupRandomShares(20, 14)
	if err != nil {
		t.Fatal(err)
	}

	shares = append(shares, shares[0])

	valid, _ := pointsUnique(shares)

	if valid {
		t.Error("Duplicate point not detected")
	}
}

func TestPointFromShare(t *testing.T) {
	var sk SECP256K1_fr.Element
	_, err := sk.SetRandom()
	if err != nil {
		t.Fatal(err)
	}
	var vk BN254_fr.Element
	_, err = vk.SetRandom()
	if err != nil {
		t.Fatal(err)
	}

	s := Share{
		Point:        "1",
		SpendingEval: sk.Text(16),
		ViewingEval:  vk.Text(16),
	}

	var p point
	err = p.fromShare(s)
	if err != nil {
		t.Fatalf("failed to recover point from share: %s\n", err)
	}

	if !sk.Equal(&p.yS) {
		t.Fatal("spending key does not match")
	}

	if !vk.Equal(&p.yV) {
		t.Fatal("viewing key does not match")
	}

}

func BenchmarkSplitAndRecover(b *testing.B) {
	spendingKeyStr, viewingKeyStr, err := setupRandomKeys()
	if err != nil {
		b.Fatal(err)
	}

	n := 20
	threshold := 14

	b.Run("Split", func(b *testing.B) {
		b.ResetTimer()
		for range b.N {
			Split(threshold, n, spendingKeyStr, viewingKeyStr)
		}
	})

	shares, err := Split(threshold, n, spendingKeyStr, viewingKeyStr)
	if err != nil {
		b.Fatal(err)
	}

	b.Run("Recover (full)", func(b *testing.B) {
		b.ResetTimer()
		for range b.N {
			Recover(threshold, shares)
		}
	})

	b.Run("Recover (from chosen points)", func(b *testing.B) {
		points, err := extractPointsFromShares(shares, threshold)
		if err != nil {
			b.Fatal(err)
		}

		b.ResetTimer()
		for range b.N {
			recoverFromPoints(points)
		}
	})

}

func setupRandomKeys() (string, string, error) {
	var spendingKey SECP256K1_fr.Element
	var viewingKey BN254_fr.Element

	_, err := spendingKey.SetRandom()
	if err != nil {
		return "", "", fmt.Errorf("failed to generate random spending key: %v\n", err)
	}
	_, err = viewingKey.SetRandom()
	if err != nil {
		return "", "", fmt.Errorf("failed to generate random viewing key: %v\n", err)
	}

	spendingKeyStr := spendingKey.Text(16)
	viewingKeyStr := viewingKey.Text(16)

	return spendingKeyStr, viewingKeyStr, nil
}

func setupRandomShares(n, threshold int) ([]Share, string, string, error) {
	spendingKeyStr, viewingKeyStr, err := setupRandomKeys()
	if err != nil {
		return nil, "", "", err
	}

	shares, err := Split(threshold, n, spendingKeyStr, viewingKeyStr)
	if err != nil {
		return nil, "", "", fmt.Errorf("Failed to construct the shares: %s\n", err)
	}

	return shares, spendingKeyStr, viewingKeyStr, nil
}
