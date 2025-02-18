package keyrecovery

import (
	"fmt"
	BN254_fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	SECP256K1_fr "github.com/consensys/gnark-crypto/ecc/secp256k1/fr"
	"math/rand"
	"testing"
	"time"
)

func TestSplitAndRecover(t *testing.T) {
	spendingKeyStr, viewingKeyStr, err := setupRandomKeys()
	if err != nil {
		t.Fatal(err)
	}

	n := 20
	threshold := 14

	t.Logf("Spending key: %s\n", spendingKeyStr)
	t.Logf("Viewing key: %s\n", viewingKeyStr)

	shares, err := Split(threshold, n, spendingKeyStr, viewingKeyStr)
	if err != nil {
		t.Fatalf("Failed to construct the shares: %s\n", err)
	}

	t.Logf("Shares: %v\n", shares)

	t.Run("xi != 0 for all i", func(t *testing.T) {
		for _, share := range shares {
			if share.Point == "0" {
				t.Fatal("One share evaluation point is zero")
			}
		}
	})

	t.Run("xi != xj for i != j", func(t *testing.T) {
		for i, share := range shares {
			for j := i + 1; j < len(shares); j++ {
				if share.Point == shares[j].Point {
					t.Fatal("Two shares have the same evaluation point")
				}
			}
		}
	})

	t.Run("given shares = t", func(t *testing.T) {
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

	t.Run("given shares = t + 1 > t", func(t *testing.T) {
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

	t.Run("given shares = t - 1 < t", func(t *testing.T) {
		_, _, err := Recover(threshold, shares[0:threshold-1])
		if err == nil {
			t.Error("Keys should not have been reconstructed")
		}
	})

	t.Run("given shares = t but has duplicate points", func(t *testing.T) {
		sharesCopy := make([]Share, threshold)
		copy(sharesCopy, shares[0:threshold])
		sharesCopy[0].Point = sharesCopy[1].Point
		_, _, err := Recover(threshold, sharesCopy[0:threshold])
		if err == nil {
			t.Error("Keys should not have been reconstructed")
		}
	})

	t.Run("given shares > t and non duplicate points >= t", func(t *testing.T) {
		sharesCopy := make([]Share, threshold*2)
		copy(sharesCopy, shares)
		copy(sharesCopy[threshold:], shares)

		r := rand.New(rand.NewSource(time.Now().UnixNano()))
		r.Shuffle(len(sharesCopy), func(i, j int) { sharesCopy[i], sharesCopy[j] = sharesCopy[j], sharesCopy[i] })

		newSpendingKeyStr, newViewingKeyStr, err := Recover(threshold, sharesCopy)
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
		points, err := choosePointsFromShares(threshold, shares)
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
