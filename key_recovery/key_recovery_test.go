package keyrecovery

import (
	BN254_fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	SECP256K1_fr "github.com/consensys/gnark-crypto/ecc/secp256k1/fr"
	"testing"
)

func TestSplitAndRecover(t *testing.T) {
	var spendingKey SECP256K1_fr.Element
	var viewingKey BN254_fr.Element

	_, err := spendingKey.SetRandom()
	if err != nil {
		t.Fatal(err)
	}
	_, err = viewingKey.SetRandom()
	if err != nil {
		t.Fatal(err)
	}

	spendingKeyStr := "0x" + spendingKey.Text(16)
	viewingKeyStr := "0x" + viewingKey.Text(16)

	n := 20
	threshold := 14

	t.Logf("Spending key: %s\n", spendingKeyStr)
	t.Logf("Viewing key: %s\n", viewingKeyStr)

	shares, err := Split(threshold, n, spendingKeyStr, viewingKeyStr)
	if err != nil {
		t.Fatalf("Failed to construct the shares: %s", err)
	}

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
			t.Fatalf("Failed to recover the shares: %s", err)
		}
		if newSpendingKeyStr != spendingKeyStr {
			t.Errorf("Spending keys do not match")
		}
		if newViewingKeyStr != viewingKeyStr {
			t.Errorf("Viewing keys do not match")
		}
	})

	t.Run("given shares = t - 1 < t", func(t *testing.T) {
		_, _, err := Recover(threshold, shares[0:threshold-1])
		if err == nil {
			t.Error("Keys should not have been reconstructed")
		}
	})
}
