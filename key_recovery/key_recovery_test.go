package keyrecovery

import (
	"testing"
)

const (
	originalSpendingKey = "123456789"
	originalViewingKey = "987654321"
	numberOfShares_n = uint64(10)
	threshold_t = uint64(6)
)


func TestAllShares(t *testing.T) {
	// Split the original spending key and viewing key into shares
	shares, err := Split(threshold_t, numberOfShares_n, originalSpendingKey, originalViewingKey)
	if err != nil {
		t.Errorf("Error splitting the key: %v", err)
	}
	if uint64(len(shares)) != numberOfShares_n {
		t.Errorf("The number of shares is not equal to the number of shares requested")
	}

	// Recover the original spending key and viewing key from all the shares
	sk, vk, err := Recover(threshold_t, shares)
	if err != nil {
		t.Errorf("Error recovering the key: %v", err)
	}
	if sk != originalSpendingKey {
		t.Errorf("The recovered spending key is not the same as the original spending key")
	}
	if vk != originalViewingKey {
		t.Errorf("The recovered viewing key is not the same as the original viewing key")
	}
}

func TestMoreThenT(t *testing.T) {
	// Split the original spending key and viewing key into shares
	shares, err := Split(threshold_t, numberOfShares_n, originalSpendingKey, originalViewingKey)
	if err != nil {
		t.Errorf("Error splitting the key: %v", err)
	}
	if uint64(len(shares)) != numberOfShares_n {
		t.Errorf("The number of shares is not equal to the number of shares requested")
	}

	// Recover the original spending key and viewing key from more than t shares
	sk, vk, err := Recover(threshold_t, shares[0:threshold_t+1])
	if err != nil {
		t.Errorf("Error recovering the key: %v", err)
	}
	if sk != originalSpendingKey {
		t.Errorf("The recovered spending key is not the same as the original spending key")
	}
	if vk != originalViewingKey {
		t.Errorf("The recovered viewing key is not the same as the original viewing key")
	}
}

func TestExaclyT(t *testing.T) {
	// Split the original spending key and viewing key into shares
	shares, err := Split(threshold_t, numberOfShares_n, originalSpendingKey, originalViewingKey)
	if err != nil {
		t.Errorf("Error splitting the key: %v", err)
	}	
	if uint64(len(shares)) != numberOfShares_n {
		t.Errorf("The number of shares is not equal to the number of shares requested")
	}

	// Recover the original spending key and viewing key from exactly t shares
	sk, vk, err := Recover(threshold_t, shares[0:threshold_t])
	if err != nil {
		t.Errorf("Error recovering the key: %v", err)
	}
	if sk != originalSpendingKey {
		t.Errorf("The recovered spending key is not the same as the original spending key")
	}
	if vk != originalViewingKey {
		t.Errorf("The recovered viewing key is not the same as the original viewing key")
	}
}

func TestLessThenT(t *testing.T) {
	// Split the original spending key and viewing key into shares
	shares, err := Split(threshold_t, numberOfShares_n, originalSpendingKey, originalViewingKey)
	if err != nil {
		t.Errorf("Error splitting the key: %v", err)
	}
	if uint64(len(shares)) != numberOfShares_n {
		t.Errorf("The number of shares is not equal to the number of shares requested")
	}

	// Recover the original spending key and viewing key from less than t shares
	sk, vk, err := Recover(threshold_t, shares[0:threshold_t-1])
	if err == nil {
		t.Errorf("The key was recovered from less than t shares")
	}
	if sk == originalSpendingKey {
		t.Errorf("The recovered spending key is the same as the original spending key")
	}
	if vk == originalViewingKey {
		t.Errorf("The recovered viewing key is the same as the original viewing key")
	}
}

func TestShareManipulation(t *testing.T) {
	// Split the original spending key and viewing key into shares
	shares, err := Split(threshold_t, numberOfShares_n, originalSpendingKey, originalViewingKey)
	if err != nil {
		t.Errorf("Error splitting the key: %v", err)
	}
	if uint64(len(shares)) != numberOfShares_n {
		t.Errorf("The number of shares is not equal to the number of shares requested")
	}

	// Change the spending coordinate of the first share
	var backup string = shares[0].GetSpending()
	shares[0].SetSpending("4582635")
	sk, vk, err := Recover(threshold_t, shares)
	if err != nil {
		t.Errorf("Error recovering the key: %v", err)
	}
	if sk == originalSpendingKey {
		t.Errorf("The recovered spending key is the same as the original spending key")
	}
	if vk != originalViewingKey {
		t.Errorf("The recovered viewing key should be the same as the original viewing key")
	}

	// Restore the spending coordinate of the first share
	shares[0].SetSpending(backup)

	// Change the viewing key of the first share
	backup = shares[0].GetViewing()
	shares[0].SetViewing("5684125")
	sk, vk, err = Recover(threshold_t, shares)
	if err != nil {
		t.Errorf("Error recovering the key: %v", err)
	}
	if sk != originalSpendingKey {
		t.Errorf("The recovered spending key should be the same as the original spending key")
	}
	if vk == originalViewingKey {
		t.Errorf("The recovered viewing key is the same as the original viewing key")
	}
	// Restore the viewing key of the first share
	shares[0].SetViewing(backup)

	// Change the x coordinate of the first share
	backup = shares[0].GetX()
	shares[0].SetX("567")
	sk, vk, err = Recover(threshold_t, shares)
	if err != nil {
		t.Errorf("Error recovering the key: %v", err)
	}
	if sk == originalSpendingKey {
		t.Errorf("The recovered spending key is the same as the original spending key")
	}
	if vk == originalViewingKey {
		t.Errorf("The recovered viewing key is the same as the original viewing key")
	}
	// Restore the x coordinate of the first share
	shares[0].SetX(backup)

	// Change first share to a random share
	shares[0].SetX("123")
	shares[0].SetSpending("456")
	shares[0].SetViewing("789")

	sk, vk, err = Recover(threshold_t, shares)
	if err != nil {
		t.Errorf("Error recovering the key: %v", err)
	}
	if sk == originalSpendingKey {
		t.Errorf("The recovered spending key is the same as the original spending key")
	}
	if vk == originalViewingKey {
		t.Errorf("The recovered viewing key is the same as the original viewing key")
	}

	// Drop the first share
	shares = shares[1:]
	sk, vk, err = Recover(threshold_t, shares)
	if err != nil {
		t.Errorf("Error recovering the key: %v", err)
	}
	if sk != originalSpendingKey {
		t.Errorf("The recovered spending key is not the same as the original spending key")
	}
	if vk != originalViewingKey {
		t.Errorf("The recovered viewing key is not the same as the original viewing key")
	}
}

// Provera da li se kljevi razlikuju ukoliko je neki od share-ova promenjen a koriste se različiti skupovi
// share-ova za rekonstrukciju
// func TestTempering(t *testing.T) {
// 	// Split the original spending key and viewing key into shares
// 	shares, err := Split(threshold_t, numberOfShares_n, originalSpendingKey, originalViewingKey)
// 	if err != nil {
// 		t.Errorf("Error splitting the key: %v", err)
// 	}
// 	if uint64(len(shares)) != numberOfShares_n {
// 		t.Errorf("The number of shares is not equal to the number of shares requested")
// 	}

// 	// Change the spending coordinate of the first share
// 	shares[1].SetSpending("4582635")
// 	sk, _, _ := Recover(threshold_t, shares[0:threshold_t])
// 	sk2, _, _ := Recover(threshold_t, shares[1:threshold_t+1])
// 	sk3, _, _ := Recover(threshold_t, shares[2:threshold_t+2])
// 	sh4 := shares[1:threshold_t-1]
// 	sh4 = append(sh4, shares[numberOfShares_n - 1])
// 	sh4 = append(sh4, shares[numberOfShares_n - 2])
// 	sk4, _, _ := Recover(threshold_t, sh4)
// 	fmt.Println(sk)
// 	fmt.Println(sk2)
// 	fmt.Println(sk3)
// 	fmt.Println("SK4:" , sk4)
// }