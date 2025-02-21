package keyrecovery

import "fmt"

type DuplicatePointInSharesError struct {
	Idx   int
	Point string
}

func (err DuplicatePointInSharesError) Error() string {
	return fmt.Sprintf("possible tampering, point 0x%s (at index %d) appears more than once", err.Point, err.Idx)
}

type RecoveredKeysDoNotMatchError struct{}

func (err RecoveredKeysDoNotMatchError) Error() string {
	return "tampering detected, keys do not match"
}

type NumberOfSharesLessThanThreshold struct {
	N int
	T int
}

func (err NumberOfSharesLessThanThreshold) Error() string {
	return fmt.Sprintf("number of shares less than threshold, n=%d < t=%d", err.N, err.T)
}
