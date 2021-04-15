package v2

import (
	"fmt"
)

// KexList is a list of key exchange algorithms.
type KexList []Kex

// Validate validates the key exchange list
func (k KexList) Validate() error {
	if len(k) == 0 {
		return fmt.Errorf("the key exchange list cannot be empty")
	}
	for _, kex := range k {
		if err := kex.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// StringList returns a list of key exchange algorithms as a list.
func (k KexList) StringList() []string {
	result := make([]string, len(k))
	for i, kex := range k {
		result[i] = kex.String()
	}
	return result
}
