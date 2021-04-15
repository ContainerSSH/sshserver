package v2

import (
	"fmt"
)

// KeyAlgoList is a list of key algorithms.
type KeyAlgoList []KeyAlgo

// Validate validates the list of ciphers to contain only supported items.
func (h KeyAlgoList) Validate() error {
	if len(h) == 0 {
		return fmt.Errorf("host key algorithm list cannot be empty")
	}
	for _, algo := range h {
		if err := algo.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// StringList returns a list of cipher names.
func (h KeyAlgoList) StringList() []string {
	algos := make([]string, len(h))
	for i, v := range h {
		algos[i] = v.String()
	}
	return algos
}
