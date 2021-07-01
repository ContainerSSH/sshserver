package sshserver

import (
	"fmt"
)

// MACList is a list of MAC algorithms
type MACList []MAC

// Validate checks if the MACList is valid.
func (m MACList) Validate() error {
	if len(m) == 0 {
		return fmt.Errorf("empty MAC list")
	}
	for _, mac := range m {
		if err := mac.Validate(); err != nil {
			return fmt.Errorf("invalid MAC (%w)", err)
		}
	}
	return nil
}

// StringList returns a list of MAC names.
func (m MACList) StringList() []string {
	ciphers := make([]string, len(m))
	for i, v := range m {
		ciphers[i] = v.String()
	}
	return ciphers
}
