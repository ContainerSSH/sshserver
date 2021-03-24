package sshserver

// CipherList is a list of supported ciphers
type CipherList []Cipher

// Validate validates the list of ciphers to contain only supported items.
func (c CipherList) Validate() error {
	if len(c) == 0 {
		return nil
	}

	for _, cipher := range c {
		if err := cipher.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// StringList returns a list of cipher names.
func (c CipherList) StringList() []string {
	ciphers := make([]string, len(c))
	for i, v := range c {
		ciphers[i] = v.String()
	}
	return ciphers
}
