package v2

import (
	"fmt"
)

var supportedCiphers = []stringer{
	CipherChaCha20Poly1305, CipherAES256GCM, CipherAES128GCM, CipherAES256CTE, CipherAES192CTR, CipherAES128CTR,
	CipherAES128CBC, CipherArcFour256, CipherArcFour128, CipherArcFour, CipherTripleDESCBCID,
}

// Cipher is the SSH cipher
type Cipher string

// Cipher is the SSH cipher
const (
	CipherChaCha20Poly1305 Cipher = "chacha20-poly1305@openssh.com"
	CipherAES256GCM        Cipher = "aes256-gcm@openssh.com"
	CipherAES128GCM        Cipher = "aes128-gcm@openssh.com"
	CipherAES256CTE        Cipher = "aes256-ctr"
	CipherAES192CTR        Cipher = "aes192-ctr"
	CipherAES128CTR        Cipher = "aes128-ctr"
	CipherAES128CBC        Cipher = "aes128-cbc"
	CipherArcFour256       Cipher = "arcfour256"
	CipherArcFour128       Cipher = "arcfour128"
	CipherArcFour          Cipher = "arcfour"
	CipherTripleDESCBCID   Cipher = "tripledescbcID"
)

// String creates a string representation.
func (c Cipher) String() string {
	return string(c)
}

// Validate validates the cipher
func (c Cipher) Validate() error {
	if c == "" {
		return fmt.Errorf("empty cipher name")
	}
	for _, supportedCiphers := range supportedCiphers {
		if c == supportedCiphers {
			return nil
		}
	}
	return fmt.Errorf("invalid cipher name: %s", c)
}
