package sshserver

import (
	"fmt"
)

var supportedKexAlgos = []stringer{
	KexCurve25519SHA256, KexECDHSHA2Nistp256, KexECDHSHA2Nistp384, KexECDHSHA2NISTp521,
	KexDHGroup1SHA1, KexDHGroup14SHA1,
}

// Kex are the SSH key exchange algorithms
type Kex string

// Kex are the SSH key exchange algorithms
const (
	KexCurve25519SHA256 Kex = "curve25519-sha256@libssh.org"
	KexECDHSHA2NISTp521 Kex = "ecdh-sha2-nistp521"
	KexECDHSHA2Nistp384 Kex = "ecdh-sha2-nistp384"
	KexECDHSHA2Nistp256 Kex = "ecdh-sha2-nistp256"
	KexDHGroup14SHA1    Kex = "diffie-hellman-group14-sha1"
	KexDHGroup1SHA1     Kex = "diffie-hellman-group1-sha1"
)

// String creates a string representation.
func (k Kex) String() string {
	return string(k)
}

// Validate checks if a given Kex is valid.
func (k Kex) Validate() error {
	if k == "" {
		return fmt.Errorf("empty key exchange algorithm")
	}
	for _, algo := range supportedKexAlgos {
		if algo == k {
			return nil
		}
	}
	return fmt.Errorf("key exchange algorithm not supported: %s", k)
}
